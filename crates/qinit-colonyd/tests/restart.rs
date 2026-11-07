// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! A colony that dies and is started again: the second one adopts what the first left, over the
//! fake cell layer and a fake process table. The real kill and restart are the `readopt` VM suite.
mod common;

use common::*;
use qinit_cell::{CellId, Notice, Report};
use qinit_colony::{Request, State};
use qinit_colonyd::args::Args;
use qinit_colonyd::daemon::Daemon;
use qinit_colonyd::readopt::{MainNow, Procs};
use qinit_colonyd::state::{CellLine, format_cells, parse_cells};
use qinit_colonyd::store::{KEY_CELLS, KEY_DB, KEY_NODES};
use qinit_colonyd::syslog::Syslog;
use qinit_ipc::memfd::{read_all, sealed};
use std::cell::RefCell;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixDatagram;

/// What every main's pidfd says: one answer for the whole test.
struct Table {
    now: MainNow,
    cgroup: u64,
}

impl Procs for Table {
    fn main_now(&self, _fd: &OwnedFd) -> MainNow {
        self.now
    }

    fn cgroup_id(&self, _fd: &OwnedFd) -> Option<u64> {
        Some(self.cgroup)
    }
}

/// The first colony's `db` main (cgroup 900) is alive.
fn alive() -> Table {
    Table {
        now: MainNow::Alive(4000),
        cgroup: 900,
    }
}

/// Nothing is left of any main.
fn gone() -> Table {
    Table {
        now: MainNow::Gone,
        cgroup: 0,
    }
}

/// Colonies one after another, with the queen that holds their state between them.
struct Site {
    tmp: Tmp,
    log: UnixDatagram,
    args: Args,
    queen: RefCell<FakeQueen>,
}

impl Site {
    fn new(tag: &str) -> Site {
        let tmp = Tmp::new(tag);
        let run = tmp.0.join("run");
        std::fs::create_dir_all(&run).unwrap();
        std::fs::create_dir_all(tmp.0.join("comb")).unwrap();
        let log = UnixDatagram::bind(tmp.0.join("log")).unwrap();
        for f in ["console", "kmsg"] {
            std::fs::write(tmp.0.join(f), b"").unwrap();
        }
        let args = Args {
            db: tmp.0.join("colony.db"),
            comb: tmp.0.join("comb"),
            socket: run.join("colony"),
            overseer: "/o".into(),
            syslog: tmp.0.join("log"),
            console: tmp.0.join("console"),
            run,
            queen_fd: None,
        };
        let (queen, _link) = FakeQueen::new();
        Site {
            tmp,
            log,
            args,
            queen: RefCell::new(queen),
        }
    }

    fn boot_over(
        &self,
        bytes: &[u8],
        cells: FakeCells,
        procs: &Table,
    ) -> Result<Daemon<FakeCells>, u8> {
        let log = Syslog::new(
            &self.args.syslog,
            &self.args.console,
            &self.tmp.0.join("kmsg"),
        );
        let store = self.queen.borrow_mut().reattach();
        inotify_slot();
        Daemon::boot_with(cells, &self.args, bytes, store, log, procs)
    }

    fn boot(
        &self,
        frames: &str,
        enable: &[&str],
        cells: FakeCells,
        procs: &Table,
    ) -> Daemon<FakeCells> {
        let bytes = database(frames, enable);
        self.boot_over(&bytes, cells, procs).expect("boots")
    }

    /// What queen holds under `key`, as text.
    fn entry(&self, key: u64) -> Option<String> {
        let mut q = self.queen.borrow_mut();
        q.pump();
        let fd = q.held.get(&key)?;
        Some(String::from_utf8(read_all(fd.as_fd(), 1 << 20).unwrap()).unwrap())
    }

    /// Replaces what queen holds under `key`.
    fn put_entry(&self, key: u64, text: &str) {
        self.queen.borrow_mut().pump();
        self.queen
            .borrow_mut()
            .held
            .insert(key, sealed(c"test", text.as_bytes()).unwrap());
    }

    fn cells(&self) -> Vec<CellLine> {
        parse_cells(&self.entry(KEY_CELLS).expect("a cells entry")).unwrap()
    }

    fn logged(&self) -> Vec<String> {
        self.log.set_nonblocking(true).unwrap();
        let mut out = Vec::new();
        let mut buf = [0u8; 512];
        while let Ok(n) = self.log.recv(&mut buf) {
            out.push(String::from_utf8_lossy(&buf[..n]).into_owned());
        }
        out
    }
}

const WORKER: &str = "[worker.db]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/db\"]\n";
const RESTARTING: &str = "[worker.db]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/db\"]\n\
                          restart = { policy = \"on-failure\", max = 3 }\n";

/// The first colony starts `db`, hears it is ready, and dies without cleaning up.
fn first_colony(site: &Site, frames: &str) {
    let mut a = site.boot(frames, &["db"], FakeCells::default(), &gone());
    a.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(0), Report::Ready));
    a.d_turn();
    drop(a);
}

trait Turn {
    fn d_turn(&mut self);
}

impl Turn for Daemon<FakeCells> {
    fn d_turn(&mut self) {
        assert_eq!(self.turn(Vec::new()), None);
    }
}

#[test]
fn a_second_colony_adopts_what_the_first_left() {
    let site = Site::new("adopt");
    first_colony(&site, WORKER);
    let saved = site.cells();
    assert_eq!(saved.len(), 1);
    assert!(saved[0].ready, "the first colony saved the ready flag");
    assert!(
        saved[0].dir_key >= 16 && saved[0].main_key >= 16,
        "{saved:?}"
    );
    let b = site.boot(WORKER, &["db"], FakeCells::default(), &alive());
    let calls = &b.colony.effects.cells.calls;
    assert_eq!(
        calls[0],
        Call::Adopt("db".into(), 900, true),
        "adopted with its main"
    );
    assert!(
        !calls.iter().any(|c| matches!(c, Call::Create(_))),
        "nothing was started again"
    );
    assert_eq!(b.colony.state(0), Some(State::Ready));
    let logged = site.logged();
    assert!(
        logged.iter().any(|l| l.contains("1 cells adopted")),
        "{logged:?}"
    );
    // And it keeps saying so: a third colony would adopt it ready too.
    assert!(site.cells()[0].ready);
}

#[test]
fn a_stopped_enabled_node_stays_stopped_across_the_restart() {
    let site = Site::new("stopped");
    let mut a = site.boot(WORKER, &["db"], FakeCells::default(), &gone());
    a.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(0), Report::Ready));
    a.d_turn();
    let out = a.colony.request(0, Request::Stop, 0);
    assert!(out.errors.is_empty());
    a.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(0), Report::MainExited(Some(0))));
    a.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(0), Report::Empty));
    a.d_turn();
    assert_eq!(a.colony.state(0), Some(State::Off));
    drop(a);
    let b = site.boot(WORKER, &["db"], FakeCells::default(), &gone());
    assert_eq!(
        b.colony.state(0),
        Some(State::Off),
        "the administrator's stop holds"
    );
    assert!(
        !b.colony
            .effects
            .cells
            .calls
            .iter()
            .any(|c| matches!(c, Call::Create(_))),
        "the enabled list is not applied again"
    );
}

#[test]
fn a_main_that_exited_while_colony_was_away_is_a_failure_with_unknown_status() {
    let site = Site::new("exited");
    first_colony(&site, RESTARTING);
    // The old main is gone; its cell is empty.
    let mut cells = FakeCells::default();
    cells.adopt_script.insert(
        "db".into(),
        Adopt {
            populated: false,
            ..Adopt::default()
        },
    );
    let b = site.boot(RESTARTING, &["db"], cells, &gone());
    let logged = site.logged();
    assert!(
        logged
            .iter()
            .any(|l| l.ends_with("db: failed (status unknown)")),
        "{logged:?}"
    );
    assert!(
        matches!(b.colony.state(0), Some(State::Waiting(_))),
        "on-failure restarts it: {:?}",
        b.colony.state(0)
    );
    assert!(
        b.colony.effects.cells.calls.contains(&Call::Remove(0)),
        "its empty cell was removed"
    );
}

#[test]
fn a_main_that_exited_with_a_recorded_status_reports_it() {
    let site = Site::new("status");
    first_colony(&site, RESTARTING);
    let mut cells = FakeCells::default();
    cells.adopt_script.insert(
        "db".into(),
        Adopt {
            populated: false,
            ..Adopt::default()
        },
    );
    let procs = Table {
        now: MainNow::Exited(9),
        cgroup: 900,
    };
    let _b = site.boot(RESTARTING, &["db"], cells, &procs);
    let logged = site.logged();
    assert!(
        logged.iter().any(|l| l.contains("db: failed")),
        "{logged:?}"
    );
    assert!(
        !logged
            .iter()
            .any(|l| l.ends_with("db: failed (status unknown)")),
        "the status is known: {logged:?}"
    );
}

#[test]
fn a_main_in_another_cgroup_is_not_the_main() {
    let site = Site::new("othercg");
    first_colony(&site, RESTARTING);
    // Alive, but in a cgroup that is not the recorded one: some other process.
    let other = Table {
        now: MainNow::Alive(4000),
        cgroup: 12345,
    };
    let mut b = site.boot(RESTARTING, &["db"], FakeCells::default(), &other);
    assert_eq!(
        b.colony.effects.cells.calls[0],
        Call::Adopt("db".into(), 900, false),
        "not adopted with that process as its main"
    );
    // The cell still has processes, so it is stopped as a cell, never through that pid.
    let g = std::time::Duration::from_millis(10_000);
    assert!(
        b.colony
            .effects
            .cells
            .calls
            .contains(&Call::Stop(0, qinit_cell::Polite::Cell, g, g)),
        "{:?}",
        b.colony.effects.cells.calls
    );
    assert!(
        !b.colony
            .effects
            .cells
            .calls
            .iter()
            .any(|c| matches!(c, Call::Signal(..))),
        "nothing is signalled through a pid"
    );
    // Once the cell is empty the exit is a failure of unknown status.
    b.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(0), Report::Empty));
    b.d_turn();
    assert!(
        site.logged()
            .iter()
            .any(|l| l.ends_with("db: failed (status unknown)"))
    );
}

#[test]
fn a_corrupt_nodes_entry_is_refused_and_only_cells_are_adopted() {
    let frames = "[worker.db]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/db\"]\n\
                  restart = { policy = \"on-failure\", max = 3 }\n\
                  [worker.web]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/web\"]\n";
    let site = Site::new("badnodes");
    let mut a = site.boot(frames, &["db", "web"], FakeCells::default(), &gone());
    a.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(1), Report::Ready));
    a.d_turn();
    drop(a);
    // `web` has its cell; `db` has none, and the entry says it is quarantined by the breaker with
    // no failures counted: not a table the scheduler can hold.
    let lines: Vec<CellLine> = site
        .cells()
        .into_iter()
        .filter(|c| c.name == "web")
        .collect();
    site.put_entry(KEY_CELLS, &format_cells(&lines));
    site.put_entry(KEY_NODES, "db 1 quarantined:breaker 0 0 0 0 0\n");
    let procs = Table {
        now: MainNow::Alive(4001),
        cgroup: lines[0].cgroup_id,
    };
    let b = site.boot(frames, &["db", "web"], FakeCells::default(), &procs);
    let web = b.colony.node_index("web").unwrap();
    assert_eq!(
        b.colony.state(web),
        Some(State::Ready),
        "the cell is adopted all the same"
    );
    let db = b.colony.node_index("db").unwrap();
    assert_ne!(
        b.colony.state(db),
        Some(State::Quarantined(qinit_colony::Reason::Breaker)),
        "the refused entry did not quarantine anything"
    );
    let logged = site.logged();
    let line = logged
        .iter()
        .find(|l| l.contains("saved node state is refused"))
        .unwrap_or_else(|| panic!("{logged:?}"));
    assert!(line.starts_with("<27>colony["), "an error: {line}");
}

#[test]
fn a_pipe_that_shares_a_key_with_a_cell_refuses_the_nodes_entry() {
    let site = Site::new("clash");
    first_colony(&site, WORKER);
    let cells = site.cells();
    assert_eq!(cells.len(), 1);
    // Two entries that name one descriptor would have it taken twice.
    site.put_entry(KEY_NODES, &format!("pipe lg {} 90\n", cells[0].dir_key));
    let procs = Table {
        now: MainNow::Alive(4001),
        cgroup: cells[0].cgroup_id,
    };
    let b = site.boot(WORKER, &["db"], FakeCells::default(), &procs);
    let logged = site.logged();
    assert!(
        logged
            .iter()
            .any(|l| l.contains("saved node state is refused") && l.contains("twice")),
        "{logged:?}"
    );
    let db = b.colony.node_index("db").unwrap();
    assert_eq!(
        b.colony.state(db),
        Some(State::Ready),
        "the cell is adopted all the same"
    );
}

#[test]
fn a_malformed_cells_entry_is_as_good_as_none() {
    let site = Site::new("garbled");
    first_colony(&site, WORKER);
    site.put_entry(KEY_CELLS, "db not-a-number\n");
    let b = site.boot(WORKER, &["db"], FakeCells::default(), &alive());
    assert!(
        b.colony
            .effects
            .cells
            .calls
            .iter()
            .any(|c| matches!(c, Call::Create(n) if n == "db")),
        "a clean start: the enabled node is started"
    );
    assert!(
        site.logged()
            .iter()
            .any(|l| l.contains("saved cell map is refused"))
    );
}

#[test]
fn leftover_instance_cells_are_stopped_and_removed_and_ids_move_on() {
    let frames = "[worker.db]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/db\"]\n\
                  [forager.backup]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/backup\"]\n\
                  [forager.backup.launch]\nconcurrency = 2\n";
    let site = Site::new("leftover");
    first_colony(&site, frames);
    let mut lines = site.cells();
    lines.push(CellLine {
        name: "backup#6".into(),
        cgroup_id: 77,
        ready: false,
        dir_key: 99,
        main_key: 0,
    });
    site.put_entry(KEY_CELLS, &format_cells(&lines));
    site.queen
        .borrow_mut()
        .held
        .insert(99, sealed(c"dir", b"").unwrap());
    let mut b = site.boot(frames, &["db"], FakeCells::default(), &alive());
    let stopped = b
        .colony
        .effects
        .cells
        .calls
        .iter()
        .any(|c| matches!(c, Call::Stop(1, qinit_cell::Polite::Cell, ..)));
    assert!(stopped, "{:?}", b.colony.effects.cells.calls);
    // The cell empties; colony removes it.
    b.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(1), Report::Empty));
    b.d_turn();
    assert!(b.colony.effects.cells.calls.contains(&Call::Remove(1)));
    // Ids continue past the highest one seen.
    let (id, _) = b
        .colony
        .launch(
            qinit_colony::LaunchArgs {
                frame: "backup".into(),
                argv_tail: Vec::new(),
                env_add: Vec::new(),
                fds: [None, None, None],
            },
            0,
        )
        .unwrap();
    assert_eq!(id, 7);
    // Queen is told to let go of the leftover's directory.
    site.queen.borrow_mut().pump();
    assert!(!site.queen.borrow().held.contains_key(&99));
}

#[test]
fn a_saved_database_that_does_not_load_starts_from_the_flag_and_ignores_node_state() {
    let site = Site::new("baddb");
    first_colony(&site, WORKER);
    site.put_entry(KEY_DB, "junk");
    let b = site.boot(WORKER, &["db"], FakeCells::default(), &alive());
    assert_eq!(
        b.colony.effects.cells.calls[0],
        Call::Adopt("db".into(), 900, true)
    );
    let logged = site.logged();
    assert!(
        logged.iter().any(|l| l.contains("saved database copy")),
        "{logged:?}"
    );
}

#[test]
fn a_held_database_carries_a_restart_past_a_broken_file() {
    let site = Site::new("heldb");
    first_colony(&site, WORKER);
    // `--db` is broken on disk now (a bad compile), but queen holds the good copy.
    let b = site
        .boot_over(b"not a database", FakeCells::default(), &alive())
        .expect("boots on the held copy");
    assert_eq!(b.colony.state(0), Some(State::Ready));
}

#[test]
fn no_store_and_a_broken_file_is_exit_three() {
    let site = Site::new("nodb");
    // Standalone: nothing held, and the flag's file does not load.
    let log = Syslog::new(
        &site.args.syslog,
        &site.args.console,
        &site.tmp.0.join("kmsg"),
    );
    inotify_slot();
    let r = Daemon::boot_with(
        FakeCells::default(),
        &site.args,
        b"not a database",
        qinit_colonyd::store::Store::standalone(),
        log,
        &gone(),
    );
    assert_eq!(r.err(), Some(qinit_colonyd::exit::DATABASE));
}

#[test]
fn an_unnamed_held_key_is_forgotten() {
    let site = Site::new("unnamed");
    first_colony(&site, WORKER);
    site.queen
        .borrow_mut()
        .held
        .insert(77, sealed(c"stray", b"x").unwrap());
    let _b = site.boot(WORKER, &["db"], FakeCells::default(), &alive());
    site.queen.borrow_mut().pump();
    assert!(!site.queen.borrow().held.contains_key(&77));
    assert!(
        site.queen.borrow().held.contains_key(&KEY_CELLS),
        "the state stays"
    );
}
