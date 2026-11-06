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
use qinit_colonyd::readopt::Procs;
use qinit_colonyd::state::State as Saved;
use qinit_colonyd::syslog::Syslog;
use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;

/// Processes by pid: `(start time, cgroup id)`.
#[derive(Default)]
struct Table(HashMap<i32, (u64, u64)>, std::cell::Cell<u64>);

impl Procs for Table {
    fn pidfd(&self, pid: i32) -> Option<OwnedFd> {
        let (_, cg) = self.0.get(&pid)?;
        self.1.set(*cg);
        std::fs::File::open("/dev/null").map(OwnedFd::from).ok()
    }

    fn start_time(&self, pid: i32) -> Option<u64> {
        self.0.get(&pid).map(|p| p.0)
    }

    fn cgroup_id(&self, _fd: &OwnedFd) -> Option<u64> {
        Some(self.1.get())
    }
}

struct Site {
    tmp: Tmp,
    log: UnixDatagram,
    args: Args,
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
        };
        Site { tmp, log, args }
    }

    fn boot(
        &self,
        frames: &str,
        enable: &[&str],
        cells: FakeCells,
        procs: &Table,
    ) -> Daemon<FakeCells> {
        let bytes = database(frames, enable);
        let log = Syslog::new(
            &self.args.syslog,
            &self.args.console,
            &self.tmp.0.join("kmsg"),
        );
        let state = Saved::open(&self.args.run).unwrap();
        Daemon::boot_with(cells, &self.args, &bytes, state, log, procs).expect("boots")
    }

    fn state(&self) -> Saved {
        Saved::open(&self.args.run).unwrap()
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
    let mut a = site.boot(frames, &["db"], FakeCells::default(), &Table::default());
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

/// The process table in which the first colony's `db` main (pid 4000, cgroup 900) is alive.
fn alive() -> Table {
    Table(HashMap::from([(4000, (0, 900))]), std::cell::Cell::new(0))
}

#[test]
fn a_second_colony_adopts_what_the_first_left() {
    let site = Site::new("adopt");
    first_colony(&site, WORKER);
    let saved = site.state().read_cells().unwrap().unwrap();
    assert_eq!(saved.len(), 1);
    assert!(saved[0].ready, "the first colony saved the ready flag");
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
    let again = site.state().read_cells().unwrap().unwrap();
    assert!(again[0].ready);
}

#[test]
fn a_stopped_enabled_node_stays_stopped_across_the_restart() {
    let site = Site::new("stopped");
    let mut a = site.boot(WORKER, &["db"], FakeCells::default(), &Table::default());
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
    let b = site.boot(WORKER, &["db"], FakeCells::default(), &Table::default());
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
            mismatch: false,
            populated: false,
        },
    );
    let b = site.boot(RESTARTING, &["db"], cells, &Table::default());
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
fn a_reused_pid_means_the_main_is_gone() {
    let site = Site::new("reused");
    first_colony(&site, RESTARTING);
    // Pid 4000 is alive but is some other process: another start time.
    let other = Table(
        HashMap::from([(4000, (12345, 900))]),
        std::cell::Cell::new(0),
    );
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
fn a_refused_nodes_file_falls_back_to_cells_only() {
    let frames = "[worker.db]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/db\"]\n\
                  restart = { policy = \"on-failure\", max = 3 }\n\
                  [worker.web]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/web\"]\n";
    let site = Site::new("badnodes");
    let mut a = site.boot(
        frames,
        &["db", "web"],
        FakeCells::default(),
        &Table::default(),
    );
    a.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(1), Report::Ready));
    a.d_turn();
    drop(a);
    // `web` has its cell; `db` has none, and the file says it is quarantined by the breaker with
    // no failures counted: not a table the scheduler can hold.
    let state = site.state();
    let lines: Vec<_> = state
        .read_cells()
        .unwrap()
        .unwrap()
        .into_iter()
        .filter(|c| c.name == "web")
        .collect();
    state.write_cells(&lines).unwrap();
    std::fs::write(
        site.args.run.join("state/nodes"),
        "db 1 quarantined:breaker 0 0 0 0 0\n",
    )
    .unwrap();
    let web_pid = lines[0].pid;
    let procs = Table(
        HashMap::from([(web_pid, (0, lines[0].cgroup_id))]),
        std::cell::Cell::new(0),
    );
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
        "the refused file did not quarantine anything"
    );
    let logged = site.logged();
    let line = logged
        .iter()
        .find(|l| l.contains("saved node state is refused"))
        .unwrap_or_else(|| panic!("{logged:?}"));
    assert!(line.starts_with("<27>colony["), "an error: {line}");
}

#[test]
fn a_malformed_state_file_is_as_good_as_none() {
    let site = Site::new("garbled");
    first_colony(&site, WORKER);
    std::fs::write(site.args.run.join("state/cells"), "db not-a-number\n").unwrap();
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
    let state = site.state();
    let mut lines = state.read_cells().unwrap().unwrap();
    lines.push(qinit_colonyd::state::CellLine {
        name: "backup#6".into(),
        cgroup_id: 77,
        ready: false,
        pid: 0,
        start_time: 0,
    });
    state.write_cells(&lines).unwrap();
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
}

#[test]
fn an_unreadable_saved_database_starts_from_the_flag_and_ignores_node_state() {
    let site = Site::new("baddb");
    first_colony(&site, WORKER);
    std::fs::write(site.args.run.join("state/colony.db"), b"junk").unwrap();
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
