// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The loop, on the host: the whole daemon over a fake cell layer (the real cgroups are the VM
//! suites'). No test here starts a process: a fork holds a copy of every descriptor until its
//! exec, so a test closing one end of a socket would not see the hang-up it waits for. The tests
//! that start the colony binary are in `binary.rs`.
mod common;

use common::*;
use qinit_cell::{CellId, Notice, Report};
use qinit_colony::{Peer, State, TimerKind};
use qinit_colonyd::args::Args;
use qinit_colonyd::daemon::{Daemon, inside_comb};
use qinit_colonyd::deadlines::Key;
use qinit_colonyd::exit;
use qinit_colonyd::state::{parse_cells, parse_nodes};
use qinit_colonyd::store::{KEY_CELLS, KEY_DB, KEY_NODES, Store};
use qinit_colonyd::syslog::Syslog;
use qinit_ipc::{connect_seqpacket, recv, send};
use qinit_proto_core::MAX_MESSAGE;
use qinit_queen_core::ToColony;
use qinit_wire::{Mode, Msg, Rep, Req, decode, encode};
use std::ffi::CString;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;

const WORKER: &str = "[worker.db]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/db\"]\n";

// ---- the cgroup check ----

#[test]
fn inside_comb_compares_whole_path_components() {
    let own = "/18/session";
    assert!(
        inside_comb(own, "/sys/fs/cgroup/18/session".as_ref()),
        "the comb itself"
    );
    assert!(
        inside_comb(own, "/sys/fs/cgroup/18".as_ref()),
        "below the comb"
    );
    assert!(
        inside_comb(own, "/sys/fs/cgroup".as_ref()),
        "below the root"
    );
    assert!(
        !inside_comb(own, "/sys/fs/cgroup/18/session/qinit".as_ref()),
        "the comb is below us"
    );
    assert!(
        !inside_comb(own, "/sys/fs/cgroup/1".as_ref()),
        "a prefix of the name is not a parent"
    );
    assert!(
        !inside_comb(own, "/elsewhere".as_ref()),
        "not a cgroup path we know"
    );
}

// ---- the daemon over a fake cell layer ----

struct Rig {
    d: Daemon<FakeCells>,
    tmp: Tmp,
    log: UnixDatagram,
    bytes: Vec<u8>,
    /// Queen, holding what the daemon puts.
    queen: FakeQueen,
}

impl Rig {
    fn run(&self) -> PathBuf {
        self.tmp.0.join("run")
    }

    fn socket(&self) -> PathBuf {
        self.run().join("colony")
    }

    /// What colony has logged so far.
    fn logged(&self) -> Vec<String> {
        lines_of(&self.log)
    }
}

fn boot(frames: &str, enable: &[&str], tag: &str) -> Rig {
    let bytes = database(frames, enable);
    let (d, tmp, log, queen) = try_boot(&bytes, tag, FakeCells::default(), |_, _| {});
    Rig {
        d: d.expect("boots"),
        tmp,
        log,
        bytes,
        queen,
    }
}

/// Boots over `bytes` and `cells`; `prep` may change the arguments or the run directory first.
fn try_boot(
    bytes: &[u8],
    tag: &str,
    cells: FakeCells,
    prep: impl FnOnce(&mut Args, &mut FakeQueen),
) -> (Result<Daemon<FakeCells>, u8>, Tmp, UnixDatagram, FakeQueen) {
    let tmp = Tmp::new(tag);
    let run = tmp.0.join("run");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::create_dir_all(tmp.0.join("comb")).unwrap();
    let log = UnixDatagram::bind(tmp.0.join("log")).unwrap();
    for f in ["console", "kmsg"] {
        std::fs::write(tmp.0.join(f), b"").unwrap();
    }
    let mut args = Args {
        db: tmp.0.join("colony.db"),
        comb: tmp.0.join("comb"),
        socket: run.join("colony"),
        overseer: "/usr/lib/qinit/overseer".into(),
        syslog: tmp.0.join("log"),
        console: tmp.0.join("console"),
        run: run.clone(),
        queen_fd: None,
    };
    let (mut queen, _link) = FakeQueen::new();
    prep(&mut args, &mut queen);
    let syslog = Syslog::new(&args.syslog, &args.console, &tmp.0.join("kmsg"));
    let store = queen.reattach();
    inotify_slot();
    let d = Daemon::boot(cells, &args, bytes, store, syslog);
    (d, tmp, log, queen)
}

fn root() -> Peer {
    Peer {
        uid: 0,
        gid: 0,
        pid: 1,
    }
}

/// A connection to the daemon that the server treats as root's.
fn connect_root(r: &mut Rig) -> OwnedFd {
    let (client, server_end) = qinit_ipc::seqpacket_pair().unwrap();
    r.d.accept_as(server_end, root());
    qinit_sys::fd::set_nonblocking(&client).unwrap();
    client
}

fn ask(client: &OwnedFd, req: Req<'_>, fds: &[std::os::fd::BorrowedFd<'_>]) {
    let mut out = vec![0u8; MAX_MESSAGE];
    let n = encode(
        &Msg::Req(req),
        u32::try_from(fds.len()).unwrap(),
        (&mut out[..]).try_into().unwrap(),
    )
    .unwrap();
    send(client.as_fd(), &out[..n], fds).unwrap();
}

fn answer<R>(client: &OwnedFd, f: impl FnOnce(Rep<'_>) -> R) -> Option<R> {
    let mut buf = vec![0u8; MAX_MESSAGE];
    let got = recv(client.as_fd(), &mut buf).ok()?;
    if got.len == 0 {
        return None;
    }
    match decode(&buf[..got.len], got.fds.len()).ok()? {
        Msg::Rep(r) => Some(f(r)),
        Msg::Req(_) => None,
    }
}

#[test]
fn boot_starts_the_enabled_nodes_and_saves_what_a_restart_needs() {
    let mut r = boot(WORKER, &["db"], "boot");
    assert!(
        r.d.colony
            .effects
            .cells
            .calls
            .iter()
            .any(|c| matches!(c, Call::Create(n) if n == "db")),
        "the enabled node was started"
    );
    assert_eq!(
        r.queen.bytes(KEY_DB).as_deref(),
        Some(&r.bytes[..]),
        "the database in force"
    );
    let cells = parse_cells(&r.queen.text(KEY_CELLS).unwrap()).unwrap();
    assert_eq!(cells.len(), 1);
    assert_eq!(
        (cells[0].name.as_str(), cells[0].cgroup_id, cells[0].ready),
        ("db", 900, false)
    );
    assert!(
        cells[0].dir_key >= 16 && cells[0].main_key >= 16,
        "{cells:?}"
    );
    assert!(
        r.queen.held.contains_key(&cells[0].dir_key),
        "the directory is held"
    );
    assert!(
        r.queen.held.contains_key(&cells[0].main_key),
        "the main is held"
    );
    let (nodes, _) = parse_nodes(&r.queen.text(KEY_NODES).unwrap()).unwrap();
    assert!(
        nodes.iter().any(|n| n.name == "db" && n.wanted),
        "{nodes:?}"
    );
    assert!(r.socket().exists(), "the control socket is bound");
    let mode = std::fs::metadata(r.socket()).unwrap();
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(&mode.permissions()) & 0o777,
        0o666
    );
}

#[test]
fn a_cell_report_reaches_its_node_the_log_and_the_cells_file() {
    let mut r = boot(WORKER, &["db"], "report");
    r.d.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(0), Report::Ready));
    assert_eq!(r.d.turn(Vec::new()), None);
    assert_eq!(r.d.colony.state(0), Some(State::Ready));
    let logged = r.logged();
    assert!(
        logged.iter().any(|l| l.ends_with("db: ready")),
        "{logged:?}"
    );
    let cells = parse_cells(&r.queen.text(KEY_CELLS).unwrap()).unwrap();
    assert!(cells[0].ready, "the ready flag is saved");
}

#[test]
fn a_client_gets_its_answer_through_the_socket() {
    let mut r = boot(WORKER, &["db"], "status");
    let path = CString::new(r.socket().to_str().unwrap()).unwrap();
    let client = connect_seqpacket(&path).unwrap();
    qinit_sys::fd::set_nonblocking(&client).unwrap();
    assert_eq!(r.d.pump(), None);
    ask(&client, Req::Status { target: "db" }, &[]);
    assert_eq!(r.d.pump(), None);
    assert_eq!(
        answer(&client, |rep| matches!(rep, Rep::NodeStatus(_))),
        Some(true)
    );
}

#[test]
fn sigterm_runs_the_ordered_shutdown_and_exits_0() {
    let mut r = boot(WORKER, &["db"], "sigterm");
    r.d.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(0), Report::Ready));
    r.d.turn(Vec::new());
    qinit_sys::proc::kill_thread_self(libc::SIGTERM).unwrap();
    assert_eq!(r.d.pump(), None, "the node still has to stop");
    assert!(
        r.d.colony
            .effects
            .cells
            .calls
            .iter()
            .any(|c| matches!(c, Call::Stop(0, ..))),
        "{:?}",
        r.d.colony.effects.cells.calls
    );
    r.d.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(0), Report::MainExited(Some(0))));
    r.d.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(0), Report::Empty));
    assert_eq!(r.d.turn(Vec::new()), Some(exit::HALT));
    let socket = r.socket();
    assert_eq!(r.d.finish(exit::HALT), exit::HALT);
    assert!(!socket.exists(), "the socket file is removed");
    r.queen.pump();
    assert!(
        r.queen.held.is_empty(),
        "nothing is left to re-adopt: {:?}",
        r.queen.held.keys().collect::<Vec<_>>()
    );
    qinit_sys::signal::unblock_all().unwrap();
}

#[test]
fn a_protocol_shutdown_that_completes_inside_the_request_still_exits_with_its_mode() {
    for (mode, code) in [
        (Mode::Poweroff, exit::POWEROFF),
        (Mode::Reboot, exit::REBOOT),
        (Mode::Halt, exit::HALT),
    ] {
        let mut r = boot(WORKER, &[], &format!("shutdown-{code}"));
        let client = connect_root(&mut r);
        ask(
            &client,
            Req::Shutdown {
                mode,
                settled: false,
                wait_ms: 0,
            },
            &[],
        );
        assert_eq!(
            r.d.pump(),
            Some(code),
            "nothing runs, so it completes in the request"
        );
        qinit_sys::signal::unblock_all().unwrap();
    }
}

#[test]
fn a_refresh_that_completes_inside_the_request_writes_colony_db() {
    let mut r = boot(WORKER, &[], "refresh");
    let client = connect_root(&mut r);
    let new = database(&WORKER.replace("/bin/db", "/bin/db2"), &[]);
    let fd = qinit_ipc::memfd::sealed(c"db", &new).unwrap();
    ask(
        &client,
        Req::Refresh {
            settled: false,
            wait_ms: 0,
        },
        &[fd.as_fd()],
    );
    assert_eq!(r.d.pump(), None);
    assert_eq!(
        r.queen.bytes(KEY_DB).as_deref(),
        Some(&new[..]),
        "the new database is the saved one"
    );
    assert!(r.logged().iter().any(|l| l.ends_with("database refreshed")));
}

#[test]
fn a_deadline_in_the_future_wakes_the_loop_through_the_timer() {
    let mut r = boot(WORKER, &["db"], "timer");
    assert_eq!(r.d.colony.state(0), Some(State::Starting));
    // Due in 20 ms of the loop's own clock: nothing is due yet, so the timer is set for it.
    let at = qinit_sys::timer::now_monotonic_ns() / 1_000_000 + 20;
    r.d.colony
        .effects
        .deadlines
        .arm(Key::Node(0, TimerKind::StartTimeout), at);
    assert_eq!(r.d.turn(Vec::new()), None);
    assert_eq!(r.d.colony.state(0), Some(State::Starting), "not yet");
    // The wait ends because the timer fires, not because anything polls.
    assert_eq!(r.d.serve_once(), Ok(None));
    assert_ne!(
        r.d.colony.state(0),
        Some(State::Starting),
        "the start timeout reached colony through the timer"
    );
}

#[test]
fn a_deadline_that_is_already_due_is_delivered_in_the_same_turn() {
    let mut r = boot(WORKER, &["db"], "due");
    r.d.colony
        .effects
        .deadlines
        .arm(Key::Node(0, TimerKind::StartTimeout), 0);
    assert_eq!(r.d.turn(Vec::new()), None);
    assert_ne!(r.d.colony.state(0), Some(State::Starting));
}

#[test]
fn sighup_is_logged_and_ignored() {
    let mut r = boot(WORKER, &[], "sighup");
    qinit_sys::proc::kill_thread_self(libc::SIGHUP).unwrap();
    assert_eq!(r.d.pump(), None);
    assert!(r.logged().iter().any(|l| l.contains("SIGHUP")));
    qinit_sys::signal::unblock_all().unwrap();
}

#[test]
fn orphans_are_logged_at_debug_level() {
    let mut r = boot(WORKER, &[], "orphan");
    r.d.colony.effects.cells.pending.push(Notice::Orphan {
        pid: 77,
        status: 256,
    });
    r.d.turn(Vec::new());
    let logged = r.logged();
    assert!(
        logged.iter().any(|l| l.starts_with("<31>colony[")
            && l.contains("orphan 77")
            && l.contains("exit 1")),
        "{logged:?}"
    );
}

#[test]
fn a_failed_start_shows_as_a_spawn_failure_not_a_crash() {
    // A node whose limit cannot be written: colony reports it and goes on serving.
    let mut cells = FakeCells::default();
    cells.limits_fail = Some(libc::EPERM);
    let frames = "[worker.db]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/db\"]\n\
                  cell = { memory_max = \"1M\" }\n";
    let tmp = Tmp::new("failstart");
    let run = tmp.0.join("run");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::create_dir_all(tmp.0.join("comb")).unwrap();
    for f in ["console", "kmsg"] {
        std::fs::write(tmp.0.join(f), b"").unwrap();
    }
    let args = Args {
        db: tmp.0.join("colony.db"),
        comb: tmp.0.join("comb"),
        socket: run.join("colony"),
        overseer: "/o".into(),
        syslog: tmp.0.join("nolog"),
        console: tmp.0.join("console"),
        run: run.clone(),
        queen_fd: None,
    };
    let bytes = database(frames, &["db"]);
    let syslog = Syslog::new(&args.syslog, &args.console, &tmp.0.join("kmsg"));
    inotify_slot();
    let mut d = Daemon::boot(cells, &args, &bytes, Store::standalone(), syslog).expect("boots");
    assert_eq!(
        d.colony.state(0),
        Some(State::Off),
        "failed, never restarted"
    );
    let console = std::fs::read_to_string(tmp.0.join("console")).unwrap();
    assert!(
        console.contains("db: failed"),
        "the failure is on the console: {console}"
    );
    assert_eq!(d.turn(Vec::new()), None, "and the daemon serves on");
}

// ---- readiness and launch failures (Task 17) ----

fn path_ready_frames(path: &std::path::Path) -> String {
    format!(
        "[worker.db]\ncredentials = {{ uid = \"svc\" }}\nexec = [\"/bin/db\"]\n\
         ready = {{ path = \"{}\" }}\n",
        path.display()
    )
}

fn marked(r: &Rig) -> usize {
    r.d.colony
        .effects
        .cells
        .calls
        .iter()
        .filter(|c| matches!(c, Call::MarkReady(_)))
        .count()
}

#[test]
fn a_path_ready_node_is_marked_when_its_file_is_created() {
    let dir = Tmp::new("pathready-dir");
    let file = dir.0.join("run/db.pid");
    let mut r = boot(&path_ready_frames(&file), &["db"], "pathready");
    assert_eq!(marked(&r), 0, "nothing yet");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, b"1").unwrap();
    assert_eq!(r.d.pump(), None);
    assert_eq!(marked(&r), 1, "the cell was marked ready once");
}

#[test]
fn a_file_that_was_there_before_the_start_does_not_mark_the_node() {
    let dir = Tmp::new("stalefile-dir");
    let file = dir.0.join("run/db.pid");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, b"old").unwrap();
    let mut r = boot(&path_ready_frames(&file), &["db"], "stalefile");
    assert_eq!(r.d.pump(), None);
    assert_eq!(marked(&r), 0, "the stale file is not readiness");
}

#[test]
fn its_watch_is_gone_after_an_exit_and_after_ready() {
    let dir = Tmp::new("watchgone-dir");
    let file = dir.0.join("run/db.pid");
    let mut r = boot(&path_ready_frames(&file), &["db"], "watchgone");
    assert_eq!(
        r.d.colony.effects.watcher.pending(),
        1,
        "waiting for its file"
    );
    r.d.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(0), Report::MainExited(Some(256))));
    r.d.turn(Vec::new());
    assert_eq!(
        r.d.colony.effects.watcher.pending(),
        0,
        "the exit ends the watch"
    );
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, b"1").unwrap();
    assert_eq!(r.d.pump(), None);
    assert_eq!(marked(&r), 0, "a later file marks nothing");

    let mut r = boot(&path_ready_frames(&file), &["db"], "watchready");
    r.d.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(0), Report::Ready));
    r.d.turn(Vec::new());
    assert_eq!(
        r.d.colony.effects.watcher.pending(),
        0,
        "ready ends the watch"
    );
}

#[test]
fn a_launch_failure_record_is_logged_with_its_step_name() {
    let mut r = boot(WORKER, &["db"], "launchfail");
    let status_w = &r.d.colony.effects.cells.spawned[0].fds[1].0;
    let rec = qinit_overseer::status::Status {
        step: qinit_overseer::status::STEP_IDENTITY,
        errno: libc::ENOENT,
    };
    rec.write(status_w.as_fd());
    assert_eq!(r.d.pump(), None);
    let logged = r.logged();
    let line = logged
        .iter()
        .find(|l| l.contains("launch failed"))
        .unwrap_or_else(|| panic!("{logged:?}"));
    assert!(line.starts_with("<27>colony["), "an error: {line}");
    assert!(line.contains("db: launch failed at identity: "), "{line}");
    assert!(line.contains("No such file or directory"), "{line}");
}

#[test]
fn a_successful_launch_closes_its_status_pipe_quietly() {
    const GUARD: u64 = u64::MAX - 1;
    let mut r = boot(WORKER, &["db"], "launchok");
    // The overseer's exec closes fd 4: the fake spawn's copy stands in for it.
    let fds = std::mem::take(&mut r.d.colony.effects.cells.spawned[0].fds);
    drop(fds);
    // The end of file arrives when the last copy of the write end is closed. That can lag the
    // `drop` slightly, so this waits for the event (with a guard) instead of looking once.
    r.d.colony
        .effects
        .events
        .add_deadline(std::time::Duration::from_secs(30), GUARD)
        .unwrap();
    while !r.d.colony.effects.status.is_empty() {
        assert_eq!(r.d.serve_once(), Ok(None));
    }
    assert!(!r.logged().iter().any(|l| l.contains("launch failed")));
}

// ---- the daemon leaves no cell behind (found by the readopt VM suite) ----

const FORAGER: &str = "[forager.backup]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/backup\"]\n\
                       [forager.backup.launch]\nconcurrency = 2\n";

fn launch_args() -> qinit_colony::LaunchArgs {
    qinit_colony::LaunchArgs {
        frame: "backup".into(),
        argv_tail: Vec::new(),
        env_add: Vec::new(),
        fds: [None, None, None],
    }
}

#[test]
fn a_completed_shutdown_waits_for_the_instance_cells_to_be_removed() {
    let mut r = boot(FORAGER, &[], "instshutdown");
    let (id, out) = r.d.colony.launch(launch_args(), 0).unwrap();
    assert_eq!(id, 1);
    drop(out);
    qinit_sys::proc::kill_thread_self(libc::SIGTERM).unwrap();
    assert_eq!(
        r.d.pump(),
        None,
        "the graph is down but an instance cell is still there"
    );
    assert!(
        r.d.colony
            .effects
            .cells
            .calls
            .iter()
            .any(|c| matches!(c, Call::Stop(0, ..))),
        "the instance was told to stop: {:?}",
        r.d.colony.effects.cells.calls
    );
    r.d.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(0), Report::MainExited(Some(0))));
    r.d.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(0), Report::Empty));
    assert_eq!(r.d.turn(Vec::new()), Some(exit::HALT));
    assert!(
        r.d.colony.effects.cells.calls.contains(&Call::Remove(0)),
        "the instance's cell was removed before the daemon left"
    );
    qinit_sys::signal::unblock_all().unwrap();
}

#[test]
fn a_cell_that_failed_to_stop_does_not_keep_the_daemon_from_leaving() {
    let mut r = boot(FORAGER, &[], "instfailed");
    r.d.colony.launch(launch_args(), 0).unwrap();
    qinit_sys::proc::kill_thread_self(libc::SIGTERM).unwrap();
    assert_eq!(r.d.pump(), None);
    // The cell layer gave up on the cell: it is stuck, and colony cannot wait for it for ever.
    r.d.colony.effects.cells.pending.push(Notice::Cell(
        CellId(0),
        Report::Failed(qinit_cell::Failure::Stuck),
    ));
    assert_eq!(r.d.turn(Vec::new()), Some(exit::HALT));
    qinit_sys::signal::unblock_all().unwrap();
}

// ---- final review: owner-keyed state ----

#[test]
fn an_instance_in_the_same_numbered_slot_leaves_a_nodes_readiness_watch_alone() {
    let dir = Tmp::new("slotwatch-dir");
    let file = dir.0.join("run/db.pid");
    // `db` sorts before `zz`, so it is node 0: the instance's slot 0 has the same number.
    let frames = format!(
        "{}{}",
        path_ready_frames(&file),
        FORAGER.replace("backup", "zz")
    );
    let mut r = boot(&frames, &["db"], "slotwatch");
    assert_eq!(
        r.d.colony.effects.watcher.pending(),
        1,
        "db waits for its file"
    );
    let args = qinit_colony::LaunchArgs {
        frame: "zz".into(),
        ..launch_args()
    };
    let (_, out) = r.d.colony.launch(args, 0).unwrap();
    drop(out);
    r.d.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(1), Report::MainExited(Some(0))));
    r.d.turn(Vec::new());
    assert_eq!(
        r.d.colony.effects.watcher.pending(),
        1,
        "an instance's exit must not end the node's readiness watch"
    );
}

fn workers(names: &[&str]) -> String {
    names
        .iter()
        .map(|n| {
            format!("[worker.{n}]\ncredentials = {{ uid = \"svc\" }}\nexec = [\"/bin/{n}\"]\n")
        })
        .collect::<Vec<_>>()
        .concat()
}

#[test]
fn a_refresh_that_renumbers_nodes_keeps_the_ready_flags_with_their_cells() {
    let mut r = boot(&workers(&["b", "c"]), &["b", "c"], "renumber");
    r.d.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(0), Report::Ready));
    assert_eq!(r.d.turn(Vec::new()), None);
    let client = connect_root(&mut r);
    // `a` sorts first and is not enabled: `b` and `c` move from nodes 0, 1 to nodes 1, 2.
    let new = database(&workers(&["a", "b", "c"]), &["b", "c"]);
    let fd = qinit_ipc::memfd::sealed(c"db", &new).unwrap();
    ask(
        &client,
        Req::Refresh {
            settled: false,
            wait_ms: 0,
        },
        &[fd.as_fd()],
    );
    assert_eq!(r.d.pump(), None);
    assert_eq!(r.d.colony.model().nodes[0].name, "a", "the swap happened");
    let lines = parse_cells(&r.queen.text(KEY_CELLS).unwrap()).unwrap();
    let ready = |name: &str| lines.iter().find(|l| l.name == name).map(|l| l.ready);
    assert_eq!(ready("b"), Some(true), "b is still ready: {lines:?}");
    assert_eq!(ready("c"), Some(false), "c never was: {lines:?}");
}

#[test]
fn a_watch_the_kernel_refuses_is_logged_not_dropped_silently() {
    if qinit_sys::cred::getuid() == 0 {
        eprintln!("skipped: root can watch a directory with no permissions");
        return;
    }
    let dir = Tmp::new("watcherr-dir");
    let file = dir.0.join("a/db.pid");
    let mut r = boot(&path_ready_frames(&file), &["db"], "watcherr");
    // The directory appears with no permissions: the watch cannot move down into it.
    std::fs::create_dir(dir.0.join("a")).unwrap();
    std::fs::set_permissions(
        dir.0.join("a"),
        std::os::unix::fs::PermissionsExt::from_mode(0o000),
    )
    .unwrap();
    let pumped = r.d.pump();
    // Before any assertion: `Tmp` cannot remove a directory with no permissions.
    std::fs::set_permissions(
        dir.0.join("a"),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    assert_eq!(pumped, None);
    let logged = r.logged();
    assert!(
        logged
            .iter()
            .any(|l| l.starts_with("<27>") && l.contains("db") && l.contains("watch")),
        "an error line names the node and the lost watch: {logged:?}"
    );
}

#[test]
fn a_listener_that_cannot_accept_is_paused_and_comes_back() {
    let mut r = boot(WORKER, &["db"], "emfile");
    let path = CString::new(r.socket().to_str().unwrap()).unwrap();
    let client = connect_seqpacket(&path).unwrap();
    qinit_sys::fd::set_nonblocking(&client).unwrap();
    // Out of descriptors: a level-triggered listener would wake the loop for ever.
    r.d.listener_failed(libc::EMFILE);
    ask(&client, Req::Status { target: "db" }, &[]);
    assert_eq!(r.d.pump(), None);
    assert_eq!(
        answer(&client, |rep| matches!(rep, Rep::NodeStatus(_))),
        None,
        "nothing is accepted while the listener is paused"
    );
    let errors = r
        .logged()
        .into_iter()
        .filter(|l| l.starts_with("<27>") && l.contains("accept"))
        .count();
    assert_eq!(errors, 1, "one error line says why");
    // Its retry comes due.
    r.d.colony.effects.deadlines.arm(Key::Listener, 0);
    assert_eq!(r.d.turn(Vec::new()), None);
    assert_eq!(r.d.pump(), None);
    assert_eq!(
        answer(&client, |rep| matches!(rep, Rep::NodeStatus(_))),
        Some(true),
        "the waiting connection is served once the listener is back"
    );
}

#[test]
fn what_boot_noticed_is_logged_even_when_it_then_refuses() {
    let (d, _tmp, log, _queen) = try_boot(
        b"not a database",
        "refusenotes",
        FakeCells::default(),
        |_, q| {
            // An earlier colony's cell map that does not parse, and a database that is refused.
            q.held.insert(
                KEY_CELLS,
                qinit_ipc::memfd::sealed(c"cells", b"garbage\n").unwrap(),
            );
        },
    );
    assert_eq!(d.err(), Some(exit::DATABASE));
    let logged = lines_of(&log);
    assert!(
        logged
            .iter()
            .any(|l| l.contains("saved cell map is refused")),
        "the note about the cell map is not lost: {logged:?}"
    );
}

#[test]
fn a_socket_that_cannot_be_bound_stops_boot_before_any_service_starts() {
    let started = std::rc::Rc::new(std::cell::Cell::new(false));
    let seen = started.clone();
    let mut cells = FakeCells::default();
    cells.on_spawn = Some(Box::new(move || seen.set(true)));
    let bytes = database(WORKER, &["db"]);
    let (d, _tmp, _log, _queen) = try_boot(&bytes, "nobind", cells, |a, _| {
        a.socket = a.run.join("no-such-dir/colony");
    });
    assert_eq!(d.err(), Some(exit::STARTUP));
    assert!(
        !started.get(),
        "a service was started that no colony will track"
    );
}

#[test]
fn a_new_cell_puts_its_descriptors_before_the_state_that_names_them() {
    let mut r = boot(WORKER, &["db"], "putorder");
    r.queen.pump();
    let cells = parse_cells(&r.queen.text(KEY_CELLS).unwrap()).unwrap();
    let (dir, main) = (cells[0].dir_key, cells[0].main_key);
    let at = |e: Sent| {
        r.queen
            .events
            .iter()
            .position(|x| *x == e)
            .unwrap_or_else(|| panic!("{e:?} in {:?}", r.queen.events))
    };
    assert!(
        at(Sent::Put(dir)) < at(Sent::Put(KEY_CELLS)),
        "the directory first"
    );
    assert!(
        at(Sent::Put(main)) < at(Sent::Put(KEY_CELLS)),
        "the main first"
    );
    assert!(at(Sent::Put(KEY_DB)) < at(Sent::Put(KEY_CELLS)));
}

#[test]
fn a_removed_cell_is_forgotten_after_the_state_that_dropped_it() {
    let mut r = boot(WORKER, &["db"], "forgetorder");
    r.d.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(0), Report::Ready));
    assert_eq!(r.d.turn(Vec::new()), None);
    let cells = parse_cells(&r.queen.text(KEY_CELLS).unwrap()).unwrap();
    let (dir, main) = (cells[0].dir_key, cells[0].main_key);
    // The node stops: the main exits and the cell empties and is removed.
    let out = r.d.colony.request(0, qinit_colony::Request::Stop, 0);
    assert!(out.errors.is_empty());
    for report in [Report::MainExited(Some(0)), Report::Empty, Report::Removed] {
        r.d.colony
            .effects
            .cells
            .pending
            .push(Notice::Cell(CellId(0), report));
    }
    assert_eq!(r.d.turn(Vec::new()), None);
    let _ = r.queen.text(KEY_CELLS);
    let events = r.queen.events.clone();
    let last_cells = events
        .iter()
        .rposition(|e| *e == Sent::Put(KEY_CELLS))
        .unwrap();
    for key in [dir, main] {
        let at = events.iter().position(|e| *e == Sent::Drop(key));
        let at = at.unwrap_or_else(|| panic!("{key} was not forgotten: {events:?}"));
        assert!(
            at > last_cells,
            "{key} forgotten before the state stopped naming it: {events:?}"
        );
    }
    assert!(!r.queen.held.contains_key(&dir));
}

// ---- a request's replies follow the state they report (D67) ----

/// Whether a message waits on `fd` (the daemon keeps its end open), left where it is.
fn has_message(fd: &OwnedFd) -> bool {
    qinit_ipc::poll_readable(fd.as_fd(), 0).unwrap()
}

fn launch_backup() -> Req<'static> {
    Req::Launch {
        frame: "backup",
        argv_tail: qinit_wire::StrList::new(b""),
        env_add: qinit_wire::StrList::new(b""),
        fd_roles: 0,
        wait_ms: 60_000,
        flags: 0,
    }
}

#[test]
fn the_save_is_on_the_channel_before_a_launch_is_answered() {
    let mut r = boot(FORAGER, &[], "replyorder");
    let client = connect_root(&mut r);
    // The client's socket, looked at the moment the instance's cell is first put in queen's
    // store, before the `cells` text that names it is saved. That moment is the start of
    // `persist` (its `sync_store`), not the save of `cells` itself: it shows the reply was not
    // sent before the saves began. That it goes after them is the order of `after_wakeup`
    // (`persist`, then `flush_replies`); with the two swapped this test fails.
    let probe = client.try_clone().unwrap();
    let early = std::rc::Rc::new(std::cell::Cell::new(None));
    let seen = early.clone();
    r.d.colony.effects.cells.on_dir_fd = Some(Box::new(move || {
        if seen.get().is_none() {
            seen.set(Some(has_message(&probe)));
        }
    }));
    ask(&client, launch_backup(), &[]);
    assert_eq!(r.d.pump(), None);
    assert_eq!(
        early.get(),
        Some(false),
        "the client could read its reply before the instance's state went to queen"
    );
    // The client's socket first: once it has the reply, the channel names the instance.
    let id = answer(&client, |rep| match rep {
        Rep::Launched { id } => id,
        other => panic!("{other:?}"),
    })
    .expect("the launch is answered");
    let cells = parse_cells(&r.queen.text(KEY_CELLS).unwrap()).unwrap();
    let name = format!("backup#{id}");
    assert!(
        cells.iter().any(|c| c.name == name),
        "{name} is not in the cells entry: {cells:?}"
    );
}

#[test]
fn a_client_gone_before_the_flush_costs_nothing() {
    let frames = format!("{WORKER}{FORAGER}");
    let mut r = boot(&frames, &["db"], "replygone");
    let gone = connect_root(&mut r);
    let other = connect_root(&mut r);
    ask(&gone, launch_backup(), &[]);
    ask(&other, Req::Status { target: "db" }, &[]);
    // The launching client closes after its request was served and before its reply is sent:
    // while the instance's state is being saved.
    let held = std::rc::Rc::new(std::cell::RefCell::new(Some(gone)));
    let closer = held.clone();
    r.d.colony.effects.cells.on_dir_fd = Some(Box::new(move || {
        closer.borrow_mut().take();
    }));
    assert_eq!(r.d.connections(), 2);
    // One wake-up serves both requests; its flush finds the launching client gone and closes
    // the connection, before any later wake-up could see it hang up.
    let ready = r.d.colony.effects.events.poll().unwrap();
    assert_eq!(r.d.turn(ready), None);
    assert!(
        held.borrow().is_none(),
        "the client closed during the wake-up"
    );
    assert_eq!(
        r.d.connections(),
        1,
        "the gone client's connection stays open"
    );
    // The state of what its request did is saved all the same.
    let cells = parse_cells(&r.queen.text(KEY_CELLS).unwrap()).unwrap();
    assert!(
        cells.iter().any(|c| c.name == "backup#1"),
        "the instance is in the cells entry: {cells:?}"
    );
    // The other connection is answered and stays usable.
    assert_eq!(
        answer(&other, |rep| matches!(rep, Rep::NodeStatus(_))),
        Some(true)
    );
    ask(&other, Req::Status { target: "db" }, &[]);
    assert_eq!(r.d.pump(), None);
    assert_eq!(
        answer(&other, |rep| matches!(rep, Rep::NodeStatus(_))),
        Some(true)
    );
}

#[test]
fn without_a_queen_nothing_is_saved() {
    let tmp = Tmp::new("noqueen");
    let run = tmp.0.join("run");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::create_dir_all(tmp.0.join("comb")).unwrap();
    for f in ["console", "kmsg"] {
        std::fs::write(tmp.0.join(f), b"").unwrap();
    }
    let args = Args {
        db: tmp.0.join("colony.db"),
        comb: tmp.0.join("comb"),
        socket: run.join("colony"),
        overseer: "/o".into(),
        syslog: tmp.0.join("nolog"),
        console: tmp.0.join("console"),
        run: run.clone(),
        queen_fd: None,
    };
    let bytes = database(WORKER, &["db"]);
    let syslog = Syslog::new(&args.syslog, &args.console, &tmp.0.join("kmsg"));
    inotify_slot();
    let mut d = Daemon::boot(
        FakeCells::default(),
        &args,
        &bytes,
        Store::standalone(),
        syslog,
    )
    .expect("boots");
    assert_eq!(d.turn(Vec::new()), None);
    assert!(d.colony.effects.store.link().is_none());
    assert!(
        !run.join("state").exists(),
        "no state directory is made any more"
    );
}

fn status_pending(r: &mut Rig) {
    r.d.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(0), Report::Running));
    r.d.colony
        .effects
        .cells
        .pending
        .push(Notice::StatusPending(CellId(0)));
    assert_eq!(r.d.turn(Vec::new()), None);
}

fn settles(r: &Rig) -> Vec<Call> {
    r.d.colony
        .effects
        .cells
        .calls
        .iter()
        .filter(|c| matches!(c, Call::Settle(..)))
        .cloned()
        .collect()
}

#[test]
fn a_daemon_with_a_queen_waits_for_statuses() {
    let r = boot(WORKER, &["db"], "waits");
    assert!(
        r.d.colony.effects.cells.waits,
        "the cell layer was told to wait for a reap"
    );
    let standalone = {
        let tmp = Tmp::new("nowait");
        std::fs::create_dir_all(tmp.0.join("run")).unwrap();
        std::fs::create_dir_all(tmp.0.join("comb")).unwrap();
        for f in ["console", "kmsg"] {
            std::fs::write(tmp.0.join(f), b"").unwrap();
        }
        let args = Args {
            db: tmp.0.join("colony.db"),
            comb: tmp.0.join("comb"),
            socket: tmp.0.join("run/colony"),
            overseer: "/o".into(),
            syslog: tmp.0.join("nolog"),
            console: tmp.0.join("console"),
            run: tmp.0.join("run"),
            queen_fd: None,
        };
        let syslog = Syslog::new(&args.syslog, &args.console, &tmp.0.join("kmsg"));
        inotify_slot();
        let d = Daemon::boot(
            FakeCells::default(),
            &args,
            &database(WORKER, &["db"]),
            Store::standalone(),
            syslog,
        )
        .expect("boots");
        d.colony.effects.cells.waits
    };
    assert!(!standalone, "without queen nothing waits for a reap");
}

#[test]
fn a_reaped_wake_delivers_a_pending_status() {
    let mut r = boot(WORKER, &["db"], "reaped");
    status_pending(&mut r);
    assert!(
        r.d.colony
            .effects
            .deadlines
            .is_armed(Key::Status(CellId(0)))
    );
    r.d.colony.effects.cells.settled.insert(0);
    r.queen.send(ToColony::Reaped, None);
    assert_eq!(r.d.pump(), None);
    assert_eq!(settles(&r), [Call::Settle(0, false)]);
    assert!(
        !r.d.colony
            .effects
            .deadlines
            .is_armed(Key::Status(CellId(0))),
        "a settled status needs no deadline"
    );
}

#[test]
fn a_wake_before_the_status_is_there_keeps_waiting() {
    let mut r = boot(WORKER, &["db"], "early");
    status_pending(&mut r);
    r.queen.send(ToColony::Reaped, None);
    assert_eq!(r.d.pump(), None);
    assert_eq!(settles(&r), [Call::Settle(0, false)]);
    assert!(
        r.d.colony
            .effects
            .deadlines
            .is_armed(Key::Status(CellId(0)))
    );
}

#[test]
fn a_status_that_never_comes_is_given_up_after_a_second() {
    let mut r = boot(WORKER, &["db"], "giveup");
    status_pending(&mut r);
    r.d.colony.effects.cells.settled.insert(0);
    r.d.colony.effects.deadlines.arm(Key::Status(CellId(0)), 0);
    assert_eq!(r.d.turn(Vec::new()), None);
    assert_eq!(settles(&r), [Call::Settle(0, true)]);
    assert!(
        !r.d.colony
            .effects
            .deadlines
            .is_armed(Key::Status(CellId(0)))
    );
}

#[test]
fn a_wake_with_nothing_pending_does_nothing() {
    let mut r = boot(WORKER, &["db"], "nothing");
    r.queen.send(ToColony::Reaped, None);
    assert_eq!(r.d.pump(), None);
    assert!(settles(&r).is_empty());
}

#[test]
fn queen_going_away_does_not_stop_colony() {
    let mut r = boot(WORKER, &["db"], "gone");
    let queen = std::mem::replace(&mut r.queen, FakeQueen::new().0);
    drop(queen);
    assert_eq!(r.d.pump(), None);
    assert!(r.d.colony.effects.store.link().is_none());
    let said = r.logged().iter().filter(|l| l.contains("queen")).count();
    assert_eq!(said, 1, "logged once: {:?}", r.logged());
    // Colony serves on: a report still reaches its node.
    r.d.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(0), Report::Ready));
    assert_eq!(r.d.turn(Vec::new()), None);
    assert_eq!(r.d.colony.state(0), Some(State::Ready));
}

#[test]
fn a_save_that_fails_for_good_lets_the_loop_go_of_the_channel() {
    let mut r = boot(WORKER, &["db"], "lost");
    let queen = std::mem::replace(&mut r.queen, FakeQueen::new().0);
    drop(queen);
    // A state change saves before the loop has seen the hang-up: the send is what finds it.
    r.d.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(0), Report::Ready));
    assert_eq!(r.d.turn(Vec::new()), None);
    assert!(r.d.colony.effects.store.link().is_none());
    assert!(
        r.d.colony.effects.store.take_lost().is_none(),
        "the daemon removed the channel from its loop and closed it"
    );
    assert_eq!(r.d.pump(), None);
    assert_eq!(r.d.colony.state(0), Some(State::Ready));
}

/// Gets a booted `db` ready, then lets the cells of its shutdown come back.
fn ready(r: &mut Rig) {
    r.d.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(0), Report::Ready));
    assert_eq!(r.d.turn(Vec::new()), None);
}

fn graph_down(r: &mut Rig) -> Option<u8> {
    for report in [Report::MainExited(Some(0)), Report::Empty, Report::Removed] {
        r.d.colony
            .effects
            .cells
            .pending
            .push(Notice::Cell(CellId(0), report));
    }
    r.d.turn(Vec::new())
}

#[test]
fn a_shutdown_record_reaches_queen_before_a_cell_is_stopped() {
    let tmp = Tmp::new("announce-order");
    let _ = tmp;
    let seen = std::rc::Rc::new(std::cell::Cell::new(None));
    let mut cells = FakeCells::default();
    let bytes = database(WORKER, &["db"]);
    let (d, _tmp, _log, mut queen) = try_boot(&bytes, "announce", FakeCells::default(), |_, _| {});
    let mut d = d.expect("boots");
    let peer = queen.peer.try_clone().unwrap();
    let flag = seen.clone();
    cells.on_stop = Some(Box::new(move || {
        let mut found = false;
        loop {
            let mut buf = [0u8; 32];
            let Ok(r) = qinit_ipc::recv(std::os::fd::AsFd::as_fd(&peer), &mut buf) else {
                break;
            };
            found |= matches!(
                qinit_queen_core::decode_from_colony(&buf[..r.len], r.fds.len()),
                Some(qinit_queen_core::FromColony::Shutdown {
                    mode: qinit_queen_core::Mode::Poweroff
                })
            );
        }
        flag.set(Some(found));
    }));
    // Swap the fake cell layer's hook in: the stop must find the record already sent.
    d.colony.effects.cells.on_stop = cells.on_stop.take();
    d.colony
        .effects
        .cells
        .pending
        .push(Notice::Cell(CellId(0), Report::Ready));
    assert_eq!(d.turn(Vec::new()), None);
    let out = d
        .colony
        .request_shutdown(qinit_colony::ShutdownMode::Poweroff, 0);
    assert!(out.errors.is_empty());
    assert_eq!(
        seen.get(),
        Some(true),
        "the first stop found the Shutdown record in queen's socket"
    );
    let _ = &mut queen;
}

#[test]
fn a_queen_request_shuts_down_in_its_mode() {
    for (mode, code) in [
        (qinit_queen_core::Mode::Poweroff, exit::POWEROFF),
        (qinit_queen_core::Mode::Reboot, exit::REBOOT),
        (qinit_queen_core::Mode::Halt, exit::HALT),
    ] {
        let mut r = boot(WORKER, &["db"], "queenreq");
        ready(&mut r);
        r.queen.send(ToColony::Request { mode }, None);
        assert_eq!(r.d.pump(), None, "the graph is not down yet");
        assert!(
            r.d.colony
                .effects
                .cells
                .calls
                .iter()
                .any(|c| matches!(c, Call::Stop(0, ..))),
            "{mode:?}: the node is stopped"
        );
        assert_eq!(graph_down(&mut r), Some(code), "{mode:?}");
        r.queen.pump();
        assert!(
            r.queen.shutdowns.contains(&match mode {
                qinit_queen_core::Mode::Poweroff => qinit_queen_core::Mode::Poweroff,
                qinit_queen_core::Mode::Reboot => qinit_queen_core::Mode::Reboot,
                qinit_queen_core::Mode::Halt => qinit_queen_core::Mode::Halt,
            }),
            "colony announced the mode it ends in: {:?}",
            r.queen.shutdowns
        );
    }
}

#[test]
fn a_request_read_at_boot_starts_the_shutdown() {
    let bytes = database(WORKER, &["db"]);
    let (d, _tmp, _log, _queen) = try_boot(&bytes, "bootreq", FakeCells::default(), |_, q| {
        // Ctrl-Alt-Del came before colony was up: queen sends it right after the hand-over.
        q.queued.push(ToColony::Request {
            mode: qinit_queen_core::Mode::Reboot,
        });
    });
    let mut d = d.expect("boots");
    assert_eq!(d.pump(), None);
    assert!(
        d.colony
            .effects
            .cells
            .calls
            .iter()
            .any(|c| matches!(c, Call::Stop(0, ..))),
        "the shutdown has begun"
    );
    for report in [Report::MainExited(Some(0)), Report::Empty, Report::Removed] {
        d.colony
            .effects
            .cells
            .pending
            .push(Notice::Cell(CellId(0), report));
    }
    assert_eq!(d.turn(Vec::new()), Some(exit::REBOOT));
}

#[test]
fn cells_left_in_the_comb_are_logged_and_left_alone() {
    let tmp = Tmp::new("leftalone");
    let run = tmp.0.join("run");
    std::fs::create_dir_all(&run).unwrap();
    let comb = tmp.0.join("comb");
    std::fs::create_dir_all(comb.join("old-a")).unwrap();
    std::fs::create_dir_all(comb.join("old-b")).unwrap();
    std::fs::write(comb.join("cgroup.procs"), b"").unwrap();
    for f in ["console", "kmsg"] {
        std::fs::write(tmp.0.join(f), b"").unwrap();
    }
    let log = UnixDatagram::bind(tmp.0.join("log")).unwrap();
    let args = Args {
        db: tmp.0.join("colony.db"),
        comb,
        socket: run.join("colony"),
        overseer: "/o".into(),
        syslog: tmp.0.join("log"),
        console: tmp.0.join("console"),
        run,
        queen_fd: None,
    };
    let bytes = database(WORKER, &["db"]);
    let syslog = Syslog::new(&args.syslog, &args.console, &tmp.0.join("kmsg"));
    inotify_slot();
    let d = Daemon::boot(
        FakeCells::default(),
        &args,
        &bytes,
        Store::standalone(),
        syslog,
    )
    .expect("boots");
    let said = lines_of(&log);
    for name in ["old-a", "old-b"] {
        let n = said
            .iter()
            .filter(|l| l.contains(&format!("the cell {name} was found in the comb")))
            .count();
        assert_eq!(n, 1, "{name}: {said:?}");
    }
    assert!(
        !said.iter().any(|l| l.contains("cgroup.procs")),
        "only directories are cells"
    );
    assert!(
        !d.colony
            .effects
            .cells
            .calls
            .iter()
            .any(|c| matches!(c, Call::Adopt(..))),
        "nothing is re-adopted"
    );
    assert!(args.comb.join("old-a").exists(), "and nothing is removed");
}

#[test]
fn a_second_shutdown_request_on_one_connection_is_accepted_and_changes_the_mode() {
    let mut r = boot(WORKER, &["db"], "twoshut");
    ready(&mut r);
    let client = connect_root(&mut r);
    for mode in [Mode::Poweroff, Mode::Reboot] {
        ask(
            &client,
            Req::Shutdown {
                mode,
                settled: false,
                wait_ms: 0,
            },
            &[],
        );
        assert_eq!(r.d.pump(), None, "the node is still stopping");
        assert_eq!(
            answer(&client, |rep| matches!(rep, Rep::Accepted)),
            Some(true),
            "{mode:?} was accepted on the same connection"
        );
    }
    assert_eq!(
        r.d.colony.shutdown_mode(),
        Some(qinit_colony::ShutdownMode::Reboot),
        "the last request wins"
    );
    qinit_sys::signal::unblock_all().unwrap();
}

#[test]
fn saves_dropped_while_queen_did_not_read_are_sent_again_and_never_name_a_missing_key() {
    let mut r = boot(WORKER, &["db"], "stalled");
    ready(&mut r);
    // Queen stops reading until colony's socket is full and one send has given up.
    let mut n = 0;
    while r.d.colony.effects.store.warnings_pending() == 0 {
        let _ = r.d.colony.effects.store.save(KEY_DB, b"filler");
        n += 1;
        assert!(n < 100_000, "the socket never filled");
    }
    // The node is stopped and started again while queen is deaf: new descriptors, new texts.
    let out = r.d.colony.request(0, qinit_colony::Request::Stop, 0);
    assert!(out.errors.is_empty());
    for report in [Report::MainExited(Some(0)), Report::Empty, Report::Removed] {
        r.d.colony
            .effects
            .cells
            .pending
            .push(Notice::Cell(CellId(0), report));
    }
    assert_eq!(r.d.turn(Vec::new()), None);
    assert_eq!(r.d.colony.state(0), Some(State::Off), "stopped");
    let out = r.d.colony.request(0, qinit_colony::Request::Start, 0);
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    assert_eq!(r.d.turn(Vec::new()), None);
    // The start waits out a backoff; it is due now.
    r.d.colony
        .effects
        .deadlines
        .arm(Key::Node(0, qinit_colony::TimerKind::Backoff), 0);
    assert_eq!(r.d.turn(Vec::new()), None);
    assert_eq!(r.d.colony.state(0), Some(State::Starting), "started again");
    // Queen reads again (whatever got through is applied), and colony wakes once more.
    r.queen.pump();
    assert_eq!(r.d.turn(Vec::new()), None);
    r.queen.pump();
    assert_eq!(r.d.turn(Vec::new()), None);
    let cells = parse_cells(&r.queen.text(KEY_CELLS).expect("the cells entry")).unwrap();
    assert_eq!(
        cells.len(),
        1,
        "{cells:?}; calls {:?}; events {:?}; log {:?}",
        r.d.colony.effects.cells.calls,
        r.queen.events,
        r.logged()
    );
    for key in [cells[0].dir_key, cells[0].main_key] {
        assert!(
            r.queen.held.contains_key(&key),
            "the state names key {key}, which queen does not hold: {:?}",
            r.queen.held.keys().collect::<Vec<_>>()
        );
    }
}

#[test]
fn colony_tells_queen_it_is_turning_every_alive_period() {
    use common::Sent;
    use qinit_colonyd::daemon::ALIVE_MS;
    let mut r = boot(WORKER, &["db"], "alive");
    r.queen.pump();
    let alives = |q: &common::FakeQueen| q.events.iter().filter(|e| **e == Sent::Alive).count();
    assert_eq!(alives(&r.queen), 1, "the first heartbeat is at boot");
    let t = u64::MAX / 4;
    assert!(r.d.beat(t), "a period later");
    assert!(!r.d.beat(t + ALIVE_MS - 1), "not before the period is over");
    assert!(r.d.beat(t + ALIVE_MS));
    r.queen.pump();
    assert_eq!(alives(&r.queen), 3);
}

#[test]
fn without_queen_there_is_no_heartbeat() {
    use qinit_colonyd::daemon::ALIVE_MS;
    let mut r = boot(WORKER, &["db"], "no-heartbeat");
    r.d.colony.effects.store.detach();
    assert!(!r.d.beat(u64::MAX / 4 + ALIVE_MS));
}
