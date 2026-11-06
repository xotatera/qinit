// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The loop, on the host: start-up refusals through the real binary, and the whole daemon over a
//! fake cell layer (the real cgroups are the VM suites').
mod common;

use common::*;
use qinit_cell::{CellId, Notice, Report};
use qinit_colony::{Peer, State, TimerKind};
use qinit_colonyd::args::Args;
use qinit_colonyd::daemon::{Daemon, inside_comb};
use qinit_colonyd::deadlines::Key;
use qinit_colonyd::exit;
use qinit_colonyd::state::State as Saved;
use qinit_colonyd::syslog::Syslog;
use qinit_ipc::{connect_seqpacket, recv, send};
use qinit_proto_core::MAX_MESSAGE;
use qinit_wire::{Mode, Msg, Rep, Req, decode, encode};
use std::ffi::CString;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::process::Command;

const WORKER: &str = "[worker.db]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/db\"]\n";

fn colony_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_colony"))
}

// ---- start-up refusals, through the binary ----

#[test]
fn usage_errors_exit_2() {
    let out = colony_bin().arg("--bogus").output().unwrap();
    assert_eq!(out.status.code(), Some(i32::from(exit::USAGE)));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--bogus") && err.contains("usage"), "{err}");
    assert_eq!(
        colony_bin().args(["--db"]).output().unwrap().status.code(),
        Some(i32::from(exit::USAGE))
    );
}

fn own_cgroup() -> Option<String> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::to_owned)
}

#[test]
fn colony_inside_the_comb_refuses_to_start() {
    let Some(own) = own_cgroup() else {
        eprintln!("skipped: no cgroup v2 line in /proc/self/cgroup");
        return;
    };
    let tmp = Tmp::new("inside");
    let comb = format!("/sys/fs/cgroup{own}");
    let out = colony_bin()
        .args(["--comb", &comb, "--run"])
        .arg(&tmp.0)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(i32::from(exit::STARTUP)), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("inside the comb"), "{err}");
}

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

#[test]
fn a_refused_database_exits_3_before_anything_else_is_touched() {
    let tmp = Tmp::new("baddb");
    let db = tmp.0.join("colony.db");
    std::fs::write(&db, b"not a database").unwrap();
    let comb = tmp.0.join("comb");
    let out = colony_bin()
        .arg("--db")
        .arg(&db)
        .arg("--run")
        .arg(tmp.0.join("run"))
        .arg("--comb")
        .arg(&comb)
        .arg("--syslog")
        .arg(tmp.0.join("nolog"))
        .arg("--console")
        .arg(tmp.0.join("console"))
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(i32::from(exit::DATABASE)),
        "{out:?}"
    );
    assert!(!comb.exists(), "the comb was not touched");
    let missing = colony_bin()
        .arg("--db")
        .arg(tmp.0.join("absent.db"))
        .arg("--run")
        .arg(tmp.0.join("run"))
        .output()
        .unwrap();
    assert_eq!(
        missing.status.code(),
        Some(i32::from(exit::DATABASE)),
        "{missing:?}"
    );
}

// ---- the daemon over a fake cell layer ----

struct Rig {
    d: Daemon<FakeCells>,
    tmp: Tmp,
    log: UnixDatagram,
    bytes: Vec<u8>,
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
    let (d, tmp, log) = try_boot(&bytes, tag, FakeCells::default(), |_| {});
    Rig {
        d: d.expect("boots"),
        tmp,
        log,
        bytes,
    }
}

/// Boots over `bytes` and `cells`; `prep` may change the arguments or the run directory first.
fn try_boot(
    bytes: &[u8],
    tag: &str,
    cells: FakeCells,
    prep: impl FnOnce(&mut Args),
) -> (Result<Daemon<FakeCells>, u8>, Tmp, UnixDatagram) {
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
    };
    prep(&mut args);
    let syslog = Syslog::new(&args.syslog, &args.console, &tmp.0.join("kmsg"));
    let state = Saved::open(&run).unwrap();
    let d = Daemon::boot(cells, &args, bytes, state, syslog);
    (d, tmp, log)
}

fn lines_of(log: &UnixDatagram) -> Vec<String> {
    log.set_nonblocking(true).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    while let Ok(n) = log.recv(&mut buf) {
        out.push(String::from_utf8_lossy(&buf[..n]).into_owned());
    }
    out
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
    let r = boot(WORKER, &["db"], "boot");
    assert!(
        r.d.colony
            .effects
            .cells
            .calls
            .iter()
            .any(|c| matches!(c, Call::Create(n) if n == "db")),
        "the enabled node was started"
    );
    let saved = Saved::open(&r.run()).unwrap();
    assert_eq!(
        saved.read_db().unwrap().as_deref(),
        Some(&r.bytes[..]),
        "the database in force"
    );
    let cells = saved.read_cells().unwrap().unwrap();
    assert_eq!(cells.len(), 1);
    assert_eq!(
        (cells[0].name.as_str(), cells[0].cgroup_id, cells[0].ready),
        ("db", 900, false)
    );
    let nodes = saved.read_nodes().unwrap().unwrap();
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
    let saved = Saved::open(&r.run()).unwrap();
    assert!(
        saved.read_cells().unwrap().unwrap()[0].ready,
        "the ready flag is saved"
    );
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
    let (socket, run) = (r.socket(), r.run());
    assert_eq!(r.d.finish(exit::HALT), exit::HALT);
    assert!(!socket.exists(), "the socket file is removed");
    let saved = Saved::open(&run).unwrap();
    assert_eq!(saved.read_cells(), Ok(None), "nothing is left to re-adopt");
    assert_eq!(saved.read_db(), Ok(None));
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
    let saved = Saved::open(&r.run()).unwrap();
    assert_eq!(
        saved.read_db().unwrap().as_deref(),
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
    };
    let bytes = database(frames, &["db"]);
    let syslog = Syslog::new(&args.syslog, &args.console, &tmp.0.join("kmsg"));
    let state = Saved::open(&run).unwrap();
    let mut d = Daemon::boot(cells, &args, &bytes, state, syslog).expect("boots");
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
    // The end of file arrives when the last copy of the write end is closed. Another test's
    // `fork` may hold a copy for the moment before its `exec`, so this waits for the event (with
    // a guard) instead of looking once.
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
        .collect()
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
    let saved = Saved::open(&r.run()).unwrap();
    let lines = saved.read_cells().unwrap().unwrap();
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
        std::os::unix::fs::PermissionsExt::from_mode(0),
    )
    .unwrap();
    assert_eq!(r.d.pump(), None);
    let logged = r.logged();
    assert!(
        logged
            .iter()
            .any(|l| l.starts_with("<27>") && l.contains("db") && l.contains("watch")),
        "an error line names the node and the lost watch: {logged:?}"
    );
    std::fs::set_permissions(
        dir.0.join("a"),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
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
    let (d, _tmp, log) = try_boot(
        b"not a database",
        "refusenotes",
        FakeCells::default(),
        |a| {
            // An earlier colony's cell map that does not parse, and a database that is refused.
            let state = Saved::open(&a.run).unwrap();
            drop(state);
            std::fs::write(a.run.join("state/cells"), b"garbage\n").unwrap();
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
    let (d, _tmp, _log) = try_boot(&bytes, "nobind", cells, |a| {
        a.socket = a.run.join("no-such-dir/colony");
    });
    assert_eq!(d.err(), Some(exit::STARTUP));
    assert!(
        !started.get(),
        "a service was started that no colony will track"
    );
}
