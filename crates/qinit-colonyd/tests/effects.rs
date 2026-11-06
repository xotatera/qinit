// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The real effects over a fake cell layer: what they ask of the cells, in what order, with
//! what descriptors.
mod common;

use common::*;
use qinit_cell::{CellId, Notice, Phase, Polite, ReadyMode};
use qinit_colony::{Effects, Errno, StopMode, TimerKind};
use qinit_colonyd::deadlines::Key;
use qinit_colonyd::effects::{RealEffects, deadline_ms};
use qinit_colonyd::route::Owner;
use qinit_db::Ready;
use std::os::fd::AsFd;
use std::time::Duration;

fn rig(cells: FakeCells, comb: &std::path::Path) -> RealEffects<FakeCells> {
    let events = qinit_event::Loop::new().unwrap();
    RealEffects::new(
        cells,
        "/usr/lib/qinit/overseer".into(),
        comb.to_owned(),
        events,
        9,
    )
    .unwrap()
}

/// Whether `needle` occurs in `hay`.
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn deadline_ms_follows_r16() {
    assert_eq!(deadline_ms(0), 30_000);
    assert_eq!(deadline_ms(5_000), 5_000);
    assert_eq!(deadline_ms(30_000), 30_000);
    assert_eq!(deadline_ms(90_000), 30_000);
}

#[test]
fn start_creates_limits_then_spawns_the_overseer_with_the_request_at_3() {
    let tmp = Tmp::new("start");
    let mut node = worker("db");
    node.memory_max_kib = 1024;
    node.pids_max = 32;
    let m = model(vec![node]);
    let mut fx = rig(FakeCells::default(), &tmp.0);
    let pid = fx.start(0, &spec_of(&m, 0), &m).unwrap();
    assert_eq!(pid, 4000);
    let calls: Vec<_> = fx.cells.calls.clone();
    assert_eq!(
        calls,
        [
            Call::Create("db".into()),
            Call::SetLimits(0, 1_048_576, 32),
            Call::Spawn(0, ReadyMode::Pipe),
        ]
    );
    let sp = &fx.cells.spawned[0];
    assert_eq!(sp.path, std::path::Path::new("/usr/lib/qinit/overseer"));
    assert_eq!(sp.argv, ["overseer"]);
    let numbers: Vec<i32> = sp.fds.iter().map(|(_, n)| *n).collect();
    assert_eq!(numbers, [3, 4], "the request and the status pipe");
    assert_eq!(
        sp.ready_fd, 5,
        "the readiness pipe is made by the cell layer at 5"
    );
    // The request at 3 is sealed, decodes, and is the one the builder makes for this node.
    let req = qinit_ipc::memfd::read_all(sp.fds[0].0.as_fd(), 1 << 20).unwrap();
    assert_eq!(qinit_overseer_core::decode(&req), Ok(()));
    let want = qinit_overseer::request::from_model(
        &m.nodes[0],
        &m,
        &qinit_overseer::request::Routed {
            stdin: None,
            stdout: None,
            stderr: None,
            ready: Some(5),
        },
        deadline_ms(90_000),
    )
    .unwrap()
    .bytes()
    .unwrap();
    assert_eq!(req, want);
    assert!(
        req.windows(7).any(|w| w == b"/bin/db"),
        "the node's own argv"
    );
    assert_eq!(fx.routes.cell(Owner::Node(0)), Some(CellId(0)));
    assert!(fx.dirty, "the cell map changed");
}

#[test]
fn a_zero_limit_asks_for_nothing_to_be_written() {
    let tmp = Tmp::new("nolimit");
    let m = model(vec![worker("db")]);
    let mut fx = rig(FakeCells::default(), &tmp.0);
    fx.start(0, &spec_of(&m, 0), &m).unwrap();
    assert!(
        fx.cells.calls.contains(&Call::SetLimits(0, 0, 0)),
        "passed through as 0: the cell layer skips the file"
    );
}

#[test]
fn a_limit_that_cannot_be_written_removes_the_cell_and_fails_the_start() {
    let tmp = Tmp::new("limitfail");
    let mut node = worker("db");
    node.pids_max = 8;
    let m = model(vec![node]);
    let mut cells = FakeCells::default();
    cells.limits_fail = Some(libc::EPERM);
    let mut fx = rig(cells, &tmp.0);
    assert_eq!(fx.start(0, &spec_of(&m, 0), &m), Err(Errno(libc::EPERM)));
    assert!(fx.cells.calls.contains(&Call::Remove(0)));
    assert!(!fx.cells.calls.iter().any(|c| matches!(c, Call::Spawn(..))));
    assert_eq!(fx.routes.cell(Owner::Node(0)), None);
    assert!(fx.status.is_empty(), "no status pipe is kept");
}

#[test]
fn an_existing_directory_fails_the_start_without_touching_it() {
    // Something else made `db` in the comb: colony never kills or removes what it cannot show is
    // its own, so it does not even ask the cell layer for a cell of that name.
    let tmp = Tmp::new("exists");
    std::fs::create_dir(tmp.0.join("db")).unwrap();
    let m = model(vec![worker("db")]);
    let mut fx = rig(FakeCells::default(), &tmp.0);
    assert_eq!(fx.start(0, &spec_of(&m, 0), &m), Err(Errno(libc::EEXIST)));
    assert!(fx.cells.calls.is_empty(), "{:?}", fx.cells.calls);
    assert!(
        tmp.0.join("db").is_dir(),
        "the foreign directory is still there"
    );
    assert_eq!(fx.routes.cell(Owner::Node(0)), None);
    assert!(fx.status.is_empty());
}

#[test]
fn a_late_create_failure_is_reported_once() {
    let tmp = Tmp::new("late");
    let m = model(vec![worker("db")]);
    let mut cells = FakeCells::default();
    cells.create_fails = true;
    let mut fx = rig(cells, &tmp.0);
    assert_eq!(
        fx.start(0, &spec_of(&m, 0), &m),
        Err(Errno(libc::EIO)),
        "the cell layer could not make the directory, and there was none before"
    );
    assert!(fx.cells.calls.contains(&Call::Remove(0)));
    assert!(
        !fx.cells
            .calls
            .iter()
            .any(|c| matches!(c, Call::SetLimits(..) | Call::Spawn(..))),
        "a failed cell is not written to or spawned into"
    );
    assert_eq!(fx.routes.cell(Owner::Node(0)), None);
    // The failure notice the cell layer queued is not delivered a second time.
    let heard = fx.drain_notices().unwrap();
    assert!(heard.cells.is_empty(), "{:?}", heard.cells);
}

#[test]
fn a_failed_starts_slot_is_not_confused_with_the_next_cell() {
    let tmp = Tmp::new("reuse");
    let m = model(vec![worker("a"), worker("b")]);
    let mut cells = FakeCells::default();
    cells.create_fails = true;
    let mut fx = rig(cells, &tmp.0);
    assert!(fx.start(0, &spec_of(&m, 0), &m).is_err());
    fx.start(1, &spec_of(&m, 1), &m).unwrap();
    // A notice of the later cell is routed to it, and only it.
    fx.cells
        .pending
        .push(Notice::Cell(CellId(1), qinit_cell::Report::Ready));
    let heard = fx.drain_notices().unwrap();
    assert_eq!(heard.cells, [(Owner::Node(1), qinit_cell::Report::Ready)]);
}

#[test]
fn stop_without_a_main_stops_the_cell() {
    let tmp = Tmp::new("nomain");
    let m = model(vec![worker("db")]);
    let mut fx = rig(FakeCells::default(), &tmp.0);
    fx.start(0, &spec_of(&m, 0), &m).unwrap();
    fx.stop(0, StopMode::Main, 2_000).unwrap();
    let g = Duration::from_millis(2_000);
    assert_eq!(
        fx.cells.calls.last(),
        Some(&Call::Stop(0, Polite::Main, g, g))
    );
    // An adopted cell whose main did not come back has no main to signal.
    fx.cells.mains.clear();
    fx.stop(0, StopMode::Main, 2_000).unwrap();
    assert_eq!(
        fx.cells.calls.last(),
        Some(&Call::Stop(0, Polite::Cell, g, g))
    );
    fx.stop(0, StopMode::Cell, 2_000).unwrap();
    assert_eq!(
        fx.cells.calls.last(),
        Some(&Call::Stop(0, Polite::Cell, g, g))
    );
    assert_eq!(
        fx.stop(5, StopMode::Main, 1),
        Err(Errno(libc::ENOENT)),
        "no cell"
    );
}

#[test]
fn release_removes_the_cell_and_forgets_everything_of_it() {
    let tmp = Tmp::new("release");
    let m = model(vec![worker("db")]);
    let mut fx = rig(FakeCells::default(), &tmp.0);
    fx.start(0, &spec_of(&m, 0), &m).unwrap();
    assert_eq!(fx.status.len(), 1);
    fx.dirty = false;
    fx.release(0);
    assert!(fx.cells.calls.contains(&Call::Remove(0)));
    assert_eq!(fx.routes.cell(Owner::Node(0)), None);
    assert!(fx.status.is_empty(), "the status pipe is dropped");
    assert!(fx.dirty);
}

#[test]
fn socket_readiness_watches_before_the_spawn() {
    let tmp = Tmp::new("sock");
    let sock = tmp.0.join("run/s.sock");
    let mut node = worker("web");
    node.ready = Ready::Socket(sock.to_string_lossy().into_owned());
    let m = model(vec![node]);
    let mut cells = FakeCells::default();
    // The service binds its socket the instant it is spawned.
    let at = sock.clone();
    cells.on_spawn = Some(Box::new(move || {
        std::fs::create_dir_all(at.parent().unwrap()).unwrap();
        std::mem::forget(std::os::unix::net::UnixListener::bind(&at).unwrap());
    }));
    let mut fx = rig(cells, &tmp.0);
    fx.start(0, &spec_of(&m, 0), &m).unwrap();
    assert_eq!(fx.cells.calls[2], Call::Spawn(0, ReadyMode::External));
    let ready = fx.take_path_events().unwrap();
    assert_eq!(
        ready,
        [qinit_colonyd::effects::PathEvent::Ready(Owner::Node(0))]
    );
}

#[test]
fn a_path_or_socket_that_exists_before_the_start_is_not_ready() {
    let tmp = Tmp::new("stale");
    let pid = tmp.0.join("run/x.pid");
    std::fs::create_dir_all(pid.parent().unwrap()).unwrap();
    std::fs::write(&pid, b"1").unwrap();
    let mut node = worker("d");
    node.ready = Ready::Path(pid.to_string_lossy().into_owned());
    let m = model(vec![node]);
    let mut fx = rig(FakeCells::default(), &tmp.0);
    fx.start(0, &spec_of(&m, 0), &m).unwrap();
    assert_eq!(fx.take_path_events().unwrap(), []);
    assert_eq!(fx.cells.calls[2], Call::Spawn(0, ReadyMode::External));
}

#[test]
fn timers_and_waits_live_in_the_deadline_queue() {
    let tmp = Tmp::new("timers");
    let mut fx = rig(FakeCells::default(), &tmp.0);
    fx.now_ms = 1_000;
    fx.arm(3, TimerKind::Backoff, 250).unwrap();
    fx.arm_wait(7, 100).unwrap();
    assert_eq!(fx.deadlines.next(), Some(1_100));
    fx.cancel_wait(7);
    fx.arm(3, TimerKind::Backoff, 500).unwrap();
    assert_eq!(fx.deadlines.next(), Some(1_500), "a re-arm replaces");
    fx.cancel(3, TimerKind::Backoff).unwrap();
    assert_eq!(fx.deadlines.next(), None);
}

#[test]
fn watch_path_reports_an_existing_path_at_once_and_a_later_one_by_event() {
    let tmp = Tmp::new("edge");
    let there = tmp.0.join("there");
    std::fs::write(&there, b"x").unwrap();
    let later = tmp.0.join("d/later");
    let mut fx = rig(FakeCells::default(), &tmp.0);
    assert_eq!(fx.watch_path(there.to_str().unwrap()), Ok(true));
    assert_eq!(fx.watch_path(later.to_str().unwrap()), Ok(false));
    std::fs::create_dir_all(later.parent().unwrap()).unwrap();
    std::fs::write(&later, b"x").unwrap();
    assert_eq!(
        fx.take_path_events().unwrap(),
        [qinit_colonyd::effects::PathEvent::Path(
            later.to_string_lossy().into_owned()
        )]
    );
}

#[test]
fn remap_moves_routes_and_timers() {
    let tmp = Tmp::new("remap");
    let m = model(vec![worker("a"), worker("b")]);
    let mut fx = rig(FakeCells::default(), &tmp.0);
    fx.start(0, &spec_of(&m, 0), &m).unwrap();
    fx.start(1, &spec_of(&m, 1), &m).unwrap();
    fx.now_ms = 10;
    fx.arm(1, TimerKind::StartTimeout, 40).unwrap();
    fx.arm(0, TimerKind::StartTimeout, 60).unwrap();
    // New node 0 is new, new 1 was `b`; `a` is gone.
    fx.remap(&[u32::MAX, 1]);
    assert_eq!(
        fx.routes.cell(Owner::Node(1)),
        Some(CellId(1)),
        "b's cell moved with b"
    );
    assert_eq!(fx.routes.cell(Owner::Node(0)), None);
    assert_eq!(
        fx.routes.owner(CellId(0)),
        None,
        "a's cell has no owner now"
    );
    assert_eq!(fx.status.len(), 1);
    assert_eq!(
        fx.deadlines.due(1_000),
        [Key::Node(1, TimerKind::StartTimeout)],
        "only b's timer survives, on b's new index"
    );
}

#[test]
fn signal_goes_to_the_cells_main() {
    let tmp = Tmp::new("signal");
    let m = model(vec![worker("db")]);
    let mut fx = rig(FakeCells::default(), &tmp.0);
    fx.start(0, &spec_of(&m, 0), &m).unwrap();
    fx.signal(0, libc::SIGHUP).unwrap();
    assert_eq!(fx.cells.calls.last(), Some(&Call::Signal(0, libc::SIGHUP)));
    assert_eq!(fx.signal(4, libc::SIGHUP), Err(Errno(libc::ENOENT)));
}

#[test]
fn a_cell_the_effects_do_not_own_routes_to_nothing() {
    let tmp = Tmp::new("stray");
    let mut fx = rig(FakeCells::default(), &tmp.0);
    fx.cells
        .pending
        .push(Notice::Cell(CellId(40), qinit_cell::Report::Empty));
    fx.cells.pending.push(Notice::Orphan {
        pid: 77,
        status: 256,
    });
    let heard = fx.drain_notices().unwrap();
    assert!(heard.cells.is_empty());
    assert_eq!(heard.orphans, [(77, 256)]);
    let _ = Phase::Absent;
}

// ---- instances (Task 14) ----

use qinit_colony::InstanceSpec;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;

fn forager_frame() -> qinit_db::Node {
    let mut n = worker("backup");
    n.kind = qinit_db::Kind::Forager;
    n.ready = Ready::Exit;
    n.env = vec!["MODE=full".to_owned()];
    n
}

fn pipe_write_end() -> OwnedFd {
    let (r, w) = qinit_sys::fd::pipe(libc::O_CLOEXEC).unwrap();
    std::mem::forget(r);
    w
}

fn ino(fd: &OwnedFd) -> (u64, u64) {
    let f = std::fs::File::from(fd.try_clone().unwrap());
    let m = f.metadata().unwrap();
    (m.dev(), m.ino())
}

fn frame_instance(m: &qinit_db::Model, fds: [Option<OwnedFd>; 3]) -> InstanceSpec {
    InstanceSpec {
        name: "backup#1".into(),
        frame: 0,
        node: spec_of(m, 0),
        argv_tail: vec!["--fast".into()],
        env_add: vec![
            ("TARGET".into(), "/srv".into()),
            ("MODE".into(), "quick".into()),
        ],
        fds,
        request: None,
        memory_max_kib: 2048,
        pids_max: 16,
        ready_fd: None,
    }
}

#[test]
fn a_frame_instance_carries_the_tail_env_and_caller_fds() {
    let tmp = Tmp::new("inst");
    let m = model(vec![forager_frame()]);
    let mut fx = rig(FakeCells::default(), &tmp.0);
    let out = pipe_write_end();
    let out_ino = ino(&out);
    let pid = fx
        .start_instance(2, frame_instance(&m, [None, Some(out), None]), &m)
        .unwrap();
    assert_eq!(pid, 4000);
    assert_eq!(
        fx.cells.calls[..3],
        [
            Call::Create("backup#1".into()),
            Call::SetLimits(0, 2048 * 1024, 16),
            Call::Spawn(0, ReadyMode::Exit),
        ]
    );
    let sp = &fx.cells.spawned[0];
    let numbers: Vec<i32> = sp.fds.iter().map(|(_, n)| *n).collect();
    assert_eq!(
        numbers,
        [3, 4, 6],
        "request, status, then the caller's stdout from 6"
    );
    assert_eq!(ino(&sp.fds[2].0), out_ino, "the caller's own pipe");
    let req = qinit_ipc::memfd::read_all(sp.fds[0].0.as_fd(), 1 << 20).unwrap();
    assert_eq!(qinit_overseer_core::decode(&req), Ok(()));
    let want = qinit_overseer::request::from_instance(
        &m.nodes[0],
        &m,
        &qinit_overseer::request::Routed {
            stdin: None,
            stdout: Some(6),
            stderr: None,
            ready: None,
        },
        &["--fast".to_owned()],
        &[
            ("TARGET".to_owned(), "/srv".to_owned()),
            ("MODE".to_owned(), "quick".to_owned()),
        ],
        deadline_ms(90_000),
    )
    .unwrap()
    .bytes()
    .unwrap();
    assert_eq!(req, want);
    assert!(contains(&req, b"--fast"), "the argv tail");
    assert!(contains(&req, b"MODE=quick"), "the override");
    assert!(
        !contains(&req, b"MODE=full"),
        "the frame's own value is replaced"
    );
    assert_eq!(fx.routes.cell(Owner::Instance(2)), Some(CellId(0)));
    assert_eq!(fx.status.len(), 1);
}

#[test]
fn a_run_instance_passes_the_callers_request_unchanged() {
    let tmp = Tmp::new("run");
    let m = model(vec![forager_frame()]);
    let sealed = qinit_ipc::memfd::sealed(c"mine", b"QLR1 caller bytes").unwrap();
    let before = ino(&sealed);
    let mut spec = frame_instance(&m, [None, None, None]);
    spec.name = "~job#4".into();
    spec.frame = u32::MAX;
    spec.request = Some(sealed);
    let out = pipe_write_end();
    let err = pipe_write_end();
    spec.fds = [None, Some(out), Some(err)];
    let mut fx = rig(FakeCells::default(), &tmp.0);
    fx.start_instance(0, spec, &m).unwrap();
    let sp = &fx.cells.spawned[0];
    let numbers: Vec<i32> = sp.fds.iter().map(|(_, n)| *n).collect();
    assert_eq!(
        numbers,
        [3, 4, 6, 7],
        "stdout and stderr where the request routes them"
    );
    assert_eq!(ino(&sp.fds[0].0), before, "the same file, not a copy");
    assert_eq!(fx.cells.calls[0], Call::Create("~job#4".into()));
    assert_eq!(fx.cells.calls[2], Call::Spawn(0, ReadyMode::Exit));
}

#[test]
fn a_run_that_waits_for_ready_routes_the_pipe_at_its_number() {
    let tmp = Tmp::new("runready");
    let m = model(vec![forager_frame()]);
    let mut spec = frame_instance(&m, [None, None, None]);
    spec.name = "~svc#9".into();
    spec.frame = u32::MAX;
    spec.request = Some(qinit_ipc::memfd::sealed(c"mine", b"x").unwrap());
    spec.node.ready = Ready::Pipe;
    spec.ready_fd = Some(9);
    let mut fx = rig(FakeCells::default(), &tmp.0);
    fx.start_instance(1, spec, &m).unwrap();
    assert_eq!(fx.cells.calls[2], Call::Spawn(0, ReadyMode::Pipe));
    assert_eq!(fx.cells.spawned[0].ready_fd, 9);
}

#[test]
fn an_instance_is_stopped_released_and_given_a_pidfd_like_a_node() {
    let tmp = Tmp::new("instops");
    let m = model(vec![forager_frame()]);
    let mut fx = rig(FakeCells::default(), &tmp.0);
    fx.start_instance(3, frame_instance(&m, [None, None, None]), &m)
        .unwrap();
    assert!(fx.instance_pidfd(3).is_ok());
    assert_eq!(fx.instance_pidfd(8).err(), Some(Errno(libc::ENOENT)));
    fx.stop_instance(3, StopMode::Main, 1_000).unwrap();
    let g = Duration::from_millis(1_000);
    assert_eq!(
        fx.cells.calls.last(),
        Some(&Call::Stop(0, Polite::Main, g, g))
    );
    fx.release_instance(3);
    assert!(fx.cells.calls.contains(&Call::Remove(0)));
    assert_eq!(fx.routes.cell(Owner::Instance(3)), None);
    assert!(fx.status.is_empty());
    fx.release_instance(3); // colony may call it again after a failed start: nothing to do
}

#[test]
fn a_failed_instance_start_leaves_nothing_behind() {
    let tmp = Tmp::new("instfail");
    let m = model(vec![forager_frame()]);
    let mut cells = FakeCells::default();
    cells.limits_fail = Some(libc::EPERM);
    let mut fx = rig(cells, &tmp.0);
    assert_eq!(
        fx.start_instance(0, frame_instance(&m, [None, None, None]), &m)
            .err(),
        Some(Errno(libc::EPERM))
    );
    assert_eq!(fx.routes.cell(Owner::Instance(0)), None);
    assert!(fx.status.is_empty());
}

#[test]
fn remap_keeps_status_pipes_registered_under_their_new_owner() {
    use qinit_colonyd::effects::{STATUS_NODE, status_owner, status_token};
    let tmp = Tmp::new("statusmap");
    let m = model(vec![worker("a"), worker("b")]);
    let mut fx = rig(FakeCells::default(), &tmp.0);
    fx.start(0, &spec_of(&m, 0), &m).unwrap();
    fx.start(1, &spec_of(&m, 1), &m).unwrap();
    // Swap the two nodes' places.
    fx.remap(&[1, 0]);
    // `b`'s launch fails: the record arrives on its pipe, which is now node 0's.
    let b_write = &fx.cells.spawned[1].fds[1].0;
    qinit_overseer::status::Status {
        step: qinit_overseer::status::STEP_DECODE,
        errno: libc::EINVAL,
    }
    .write(b_write.as_fd());
    let ready = fx.events.poll().unwrap();
    let tokens: Vec<u64> = ready
        .iter()
        .filter_map(|r| match r {
            qinit_event::Ready::Readable(t) | qinit_event::Ready::Hangup(t) => Some(*t),
            _ => None,
        })
        .collect();
    assert_eq!(tokens, [status_token(Owner::Node(0))], "{ready:?}");
    assert_eq!(status_owner(STATUS_NODE), Some(Owner::Node(0)));
    assert_eq!(status_owner(7), None);
    let failure = fx.take_launch_record(Owner::Node(0)).unwrap();
    assert_eq!(failure.name, "b");
    assert_eq!((failure.step, failure.errno), ("decode", libc::EINVAL));
}

// ---- final review ----

#[test]
fn a_leftover_cell_the_cell_layer_gave_up_on_is_no_longer_waited_for() {
    use qinit_colonyd::effects::CellOps;
    let tmp = Tmp::new("clearfail");
    let mut fx = rig(FakeCells::default(), &tmp.0);
    let id = fx.cells.adopt("stray", 7, None).unwrap();
    fx.clear_cell(id, Duration::from_millis(10)).unwrap();
    assert!(fx.is_clearing());
    fx.cells.pending.clear();
    fx.cells.pending.push(Notice::Cell(
        id,
        qinit_cell::Report::Failed(qinit_cell::Failure::Stuck),
    ));
    let heard = fx.drain_notices().unwrap();
    assert_eq!(heard.strays.len(), 1, "the failure is still reported");
    assert!(!fx.is_clearing(), "a cell that failed is not waited for");
}

#[test]
fn a_new_cell_for_an_owner_clears_its_failed_and_ready_marks() {
    let tmp = Tmp::new("newcell");
    let m = model(vec![worker("db")]);
    let mut fx = rig(FakeCells::default(), &tmp.0);
    fx.failed.insert(Owner::Node(0));
    fx.ready.insert(Owner::Node(0));
    fx.start(0, &spec_of(&m, 0), &m).unwrap();
    assert!(!fx.failed.contains(&Owner::Node(0)), "failed is per cell");
    assert!(!fx.ready.contains(&Owner::Node(0)), "ready is per cell");
}
