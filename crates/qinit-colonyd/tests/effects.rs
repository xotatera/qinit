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
fn a_late_create_failure_is_reported_once() {
    let tmp = Tmp::new("late");
    std::fs::create_dir(tmp.0.join("db")).unwrap();
    let m = model(vec![worker("db")]);
    let mut cells = FakeCells::default();
    cells.create_fails = true;
    let mut fx = rig(cells, &tmp.0);
    assert_eq!(
        fx.start(0, &spec_of(&m, 0), &m),
        Err(Errno(libc::EEXIST)),
        "the directory exists"
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
    // Without the directory, the errno is EIO.
    let tmp2 = Tmp::new("late2");
    let mut cells = FakeCells::default();
    cells.create_fails = true;
    let mut fx = rig(cells, &tmp2.0);
    assert_eq!(fx.start(0, &spec_of(&m, 0), &m), Err(Errno(libc::EIO)));
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
