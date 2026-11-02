// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The node machine on its own: `node_step` over hand-built `Params`, driven the way the
//! scheduler drives it (a stop is issued by the scheduler, so these tests go from a recorded
//! stop straight to the cell's `Empty`).
use qinit_colony_core::*;

fn worker(policy: u32, max: u32, window_ms: u32, delay_ms: u32) -> Params {
    Params {
        kind: 0,
        ready_kind: 0,
        policy,
        max,
        window_ms,
        delay_ms,
        stop_mode: 0,
        grace_ms: 10_000,
        start_timeout_ms: 90_000,
    }
}

fn forager() -> Params {
    Params {
        kind: 1,
        ready_kind: 1,
        policy: 0,
        ..worker(0, 0, 0, 1000)
    }
}

fn step(ns: NodeState, p: Params, input: NodeInput, now: u64) -> NodeState {
    node_step(ns, p, false, input, now)
}

fn cell(ns: NodeState, p: Params, r: CellReport, now: u64) -> NodeState {
    step(ns, p, NodeInput::Cell(r), now)
}

/// A wanted node that has just been started at `now` and reported ready.
fn ready_at(p: Params, now: u64) -> NodeState {
    let wanted = NodeState {
        wanted: true,
        ..off()
    };
    let s = begin_start(wanted, p, now);
    cell(s, p, CellReport::Ready, now)
}

/// A failure at `now`: the main process dies with status 1 and the cell is empty.
fn fail_at(ns: NodeState, p: Params, now: u64) -> NodeState {
    let s = cell(ns, p, CellReport::MainExited(Some(1)), now);
    assert!(s.to_stop, "{s:?}");
    cell(s, p, CellReport::Empty, now)
}

/// Waits out the back-off the way the scheduler does (the failure time is in
/// `wait_since_ms`, see `fail_noting`), then starts and reports ready at the time the back-off
/// ends. Returns the node and the time it started.
fn restart(ns: NodeState, p: Params) -> (NodeState, u64) {
    let due = match ns.emit_arm {
        Some((TimerKind::Backoff, ms)) => ns.wait_since_ms + u64::from(ms),
        _ => ns.wait_since_ms,
    };
    let s = if matches!(ns.state, State::Waiting(Why::Backoff)) {
        let cleared = NodeState {
            emit_arm: None,
            ..ns
        };
        step(cleared, p, NodeInput::Deadline(TimerKind::Backoff), due)
    } else {
        ns
    };
    let s = begin_start(s, p, due);
    (cell(s, p, CellReport::Ready, due), due)
}

#[test]
fn backoff_doubles_from_the_base_and_caps_at_ten_times() {
    let got: Vec<u64> = (0..7).map(|k| backoff_ms(1000, k)).collect();
    assert_eq!(got, [1000, 2000, 4000, 8000, 10_000, 10_000, 10_000]);
    assert_eq!(backoff_ms(1000, u32::MAX), 10_000);
    assert_eq!(backoff_ms(100, 3), 800);
    assert_eq!(backoff_ms(0, 5), 0);
    assert_eq!(backoff_ms(u32::MAX, 40), 10 * u64::from(u32::MAX));
}

#[test]
fn a_node_is_paced_once_the_backoff_since_its_last_start_has_elapsed() {
    let s = NodeState {
        last_start_ms: 5000,
        backoff_exp: 3,
        ..off()
    };
    // The third failure asks for 4 s.
    assert!(!paced(s, 1000, 8999));
    assert!(paced(s, 1000, 9000));
    assert!(!paced(s, 1000, 4999), "the clock went backwards");
    assert_eq!(remaining_ms(s, 1000, 6000), 3000);
    assert_eq!(remaining_ms(s, 1000, 9000), 0);
    assert!(paced(off(), 1000, 0));
}

/// Fails the node at `t` and returns the state, with the failure time kept in
/// `wait_since_ms` so `restart` can find when the back-off ends.
fn fail_noting(ns: NodeState, p: Params, t: u64) -> NodeState {
    let s = fail_at(ns, p, t);
    NodeState {
        wait_since_ms: t,
        ..s
    }
}

#[test]
fn the_breaker_trips_on_the_max_plus_first_failure_in_a_window() {
    let p = worker(1, 2, 60_000, 1000);
    let mut s = ready_at(p, 0);
    for (i, due) in [0u64, 1000, 3000].iter().enumerate() {
        s = fail_noting(s, p, *due);
        if i < 2 {
            assert!(
                matches!(s.state, State::Waiting(Why::Backoff)),
                "failure {} -> {:?}",
                i + 1,
                s.state
            );
            let (n, started) = restart(s, p);
            assert_eq!(started, [1000u64, 3000][i], "start after failure {}", i + 1);
            s = n;
        }
    }
    assert_eq!(s.state, State::Quarantined(Reason::Breaker));
    assert_eq!(s.burst_count, 3);
    assert_eq!(s.report_b, Some(Report::Quarantined(Reason::Breaker)));
}

#[test]
fn the_back_off_between_starts_doubles_on_fast_failures() {
    let p = worker(2, 0, 0, 1000);
    let mut s = ready_at(p, 0);
    let mut starts = vec![0u64];
    let mut t = 0;
    for _ in 0..6 {
        s = fail_noting(s, p, t);
        let (n, started) = restart(s, p);
        starts.push(started);
        s = n;
        t = started;
    }
    let gaps: Vec<u64> = starts.windows(2).map(|w| w[1] - w[0]).collect();
    assert_eq!(gaps, [1000, 2000, 4000, 8000, 10_000, 10_000]);
}

#[test]
fn a_failure_after_the_window_starts_a_new_burst() {
    let p = worker(1, 2, 10_000, 1000);
    let mut s = ready_at(p, 0);
    s = fail_noting(s, p, 0);
    let (n, _) = restart(s, p);
    s = fail_noting(n, p, 1000);
    assert_eq!(s.burst_count, 2);
    let (n, started) = restart(s, p);
    assert_eq!(started, 3000);
    // It runs until 20 s: past the window and past the cap, so a new burst and a fresh back-off.
    s = fail_noting(n, p, 20_000);
    assert!(matches!(s.state, State::Waiting(_)), "{:?}", s.state);
    assert_eq!(s.burst_count, 1);
    assert_eq!(s.burst_begin_ms, 20_000);
    assert_eq!(s.backoff_exp, 1, "a long run resets the back-off");
}

#[test]
fn max_zero_never_quarantines() {
    let p = worker(2, 0, 0, 100);
    let mut s = ready_at(p, 0);
    let mut t = 0;
    for _ in 0..50 {
        s = fail_noting(s, p, t);
        assert!(matches!(s.state, State::Waiting(_)), "{:?}", s.state);
        let (n, started) = restart(s, p);
        s = n;
        t = started;
    }
}

#[test]
fn exit_zero_under_on_failure_is_not_a_failure() {
    let p = worker(1, 3, 60_000, 1000);
    let s = ready_at(p, 0);
    let s = cell(s, p, CellReport::MainExited(Some(0)), 500);
    assert!(s.to_stop);
    assert_eq!(s.left, Left::Restart);
    assert_eq!(s.state, State::Ready, "the scheduler issues the stop");
    let s = cell(s, p, CellReport::Empty, 500);
    assert_eq!(s.state, State::Off);
    assert!(!s.wanted);
    assert_eq!(s.burst_count, 0);
    assert_eq!(s.report_b, Some(Report::Stopped));
}

#[test]
fn an_always_worker_that_exits_zero_is_paced_and_counted() {
    let p = worker(2, 3, 60_000, 1000);
    let s = ready_at(p, 0);
    let s = cell(s, p, CellReport::MainExited(Some(0)), 100);
    assert_eq!(s.left, Left::Restart);
    let s = cell(s, p, CellReport::Empty, 100);
    assert!(
        matches!(s.state, State::Waiting(Why::Backoff)),
        "{:?}",
        s.state
    );
    assert_eq!(s.burst_count, 1);
    assert_eq!(s.emit_arm, Some((TimerKind::Backoff, 900)));
}

#[test]
fn a_ready_exit_worker_that_exits_zero_is_done() {
    let p = Params {
        ready_kind: 1,
        ..worker(0, 0, 0, 1000)
    };
    let s = begin_start(
        NodeState {
            wanted: true,
            ..off()
        },
        p,
        0,
    );
    let s = cell(s, p, CellReport::Ready, 5);
    assert_eq!(s.state, State::Starting, "ready by exit waits for the exit");
    assert!(s.done);
    let s = cell(s, p, CellReport::MainExited(Some(0)), 6);
    assert!(s.to_stop);
    let s = cell(s, p, CellReport::Empty, 6);
    assert_eq!(s.state, State::Done);
    assert!(s.wanted, "a worker stays wanted");
    assert_eq!(s.report_b, Some(Report::Done));
}

#[test]
fn a_start_timeout_counts_as_a_failure() {
    let p = worker(1, 3, 60_000, 1000);
    let s = begin_start(
        NodeState {
            wanted: true,
            ..off()
        },
        p,
        0,
    );
    assert_eq!(s.emit_arm, Some((TimerKind::StartTimeout, 90_000)));
    let s = step(s, p, NodeInput::Deadline(TimerKind::StartTimeout), 90_000);
    assert!(s.to_stop && s.timed_out);
    assert_eq!(s.left, Left::Error);
    assert!(s.timer.is_none());
    let s = cell(s, p, CellReport::Empty, 90_001);
    assert!(matches!(s.state, State::Waiting(_)));
    assert_eq!(s.burst_count, 1);
    // A node that is never restarted is quarantined instead.
    let p = worker(0, 0, 0, 1000);
    let s = begin_start(
        NodeState {
            wanted: true,
            ..off()
        },
        p,
        0,
    );
    let s = step(s, p, NodeInput::Deadline(TimerKind::StartTimeout), 90_000);
    let s = cell(s, p, CellReport::Empty, 90_001);
    assert_eq!(s.state, State::Quarantined(Reason::StartTimeout));
}

#[test]
fn a_pipe_worker_that_exits_before_ready_is_a_failure() {
    let p = worker(1, 3, 60_000, 1000);
    let s = begin_start(
        NodeState {
            wanted: true,
            ..off()
        },
        p,
        0,
    );
    let s = cell(s, p, CellReport::MainExited(Some(0)), 10);
    assert_eq!(s.left, Left::Error, "D18: exited before its ready line");
}

#[test]
fn stale_cell_reports_are_ignored() {
    let p = worker(1, 3, 60_000, 1000);
    let wanted = NodeState {
        wanted: true,
        ..off()
    };
    for r in [
        CellReport::Empty,
        CellReport::Ready,
        CellReport::NotReady,
        CellReport::Spawned,
        CellReport::MainExited(Some(1)),
        CellReport::CellFailed,
    ] {
        assert_eq!(cell(wanted, p, r, 5), wanted, "{r:?} on an Off node");
    }
    let waiting = NodeState {
        state: State::Waiting(Why::Deps),
        ..wanted
    };
    assert_eq!(cell(waiting, p, CellReport::Ready, 5), waiting);
    let ready = ready_at(p, 0);
    assert_eq!(cell(ready, p, CellReport::Spawned, 5), ready);
    assert_eq!(
        cell(ready, p, CellReport::Ready, 5),
        ready,
        "a second Ready"
    );
    // A start timeout that fires after the node became ready has no timer to match.
    assert_eq!(
        step(ready, p, NodeInput::Deadline(TimerKind::StartTimeout), 9),
        ready
    );
}

#[test]
fn clear_resets_the_counters_and_refuses_when_not_quarantined() {
    let p = worker(1, 1, 60_000, 1000);
    let mut s = ready_at(p, 0);
    s = fail_noting(s, p, 0);
    let (n, _) = restart(s, p);
    s = fail_noting(n, p, 1000);
    assert_eq!(s.state, State::Quarantined(Reason::Breaker));
    let s = step(s, p, NodeInput::Req(Request::Clear), 2000);
    assert_eq!(s.state, State::Off);
    assert_eq!((s.burst_count, s.backoff_exp), (0, 0));
    let again = step(s, p, NodeInput::Req(Request::Clear), 2001);
    assert_eq!(again.report_b.or(again.report_a), Some(Report::Refused));
}

#[test]
fn a_forager_runs_once_and_is_never_restarted() {
    let p = forager();
    let s = step(off(), p, NodeInput::Req(Request::Run), 0);
    assert!(s.wanted);
    let mut s = begin_start(s, p, 0);
    for round in 0..5u64 {
        s = cell(s, p, CellReport::MainExited(Some(1)), round);
        s = cell(s, p, CellReport::Empty, round);
        assert_eq!(s.state, State::Off, "round {round}");
        assert!(!s.wanted, "a failed forager is not wanted again");
        s = step(s, p, NodeInput::Req(Request::Run), round);
        s = begin_start(s, p, round + 1);
    }
    s = cell(s, p, CellReport::MainExited(Some(0)), 9);
    s = cell(s, p, CellReport::Empty, 9);
    assert_eq!(s.state, State::Done);
    assert!(!s.wanted);
    // A worker cannot be run, a forager cannot be started.
    let w = step(
        off(),
        worker(0, 0, 0, 1000),
        NodeInput::Req(Request::Run),
        0,
    );
    assert_eq!(w.report_a, Some(Report::Refused));
    let f = step(off(), p, NodeInput::Req(Request::Start), 0);
    assert_eq!(f.report_a, Some(Report::Refused));
}

#[test]
fn every_exit_goes_through_the_scheduler_and_the_cells_empty() {
    let p = worker(2, 3, 60_000, 1000);
    let s = ready_at(p, 0);
    let s = cell(s, p, CellReport::MainExited(Some(137)), 50);
    assert_eq!(
        s.state,
        State::Ready,
        "no Off before the stop is issued and the cell is empty"
    );
    assert!(
        s.to_stop && !s.emit_stop,
        "node_step records, the scheduler issues"
    );
    assert_eq!(s.status, Some(137));
}

#[test]
fn a_failure_while_an_administrator_stop_is_pending_is_not_a_failure() {
    let p = worker(1, 3, 60_000, 1000);
    let s = ready_at(p, 0);
    let s = step(s, p, NodeInput::Req(Request::Stop), 10);
    assert!(s.to_stop && !s.wanted);
    assert_eq!(s.left, Left::Restart);
    let s = cell(s, p, CellReport::MainExited(Some(143)), 11);
    assert_eq!(s.left, Left::Restart, "the first reason stays");
    let s = cell(s, p, CellReport::Empty, 11);
    assert_eq!(s.state, State::Off);
    assert_eq!(s.burst_count, 0);
}

#[test]
fn a_stop_that_fails_in_the_cell_quarantines_a_worker() {
    let p = worker(1, 3, 60_000, 1000);
    let s = ready_at(p, 0);
    let s = step(s, p, NodeInput::Req(Request::Stop), 10);
    let s = cell(s, p, CellReport::CellFailed, 20);
    assert_eq!(s.state, State::Quarantined(Reason::StopFailed));
    assert!(!s.to_stop);
}

#[test]
fn shutdown_unwants_everything_and_cancels_waits() {
    let p = worker(2, 0, 0, 1000);
    let mut s = ready_at(p, 0);
    s = fail_noting(s, p, 0);
    assert!(matches!(s.state, State::Waiting(Why::Backoff)));
    let s = node_step(s, p, true, NodeInput::Shutdown, 5);
    assert_eq!(s.state, State::Off);
    assert!(!s.wanted);
    assert_eq!(s.emit_cancel, Some(TimerKind::Backoff));
    let started = node_step(off(), p, true, NodeInput::Req(Request::Start), 6);
    assert_eq!(started.report_a, Some(Report::Refused));
}
