// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Scenario tests of the cell machine (spec 2026-10-27 §6.1 tier 1). The proofs say what holds
//! after every step; these pin the sequences a cell actually goes through.
use qinit_cell_core::{
    Action, Cell, Event, Failure, Main, Phase, Polite, ReadyMode, Report, Request, Sig, StopStep,
    Timer, absent, step,
};

/// Runs `events` from `c`; the final cell and every step's actions.
fn run(mut c: Cell, events: &[Event]) -> (Cell, Vec<Vec<Action>>) {
    let mut all = Vec::new();
    for &e in events {
        let (n, acts) = step(c, e);
        all.push(acts.items().into_iter().flatten().collect());
        c = n;
    }
    (c, all)
}

fn stop(polite: Polite) -> Event {
    Event::Request(Request::Stop {
        polite,
        grace_ms: 3000,
        kill_ms: 5000,
    })
}

fn level(populated: bool, frozen: bool) -> Event {
    Event::Level { populated, frozen }
}

/// A created cell running main process 7 that announced readiness.
fn running() -> Cell {
    let (c, _) = run(
        absent(),
        &[
            Event::Request(Request::Create),
            Event::Created,
            Event::Request(Request::Spawn(ReadyMode::Pipe)),
            Event::Spawned(7),
            Event::ReadyLine,
        ],
    );
    assert_eq!(c.phase, Phase::Running);
    c
}

#[test]
fn create_spawn_ready_reports_in_order() {
    let (_, acts) = run(
        absent(),
        &[
            Event::Request(Request::Create),
            Event::Created,
            Event::Request(Request::Spawn(ReadyMode::Pipe)),
            Event::Spawned(7),
            Event::ReadyLine,
        ],
    );
    assert_eq!(
        acts,
        [
            vec![Action::CreateDir],
            vec![Action::Report(Report::Created)],
            vec![Action::Spawn],
            vec![],
            vec![Action::Report(Report::Ready)],
        ]
    );
}

#[test]
fn a_main_stop_signals_the_pidfd_and_ends_empty_and_removed() {
    let (c, acts) = run(
        running(),
        &[
            stop(Polite::Main),
            Event::MainExited(Some(15)),
            level(false, false),
            Event::Request(Request::Remove),
            Event::Removed,
        ],
    );
    assert_eq!(
        acts[0],
        [
            Action::SignalMain(7, Sig::Term),
            Action::Arm(Timer::Grace, 3000)
        ]
    );
    assert_eq!(acts[1], [], "still populated: wait");
    assert_eq!(
        acts[2],
        [Action::Cancel(Timer::Grace), Action::Report(Report::Empty)]
    );
    assert_eq!(acts[3], [Action::RemoveDir]);
    assert_eq!(acts[4], [Action::Report(Report::Removed)]);
    assert_eq!(c.phase, Phase::Removed);
}

#[test]
fn a_cell_stop_freezes_signals_every_member_thaws_then_escalates() {
    let (c, acts) = run(
        running(),
        &[
            stop(Polite::Cell),
            level(true, true),
            Event::Signalled,
            level(true, false),
            Event::Deadline(Timer::Grace),
            Event::MainExited(Some(9)),
            level(false, false),
        ],
    );
    assert_eq!(acts[0], [Action::Freeze, Action::Arm(Timer::Grace, 3000)]);
    assert_eq!(acts[1], [Action::SignalMembers(Sig::Term)]);
    assert_eq!(acts[2], [Action::Thaw]);
    assert_eq!(acts[3], []);
    assert_eq!(acts[4], [Action::Kill, Action::Arm(Timer::Kill, 5000)]);
    assert_eq!(acts[5], []);
    assert_eq!(
        acts[6],
        [Action::Cancel(Timer::Kill), Action::Report(Report::Empty)]
    );
    assert_eq!(c.phase, Phase::Empty);
}

#[test]
fn the_grace_deadline_while_frozen_thaws_before_killing() {
    let (c, acts) = run(
        running(),
        &[stop(Polite::Cell), Event::Deadline(Timer::Grace)],
    );
    assert_eq!(
        acts[1],
        [Action::Thaw, Action::Kill, Action::Arm(Timer::Kill, 5000)]
    );
    assert!(!c.freeze_held);
    assert_eq!(c.phase, Phase::Killing);
}

#[test]
fn a_cell_that_survives_the_kill_deadline_is_stuck() {
    let (c, acts) = run(
        running(),
        &[
            stop(Polite::Main),
            Event::Deadline(Timer::Grace),
            Event::Deadline(Timer::Kill),
            Event::Request(Request::Remove),
        ],
    );
    assert_eq!(acts[2], [Action::Report(Report::Failed(Failure::Stuck))]);
    assert_eq!(
        acts[3],
        [Action::RemoveDir],
        "a stuck cell may still be removed (rmdir reports EBUSY)"
    );
    assert_eq!(c.phase, Phase::Removing);
}

#[test]
fn readiness_by_exit() {
    let base = run(
        absent(),
        &[
            Event::Request(Request::Create),
            Event::Created,
            Event::Request(Request::Spawn(ReadyMode::Exit)),
            Event::Spawned(3),
        ],
    )
    .0;
    let (c, acts) = run(base, &[Event::MainExited(Some(0))]);
    assert_eq!(
        acts[0],
        [Action::Report(Report::Ready)],
        "status 0 with the cell still populated: ready"
    );
    assert_eq!(c.phase, Phase::Running);
    let (unknown, acts) = run(base, &[Event::MainExited(None)]);
    assert_eq!(unknown.phase, Phase::Exited);
    assert_eq!(acts[0], [Action::Report(Report::MainExited(None))]);
    let (c, acts) = run(base, &[Event::MainExited(Some(1 << 8))]);
    assert_eq!(acts[0], [Action::Report(Report::MainExited(Some(1 << 8)))]);
    assert_eq!(c.phase, Phase::Exited);
    let (c, acts) = run(base, &[level(false, false), Event::MainExited(Some(0))]);
    assert_eq!(
        acts[1],
        [Action::Report(Report::Ready), Action::Report(Report::Empty)],
        "a oneshot that left nothing behind"
    );
    assert_eq!(c.phase, Phase::Empty);
}

#[test]
fn a_stop_before_exec_confirmation_uses_the_cell() {
    let (c, _) = run(
        absent(),
        &[
            Event::Request(Request::Create),
            Event::Created,
            Event::Request(Request::Spawn(ReadyMode::Pipe)),
        ],
    );
    let (_, acts) = run(c, &[stop(Polite::Main)]);
    assert_eq!(
        acts[0],
        [Action::Freeze, Action::Arm(Timer::Grace, 3000)],
        "no main pidfd yet: freeze-signal-thaw"
    );
}

#[test]
fn a_stale_empty_level_before_spawned_does_not_end_the_cell() {
    let (c, _) = run(
        absent(),
        &[
            Event::Request(Request::Create),
            Event::Created,
            Event::Request(Request::Spawn(ReadyMode::Pipe)),
        ],
    );
    let (c, acts) = run(c, &[level(false, false)]);
    assert_eq!(acts[0], []);
    assert_eq!(c.phase, Phase::Starting);
}

#[test]
fn adoption_checks_the_cgroup_id() {
    let (c, acts) = run(
        absent(),
        &[
            Event::Request(Request::Adopt(None)),
            Event::AdoptChecked {
                id_matches: false,
                populated: true,
            },
        ],
    );
    assert_eq!(acts[0], [Action::CheckAdopt]);
    assert_eq!(
        acts[1],
        [Action::Report(Report::Failed(Failure::IdMismatch))]
    );
    assert_eq!(c.phase, Phase::Failed(Failure::IdMismatch));
    let (c, acts) = run(
        absent(),
        &[
            Event::Request(Request::Adopt(None)),
            Event::AdoptChecked {
                id_matches: true,
                populated: true,
            },
            stop(Polite::Main),
        ],
    );
    assert_eq!(acts[1], [Action::Report(Report::Running)]);
    assert_eq!(
        acts[2],
        [Action::Freeze, Action::Arm(Timer::Grace, 3000)],
        "adopted without a pidfd: main mode becomes cell mode"
    );
    assert_eq!(c.main, Main::None);
    let (c, _) = run(
        absent(),
        &[
            Event::Request(Request::Adopt(Some(4))),
            Event::AdoptChecked {
                id_matches: true,
                populated: true,
            },
        ],
    );
    assert_eq!(c.main, Main::Live(4));
}

#[test]
fn nothing_is_signalled_after_empty_and_stale_deadlines_are_ignored() {
    let (empty, _) = run(
        running(),
        &[
            stop(Polite::Main),
            Event::MainExited(Some(15)),
            level(false, false),
        ],
    );
    for e in [
        Event::Deadline(Timer::Grace),
        Event::Deadline(Timer::Kill),
        level(true, true),
        stop(Polite::Cell),
        Event::Signalled,
    ] {
        let (_, acts) = step(empty, e);
        assert!(
            acts.items()
                .into_iter()
                .flatten()
                .all(|a| matches!(a, Action::Report(_))),
            "{e:?} gave {acts:?}"
        );
    }
    let (_, acts) = step(running(), Event::Deadline(Timer::Grace));
    assert_eq!(acts.items(), [None; 4]);
}

#[test]
fn requests_in_the_wrong_phase_are_refused() {
    for (c, q) in [
        (absent(), Request::Spawn(ReadyMode::Pipe)),
        (running(), Request::Create),
        (running(), Request::Remove),
        (running(), Request::Adopt(None)),
    ] {
        let (n, acts) = step(c, Event::Request(q));
        assert_eq!(
            acts.items()[0],
            Some(Action::Report(Report::Refused)),
            "{q:?}"
        );
        assert_eq!(n, c, "a refusal changes nothing");
    }
}

#[test]
fn a_stop_while_stopping_changes_nothing() {
    let (c, _) = run(running(), &[stop(Polite::Main)]);
    let (n, acts) = step(c, stop(Polite::Cell));
    assert_eq!(acts.items(), [None; 4]);
    assert_eq!(n.phase, Phase::Stopping(StopStep::Waiting));
}

/// A cell stopped after `Spawn` was requested but before the exec was confirmed.
fn stopped_before_spawned() -> Cell {
    let (c, _) = run(
        absent(),
        &[
            Event::Request(Request::Create),
            Event::Created,
            Event::Request(Request::Spawn(ReadyMode::Pipe)),
            stop(Polite::Main),
        ],
    );
    assert_eq!(c.phase, Phase::Stopping(StopStep::Freezing));
    c
}

#[test]
fn a_spawn_confirmed_after_the_stop_began_is_still_tracked() {
    let (c, acts) = run(stopped_before_spawned(), &[Event::Spawned(7)]);
    assert_eq!(acts[0], []);
    assert_eq!(c.main, Main::Live(7), "the handle is recorded, not dropped");
    let (c, acts) = run(c, &[Event::MainExited(Some(15)), level(false, false)]);
    assert_eq!(acts[0], [], "still populated: wait");
    assert_eq!(
        acts[1],
        [
            Action::Cancel(Timer::Grace),
            Action::Thaw,
            Action::Report(Report::Empty)
        ]
    );
    assert_eq!(c.phase, Phase::Empty);
    assert_eq!(c.main, Main::Reaped(Some(15)));
}

#[test]
fn a_spawn_failure_after_the_stop_began_ends_the_stop_and_is_reported() {
    let (c, acts) = run(stopped_before_spawned(), &[Event::SpawnFailed]);
    assert_eq!(
        acts[0],
        [
            Action::Cancel(Timer::Grace),
            Action::Thaw,
            Action::Report(Report::Failed(Failure::Spawn))
        ]
    );
    assert_eq!(c.phase, Phase::Failed(Failure::Spawn));
    assert!(!c.freeze_held);
    assert_eq!(c.armed, None);
    assert_eq!(c.main, Main::None, "the outstanding spawn is forgotten");
}

#[test]
fn an_empty_level_before_spawned_while_stopping_waits_for_the_main_process() {
    let c = stopped_before_spawned();
    assert_eq!(c.main, Main::Pending);
    // The child may have exited as an unreaped zombie, which does not count as populated.
    let (c, acts) = run(c, &[level(false, false)]);
    assert_eq!(acts[0], []);
    assert_eq!(
        c.phase,
        Phase::Stopping(StopStep::Freezing),
        "an outstanding spawn keeps the cell out of Empty"
    );
    let (c, acts) = run(
        c,
        &[
            Event::Spawned(7),
            level(false, false),
            Event::MainExited(Some(9)),
        ],
    );
    assert_eq!(acts[0], []);
    assert_eq!(acts[1], [], "the main process is live: wait for its exit");
    assert_eq!(
        acts[2],
        [
            Action::Cancel(Timer::Grace),
            Action::Thaw,
            Action::Report(Report::Empty)
        ],
        "reaped, and the last level read empty"
    );
    assert_eq!(c.phase, Phase::Empty);
    assert_eq!(c.main, Main::Reaped(Some(9)));
}
