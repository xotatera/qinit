// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The engine against the simulated effects (spec §6.1 tier 2).
use qinit_cell::effects::{Command, Reaped};
use qinit_cell::engine::{CellId, Engine, Error, Notice, ORPHANS};
use qinit_cell::sim::{Call, Sim};
use qinit_cell_core::{Failure, Phase, Polite, ReadyMode, Report, Sig, Timer};
use qinit_cell_drive::{CAPACITY, Source, token};
use qinit_event::Ready;
use std::time::Duration;

fn cmd() -> Command {
    Command {
        path: "/bin/true".into(),
        argv: Vec::new(),
        env: Vec::new(),
        fds: Vec::new(),
        ready_fd: 3,
    }
}

fn reports(e: &mut Engine<Sim>) -> Vec<Report> {
    e.take_notices()
        .into_iter()
        .filter_map(|n| match n {
            Notice::Cell(_, r) => Some(r),
            Notice::Orphan { .. } | Notice::StatusPending(_) => None,
        })
        .collect()
}

fn count(e: &Engine<Sim>, call: &Call) -> usize {
    e.effects.calls.iter().filter(|c| *c == call).count()
}

const SEC: Duration = Duration::from_secs(1);

#[test]
fn failed_effects_escalate_and_do_not_lose_batch_events() {
    use qinit_cell_core::Effect;
    for effect in [
        Effect::Freeze,
        Effect::SignalMain,
        Effect::Thaw,
        Effect::SignalMembers,
    ] {
        let mut e = running();
        e.effects.failures.push_back(effect);
        let polite = if effect == Effect::SignalMain {
            Polite::Main
        } else {
            Polite::Cell
        };
        e.stop(CellId(0), polite, SEC, SEC).unwrap();
        if matches!(effect, Effect::Thaw | Effect::SignalMembers) {
            e.effects.levels.push_back((true, true));
            assert_eq!(
                e.on_batch(&[
                    Ready::Priority(token(0, Source::Events)),
                    Ready::Deadline(token(0, Source::Grace)),
                    Ready::Exited(token(0, Source::Main), 9),
                ]),
                None
            );
        }
        assert_eq!(e.phase(CellId(0)), Some(Phase::Killing));
        assert!(e.effects.calls.contains(&Call::Kill(0)));
        assert!(e.effects.calls.contains(&Call::Arm(0, Timer::Kill, 1000)));
        if effect == Effect::SignalMembers {
            e.effects.levels.push_back((false, false));
            e.on_ready(&Ready::Priority(token(0, Source::Events)))
                .unwrap();
            assert_eq!(
                reports(&mut e),
                [Report::Empty],
                "the batch exit was retained"
            );
        } else {
            e.on_ready(&Ready::Deadline(token(0, Source::Kill)))
                .unwrap();
            assert_eq!(reports(&mut e), [Report::Failed(Failure::Stuck)]);
        }
    }
}

#[test]
fn noneffect_errors_keep_first_error_but_run_every_action_and_event() {
    use qinit_cell_core::Effect;
    let mut e = running();
    e.effects.failures.push_back(Effect::Freeze);
    e.effects.arm_error = Some(qinit_sys::Errno(libc::ENOMEM));
    e.effects.cancel_error = Some(qinit_sys::Errno(libc::EIO));
    assert_eq!(
        e.stop(CellId(0), Polite::Cell, SEC, SEC),
        Err(Error::Sys(qinit_sys::Errno(libc::ENOMEM)))
    );
    assert!(
        e.effects.calls.contains(&Call::Kill(0)),
        "cancel failure did not skip kill"
    );
    assert!(e.effects.calls.contains(&Call::Arm(0, Timer::Kill, 1000)));
    e.effects.levels.push_back((false, false));
    assert_eq!(
        e.on_batch(&[
            Ready::Exited(token(0, Source::Main), 9),
            Ready::Priority(token(0, Source::Events)),
            Ready::Deadline(token(0, Source::Kill)),
        ]),
        Some(Error::Sys(qinit_sys::Errno(libc::EIO)))
    );
    assert_eq!(
        reports(&mut e),
        [Report::Empty],
        "report after failed Cancel still runs"
    );
}

#[test]
fn failed_kill_reports_kill_failure_after_arming_and_cancelling() {
    use qinit_cell_core::Effect;
    let mut e = running();
    e.effects.failures.extend([Effect::Freeze, Effect::Kill]);
    e.stop(CellId(0), Polite::Cell, SEC, SEC).unwrap();
    assert_eq!(e.phase(CellId(0)), Some(Phase::Failed(Failure::Kill)));
    assert_eq!(reports(&mut e), [Report::Failed(Failure::Kill)]);
    assert!(e.effects.calls.contains(&Call::Arm(0, Timer::Kill, 1000)));
    assert!(e.effects.calls.contains(&Call::Cancel(0, Timer::Kill)));
}

#[test]
fn unsettled_exec_pipe_keeps_handle_and_exit_until_eof() {
    let mut e = Engine::new(Sim::default());
    let id = e.create("pending").unwrap();
    e.spawn(id, cmd(), ReadyMode::Exit).unwrap();
    e.effects.exec_pending = true;
    e.on_ready(&Ready::Exited(token(0, Source::Main), 0))
        .unwrap();
    assert_eq!(e.phase(id), Some(Phase::Starting));
    assert!(!e.effects.calls.contains(&Call::Close(0, Source::ExecError)));
    e.effects.exec_pending = false;
    e.on_ready(&Ready::Readable(token(0, Source::ExecError)))
        .unwrap();
    assert!(reports(&mut e).contains(&Report::Ready));
    assert_eq!(
        e.phase(id),
        Some(Phase::Empty),
        "the earlier empty edge cannot be lost"
    );
}

#[test]
fn a_ready_read_is_not_skipped_when_settling_a_held_exit_fails() {
    for chunk in [b"\n".as_slice(), b"".as_slice()] {
        let mut e = Engine::new(Sim::default());
        let id = e.create("settle-error").unwrap();
        e.spawn(id, cmd(), ReadyMode::Pipe).unwrap();
        e.effects.exec_pending = true;
        e.stop(id, Polite::Cell, SEC, SEC).unwrap();
        e.on_ready(&Ready::Exited(token(0, Source::Main), 0))
            .unwrap();
        e.effects.exec_pending = false;
        e.effects.cancel_error = Some(qinit_sys::Errno(libc::EIO));
        e.effects.ready_chunks.push_back(chunk.to_vec());
        assert_eq!(
            e.on_ready(&Ready::Readable(token(0, Source::Ready))),
            Err(Error::Sys(qinit_sys::Errno(libc::EIO)))
        );
        assert!(
            e.effects.ready_chunks.is_empty(),
            "ready read was skipped after exec-settlement error"
        );
        if chunk.is_empty() {
            assert!(
                e.effects.calls.contains(&Call::Close(0, Source::Ready)),
                "EOF cleanup still runs after the first error"
            );
        }
        assert_eq!(reports(&mut e), [Report::Created, Report::Empty]);
        assert_eq!(e.phase(id), Some(Phase::Empty));
    }
}

#[test]
fn a_ready_line_waits_for_an_unsettled_exec() {
    let mut e = Engine::new(Sim::default());
    let id = e.create("pending-ready").unwrap();
    e.spawn(id, cmd(), ReadyMode::Pipe).unwrap();
    e.effects.exec_pending = true;
    e.effects.ready_chunks.push_back(b"ready\n".to_vec());
    e.on_ready(&Ready::Readable(token(0, Source::Ready)))
        .unwrap();
    assert_eq!(reports(&mut e), [Report::Created]);
    e.effects.exec_pending = false;
    e.on_ready(&Ready::Readable(token(0, Source::ExecError)))
        .unwrap();
    assert_eq!(
        e.phase(id),
        Some(Phase::Running),
        "deferred line must reach Running"
    );
    assert_eq!(reports(&mut e), [Report::Ready]);
    e.effects.ready_chunks.push_back(b"again\n".to_vec());
    e.on_ready(&Ready::Readable(token(0, Source::Ready)))
        .unwrap();
    e.on_ready(&Ready::Readable(token(0, Source::ExecError)))
        .unwrap();
    assert!(
        reports(&mut e).is_empty(),
        "Ready must be reported exactly once"
    );
}

#[test]
fn held_readiness_and_exit_keep_arrival_order() {
    for ready_first in [true, false] {
        let mut e = Engine::new(Sim::default());
        let id = e.create("ordered-ready").unwrap();
        e.spawn(id, cmd(), ReadyMode::Pipe).unwrap();
        e.effects.exec_pending = true;
        e.effects.ready_chunks.push_back(b"\n".to_vec());
        let ready = Ready::Readable(token(0, Source::Ready));
        let exit = Ready::Exited(token(0, Source::Main), 0);
        let batch = if ready_first {
            [ready, exit]
        } else {
            [exit, ready]
        };
        assert_eq!(e.on_batch(&batch), None);
        assert_eq!(reports(&mut e), [Report::Created]);
        e.effects.exec_pending = false;
        e.on_ready(&Ready::Readable(token(0, Source::ExecError)))
            .unwrap();
        let mut want = Vec::new();
        if ready_first {
            want.push(Report::Ready);
        }
        want.extend([Report::MainExited(Some(0)), Report::Empty]);
        assert_eq!(reports(&mut e), want, "ready_first={ready_first}");
        assert_eq!(e.phase(id), Some(Phase::Empty));
    }
}

#[test]
fn a_ready_line_before_the_exec_result_in_one_batch_is_not_lost() {
    let mut e = Engine::new(Sim::default());
    let id = e.create("batch-ready").unwrap();
    e.spawn(id, cmd(), ReadyMode::Pipe).unwrap();
    e.effects.ready_chunks.push_back(b"\n".to_vec());
    assert_eq!(
        e.on_batch(&[
            Ready::Readable(token(0, Source::Ready)),
            Ready::Readable(token(0, Source::ExecError)),
        ]),
        None
    );
    assert_eq!(
        e.phase(id),
        Some(Phase::Running),
        "same-batch line must reach Running"
    );
    assert_eq!(reports(&mut e), [Report::Created, Report::Ready]);
}

#[test]
fn ready_eof_under_an_unsettled_failed_exec_reports_only_spawn_failed() {
    let mut e = Engine::new(Sim::default());
    let id = e.create("failed-ready").unwrap();
    e.spawn(id, cmd(), ReadyMode::Pipe).unwrap();
    e.effects.exec_pending = true;
    e.on_ready(&Ready::Hangup(token(0, Source::Ready))).unwrap();
    let mut seen = reports(&mut e);
    assert_eq!(
        seen,
        [Report::Created],
        "EOF cannot report NotReady before exec settles"
    );
    e.effects
        .exec_errors
        .push_back(Some(qinit_sys::Errno(libc::ENOENT)));
    e.effects.exec_pending = false;
    e.on_ready(&Ready::Readable(token(0, Source::ExecError)))
        .unwrap();
    seen.extend(reports(&mut e));
    assert_eq!(seen, [Report::Created, Report::Failed(Failure::Spawn)]);
    assert_eq!(e.phase(id), Some(Phase::Failed(Failure::Spawn)));
}

/// An engine with cell 0 running (ready by pipe) and its notices taken.
fn running() -> Engine<Sim> {
    let mut e = Engine::new(Sim::default());
    let id = e.create("w").unwrap();
    e.spawn(id, cmd(), ReadyMode::Pipe).unwrap();
    e.on_ready(&Ready::Readable(token(0, Source::ExecError)))
        .unwrap();
    e.effects.ready_chunks.push_back(b"\n".to_vec());
    e.on_ready(&Ready::Readable(token(0, Source::Ready)))
        .unwrap();
    assert_eq!(reports(&mut e), [Report::Created, Report::Ready]);
    e
}

#[test]
fn a_full_table_refuses_create_without_a_directory() {
    let mut e = Engine::new(Sim::default());
    for i in 0..CAPACITY {
        e.create(&format!("c{i}")).unwrap();
    }
    assert_eq!(e.create("one-more"), Err(Error::Full));
    let creates = e
        .effects
        .calls
        .iter()
        .filter(|c| matches!(c, Call::Create(..)))
        .count();
    assert_eq!(creates, usize::from(CAPACITY));
}

#[test]
fn a_bad_name_is_refused_before_any_effect() {
    let mut e = Engine::new(Sim::default());
    for bad in ["../x", "a/b", ".", "..", "", "a\0b"] {
        assert!(matches!(e.create(bad), Err(Error::BadName(_))), "{bad:?}");
    }
    assert!(e.effects.calls.is_empty());
}

#[test]
fn create_spawn_and_ready_by_pipe() {
    let e = running();
    assert_eq!(
        e.effects.calls[..2],
        [Call::Create(0, "w".into()), Call::Spawn(0, ReadyMode::Pipe)]
    );
    assert!(e.effects.calls.contains(&Call::Close(0, Source::ExecError)));
    assert_eq!(
        count(&e, &Call::Close(0, Source::Main)),
        0,
        "a running cell keeps its main pidfd"
    );
}

#[test]
fn ready_lines_are_found_across_reads() {
    let mut e = Engine::new(Sim::default());
    let id = e.create("w").unwrap();
    e.spawn(id, cmd(), ReadyMode::Pipe).unwrap();
    e.on_ready(&Ready::Readable(token(0, Source::ExecError)))
        .unwrap();
    for chunk in [&b"ab"[..], b"c\nmore", b""] {
        e.effects.ready_chunks.push_back(chunk.to_vec());
        e.on_ready(&Ready::Readable(token(0, Source::Ready)))
            .unwrap();
    }
    assert_eq!(
        reports(&mut e),
        [Report::Created, Report::Ready],
        "one Ready, no NotReady after it"
    );
}

#[test]
fn a_cell_stop_signals_members_between_freeze_and_thaw() {
    let mut e = running();
    e.stop(CellId(0), Polite::Cell, SEC, SEC).unwrap();
    e.effects.levels.push_back((true, true));
    e.on_ready(&Ready::Priority(token(0, Source::Events)))
        .unwrap();
    let tail: Vec<Call> = e
        .effects
        .calls
        .iter()
        .rev()
        .take(4)
        .rev()
        .cloned()
        .collect();
    assert_eq!(
        tail,
        [
            Call::Freeze(0, true),
            Call::Arm(0, Timer::Grace, 1000),
            Call::SignalMembers(0, Sig::Term),
            Call::Freeze(0, false)
        ]
    );
}

#[test]
fn a_removed_cell_frees_its_slot() {
    let mut e = running();
    e.stop(CellId(0), Polite::Main, SEC, SEC).unwrap();
    assert!(e.effects.calls.contains(&Call::SignalMain(0, 0, Sig::Term)));
    // While stopping, the main process's exit is recorded, not reported (the machine).
    e.on_ready(&Ready::Exited(token(0, Source::Main), 15))
        .unwrap();
    e.effects.levels.push_back((false, false));
    e.on_ready(&Ready::Priority(token(0, Source::Events)))
        .unwrap();
    e.remove(CellId(0)).unwrap();
    assert_eq!(reports(&mut e), [Report::Empty, Report::Removed]);
    assert!(e.effects.calls.contains(&Call::Release(0)));
    assert_eq!(e.phase(CellId(0)), None);
    assert_eq!(
        e.create("next").unwrap(),
        CellId(0),
        "the slot is free again"
    );
}

#[test]
fn an_exec_failure_reports_spawn_failed() {
    let mut e = Engine::new(Sim::default());
    let id = e.create("w").unwrap();
    e.spawn(id, cmd(), ReadyMode::Pipe).unwrap();
    e.effects
        .exec_errors
        .push_back(Some(qinit_sys::Errno(libc::ENOENT)));
    e.on_ready(&Ready::Readable(token(0, Source::ExecError)))
        .unwrap();
    assert_eq!(
        reports(&mut e),
        [Report::Created, Report::Failed(Failure::Spawn)]
    );
}

#[test]
fn ready_eof_before_a_failed_exec_reports_only_spawn_failed() {
    let mut e = Engine::new(Sim::default());
    let id = e.create("w").unwrap();
    e.spawn(id, cmd(), ReadyMode::Pipe).unwrap();
    e.effects
        .exec_errors
        .push_back(Some(qinit_sys::Errno(libc::ENOENT)));
    e.on_ready(&Ready::Hangup(token(0, Source::Ready))).unwrap();
    e.on_ready(&Ready::Readable(token(0, Source::ExecError)))
        .unwrap();
    assert_eq!(
        reports(&mut e),
        [Report::Created, Report::Failed(Failure::Spawn)]
    );
    assert_eq!(count(&e, &Call::Close(0, Source::ExecError)), 1);
}

#[test]
fn deadlines_escalate_then_report_stuck() {
    let mut e = running();
    e.stop(CellId(0), Polite::Main, SEC, Duration::from_secs(2))
        .unwrap();
    e.on_ready(&Ready::Deadline(token(0, Source::Grace)))
        .unwrap();
    assert!(
        e.effects
            .calls
            .ends_with(&[Call::Kill(0), Call::Arm(0, Timer::Kill, 2000)])
    );
    e.on_ready(&Ready::Deadline(token(0, Source::Kill)))
        .unwrap();
    assert_eq!(reports(&mut e), [Report::Failed(Failure::Stuck)]);
}

#[test]
fn orphans_and_reaped_mains_are_reported() {
    let mut e = running();
    e.effects.children.push_back(Reaped::Orphan(42, 0));
    e.effects.children.push_back(Reaped::Main(0, 4242, 9));
    e.on_ready(&Ready::Signal(ORPHANS, libc::SIGCHLD as u32))
        .unwrap();
    let notices = e.take_notices();
    assert!(notices.contains(&Notice::Orphan { pid: 42, status: 0 }));
    assert!(notices.contains(&Notice::Cell(CellId(0), Report::MainExited(Some(9)))));
}

#[test]
fn results_for_no_cell_are_ignored() {
    let mut e = Engine::new(Sim::default());
    e.on_ready(&Ready::Readable(token(5, Source::Ready)))
        .unwrap();
    e.on_ready(&Ready::Deadline(token(9, Source::Grace)))
        .unwrap();
    e.on_ready(&Ready::Priority(12_345_678)).unwrap();
    assert!(e.effects.calls.is_empty());
    assert!(e.take_notices().is_empty());
}

#[test]
fn adoption_compares_the_recorded_id() {
    let mut e = Engine::new(Sim::default());
    e.effects.existing = Some((77, true));
    e.adopt("old", 77, None).unwrap();
    e.adopt("other", 78, None).unwrap();
    assert_eq!(
        reports(&mut e),
        [Report::Running, Report::Failed(Failure::IdMismatch)]
    );
}

#[test]
fn removing_a_mismatched_adoption_releases_only_the_slot() {
    for populated in [false, true] {
        let mut e = Engine::new(Sim::default());
        e.effects.existing = Some((77, populated));
        let id = e.adopt("foreign", 78, None).unwrap();
        assert_eq!(reports(&mut e), [Report::Failed(Failure::IdMismatch)]);
        e.effects.calls.clear();
        e.remove(id).unwrap();
        assert_eq!(reports(&mut e), [Report::Removed]);
        assert_eq!(e.effects.calls, [Call::Release(id.0)]);
        assert_eq!(e.phase(id), None);
        assert_eq!(e.create("next").unwrap(), id);
        e.remove(id).unwrap();
        assert!(e.effects.calls.contains(&Call::Remove(id.0, "next".into())));
    }
}

#[test]
fn an_exit_seen_before_the_exec_result_is_not_lost() {
    // The loop puts `Exited` first in a batch, so a quick child's exit can come before the
    // exec pipe's EOF: the engine settles the exec result first.
    let mut e = Engine::new(Sim::default());
    let id = e.create("w").unwrap();
    e.spawn(id, cmd(), ReadyMode::Exit).unwrap();
    e.on_ready(&Ready::Exited(token(0, Source::Main), 0))
        .unwrap();
    e.on_ready(&Ready::Hangup(token(0, Source::ExecError)))
        .unwrap();
    assert_eq!(reports(&mut e), [Report::Created, Report::Ready]);
    assert_eq!(e.phase(id), Some(Phase::Running));
    assert_eq!(
        count(&e, &Call::Close(0, Source::ExecError)),
        1,
        "the exec pipe is read once"
    );
}

#[test]
fn an_exit_before_a_failed_exec_reports_spawn_failed() {
    let mut e = Engine::new(Sim::default());
    let id = e.create("w").unwrap();
    e.spawn(id, cmd(), ReadyMode::Exit).unwrap();
    e.effects
        .exec_errors
        .push_back(Some(qinit_sys::Errno(libc::ENOENT)));
    e.on_ready(&Ready::Exited(token(0, Source::Main), 127 << 8))
        .unwrap();
    e.on_ready(&Ready::Readable(token(0, Source::ExecError)))
        .unwrap();
    assert_eq!(
        reports(&mut e),
        [Report::Created, Report::Failed(Failure::Spawn)]
    );
}

#[test]
fn a_late_spawn_result_after_the_cell_failed_releases_the_main_pidfd() {
    let mut e = Engine::new(Sim::default());
    let id = e.create("w").unwrap();
    e.spawn(id, cmd(), ReadyMode::Pipe).unwrap();
    // A stop with the exec result outstanding, and it gives up before the result comes.
    e.stop(id, Polite::Main, SEC, SEC).unwrap();
    e.on_ready(&Ready::Deadline(token(0, Source::Grace)))
        .unwrap();
    e.on_ready(&Ready::Deadline(token(0, Source::Kill)))
        .unwrap();
    assert_eq!(e.phase(id), Some(Phase::Failed(Failure::Stuck)));
    assert_eq!(count(&e, &Call::Close(0, Source::Main)), 0);
    e.on_ready(&Ready::Readable(token(0, Source::ExecError)))
        .unwrap();
    assert_eq!(
        e.phase(id),
        Some(Phase::Failed(Failure::Stuck)),
        "a late result changes no phase"
    );
    assert_eq!(
        count(&e, &Call::Close(0, Source::Main)),
        1,
        "nothing will act on that pidfd"
    );
    // Its exit, if the loop still reports one, is ignored; removal frees the slot.
    e.on_ready(&Ready::Exited(token(0, Source::Main), 0))
        .unwrap();
    e.remove(id).unwrap();
    assert_eq!(
        reports(&mut e),
        [
            Report::Created,
            Report::Failed(Failure::Stuck),
            Report::Removed
        ]
    );
    assert_eq!(e.phase(id), None);
}

#[test]
fn a_spawn_result_while_stopping_keeps_the_main_pidfd() {
    let mut e = Engine::new(Sim::default());
    let id = e.create("w").unwrap();
    e.spawn(id, cmd(), ReadyMode::Pipe).unwrap();
    e.stop(id, Polite::Main, SEC, SEC).unwrap();
    e.on_ready(&Ready::Readable(token(0, Source::ExecError)))
        .unwrap();
    assert_eq!(
        count(&e, &Call::Close(0, Source::Main)),
        0,
        "the stop still waits for its exit"
    );
    e.on_ready(&Ready::Exited(token(0, Source::Main), 15))
        .unwrap();
    e.effects.levels.push_back((false, false));
    e.on_ready(&Ready::Priority(token(0, Source::Events)))
        .unwrap();
    assert_eq!(e.phase(id), Some(Phase::Empty));
}

#[test]
fn a_failed_adoption_hand_over_frees_the_slot() {
    let mut e = Engine::new(Sim::default());
    e.effects.adopt_fails = true;
    let fd = std::fs::File::open("/dev/null").unwrap();
    assert!(matches!(
        e.adopt("old", 7, Some(fd.into())),
        Err(Error::Sys(_))
    ));
    assert_eq!(e.phase(CellId(0)), None);
    assert_eq!(e.create("next").unwrap(), CellId(0));
}

#[test]
fn a_handed_over_main_is_seen_exiting_without_a_status() {
    let mut e = Engine::new(Sim::default());
    e.effects.existing = Some((77, true));
    let fd = std::fs::File::open("/dev/null").unwrap();
    let id = e.adopt("old", 77, Some(fd.into())).unwrap();
    // Watched without reaping: the pidfd turns readable when the process exits.
    e.on_ready(&Ready::Readable(token(0, Source::Main)))
        .unwrap();
    assert_eq!(
        count(&e, &Call::Close(0, Source::Main)),
        1,
        "the source goes once it fired"
    );
    assert_eq!(e.phase(id), Some(Phase::Exited));
    e.effects.levels.push_back((false, false));
    e.on_ready(&Ready::Priority(token(0, Source::Events)))
        .unwrap();
    assert_eq!(
        reports(&mut e),
        [Report::Running, Report::MainExited(None), Report::Empty]
    );
}

#[test]
fn children_reaped_outside_any_cell_are_orphans() {
    let mut e = running();
    e.effects.reaped.push((77, 3 << 8));
    assert_eq!(
        e.take_notices(),
        [Notice::Orphan {
            pid: 77,
            status: 3 << 8
        }]
    );
}

#[test]
fn a_main_reaped_after_its_cell_is_gone_is_an_orphan() {
    let mut e = Engine::new(Sim::default());
    e.effects.children.push_back(Reaped::Main(3, 99, 0));
    e.on_ready(&Ready::Signal(ORPHANS, libc::SIGCHLD as u32))
        .unwrap();
    assert_eq!(e.take_notices(), [Notice::Orphan { pid: 99, status: 0 }]);
}

#[test]
fn limits_are_written_before_the_spawn() {
    let mut e = Engine::new(Sim::default());
    let id = e.create("w").unwrap();
    e.set_limits(id, 1_048_576, 32).unwrap();
    e.spawn(id, cmd(), ReadyMode::Pipe).unwrap();
    let calls: Vec<&Call> = e
        .effects
        .calls
        .iter()
        .filter(|c| {
            matches!(
                c,
                Call::Create(..) | Call::WriteLimits(..) | Call::Spawn(..)
            )
        })
        .collect();
    assert_eq!(
        calls,
        [
            &Call::Create(0, "w".into()),
            &Call::WriteLimits(0, 1_048_576, 32),
            &Call::Spawn(0, ReadyMode::Pipe)
        ]
    );
}

#[test]
fn a_zero_limit_is_passed_through_for_the_kernel_effect_to_skip() {
    let mut e = Engine::new(Sim::default());
    let id = e.create("w").unwrap();
    e.set_limits(id, 0, 0).unwrap();
    assert!(e.effects.calls.contains(&Call::WriteLimits(0, 0, 0)));
}

#[test]
fn limits_after_the_spawn_are_refused() {
    let mut e = running();
    let before = e.effects.calls.len();
    assert_eq!(
        e.set_limits(CellId(0), 1 << 20, 8),
        Err(Error::Sys(qinit_sys::Errno(libc::EBUSY)))
    );
    assert_eq!(e.effects.calls.len(), before, "nothing was written");
    assert_eq!(
        e.set_limits(CellId(9), 1, 1),
        Err(Error::NoSuchCell(9)),
        "no such cell"
    );
}

#[test]
fn an_external_cell_is_ready_when_marked() {
    let mut e = Engine::new(Sim::default());
    let id = e.create("w").unwrap();
    e.spawn(id, cmd(), ReadyMode::External).unwrap();
    e.on_ready(&Ready::Readable(token(0, Source::ExecError)))
        .unwrap();
    assert_eq!(reports(&mut e), [Report::Created]);
    e.mark_ready(id).unwrap();
    assert_eq!(reports(&mut e), [Report::Ready]);
    assert_eq!(e.phase(id), Some(Phase::Running));
}

#[test]
fn a_mark_before_the_exec_is_confirmed_waits_for_it() {
    let mut e = Engine::new(Sim::default());
    let id = e.create("w").unwrap();
    e.effects.exec_pending = true;
    e.spawn(id, cmd(), ReadyMode::External).unwrap();
    e.mark_ready(id).unwrap();
    assert_eq!(reports(&mut e), [Report::Created], "not ready yet");
    e.effects.exec_pending = false;
    e.on_ready(&Ready::Readable(token(0, Source::ExecError)))
        .unwrap();
    assert_eq!(reports(&mut e), [Report::Ready]);
}

#[test]
fn signal_main_without_a_main_is_esrch() {
    let mut e = Engine::new(Sim::default());
    let id = e.create("w").unwrap();
    assert_eq!(
        e.signal_main(id, libc::SIGHUP),
        Err(Error::Sys(qinit_sys::Errno(libc::ESRCH)))
    );
    e.spawn(id, cmd(), ReadyMode::Pipe).unwrap();
    e.signal_main(id, libc::SIGHUP).unwrap();
    assert!(
        e.effects
            .calls
            .contains(&Call::SignalNumber(0, libc::SIGHUP))
    );
}

#[test]
fn the_main_pidfd_exists_only_while_a_main_is_tracked() {
    let mut e = Engine::new(Sim::default());
    let id = e.create("w").unwrap();
    assert!(matches!(
        e.main_pidfd(id),
        Err(Error::Sys(qinit_sys::Errno(libc::ESRCH)))
    ));
    e.spawn(id, cmd(), ReadyMode::Pipe).unwrap();
    assert!(e.main_pidfd(id).is_ok());
}

fn devnull() -> std::os::fd::OwnedFd {
    std::fs::File::open("/dev/null").unwrap().into()
}

/// An engine with one adopted cell whose main was handed over.
fn adopted() -> (Engine<Sim>, CellId) {
    let mut e = Engine::new(Sim::default());
    e.effects.existing = Some((77, true));
    let id = e.adopt("old", 77, Some(devnull())).unwrap();
    assert_eq!(reports(&mut e), [Report::Running]);
    (e, id)
}

fn main_readable(e: &mut Engine<Sim>) {
    e.on_ready(&Ready::Readable(token(0, Source::Main)))
        .unwrap();
}

#[test]
fn a_handed_over_main_with_a_recorded_status_reports_it() {
    let (mut e, id) = adopted();
    e.effects.statuses.insert(0, 9);
    main_readable(&mut e);
    assert_eq!(count(&e, &Call::Close(0, Source::Main)), 1);
    assert_eq!(e.phase(id), Some(Phase::Exited));
    assert_eq!(reports(&mut e), [Report::MainExited(Some(9))]);
}

#[test]
fn without_the_wait_an_unrecorded_status_is_none_as_before() {
    let (mut e, id) = adopted();
    main_readable(&mut e);
    assert_eq!(count(&e, &Call::UnwatchMain(0)), 0);
    assert_eq!(e.phase(id), Some(Phase::Exited));
    let notices = e.take_notices();
    assert_eq!(notices, [Notice::Cell(id, Report::MainExited(None))]);
}

#[test]
fn with_the_wait_an_unrecorded_status_is_pending_and_watching_stops() {
    let (mut e, id) = adopted();
    e.wait_for_status();
    main_readable(&mut e);
    assert_eq!(e.take_notices(), [Notice::StatusPending(id)]);
    assert_eq!(count(&e, &Call::UnwatchMain(0)), 1);
    assert_eq!(
        count(&e, &Call::Close(0, Source::Main)),
        0,
        "the pidfd is kept"
    );
    assert_eq!(
        e.phase(id),
        Some(Phase::Running),
        "the machine has not heard yet"
    );
}

#[test]
fn a_recorded_status_is_not_pending_even_with_the_wait() {
    let (mut e, id) = adopted();
    e.wait_for_status();
    e.effects.statuses.insert(0, 3 << 8);
    main_readable(&mut e);
    assert_eq!(
        e.take_notices(),
        [Notice::Cell(id, Report::MainExited(Some(3 << 8)))]
    );
}

#[test]
fn settle_delivers_a_status_that_has_arrived() {
    let (mut e, id) = adopted();
    e.wait_for_status();
    main_readable(&mut e);
    e.take_notices();
    e.effects.statuses.insert(0, 3 << 8);
    assert_eq!(e.settle_status(id, false), Ok(true));
    assert_eq!(count(&e, &Call::Close(0, Source::Main)), 1);
    assert_eq!(reports(&mut e), [Report::MainExited(Some(3 << 8))]);
    assert_eq!(
        e.settle_status(id, false),
        Ok(false),
        "nothing is pending any more"
    );
}

#[test]
fn settle_stays_pending_until_given_up() {
    let (mut e, id) = adopted();
    e.wait_for_status();
    main_readable(&mut e);
    e.take_notices();
    assert_eq!(e.settle_status(id, false), Ok(false));
    assert_eq!(e.settle_status(id, false), Ok(false));
    assert_eq!(e.phase(id), Some(Phase::Running));
    assert!(reports(&mut e).is_empty());
}

#[test]
fn giving_up_delivers_none() {
    let (mut e, id) = adopted();
    e.wait_for_status();
    main_readable(&mut e);
    e.take_notices();
    assert_eq!(e.settle_status(id, true), Ok(true));
    assert_eq!(reports(&mut e), [Report::MainExited(None)]);
    assert_eq!(e.phase(id), Some(Phase::Exited));
}

#[test]
fn a_cell_stopped_while_pending_still_ends() {
    let (mut e, id) = adopted();
    e.wait_for_status();
    main_readable(&mut e);
    e.take_notices();
    e.stop(id, Polite::Main, SEC, SEC).unwrap();
    assert_eq!(e.settle_status(id, true), Ok(true));
    e.effects.levels.push_back((false, false));
    e.on_ready(&Ready::Priority(token(0, Source::Events)))
        .unwrap();
    assert_eq!(
        reports(&mut e),
        [Report::Empty],
        "the stop ends, as it would have"
    );
    assert_eq!(e.phase(id), Some(Phase::Empty));
}

#[test]
fn a_held_directory_is_used_and_the_id_still_checked() {
    let mut e = Engine::new(Sim::default());
    e.effects.existing = Some((77, true));
    e.adopt_held("old", 77, devnull(), None).unwrap();
    e.adopt_held("other", 78, devnull(), None).unwrap();
    assert_eq!(
        reports(&mut e),
        [Report::Running, Report::Failed(Failure::IdMismatch)]
    );
    let calls = &e.effects.calls;
    let hand = calls.iter().position(|c| *c == Call::HandDir(0)).unwrap();
    let open = calls
        .iter()
        .position(|c| *c == Call::OpenExisting(0, "old".into()))
        .unwrap();
    assert!(
        hand < open,
        "the directory is handed before the cell is opened: {calls:?}"
    );
}

#[test]
fn a_directory_can_be_duplicated_for_the_store() {
    let (mut e, id) = adopted();
    assert!(e.dir_fd(id).is_ok());
    assert!(matches!(e.dir_fd(CellId(5)), Err(Error::NoSuchCell(5))));
}
