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
            Notice::Orphan { .. } => None,
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
fn r1_ready_line_waits_for_exec_across_batches() {
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

    // Retained readiness and exits must follow observation order, not source priority.
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
fn r1_ready_line_before_exec_readable_in_same_batch() {
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
fn r1_ready_eof_waits_for_failed_exec_without_not_ready() {
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
