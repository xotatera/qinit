// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The engine against the simulated effects (spec §6.1 tier 2).
use qinit_cell::effects::{Command, Reaped};
use qinit_cell::engine::{CellId, Engine, Error, Notice, ORPHANS};
use qinit_cell::sim::{Call, Sim};
use qinit_cell_core::{Failure, Phase, Polite, ReadyMode, Report, STATUS_UNKNOWN, Sig, Timer};
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
    assert!(notices.contains(&Notice::Cell(CellId(0), Report::MainExited(9))));
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
        [
            Report::Running,
            Report::MainExited(STATUS_UNKNOWN),
            Report::Empty
        ]
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
