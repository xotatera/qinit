// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The machine, one test per row of the transition table, and the named cases of the spec.
use qinit_queen_core::machine::{
    Action, Actions, Event, Input, LIMITS, Limits, MAX_EXITS, Phase, State, exit_code, initial,
    next_record, orphan_reaped, record_sent, step,
};
use qinit_queen_core::store::{CAPACITY, DB_KEY, Entry, FREE};
use qinit_queen_core::{FromColony, Mode, ToColony};

const COLONY: i32 = 100;
const RESCUE: i32 = 200;

struct Rig {
    s: State,
    t: Vec<Entry>,
    now: u64,
}

fn acts(a: &Actions) -> Vec<Action> {
    (0..a.len).map(|i| a.get(i).unwrap()).collect()
}

fn exited(code: i32) -> i32 {
    code << 8
}

const KILLED: i32 = 9;

impl Rig {
    /// Colony started and attached.
    fn running() -> Rig {
        let (s, a) = initial();
        assert_eq!(acts(&a), [Action::SpawnColony]);
        let mut r = Rig {
            s,
            t: vec![FREE; 8],
            now: 1_000,
        };
        r.feed(Input::ColonySpawned(COLONY));
        r
    }

    fn feed(&mut self, i: Input) -> Vec<Action> {
        acts(&step(&mut self.s, &mut self.t, &LIMITS, i, self.now))
    }

    fn colony_exits(&mut self, status: i32) -> Vec<Action> {
        self.feed(Input::Child {
            pid: COLONY,
            status,
        })
    }

    /// Running, then the colony exits with `code`, then rescue is spawned as `RESCUE`.
    fn in_rescue() -> Rig {
        let mut r = Rig::running();
        r.colony_exits(exited(3));
        r.feed(Input::RescueSpawned(RESCUE));
        assert_eq!(r.s.phase, Phase::Rescue);
        r
    }

    fn in_hold() -> Rig {
        let mut r = Rig::in_rescue();
        r.feed(Input::Child {
            pid: RESCUE,
            status: exited(1),
        });
        assert_eq!(r.s.phase, Phase::Hold);
        r
    }

    fn stopping(mode_input: Input) -> Rig {
        let mut r = Rig::running();
        r.feed(mode_input);
        assert_eq!(r.s.phase, Phase::Stopping);
        r
    }
}

fn has(v: &[Action], a: Action) -> bool {
    v.contains(&a)
}

fn logs(v: &[Action], e: Event) -> bool {
    has(v, Action::Log(e))
}

fn no_spawn(v: &[Action]) -> bool {
    !v.iter().any(|a| matches!(a, Action::SpawnColony))
}

#[test]
fn the_machine_starts_by_spawning_colony() {
    let (s, a) = initial();
    assert_eq!(s.phase, Phase::Running);
    assert_eq!(acts(&a), [Action::SpawnColony]);
    assert!(!s.stopped);
}

#[test]
fn colony_exit_0_10_11_runs_zero_in_the_codes_mode() {
    for (code, mode) in [(0, Mode::Halt), (10, Mode::Poweroff), (11, Mode::Reboot)] {
        let mut r = Rig::running();
        let v = r.colony_exits(exited(code));
        assert!(has(&v, Action::ExecZero(mode)), "{code}: {v:?}");
        assert!(no_spawn(&v));
        assert!(r.s.stopped);
        assert_eq!(r.s.colony, 0);
    }
}

#[test]
fn exit_two_and_three_go_to_rescue_at_once() {
    for code in [2, 3] {
        let mut r = Rig::running();
        let v = r.colony_exits(exited(code));
        assert!(has(&v, Action::SpawnRescue), "{v:?}");
        assert!(no_spawn(&v));
        assert_eq!(r.s.phase, Phase::Rescue);
        assert_eq!(r.s.nexits, 0, "not counted");
        assert!(!r.s.stopped);
    }
}

#[test]
fn any_other_exit_or_a_signal_is_counted_and_restarts() {
    for status in [
        exited(4),
        exited(5),
        exited(1),
        exited(255),
        KILLED,
        0x0b | 0x80,
    ] {
        let mut r = Rig::running();
        let v = r.colony_exits(status);
        assert!(has(&v, Action::SpawnColony), "{status}: {v:?}");
        assert_eq!(r.s.nexits, 1);
        assert_eq!(r.s.phase, Phase::Running);
    }
}

#[test]
fn a_failed_spawn_is_counted_like_an_exit() {
    let mut r = Rig::running();
    r.colony_exits(KILLED);
    let v = r.feed(Input::ColonySpawnFailed);
    assert!(has(&v, Action::SpawnColony));
    assert_eq!(r.s.nexits, 2);
}

#[test]
fn five_exits_in_a_minute_restart_and_the_sixth_runs_rescue() {
    let mut r = Rig::running();
    for n in 1..=MAX_EXITS {
        let v = r.colony_exits(KILLED);
        assert!(has(&v, Action::SpawnColony), "exit {n}: {v:?}");
        r.now += 1_000;
        r.feed(Input::ColonySpawned(COLONY));
    }
    let v = r.colony_exits(KILLED);
    assert!(no_spawn(&v), "{v:?}");
    assert!(logs(&v, Event::LimitTripped));
    assert!(has(&v, Action::SpawnRescue));
    assert_eq!(r.s.phase, Phase::Rescue);
}

#[test]
fn an_exit_outside_the_window_does_not_count() {
    let mut r = Rig::running();
    for _ in 0..MAX_EXITS {
        r.colony_exits(KILLED);
        r.feed(Input::ColonySpawned(COLONY));
    }
    // The oldest of the five is exactly one window old: outside it.
    r.now += LIMITS.window_ms;
    let v = r.colony_exits(KILLED);
    assert!(has(&v, Action::SpawnColony), "{v:?}");
    assert_eq!(r.s.nexits, MAX_EXITS);
    assert_eq!(r.s.exits[MAX_EXITS - 1], r.now, "the newest is last");
}

#[test]
fn an_exit_just_inside_the_window_trips() {
    let mut r = Rig::running();
    for _ in 0..MAX_EXITS {
        r.colony_exits(KILLED);
        r.feed(Input::ColonySpawned(COLONY));
    }
    r.now += LIMITS.window_ms - 1;
    let v = r.colony_exits(KILLED);
    assert!(logs(&v, Event::LimitTripped));
}

#[test]
fn a_shutdown_record_starts_the_shutdown() {
    let mut r = Rig::running();
    let v = r.feed(Input::Record(
        FromColony::Shutdown { mode: Mode::Reboot },
        -1,
    ));
    assert_eq!(r.s.phase, Phase::Stopping);
    assert!(r.s.stopped);
    assert_eq!(r.s.mode, Mode::Reboot);
    assert!(has(&v, Action::CadOn));
    assert!(has(&v, Action::ArmTimer(LIMITS.shutdown_ms)));
    assert_eq!(r.s.request, None, "colony announced it; nothing to forward");
}

#[test]
fn cad_asks_colony_for_a_reboot() {
    let mut r = Rig::running();
    let v = r.feed(Input::Cad);
    assert_eq!(r.s.phase, Phase::Stopping);
    assert_eq!(r.s.mode, Mode::Reboot);
    assert_eq!(r.s.request, Some(Mode::Reboot));
    assert!(has(&v, Action::CadOn) && has(&v, Action::ArmTimer(LIMITS.shutdown_ms)));
}

#[test]
fn pwr_asks_colony_for_a_poweroff() {
    let mut r = Rig::running();
    let v = r.feed(Input::Pwr);
    assert_eq!(r.s.phase, Phase::Stopping);
    assert_eq!(r.s.mode, Mode::Poweroff);
    assert_eq!(r.s.request, Some(Mode::Poweroff));
    assert!(has(&v, Action::CadOn));
}

#[test]
fn a_bad_channel_kills_colony_and_the_reap_counts_it() {
    let mut r = Rig::running();
    let v = r.feed(Input::ChannelBad);
    assert!(has(&v, Action::Kill(COLONY)) && logs(&v, Event::ChannelBad));
    let v = r.colony_exits(KILLED);
    assert!(has(&v, Action::SpawnColony));
    assert_eq!(r.s.nexits, 1);

    let mut r = Rig::stopping(Input::Cad);
    let v = r.feed(Input::ChannelBad);
    assert!(has(&v, Action::Kill(COLONY)));
}

#[test]
fn a_closed_channel_does_nothing() {
    for mut r in [Rig::running(), Rig::stopping(Input::Pwr), Rig::in_rescue()] {
        let before = r.s;
        assert_eq!(r.feed(Input::ChannelClosed), []);
        assert_eq!(r.s, before);
    }
}

#[test]
fn a_late_shutdown_record_changes_the_mode_and_not_the_timer() {
    let mut r = Rig::stopping(Input::Cad);
    let v = r.feed(Input::Record(FromColony::Shutdown { mode: Mode::Halt }, -1));
    assert_eq!(r.s.mode, Mode::Halt);
    assert_eq!(v, [], "no timer, no second request");
    assert_eq!(r.s.phase, Phase::Stopping);
}

#[test]
fn cad_and_pwr_while_stopping_do_nothing() {
    let mut r = Rig::stopping(Input::Pwr);
    let before = r.s;
    assert_eq!(r.feed(Input::Cad), []);
    assert_eq!(r.feed(Input::Pwr), []);
    assert_eq!(r.s, before);
}

#[test]
fn the_shutdown_timer_kills_colony_and_arms_the_kill_wait() {
    let mut r = Rig::stopping(Input::Cad);
    let v = r.feed(Input::Timer);
    assert_eq!(r.s.phase, Phase::Killed);
    assert!(has(&v, Action::Kill(COLONY)) && has(&v, Action::ArmTimer(LIMITS.kill_wait_ms)));
}

#[test]
fn colony_reaped_while_stopping_runs_zero_and_cancels_the_timer() {
    let mut r = Rig::stopping(Input::Cad);
    let v = r.colony_exits(KILLED);
    assert!(has(&v, Action::CancelTimer));
    assert!(
        has(&v, Action::ExecZero(Mode::Reboot)),
        "the recorded mode: {v:?}"
    );
    let mut r = Rig::stopping(Input::Cad);
    r.feed(Input::Timer);
    let v = r.colony_exits(KILLED);
    assert!(has(&v, Action::ExecZero(Mode::Reboot)));
}

#[test]
fn the_exit_code_beats_the_recorded_mode() {
    let mut r = Rig::stopping(Input::Cad);
    let v = r.colony_exits(exited(10));
    assert!(has(&v, Action::ExecZero(Mode::Poweroff)), "{v:?}");
    assert_eq!(r.s.mode, Mode::Poweroff);
    let mut r = Rig::stopping(Input::Pwr);
    let v = r.colony_exits(exited(0));
    assert!(has(&v, Action::ExecZero(Mode::Halt)));
    let mut r = Rig::stopping(Input::Pwr);
    let v = r.colony_exits(exited(11));
    assert!(has(&v, Action::ExecZero(Mode::Reboot)));
    let mut r = Rig::stopping(Input::Pwr);
    let v = r.colony_exits(exited(3));
    assert!(
        has(&v, Action::ExecZero(Mode::Poweroff)),
        "exit 3 during a shutdown: the record"
    );
}

#[test]
fn an_unreaped_colony_does_not_stop_the_way_down() {
    let mut r = Rig::stopping(Input::Cad);
    let v = r.feed(Input::Timer);
    assert!(!v.iter().any(|a| matches!(a, Action::ExecZero(_))));
    let v = r.feed(Input::Timer);
    assert!(has(&v, Action::ExecZero(Mode::Reboot)), "{v:?}");
}

#[test]
fn a_stale_timer_does_nothing_elsewhere() {
    for mut r in [Rig::running(), Rig::in_rescue(), Rig::in_hold()] {
        let before = r.s;
        assert_eq!(r.feed(Input::Timer), []);
        assert_eq!(r.s, before);
    }
}

#[test]
fn a_failed_exec_runs_rescue_and_rescue_then_holds_for_good() {
    let mut r = Rig::stopping(Input::Pwr);
    r.colony_exits(exited(10));
    let v = r.feed(Input::ExecFailed);
    assert!(logs(&v, Event::ExecFailed) && has(&v, Action::SpawnRescue));
    assert_eq!(r.s.phase, Phase::Rescue);
    assert!(r.s.stopped, "stopped is sticky");
    r.feed(Input::RescueSpawned(RESCUE));
    r.now += LIMITS.rescue_min_ms + 1;
    let v = r.feed(Input::Child {
        pid: RESCUE,
        status: exited(0),
    });
    assert_eq!(
        r.s.phase,
        Phase::Hold,
        "no colony after a shutdown began: {v:?}"
    );
    assert!(no_spawn(&v));
}

#[test]
fn a_failed_exec_with_rescue_already_running_spawns_no_second_one() {
    let mut r = Rig::in_rescue();
    let v = r.feed(Input::Pwr);
    assert!(
        v.iter()
            .any(|a| matches!(a, Action::ExecZero(Mode::Poweroff)))
    );
    let v = r.feed(Input::ExecFailed);
    assert!(!has(&v, Action::SpawnRescue));
}

#[test]
fn rescue_exiting_zero_after_the_minimum_clears_the_limit() {
    let mut r = Rig::running();
    for _ in 0..3 {
        r.colony_exits(KILLED);
        r.feed(Input::ColonySpawned(COLONY));
    }
    r.colony_exits(exited(3));
    r.feed(Input::RescueSpawned(RESCUE));
    assert_eq!(r.s.nexits, 3);
    r.now += LIMITS.rescue_min_ms;
    let v = r.feed(Input::Child {
        pid: RESCUE,
        status: exited(0),
    });
    assert!(has(&v, Action::SpawnColony), "{v:?}");
    assert_eq!(r.s.phase, Phase::Running);
    assert_eq!(r.s.nexits, 0);
    assert_eq!(r.s.rescue, 0);
}

#[test]
fn rescue_exiting_zero_too_soon_holds() {
    let mut r = Rig::in_rescue();
    r.now += LIMITS.rescue_min_ms - 1;
    let v = r.feed(Input::Child {
        pid: RESCUE,
        status: exited(0),
    });
    assert_eq!(r.s.phase, Phase::Hold);
    assert!(logs(&v, Event::Hold) && no_spawn(&v));
}

#[test]
fn rescue_exiting_non_zero_holds() {
    for status in [exited(1), exited(3), KILLED] {
        let mut r = Rig::in_rescue();
        r.now += 10 * LIMITS.rescue_min_ms;
        let v = r.feed(Input::Child {
            pid: RESCUE,
            status,
        });
        assert_eq!(r.s.phase, Phase::Hold, "{status}");
        assert!(no_spawn(&v));
    }
}

#[test]
fn a_rescue_that_cannot_start_holds() {
    let mut r = Rig::running();
    r.colony_exits(exited(2));
    let v = r.feed(Input::RescueSpawnFailed);
    assert_eq!(r.s.phase, Phase::Hold);
    assert!(logs(&v, Event::Hold));
}

#[test]
fn pwr_in_rescue_or_hold_runs_zero_poweroff() {
    for mut r in [Rig::in_rescue(), Rig::in_hold()] {
        let v = r.feed(Input::Pwr);
        assert!(has(&v, Action::ExecZero(Mode::Poweroff)), "{v:?}");
        assert!(r.s.stopped);
    }
}

#[test]
fn cad_in_hold_starts_colony_again() {
    let mut r = Rig::in_hold();
    let v = r.feed(Input::Cad);
    assert!(has(&v, Action::SpawnColony));
    assert_eq!(r.s.phase, Phase::Running);
    assert_eq!(r.s.nexits, 0);
}

#[test]
fn cad_in_rescue_or_in_a_stopped_hold_is_ignored() {
    let mut r = Rig::in_rescue();
    assert_eq!(r.feed(Input::Cad), [Action::Log(Event::CadIgnored)]);
    assert_eq!(r.s.phase, Phase::Rescue);

    let mut r = Rig::stopping(Input::Pwr);
    r.colony_exits(exited(10));
    r.feed(Input::ExecFailed);
    r.feed(Input::RescueSpawned(RESCUE));
    r.feed(Input::Child {
        pid: RESCUE,
        status: exited(1),
    });
    assert_eq!(r.s.phase, Phase::Hold);
    let v = r.feed(Input::Cad);
    assert_eq!(v, [Action::Log(Event::CadIgnored)]);
}

#[test]
fn a_colony_reaped_in_rescue_or_hold_only_clears_its_pid() {
    let mut r = Rig::stopping(Input::Pwr);
    r.feed(Input::Timer);
    r.feed(Input::Timer);
    r.feed(Input::ExecFailed);
    assert_eq!(r.s.phase, Phase::Rescue);
    assert_eq!(r.s.colony, COLONY, "never reaped");
    let v = r.colony_exits(KILLED);
    assert_eq!(r.s.colony, 0);
    assert!(no_spawn(&v) && !has(&v, Action::SpawnRescue));
}

#[test]
fn an_orphan_is_nobodys_business() {
    let mut r = Rig::running();
    let before = r.s;
    let v = r.feed(Input::Child {
        pid: 4242,
        status: exited(0),
    });
    assert_eq!(v, []);
    assert_eq!(r.s, before);
    orphan_reaped(&mut r.s);
    assert!(r.s.reaped);
}

#[test]
fn a_put_stores_replaces_and_a_full_table_closes() {
    let mut r = Rig::running();
    r.t = vec![FREE; 2];
    assert_eq!(r.feed(Input::Record(FromColony::Put { key: 16 }, 7)), []);
    assert_eq!(
        r.feed(Input::Record(FromColony::Put { key: 16 }, 8)),
        [Action::Close(7)]
    );
    assert_eq!(r.feed(Input::Record(FromColony::Put { key: 17 }, 9)), []);
    let v = r.feed(Input::Record(FromColony::Put { key: 18 }, 10));
    assert_eq!(v, [Action::Close(10), Action::Log(Event::StoreFull(18))]);
    assert_eq!(r.s.refused, 18);
}

#[test]
fn a_drop_closes_the_descriptor_and_an_unknown_key_does_nothing() {
    let mut r = Rig::running();
    r.feed(Input::Record(FromColony::Put { key: 16 }, 7));
    assert_eq!(
        r.feed(Input::Record(FromColony::Drop { key: 16 }, -1)),
        [Action::Close(7)]
    );
    assert_eq!(r.feed(Input::Record(FromColony::Drop { key: 16 }, -1)), []);
}

#[test]
fn a_full_store_closes_the_new_descriptor_and_refuses() {
    let mut r = Rig::running();
    r.t = vec![FREE; 1];
    r.feed(Input::Record(FromColony::Put { key: 1 }, 5));
    let v = r.feed(Input::Record(FromColony::Put { key: 2 }, 6));
    assert!(has(&v, Action::Close(6)));
    // Refused is the next record to colony once the hand-over is done.
    r.s.handed_over = true;
    assert_eq!(
        next_record(&r.s, &r.t),
        Some((ToColony::Refused { key: 2 }, -1))
    );
}

#[test]
fn puts_and_drops_are_taken_in_every_phase() {
    for mut r in [Rig::stopping(Input::Cad), Rig::in_rescue(), Rig::in_hold()] {
        assert_eq!(r.feed(Input::Record(FromColony::Put { key: 16 }, 7)), []);
        assert_eq!(
            r.feed(Input::Record(FromColony::Drop { key: 16 }, -1)),
            [Action::Close(7)]
        );
    }
}

#[test]
fn a_shutdown_record_in_rescue_or_hold_is_ignored() {
    for mut r in [Rig::in_rescue(), Rig::in_hold()] {
        let before = r.s;
        assert_eq!(
            r.feed(Input::Record(FromColony::Shutdown { mode: Mode::Halt }, -1)),
            []
        );
        assert_eq!(r.s, before);
    }
}

#[test]
fn a_new_colony_gets_the_whole_store_again() {
    let mut r = Rig::running();
    for (k, fd) in [(16, 20), (17, 21), (18, 22)] {
        r.feed(Input::Record(FromColony::Put { key: k }, fd));
    }
    // Two of three sent to the first colony, then it dies.
    for _ in 0..2 {
        assert!(matches!(
            next_record(&r.s, &r.t),
            Some((ToColony::Held { .. }, _))
        ));
        record_sent(&mut r.s, &r.t);
    }
    r.colony_exits(KILLED);
    assert_eq!(next_record(&r.s, &r.t), None, "no colony attached");
    r.feed(Input::ColonySpawned(COLONY + 1));
    let mut held = Vec::new();
    while let Some((rec, fd)) = next_record(&r.s, &r.t) {
        record_sent(&mut r.s, &r.t);
        match rec {
            ToColony::Held { key } => held.push((key, fd)),
            ToColony::HeldEnd { count } => {
                assert_eq!(count, 3);
                break;
            }
            other => panic!("{other:?}"),
        }
    }
    held.sort_unstable();
    assert_eq!(held, [(16, 20), (17, 21), (18, 22)]);
    assert_eq!(next_record(&r.s, &r.t), None);
}

#[test]
fn a_request_before_colony_attaches_is_sent_after_the_hand_over() {
    let mut r = Rig::running();
    r.feed(Input::Record(FromColony::Put { key: 16 }, 20));
    r.feed(Input::Cad);
    assert_eq!(
        next_record(&r.s, &r.t),
        Some((ToColony::Held { key: 16 }, 20))
    );
    record_sent(&mut r.s, &r.t);
    assert_eq!(
        next_record(&r.s, &r.t),
        Some((ToColony::HeldEnd { count: 1 }, -1))
    );
    record_sent(&mut r.s, &r.t);
    assert_eq!(
        next_record(&r.s, &r.t),
        Some((ToColony::Request { mode: Mode::Reboot }, -1))
    );
    record_sent(&mut r.s, &r.t);
    assert_eq!(next_record(&r.s, &r.t), None);
    assert_eq!(r.s.request, None);
}

#[test]
fn repeated_reaped_wakes_coalesce() {
    let mut r = Rig::running();
    record_sent_all(&mut r);
    orphan_reaped(&mut r.s);
    orphan_reaped(&mut r.s);
    orphan_reaped(&mut r.s);
    assert_eq!(next_record(&r.s, &r.t), Some((ToColony::Reaped, -1)));
    record_sent(&mut r.s, &r.t);
    assert_eq!(next_record(&r.s, &r.t), None);
}

fn record_sent_all(r: &mut Rig) {
    while next_record(&r.s, &r.t).is_some() {
        record_sent(&mut r.s, &r.t);
    }
}

#[test]
fn the_records_after_the_hand_over_come_in_order() {
    let mut r = Rig::running();
    r.t = vec![FREE; 1];
    r.feed(Input::Record(FromColony::Put { key: 1 }, 5));
    r.feed(Input::Record(FromColony::Put { key: 2 }, 6));
    orphan_reaped(&mut r.s);
    r.feed(Input::Cad);
    let mut seen = Vec::new();
    while let Some((rec, _)) = next_record(&r.s, &r.t) {
        record_sent(&mut r.s, &r.t);
        seen.push(rec);
    }
    assert_eq!(
        seen,
        [
            ToColony::Held { key: 1 },
            ToColony::HeldEnd { count: 1 },
            ToColony::Request { mode: Mode::Reboot },
            ToColony::Reaped,
            ToColony::Refused { key: 2 },
        ]
    );
}

#[test]
fn exit_code_reads_a_wait_status() {
    assert_eq!(exit_code(0), Some(0));
    assert_eq!(exit_code(exited(10)), Some(10));
    assert_eq!(exit_code(exited(255)), Some(255));
    assert_eq!(exit_code(KILLED), None);
    assert_eq!(exit_code(0x0b | 0x80), None, "a core dump");
}

#[test]
fn a_spawned_colony_resets_the_hand_over() {
    let mut r = Rig::running();
    r.feed(Input::Record(FromColony::Put { key: 16 }, 20));
    record_sent_all(&mut r);
    assert!(r.s.handed_over);
    r.colony_exits(KILLED);
    r.feed(Input::ColonySpawned(COLONY + 1));
    assert!(!r.s.handed_over);
    assert_eq!(r.s.cursor, 0);
    assert!(!r.s.reaped);
}

#[test]
fn the_capacity_table_works_at_full_size() {
    let mut r = Rig::running();
    r.t = (0..CAPACITY as u64)
        .map(|k| Entry { key: k + 1, fd: 3 })
        .collect();
    let v = r.feed(Input::Record(
        FromColony::Put {
            key: CAPACITY as u64 + 1,
        },
        4,
    ));
    assert_eq!(
        v,
        [
            Action::Close(4),
            Action::Log(Event::StoreFull(CAPACITY as u64 + 1))
        ]
    );
    let v = r.feed(Input::Record(FromColony::Put { key: 77 }, 5));
    assert_eq!(v, [Action::Close(3)], "an old key is still replaced");
}

#[test]
fn a_timer_in_stopping_with_no_colony_goes_to_zero() {
    let mut r = Rig::running();
    r.feed(Input::Pwr);
    // Colony is gone and nothing will reap it: the bound still ends the shutdown.
    r.s.colony = 0;
    let v = r.feed(Input::Timer);
    assert!(
        v.iter()
            .any(|a| matches!(a, Action::ExecZero(Mode::Poweroff))),
        "{v:?}"
    );
}

impl Rig {
    fn put(&mut self, key: u64, fd: i32) {
        self.feed(Input::Record(FromColony::Put { key }, fd));
    }

    fn holds(&self, key: u64) -> bool {
        self.t.iter().any(|e| e.key == key)
    }
}

#[test]
fn a_clean_rescue_drops_the_held_database_so_the_fixed_file_is_read() {
    let mut r = Rig::running();
    r.put(1, 7);
    r.put(DB_KEY, 9);
    r.colony_exits(exited(3));
    r.feed(Input::RescueSpawned(RESCUE));
    r.now += LIMITS.rescue_min_ms;
    let v = r.feed(Input::Child {
        pid: RESCUE,
        status: exited(0),
    });
    assert!(has(&v, Action::SpawnColony), "{v:?}");
    assert!(
        has(&v, Action::Close(9)),
        "the database's descriptor is closed: {v:?}"
    );
    assert!(!r.holds(DB_KEY));
    assert!(r.holds(1), "the cells stay: they are adopted, not rebuilt");
}

#[test]
fn leaving_the_hold_with_ctrl_alt_del_drops_the_held_database() {
    let mut r = Rig::running();
    r.put(DB_KEY, 9);
    r.colony_exits(exited(3));
    r.feed(Input::RescueSpawned(RESCUE));
    r.feed(Input::Child {
        pid: RESCUE,
        status: exited(1),
    });
    assert_eq!(r.s.phase, Phase::Hold);
    assert!(r.holds(DB_KEY), "a failed rescue changed nothing");
    let v = r.feed(Input::Cad);
    assert!(has(&v, Action::SpawnColony));
    assert!(has(&v, Action::Close(9)), "{v:?}");
    assert!(!r.holds(DB_KEY));
}

#[test]
fn an_ordinary_restart_keeps_the_held_database() {
    let mut r = Rig::running();
    r.put(DB_KEY, 9);
    let v = r.colony_exits(KILLED);
    assert!(has(&v, Action::SpawnColony));
    assert!(!has(&v, Action::Close(9)));
    assert!(r.holds(DB_KEY));
}

#[test]
fn a_new_colony_arms_the_heartbeat() {
    let (s, _) = initial();
    let mut r = Rig {
        s,
        t: vec![FREE; 8],
        now: 1_000,
    };
    let v = r.feed(Input::ColonySpawned(COLONY));
    assert!(has(&v, Action::ArmTimer(LIMITS.heartbeat_ms)), "{v:?}");
}

#[test]
fn a_colony_silent_for_a_whole_period_is_killed() {
    let mut r = Rig::running();
    r.now += LIMITS.heartbeat_ms;
    let v = r.feed(Input::Timer);
    assert_eq!(v, [Action::Log(Event::ColonySilent), Action::Kill(COLONY)]);
    // Killed, it is reaped and counted like any crash.
    let v = r.colony_exits(KILLED);
    assert!(has(&v, Action::SpawnColony), "{v:?}");
}

#[test]
fn a_colony_that_spoke_is_given_another_period() {
    let mut r = Rig::running();
    r.now += LIMITS.heartbeat_ms / 2;
    assert!(r.feed(Input::Record(FromColony::Alive, -1)).is_empty());
    r.now += LIMITS.heartbeat_ms / 2;
    assert_eq!(
        r.feed(Input::Timer),
        [Action::ArmTimer(LIMITS.heartbeat_ms)]
    );
    // The next whole period passes in silence.
    r.now += LIMITS.heartbeat_ms;
    let v = r.feed(Input::Timer);
    assert!(has(&v, Action::Kill(COLONY)), "{v:?}");
}

#[test]
fn a_timer_a_restart_overtook_kills_nothing() {
    let mut r = Rig::running();
    r.now += LIMITS.heartbeat_ms;
    // The reap restarts colony in the same turn the stale timer is read.
    r.colony_exits(KILLED);
    r.feed(Input::ColonySpawned(COLONY + 1));
    assert!(r.feed(Input::Timer).is_empty());
}

#[test]
fn a_heartbeat_of_zero_is_off() {
    let lim = Limits {
        heartbeat_ms: 0,
        ..LIMITS
    };
    let (s, _) = initial();
    let (mut s, mut t) = (s, vec![FREE; 8]);
    let a = step(&mut s, &mut t, &lim, Input::ColonySpawned(COLONY), 1_000);
    assert!(acts(&a).iter().all(|x| !matches!(x, Action::ArmTimer(_))));
    let a = step(&mut s, &mut t, &lim, Input::Timer, 1_000_000);
    assert!(acts(&a).is_empty());
}

#[test]
fn a_shutdown_takes_the_timer_from_the_heartbeat() {
    let mut r = Rig::running();
    let v = r.feed(Input::Cad);
    assert!(has(&v, Action::ArmTimer(LIMITS.shutdown_ms)), "{v:?}");
    // Past a heartbeat period, still in the shutdown's: a late Alive or a timer kill nothing
    // beyond the shutdown's own bound.
    r.now += LIMITS.heartbeat_ms;
    assert!(r.feed(Input::Record(FromColony::Alive, -1)).is_empty());
}
