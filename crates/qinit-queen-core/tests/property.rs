// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Random inputs against the proved obligations. A small stand-in for the outer layer performs
//! the actions the way queen would, so the machine sees only inputs a real run could produce.
#![allow(
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]
use qinit_queen_core::machine::{
    Action, Actions, Input, LIMITS, MAX_EXITS, Phase, State, initial, next_record, record_sent,
    step,
};
use qinit_queen_core::store::{Entry, FREE};
use qinit_queen_core::{FromColony, Mode};

/// The actions of a step, in order.
pub fn actions(a: &Actions) -> Vec<Action> {
    (0..a.len).map(|i| a.get(i).unwrap()).collect()
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

struct World {
    s: State,
    t: Vec<Entry>,
    now: u64,
    rng: Rng,
    next_pid: i32,
    next_fd: i32,
    /// Times of the restarts counted since the limit was last cleared.
    restarts: Vec<u64>,
    /// `Timer` inputs seen since the machine entered Stopping, with no `ExecZero` yet.
    timers: u32,
    /// The process ended in an exec of zero.
    done: bool,
}

impl World {
    fn new(seed: u64) -> World {
        let (s, a) = initial();
        let mut w = World {
            s,
            t: vec![FREE; 6],
            now: 1_000,
            rng: Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1),
            next_pid: 100,
            next_fd: 10,
            restarts: Vec::new(),
            timers: 0,
            done: false,
        };
        w.perform(actions(&a));
        w
    }

    fn pid(&mut self) -> i32 {
        self.next_pid += 1;
        self.next_pid
    }

    /// Runs `input`, checks the obligations, and performs the actions it names.
    fn feed(&mut self, input: Input) {
        let old = self.s;
        let old_table = self.t.clone();
        let a = step(&mut self.s, &mut self.t, &LIMITS, input, self.now);
        let v = actions(&a);
        assert!(v.len() <= 4, "no action was dropped: {v:?}");
        let spawns = v
            .iter()
            .filter(|x| matches!(x, Action::SpawnColony))
            .count();
        let exec = v.iter().any(|x| matches!(x, Action::ExecZero(_)));

        // 4: no restart after a shutdown has started, and the flag is sticky.
        if old.stopped {
            assert_eq!(spawns, 0, "{old:?} {input:?}");
            assert!(self.s.stopped);
        }
        // 5: no more than five restarts in a minute without the limit cleared.
        if spawns > 0 && old.phase == Phase::Running {
            self.restarts.push(self.now);
        }
        if self.s.nexits == 0 {
            self.restarts.clear();
        }
        if self.restarts.len() > MAX_EXITS {
            let n = self.restarts.len();
            assert!(
                self.restarts[n - 1] - self.restarts[n - 1 - MAX_EXITS] >= LIMITS.window_ms,
                "{:?}",
                self.restarts
            );
        }
        // 6: from Stopping, at most two timers before zero.
        if matches!(self.s.phase, Phase::Stopping | Phase::Killed) {
            if matches!(input, Input::Timer) {
                self.timers += 1;
            }
            assert!(self.timers <= 2 || exec, "{old:?}");
        } else {
            self.timers = 0;
        }
        if exec {
            self.timers = 0;
        }
        // 7: every Put descriptor is stored or named in a Close, and keys are held once.
        if let Input::Record(FromColony::Put { key }, fd) = input {
            let stored = self.t.iter().any(|e| e.key == key && e.fd == fd);
            let closed = v.contains(&Action::Close(fd));
            assert!(stored != closed, "fd {fd} of key {key}: {v:?}");
            if stored {
                let had = old_table.iter().find(|e| e.key == key).map(|e| e.fd);
                assert_eq!(v.contains(&Action::Close(had.unwrap_or(-9))), had.is_some());
            }
        }
        let mut keys: Vec<u64> = self.t.iter().map(|e| e.key).filter(|&k| k != 0).collect();
        let n = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), n, "a key is held twice");
        // Invariants of the state.
        assert!(self.s.nexits <= MAX_EXITS);
        if self.s.phase == Phase::Running {
            assert!(!self.s.stopped);
        }
        if matches!(self.s.phase, Phase::Stopping | Phase::Killed) {
            assert!(self.s.stopped);
        }
        self.perform(v);
    }

    fn perform(&mut self, v: Vec<Action>) {
        for a in v {
            match a {
                Action::SpawnColony => {
                    if self.rng.below(5) == 0 {
                        self.feed(Input::ColonySpawnFailed);
                    } else {
                        let p = self.pid();
                        self.feed(Input::ColonySpawned(p));
                    }
                }
                Action::SpawnRescue => {
                    if self.rng.below(5) == 0 {
                        self.feed(Input::RescueSpawnFailed);
                    } else {
                        let p = self.pid();
                        self.feed(Input::RescueSpawned(p));
                    }
                }
                Action::ExecZero(_) => {
                    if self.rng.below(2) == 0 {
                        self.feed(Input::ExecFailed);
                    } else {
                        self.done = true;
                    }
                    return;
                }
                _ => {}
            }
            if self.done {
                return;
            }
        }
    }

    fn random_input(&mut self) -> Input {
        let status = [0, 10 << 8, 11 << 8, 2 << 8, 3 << 8, 4 << 8, 5 << 8, 9, 11]
            [self.rng.below(9) as usize];
        match self.rng.below(14) {
            0 => Input::Cad,
            1 => Input::Pwr,
            2 | 3 => Input::Child {
                pid: self.s.colony,
                status,
            },
            4 => Input::Child {
                pid: self.s.rescue,
                status,
            },
            5 => Input::Child { pid: 9_999, status },
            6 | 7 => {
                let key = self.rng.below(9) + 1;
                self.next_fd += 1;
                Input::Record(FromColony::Put { key }, self.next_fd)
            }
            8 => Input::Record(
                FromColony::Drop {
                    key: self.rng.below(9) + 1,
                },
                -1,
            ),
            9 => {
                let mode = [Mode::Halt, Mode::Poweroff, Mode::Reboot][self.rng.below(3) as usize];
                Input::Record(FromColony::Shutdown { mode }, -1)
            }
            10 => Input::ChannelBad,
            11 => Input::ChannelClosed,
            _ => Input::Timer,
        }
    }
}

#[test]
fn random_inputs_keep_the_obligations() {
    for seed in 1..=10_000 {
        let mut w = World::new(seed);
        for _ in 0..200 {
            if w.done {
                break;
            }
            // Time moves in steps from nothing to well past the window.
            w.now += [0, 1, 500, 5_000, 20_000, 70_000, 400_000][w.rng.below(7) as usize];
            let i = w.random_input();
            w.feed(i);
            // The outer layer also sends what the machine has queued.
            if w.rng.below(3) == 0 {
                while next_record(&w.s, &w.t).is_some() {
                    record_sent(&mut w.s, &w.t);
                }
            }
        }
    }
}
