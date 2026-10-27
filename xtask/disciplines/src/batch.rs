// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Proof gates that need to run, run together: the scheduler picks what
//! starts, each entry runs on its own thread with its output captured, and
//! every result is concluded (recorded) on the caller's thread, where the
//! gates live.
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::proofs::{self, Proof};

/// Runs one entry with its Kani jobs: its verdict and captured log
/// (`gates::proof_run` with capture outside tests).
pub type Runner<'a> = dyn Fn(&Path, &Proof, usize) -> (Result<(), String>, String) + Sync + 'a;

/// A proof that has passed `runner::prepare` and waits to run.
pub struct Waiting {
    pub index: usize,
    pub proof: Proof,
}

/// A finished entry: its index in the caller's list, verdict, log, when it
/// started, its wall-clock time, and the atc steps its thread recorded
/// (`timing::take`). `ran` is false for an entry that never started because
/// an earlier one failed: it is not run, not failed, and has no time.
pub struct Done {
    pub index: usize,
    pub ran: bool,
    pub result: Result<(), String>,
    pub log: String,
    pub start: Instant,
    pub elapsed: Duration,
    pub steps: Vec<(Instant, crate::timing::Step)>,
}

/// Runs `waiting` under `cores` and `budget`, in `order`, calling `done`
/// for each as it finishes (on this thread). Fail fast: once an entry fails,
/// no queued entry starts; the running ones finish and each queued one is
/// reported as not run.
pub fn run(
    root: &Path,
    waiting: Vec<Waiting>,
    order: &[usize],
    cores: usize,
    budget: u64,
    runner: &Runner<'_>,
    done: &mut dyn FnMut(Done),
) {
    let mut slots: Vec<Option<Waiting>> = waiting.into_iter().map(Some).collect();
    let mut queue: Vec<Waiting> = order
        .iter()
        .filter_map(|i| slots.get_mut(*i).and_then(Option::take))
        .collect();
    let (tx, rx) = mpsc::channel::<(Done, usize, u64)>();
    let (mut free_cores, mut free_budget, mut running) = (cores, budget, 0usize);
    let mut failed = false;
    std::thread::scope(|scope| {
        loop {
            while !failed {
                let entries: Vec<proofs::schedule::Entry> = queue
                    .iter()
                    .map(|w| proofs::schedule::Entry {
                        memory: w.proof.memory,
                        kani: w.proof.kind == proofs::Kind::Kani,
                    })
                    .collect();
                let Some((at, jobs)) =
                    proofs::schedule::next(&entries, free_cores, free_budget, running)
                else {
                    break;
                };
                let w = queue.remove(at);
                let index = w.index;
                let (c, b) = proofs::schedule::cost(&entries[at], jobs);
                // Charge what is free at most (a lone oversized entry takes
                // everything), and give back exactly what was charged.
                let (c, b) = (c.min(free_cores), b.min(free_budget));
                free_cores -= c;
                free_budget -= b;
                running += 1;
                let tx = tx.clone();
                let spawned = std::thread::Builder::new()
                    .name(format!("proof:{}", w.proof.name))
                    .spawn_scoped(scope, move || {
                        let start = Instant::now();
                        // A panic must still report, or `recv` below would
                        // wait forever.
                        let (result, log) =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                runner(root, &w.proof, jobs)
                            }))
                            .unwrap_or_else(|_| {
                                (Err("the proof panicked".to_string()), String::new())
                            });
                        let elapsed = start.elapsed();
                        let _ = tx.send((
                            Done {
                                index,
                                ran: true,
                                result,
                                log,
                                start,
                                elapsed,
                                steps: crate::timing::take(),
                            },
                            c,
                            b,
                        ));
                    });
                if let Err(e) = spawned {
                    running -= 1;
                    free_cores += c;
                    free_budget += b;
                    failed = true;
                    done(Done {
                        index,
                        ran: true,
                        result: Err(format!("cannot start a thread: {e}")),
                        log: String::new(),
                        start: Instant::now(),
                        elapsed: Duration::ZERO,
                        steps: Vec::new(),
                    });
                }
            }
            if running == 0 {
                break;
            }
            let Ok((d, c, b)) = rx.recv() else {
                break;
            };
            running -= 1;
            free_cores += c;
            free_budget += b;
            failed |= d.result.is_err();
            done(d);
        }
    });
    for w in queue {
        done(Done {
            index: w.index,
            ran: false,
            result: Err("not run: an earlier proof failed".to_string()),
            log: String::new(),
            start: Instant::now(),
            elapsed: Duration::ZERO,
            steps: Vec::new(),
        });
    }
}
