// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The proof scheduler: who starts next, with how many jobs, under one
//! budget of cores and memory.
use std::collections::BTreeMap;

use xtask::proofs::schedule::{Entry, cost, next, order};

const G: u64 = 1 << 30;

fn kani(gb: u64) -> Entry {
    Entry {
        memory: gb * G,
        kani: true,
    }
}

fn command(gb: u64) -> Entry {
    Entry {
        memory: gb * G,
        kani: false,
    }
}

#[test]
fn order_is_no_history_first_then_longest() {
    let d: BTreeMap<String, u64> = [("b".to_string(), 10), ("c".to_string(), 300)].into();
    assert_eq!(order(&["a", "b", "c", "d"], &d), [0, 3, 2, 1]);
    assert_eq!(order(&["x", "y"], &BTreeMap::new()), [0, 1]);
}

#[test]
fn kani_takes_what_fits_and_commands_take_one_core() {
    assert_eq!(next(&[kani(2)], 8, 10 * G, 0), Some((0, 5)));
    assert_eq!(next(&[kani(2)], 3, 10 * G, 0), Some((0, 3)));
    assert_eq!(next(&[command(4)], 8, 10 * G, 0), Some((0, 1)));
    assert_eq!(cost(&kani(2), 3), (3, 6 * G));
    assert_eq!(cost(&command(4), 1), (1, 4 * G));
}

#[test]
fn a_waiting_entry_that_does_not_fit_lets_a_later_one_start() {
    assert_eq!(next(&[kani(8), command(1)], 4, 2 * G, 1), Some((1, 1)));
    assert_eq!(next(&[kani(8)], 4, 2 * G, 1), None);
}

#[test]
fn an_entry_larger_than_the_budget_runs_alone() {
    assert_eq!(next(&[kani(64)], 8, 16 * G, 0), Some((0, 1)));
    assert_eq!(next(&[kani(64)], 8, 16 * G, 1), None);
}

#[test]
fn nothing_starts_without_a_free_core() {
    assert_eq!(next(&[command(1)], 0, 16 * G, 2), None);
}

/// Runs the scheduler over entries with known durations and checks the
/// invariants at every start: caps within the budget, jobs within cores.
#[test]
fn simulated_runs_never_exceed_the_budget_or_the_cores() {
    let entries = [kani(4), kani(2), command(1), kani(3), command(2)];
    let secs = [50u64, 20, 5, 30, 10];
    let (cores, budget) = (6usize, 10 * G);
    let mut waiting: Vec<usize> = (0..entries.len()).collect();
    let mut running: Vec<(u64, usize, usize, u64)> = Vec::new(); // (end, idx, cores, bytes)
    let mut now = 0;
    while !waiting.is_empty() || !running.is_empty() {
        loop {
            let used_c: usize = running.iter().map(|r| r.2).sum();
            let used_b: u64 = running.iter().map(|r| r.3).sum();
            let w: Vec<Entry> = waiting.iter().map(|i| entries[*i]).collect();
            let Some((at, jobs)) = next(&w, cores - used_c, budget - used_b, running.len()) else {
                break;
            };
            let idx = waiting.remove(at);
            let (c, b) = cost(&entries[idx], jobs);
            assert!(
                used_c + c <= cores && used_b + b <= budget,
                "start {idx} with {jobs}"
            );
            running.push((now + secs[idx], idx, c, b));
        }
        running.sort_unstable();
        let (end, ..) = running.remove(0);
        now = end;
    }
    assert!(now < secs.iter().sum::<u64>(), "ran in parallel: {now}");
}

#[test]
fn a_kani_entry_leaves_a_core_for_each_other_waiting_entry() {
    assert_eq!(next(&[kani(1), command(1)], 8, 16 * G, 0), Some((0, 7)));
    assert_eq!(
        next(&[kani(1), command(1), kani(1)], 8, 16 * G, 0),
        Some((0, 6))
    );
    assert_eq!(
        next(&[kani(1), command(1), command(1)], 2, 16 * G, 0),
        Some((0, 1))
    );
}

#[test]
fn a_kani_entry_leaves_memory_for_each_other_waiting_entry() {
    assert_eq!(next(&[kani(1), command(4)], 32, 16 * G, 0), Some((0, 12)));
    assert_eq!(
        next(&[kani(1), kani(2), command(1)], 32, 16 * G, 0),
        Some((0, 13))
    );
    // Not even one job's worth left over: it still starts with one job.
    assert_eq!(next(&[kani(4), command(16)], 32, 16 * G, 0), Some((0, 1)));
}
