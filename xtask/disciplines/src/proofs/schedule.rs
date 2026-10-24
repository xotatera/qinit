// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Which proof entry starts next, and with how many Kani jobs, when entries
//! share one budget of cores and memory (`runner.md`, Proof tier). Pure.
use std::collections::BTreeMap;

/// What the scheduler needs to know about one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub memory: u64,
    pub kani: bool,
}

/// Start order: entries with no recorded duration first, in declaration
/// order, then the rest by recorded duration, longest first.
#[must_use]
pub fn order(names: &[&str], durations: &BTreeMap<String, u64>) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..names.len()).collect();
    idx.sort_by_key(|i| match durations.get(names[*i]) {
        None => (0, 0),
        Some(s) => (1, u64::MAX - s),
    });
    idx
}

/// Cores and bytes an entry holds: Kani `jobs` cores and `jobs × memory`;
/// a command one core and `memory`.
#[must_use]
pub fn cost(e: &Entry, jobs: usize) -> (usize, u64) {
    if e.kani {
        let j = u64::try_from(jobs).unwrap_or(u64::MAX);
        (jobs, e.memory.saturating_mul(j))
    } else {
        (1, e.memory)
    }
}

/// The first waiting entry that fits what is free, with its jobs. A Kani
/// entry leaves one core and one job's memory for each other waiting entry,
/// so one prover cannot starve the rest with its `-j`. With
/// nothing running, the first entry starts with one job even if it does not
/// fit, as a lone run does today.
#[must_use]
pub fn next(
    waiting: &[Entry],
    free_cores: usize,
    free_budget: u64,
    running: usize,
) -> Option<(usize, usize)> {
    if free_cores == 0 && running > 0 {
        return None;
    }
    for (i, e) in waiting.iter().enumerate() {
        let by_memory = usize::try_from(free_budget / e.memory.max(1)).unwrap_or(usize::MAX);
        let jobs = if e.kani {
            // Leave one core and one job's memory for each other waiting
            // entry, but never fewer than one job when one fits.
            let others = waiting.len() - 1;
            let others_memory: u64 = waiting
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, o)| o.memory)
                .sum();
            let spare_memory =
                usize::try_from(free_budget.saturating_sub(others_memory) / e.memory.max(1))
                    .unwrap_or(usize::MAX);
            free_cores
                .saturating_sub(others)
                .min(spare_memory)
                .max(1)
                .min(free_cores)
                .min(by_memory)
        } else {
            usize::from(by_memory >= 1).min(free_cores)
        };
        if jobs >= 1 {
            return Some((i, jobs));
        }
    }
    (running == 0 && !waiting.is_empty()).then_some((0, 1))
}
