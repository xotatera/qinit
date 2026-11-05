// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! One queue for every colony timer. The loop owns a single timer fd and arms it for
//! [`Deadlines::next`]; when it fires, [`Deadlines::due`] says which keys expired.
use qinit_colony_core::TimerKind;

/// What a deadline belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// A node's timer of one kind.
    Node(u32, TimerKind),
    /// The deadline of a parked request's wait.
    Wait(u64),
}

/// Pending deadlines, at most one per key.
#[derive(Debug, Default)]
pub struct Deadlines {
    /// `(key, at_ms, arm sequence)`; small, so scanned.
    entries: Vec<(Key, u64, u64)>,
    seq: u64,
}

impl Deadlines {
    /// Arms `key` to expire at `at_ms`, replacing its earlier entry.
    pub fn arm(&mut self, key: Key, at_ms: u64) {
        self.cancel(key);
        self.seq += 1;
        self.entries.push((key, at_ms, self.seq));
    }

    /// Forgets `key`'s deadline, if any.
    pub fn cancel(&mut self, key: Key) {
        self.entries.retain(|(k, ..)| *k != key);
    }

    /// The earliest expiry, if any deadline is pending.
    #[must_use]
    pub fn next(&self) -> Option<u64> {
        self.entries.iter().map(|&(_, at, _)| at).min()
    }

    /// Removes and returns every key whose time is `now_ms` or earlier: earliest first, equal
    /// times in the order they were armed.
    pub fn due(&mut self, now_ms: u64) -> Vec<Key> {
        let mut due: Vec<(Key, u64, u64)> = Vec::new();
        self.entries.retain(|&e| {
            if e.1 <= now_ms {
                due.push(e);
                false
            } else {
                true
            }
        });
        due.sort_by_key(|&(_, at, seq)| (at, seq));
        due.into_iter().map(|(k, ..)| k).collect()
    }

    /// The node table was renumbered: new node `i` was node `map[i]` before (`u32::MAX` for a
    /// new node). Node keys move with their node; those of a node absent from `map` go.
    pub fn remap(&mut self, map: &[u32]) {
        self.entries.retain_mut(|(key, ..)| {
            let Key::Node(old, kind) = *key else {
                return true;
            };
            let Some(new) = map.iter().position(|&m| m == old) else {
                return false;
            };
            *key = Key::Node(u32::try_from(new).unwrap_or(u32::MAX), kind);
            true
        });
    }
}
