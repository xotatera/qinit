// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Keeps floods from flooding the log: at most one line per signal number and minute, and one
//! line a minute for reaped orphans, in a fixed array.

/// A minute, in milliseconds.
const MINUTE_MS: u64 = 60_000;

/// When each signal number was last logged.
pub struct Quiet {
    last: [Option<u64>; 65],
    orphans_last: Option<u64>,
    /// Orphans reaped since the last line about them.
    orphans_held: u32,
}

impl Quiet {
    #[must_use]
    pub fn new() -> Quiet {
        Quiet {
            last: [None; 65],
            orphans_last: None,
            orphans_held: 0,
        }
    }

    /// Whether to log `signo` at `now_ms`: the first time, and then once a minute.
    pub fn log(&mut self, signo: u32, now_ms: u64) -> bool {
        let slot = &mut self.last[(signo as usize).min(64)];
        match *slot {
            Some(then) if now_ms >= then && now_ms - then < MINUTE_MS => false,
            _ => {
                *slot = Some(now_ms);
                true
            }
        }
    }

    /// Counts `count` orphans reaped at `now_ms`. Returns how many the next line should report
    /// (everything since the last line) when one is due: the first time, and then once a minute.
    /// The ones held back are reported by the next line, which an orphan has to bring.
    pub fn orphans(&mut self, count: u32, now_ms: u64) -> Option<u32> {
        self.orphans_held = self.orphans_held.saturating_add(count);
        match self.orphans_last {
            Some(then) if now_ms >= then && now_ms - then < MINUTE_MS => None,
            _ => {
                self.orphans_last = Some(now_ms);
                Some(std::mem::take(&mut self.orphans_held))
            }
        }
    }
}

impl Default for Quiet {
    fn default() -> Quiet {
        Quiet::new()
    }
}
