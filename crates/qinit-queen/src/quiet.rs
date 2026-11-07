// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Keeps a flood of one signal from flooding the log: at most one line per signal number and
//! minute, in a fixed array.

/// A minute, in milliseconds.
const MINUTE_MS: u64 = 60_000;

/// When each signal number was last logged.
pub struct Quiet {
    last: [Option<u64>; 65],
}

impl Quiet {
    #[must_use]
    pub fn new() -> Quiet {
        Quiet { last: [None; 65] }
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
}

impl Default for Quiet {
    fn default() -> Quiet {
        Quiet::new()
    }
}
