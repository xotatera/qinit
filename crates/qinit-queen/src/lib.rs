// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! `qinit-queen`: the PID 1 of qinit. A thin shell around the proved machine of
//! `qinit-queen-core`: it turns epoll wake-ups into inputs and the machine's actions into calls.
//! It reaps every child, restarts colony under a limit, holds colony's descriptors, runs the
//! rescue program when colony cannot be kept up, and hands the machine to zero at the end.
//! `unsafe` stays in `qinit-sys`.
pub mod kmsg;
pub mod quiet;
pub mod real;
pub mod run;
pub mod spawn;

use qinit_queen_core::machine::{LIMITS, Limits};

/// The limits queen runs under: the spec's, or, in a guest build with the `testing` feature,
/// the three that `/run/queen-test` names (`<shutdown_ms> <kill_wait_ms> <rescue_min_ms>`).
#[must_use]
pub fn limits() -> Limits {
    #[cfg(feature = "testing")]
    if let Ok(text) = std::fs::read_to_string("/run/queen-test") {
        let n: Vec<u64> = text
            .split_whitespace()
            .filter_map(|w| w.parse().ok())
            .collect();
        if let [shutdown_ms, kill_wait_ms, rescue_min_ms] = n[..] {
            return Limits {
                shutdown_ms,
                kill_wait_ms,
                rescue_min_ms,
                ..LIMITS
            };
        }
    }
    LIMITS
}
