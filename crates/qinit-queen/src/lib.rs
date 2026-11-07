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

use qinit_queen_core::machine::{LIMITS, Limits, MIN_HEARTBEAT_MS};

/// The longest a configured bound may be: a day. A timer is armed with it, and a value no
/// timer can hold would leave the bound unarmed.
pub const MAX_BOUND_MS: u64 = 86_400_000;

/// `base` with the settings of the kernel command line `cmdline`: `qinit.shutdown_ms=` (1 to a
/// day) and `qinit.heartbeat_ms=` (0 for no watch, else [`MIN_HEARTBEAT_MS`] to a day). The last
/// of a setting wins. A value that is not allowed keeps what was there; the lines say which
/// words were refused and why.
#[must_use]
pub fn configured(base: Limits, cmdline: &str) -> (Limits, Vec<String>) {
    let mut lim = base;
    let mut refused = Vec::new();
    for word in cmdline.split_whitespace() {
        let Some((name, value)) = word.split_once('=') else {
            continue;
        };
        // The heartbeat may also be 0, which turns the watch off.
        let (what, heartbeat) = match name {
            "qinit.shutdown_ms" => ("shutdown", false),
            "qinit.heartbeat_ms" => ("heartbeat", true),
            _ => continue,
        };
        let floor = if heartbeat { MIN_HEARTBEAT_MS } else { 1 };
        match value.parse::<u64>() {
            Ok(n) if n == 0 && heartbeat || (floor..=MAX_BOUND_MS).contains(&n) => {
                if heartbeat {
                    lim.heartbeat_ms = n;
                } else {
                    lim.shutdown_ms = n;
                }
            }
            Ok(_) => {
                let off = if heartbeat { "0, or " } else { "" };
                refused.push(format!(
                    "{word}: the {what} bound must be {off}{floor} to {MAX_BOUND_MS}"
                ));
            }
            Err(_) => refused.push(format!(
                "{word}: the {what} bound is not a number of milliseconds"
            )),
        }
    }
    (lim, refused)
}

/// The limits queen runs under: the spec's with the kernel command line's settings (what was
/// refused comes back as lines for the log), or, in a guest build with the `testing` feature,
/// the three that `/run/queen-test` names (`<shutdown_ms> <kill_wait_ms> <rescue_min_ms>`) over
/// those.
#[must_use]
pub fn limits() -> (Limits, Vec<String>) {
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    #[allow(unused_mut)] // only the testing build changes them
    let (mut lim, refused) = configured(LIMITS, &cmdline);
    #[cfg(feature = "testing")]
    if let Ok(text) = std::fs::read_to_string("/run/queen-test") {
        let n: Vec<u64> = text
            .split_whitespace()
            .filter_map(|w| w.parse().ok())
            .collect();
        if let [shutdown_ms, kill_wait_ms, rescue_min_ms] = n[..] {
            lim = Limits {
                shutdown_ms,
                kill_wait_ms,
                rescue_min_ms,
                ..lim
            };
        }
    }
    (lim, refused)
}
