// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qinit-colonyd`: the colony program. See `docs/colony.md`.
#![forbid(unsafe_code)]

pub mod args;
pub mod daemon;
pub mod deadlines;
pub mod effects;
pub mod exit;
pub mod notes;
pub mod pipes;
pub mod route;
pub mod start;
pub mod state;
pub mod syslog;
pub mod watch;

/// Runs colony to the end and returns its exit status.
#[must_use]
pub fn run(args: &args::Args) -> u8 {
    start::run(args)
}
