// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qinit-colonyd`: the colony program. See `docs/colony.md`.
#![forbid(unsafe_code)]

pub mod args;
pub mod deadlines;
pub mod exit;

/// Runs colony to the end and returns its exit status.
#[must_use]
pub fn run(args: &args::Args) -> u8 {
    let _ = args;
    exit::STARTUP // until Task 16
}
