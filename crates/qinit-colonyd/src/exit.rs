// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The exit status colony ends with. Queen reads it to decide what comes next
//! (`docs/colony.md`).

/// The graph is down: halt, or a stop signal.
pub const HALT: u8 = 0;
/// The graph is down and the machine should power off.
pub const POWEROFF: u8 = 10;
/// The graph is down and the machine should reboot.
pub const REBOOT: u8 = 11;
/// The command line was wrong.
pub const USAGE: u8 = 2;
/// The database was refused.
pub const DATABASE: u8 = 3;
/// Start-up could not finish (socket, comb, state directory).
pub const STARTUP: u8 = 4;
/// The loop failed while running.
pub const LOOP: u8 = 5;
