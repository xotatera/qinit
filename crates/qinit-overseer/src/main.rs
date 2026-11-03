// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The `overseer` binary: reads the launch request from fd 3, reports on fd 4 and `execve`s
//! the service. Takes no arguments.

fn main() -> ! {
    qinit_overseer::run::launch()
}
