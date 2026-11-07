// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The `colony` binary: parses its command line and runs.
use qinit_colonyd::{args, exit, run};
use std::process::ExitCode;

fn main() -> ExitCode {
    let argv: Vec<_> = std::env::args_os().skip(1).collect();
    match args::parse(&argv) {
        Ok(a) => ExitCode::from(run(&a)),
        Err(why) => {
            eprintln!("colony: {why}");
            eprintln!(
                "usage: colony [--db P] [--comb P] [--socket P] [--overseer P] [--syslog P] \
                 [--console P] [--run P] [--queen-fd N]"
            );
            ExitCode::from(exit::USAGE)
        }
    }
}
