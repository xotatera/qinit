// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qctl`: compile frames, ask the colony, watch it (spec 2026-11-05 §4).
//!
//! Exit codes: 0 done, 1 refused or failed, 2 usage.
use std::io::Write;

pub mod args;
pub mod compile;
pub mod fill;
pub mod owner;
pub mod report;
pub mod show;
pub mod toml_text;

use args::{Command, Parsed};

/// Run `qctl` with `args` (without the program name); returns the exit code.
pub fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    run_with(args, out, err, &compile::Defaults::system())
}

/// [`run`] with the compile defaults given, so a test can point them at a temporary tree.
pub fn run_with(
    args: &[String],
    out: &mut dyn Write,
    err: &mut dyn Write,
    defaults: &compile::Defaults,
) -> i32 {
    let parsed = match args::parse(args) {
        Ok(args::Outcome::Help) => {
            let _ = out.write_all(args::HELP.as_bytes());
            return 0;
        }
        Ok(args::Outcome::Run(p)) => p,
        Err(msg) => {
            let _ = writeln!(err, "qctl: {msg}\nTry 'qctl --help'.");
            return 2;
        }
    };
    let Parsed { command, .. } = parsed;
    match command {
        Command::Compile(opts) => compile::run(&opts, defaults, out, err),
        Command::Show(opts) => show::run(&opts, defaults, out, err),
        Command::Fill(opts) => fill::run(&opts, defaults, out, err),
        other => {
            let _ = writeln!(
                err,
                "qctl: '{}' is not implemented yet\nTry 'qctl --help'.",
                other.name()
            );
            2
        }
    }
}
