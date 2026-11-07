// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qctl`: compile frames, ask the colony, watch it (spec 2026-11-05 §4).
//!
//! Exit codes: 0 done, 1 refused or failed, 2 usage.
use std::io::Write;

pub mod args;
pub mod compile;
pub mod control;
pub mod fill;
pub mod json;
pub mod launch;
pub mod owner;
pub mod report;
pub mod request;
pub mod show;
pub mod text;
pub mod toml_text;
pub mod watch;

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
    let Parsed {
        command,
        socket,
        json,
    } = parsed;
    let output = json::Output::of(json);
    match command {
        Command::Compile(opts) => compile::run(&opts, defaults, out, err),
        Command::Show(opts) => show::run(&opts, defaults, out, err),
        Command::Fill(opts) => fill::run(&opts, defaults, out, err),
        Command::Status { .. }
        | Command::List { .. }
        | Command::Change { .. }
        | Command::Refresh { .. }
        | Command::Shutdown { .. } => control::run(&command, &socket, output, out, err),
        Command::Launch(opts) => launch::launch(&opts, &socket, output, out, err),
        Command::Run(opts) => launch::run(&opts, &socket, output, out, err),
        Command::Watch { all, target } => watch::run(all, &target, &socket, output, out, err),
    }
}
