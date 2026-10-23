// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match xtask::parse_args(&args) {
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(2)
        }
        Ok(cmd) => {
            if xtask::execute(&cmd, &xtask::workspace_root()) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
