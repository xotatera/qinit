// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let root = qinit_xtask::repo_root();
    match qinit_xtask::plan(&arguments, &|stage| qinit_xtask::gate_names(stage, &root)) {
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
        Ok(plan) => {
            if qinit_xtask::execute(plan, &root) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
