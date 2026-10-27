// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! `qinit-vm run [<suite>…]`: builds the kernel and the guest programs, boots one guest per
//! suite and judges its verdicts. Exit 0 only when every suite passes.
use qinit_vm::initrd::{Entry, newc};
use qinit_vm::{guests, kernel, qemu, verdict};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Every suite, in run order; each is a binary of `qinit-vm-guests`.
const SUITES: &[&str] = &["probe"];

fn suite_run(suite: &str, image: &Path, bin: &Path, out: &Path) -> Result<usize, String> {
    let data = std::fs::read(bin).map_err(|e| format!("read {}: {e}", bin.display()))?;
    let mut entries: Vec<Entry> = ["dev", "proc", "sys", "tmp"]
        .iter()
        .map(|d| Entry {
            path: (*d).to_string(),
            mode: 0o040_755,
            data: Vec::new(),
        })
        .collect();
    entries.push(Entry {
        path: "init".to_string(),
        mode: 0o100_755,
        data,
    });
    let initrd = out.join(format!("{suite}.cpio"));
    std::fs::write(&initrd, newc(&entries)).map_err(|e| e.to_string())?;
    let serial = qemu::boot(image, &initrd, &out.join(format!("{suite}.log")))?;
    verdict::judge(suite, &verdict::parse(suite, &serial))
}

fn run(selected: &[String]) -> Result<(), String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let suites: Vec<&str> = if selected.is_empty() {
        SUITES.to_vec()
    } else {
        selected.iter().map(String::as_str).collect()
    };
    for s in &suites {
        if !SUITES.contains(s) {
            return Err(format!("unknown suite {s}; suites: {}", SUITES.join(", ")));
        }
    }
    let image = kernel::ensure()?;
    let bins = guests::build(&root)?;
    let out: PathBuf =
        kernel::cache_root(std::env::var_os("XDG_CACHE_HOME"), std::env::var_os("HOME"))?
            .join("vm-logs");
    std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let mut failed = Vec::new();
    for s in suites {
        let bin = bins
            .get(s)
            .ok_or_else(|| format!("no guest binary for suite {s}"))?;
        match suite_run(s, &image, bin, &out) {
            Ok(n) => println!("PASS vm/{s} ({n} cases)"),
            Err(e) => {
                println!("FAIL vm/{s}: {e}");
                failed.push(s);
            }
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("failed suites: {}", failed.join(", ")))
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.split_first() {
        Some((cmd, rest)) if cmd == "run" => run(rest),
        _ => Err("usage: qinit-vm run [<suite>…]".to_string()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("qinit-vm: {e}");
            ExitCode::FAILURE
        }
    }
}
