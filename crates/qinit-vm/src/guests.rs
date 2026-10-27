// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Building the guest programs (`qinit-vm-guests`, one binary per suite) as static musl
//! executables; their paths come from cargo's JSON messages, never from a guessed `target/`.
use crate::supervise::run_logged_stdout_kept;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const GUEST_TARGET: &str = "x86_64-unknown-linux-musl";
const BUILD_WITHIN: Duration = Duration::from_mins(30);
const PT_INTERP: u32 = 3;

/// Binary name → executable path of each `compiler-artifact` message with an executable.
#[must_use]
pub fn executables(json_lines: &str) -> BTreeMap<String, PathBuf> {
    json_lines
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["reason"] == "compiler-artifact")
        .filter_map(|v| {
            let exe = v["executable"].as_str()?;
            let name = v["target"]["name"].as_str()?;
            Some((name.to_string(), PathBuf::from(exe)))
        })
        .collect()
}

/// Whether the ELF64 little-endian file `elf` has a `PT_INTERP` program header (a dynamic
/// executable, which an initrd without a loader cannot run).
pub fn has_interp(elf: &[u8]) -> Result<bool, String> {
    if elf.len() < 0x40 || elf[..4] != *b"\x7fELF" || elf[4] != 2 || elf[5] != 1 {
        return Err("not an ELF64 little-endian file".to_string());
    }
    let u16_at = |at: usize| u16::from_le_bytes([elf[at], elf[at + 1]]);
    let phoff = usize::try_from(u64::from_le_bytes(
        elf[0x20..0x28].try_into().map_err(|_| "short header")?,
    ))
    .map_err(|e| e.to_string())?;
    let (size, count) = (usize::from(u16_at(0x36)), usize::from(u16_at(0x38)));
    for i in 0..count {
        let at = i.checked_mul(size).and_then(|o| o.checked_add(phoff));
        let Some(raw) = at.and_then(|at| elf.get(at..at.checked_add(4)?)) else {
            return Err("truncated ELF program header table".to_string());
        };
        if u32::from_le_bytes(raw.try_into().map_err(|_| "short entry")?) == PT_INTERP {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Ambient variables that would change what cargo builds or where: removed from the guest
/// build (as alloy's `cargo_argv` does), so the guests are the same on every host.
const AMBIENT_CARGO: &[&str] = &[
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "RUSTDOCFLAGS",
    "CARGO_ENCODED_RUSTDOCFLAGS",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_TARGET",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_TARGET_DIR",
    "CARGO_BUILD_TARGET_DIR",
];

/// The guests' flags, replacing the caller's: static, and the baseline x86-64 instruction set
/// (a `target-cpu=native` guest would die with SIGILL under TCG's CPU).
pub const GUEST_RUSTFLAGS: &str = "-C target-feature=+crt-static -C target-cpu=x86-64";

/// The guest build's cargo command in `root`, with the ambient settings scrubbed.
#[must_use]
pub fn cargo_command(root: &Path) -> Command {
    let mut cargo = Command::new("cargo");
    for v in AMBIENT_CARGO {
        cargo.env_remove(v);
    }
    cargo
        .env("RUSTFLAGS", GUEST_RUSTFLAGS)
        .current_dir(root)
        .args([
            "build",
            "--release",
            "--locked",
            "--target",
            GUEST_TARGET,
            "-p",
            "qinit-vm-guests",
            "--bins",
        ])
        .args(["--message-format", "json-render-diagnostics"]);
    cargo
}

/// Builds every guest binary in the workspace at `root`; name → static executable. The scratch
/// directory (cargo's JSON and log) is removed on success and named in the error otherwise.
pub fn build(root: &Path) -> Result<BTreeMap<String, PathBuf>, String> {
    let scratch = std::env::temp_dir().join(format!("qinit-vm-guests-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).map_err(|e| e.to_string())?;
    let bins = build_in(root, &scratch)?;
    let _ = std::fs::remove_dir_all(&scratch);
    Ok(bins)
}

fn build_in(root: &Path, scratch: &Path) -> Result<BTreeMap<String, PathBuf>, String> {
    let json = scratch.join("cargo.json");
    let log = scratch.join("build.log");
    // Truncated, not appended to: a log holds this build only.
    std::fs::File::create(&log).map_err(|e| e.to_string())?;
    let mut cargo = cargo_command(root);
    // stdout carries cargo's JSON; stderr goes to the build log.
    let out = std::fs::File::create(&json).map_err(|e| e.to_string())?;
    cargo.stdout(out);
    run_logged_stdout_kept(cargo, &log, BUILD_WITHIN)?;
    let text = std::fs::read_to_string(&json).map_err(|e| e.to_string())?;
    let bins = executables(&text);
    if bins.is_empty() {
        return Err(format!(
            "cargo built no guest binary; see {}",
            scratch.display()
        ));
    }
    for path in bins.values() {
        let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        if has_interp(&bytes)? {
            return Err(format!("{} is dynamically linked", path.display()));
        }
    }
    Ok(bins)
}
