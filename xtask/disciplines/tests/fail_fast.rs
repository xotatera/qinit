// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Fail fast in-process: once a gate fails, later gates of the run do not
//! start.
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};

use xtask::{Command, Gate, Inputs, Runner, Scope, execute_with};

static LATER_RAN: AtomicBool = AtomicBool::new(false);

#[allow(clippy::unnecessary_wraps)] // signature fixed by `Gate::run`
fn passes(_: &Path) -> Result<(), String> {
    Ok(())
}

fn fails(_: &Path) -> Result<(), String> {
    Err("fails on purpose".to_string())
}

#[allow(clippy::unnecessary_wraps)] // signature fixed by `Gate::run`
fn later(_: &Path) -> Result<(), String> {
    LATER_RAN.store(true, SeqCst);
    Ok(())
}

fn gate(name: &'static str, run: fn(&Path) -> Result<(), String>) -> Gate {
    Gate {
        name,
        run: Box::new(run),
        inputs: Inputs::Tree,
        env: &[],
        tools: &[],
        extra_paths: &[],
        cache_paths: &[],
        ignored_inputs: &[],
        cacheable: false,
        cache_on_main: true,
        blocked: None,
        decl: "",
    }
}

fn registry() -> Vec<Gate> {
    vec![
        gate("first", passes),
        gate("second", fails),
        gate("third", later),
    ]
}

#[test]
fn a_failing_gate_stops_the_later_gates() {
    let root = std::env::temp_dir().join(format!("xtask-fail-fast-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = []\nresolver = \"3\"\n",
    )
    .unwrap();
    let runner = Runner {
        registry,
        dirs: vec![PathBuf::from(env!("CARGO_MANIFEST_DIR"))],
    };
    let command = Command::Gate {
        only: None,
        no_cache: true,
        scope: Scope::All,
    };
    let passed = execute_with(&runner, &command, &root);
    std::fs::remove_dir_all(&root).unwrap();
    assert!(!passed);
    assert!(!LATER_RAN.load(SeqCst), "a gate ran after a failure");
}
