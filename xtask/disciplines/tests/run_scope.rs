// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! `will_run` and `shared` through `execute_with`, on a scratch repository
//! with two gates of its own: `a`, never cached, asks whether `b` will run
//! and computes a shared result; `b`, cached on its input, asks for the same
//! result. The test re-runs itself as a child without the gate-run variables
//! of an enclosing gate (`set_var` is `unsafe`, which the workspace forbids).
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as Proc;
use std::sync::Mutex;

use xtask::{Command, Gate, Inputs, Runner, Scope, execute_with};

const CHILD: &str = "XTASK_RUN_SCOPE_ROOT";

static LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn log(line: String) {
    LOG.lock().unwrap().push(line);
}

fn taken() -> Vec<String> {
    std::mem::take(&mut *LOG.lock().unwrap())
}

/// The shared result: logs that it ran.
const COMPUTE: fn() -> Result<(), String> = || {
    log("computed".to_string());
    Ok(())
};

const FAIL: fn() -> Result<(), String> = || {
    log("failed".to_string());
    Err("no".to_string())
};

fn gate(name: &'static str, cacheable: bool, run: xtask::Body) -> Gate {
    Gate {
        name,
        run,
        inputs: Inputs::Globs(&["*.txt"]),
        env: &[],
        tools: &[],
        extra_paths: &[],
        ignored_inputs: &[],
        cacheable,
        cache_on_main: true,
        blocked: None,
        decl: "",
    }
}

fn registry() -> Vec<Gate> {
    vec![
        gate(
            "a",
            false,
            Box::new(|_| {
                log(format!("a: b will run: {}", xtask::will_run("b")));
                xtask::shared("k", COMPUTE)?;
                // An error reaches every caller, computed once.
                for _ in 0..2 {
                    log(format!("{:?}", xtask::shared("e", FAIL)));
                }
                xtask::shared("k", COMPUTE)
            }),
        ),
        gate("b", true, Box::new(|_| xtask::shared("k", COMPUTE))),
    ]
}

fn run(root: &Path, only: Option<&str>) -> bool {
    let runner = Runner {
        registry,
        dirs: vec![PathBuf::from(env!("CARGO_MANIFEST_DIR"))],
    };
    let cmd = Command::Gate {
        only: only.map(str::to_string),
        no_cache: false,
        scope: Scope::All,
    };
    execute_with(&runner, &cmd, root)
}

fn git(root: &Path, args: &[&str]) {
    let ok = Proc::new("git")
        .args(args)
        .current_dir(root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap()
        .status
        .success();
    assert!(ok, "git {args:?}");
}

#[test]
fn a_gate_sees_what_the_run_will_run_and_shares_one_result() {
    let Some(root) = std::env::var_os(CHILD).map(PathBuf::from) else {
        let root = std::env::temp_dir().join(format!("xtask-run-scope-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("Cargo.toml"), "[workspace]\nresolver = \"3\"\n").unwrap();
        fs::write(root.join("b.txt"), "b\n").unwrap();
        git(&root, &["init", "-q", "-b", "feat/x"]);
        git(&root, &["add", "-A"]);
        git(
            &root,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "commit",
                "-qm",
                "init",
            ],
        );
        let out = Proc::new(std::env::current_exe().unwrap())
            .args([
                "a_gate_sees_what_the_run_will_run_and_shares_one_result",
                "--exact",
                "--nocapture",
            ])
            .env(CHILD, &root)
            .env_remove("DISCIPLINES_GATE_CONTEXT")
            .env_remove("DISCIPLINES_GATE_NO_CACHE")
            .output()
            .unwrap();
        let _ = fs::remove_dir_all(&root);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        // The child ran this test, not nothing.
        assert!(stdout.contains("test result: ok. 1 passed"), "{stdout}");
        return;
    };
    assert!(!xtask::will_run("b"), "no gate run yet");
    // `b` misses: `a` sees it coming, and `b` reuses `a`'s result.
    assert!(run(&root, None));
    assert_eq!(
        taken(),
        [
            "a: b will run: true",
            "computed",
            "failed",
            "Err(\"no\")",
            "Err(\"no\")"
        ]
    );
    // `b` is cached: it will not run, and the result is computed afresh.
    assert!(run(&root, None));
    assert_eq!(
        taken(),
        [
            "a: b will run: false",
            "computed",
            "failed",
            "Err(\"no\")",
            "Err(\"no\")"
        ]
    );
    // Not selected.
    fs::write(root.join("b.txt"), "b2\n").unwrap();
    assert!(run(&root, Some("a")));
    assert_eq!(
        taken(),
        [
            "a: b will run: false",
            "computed",
            "failed",
            "Err(\"no\")",
            "Err(\"no\")"
        ]
    );
}
