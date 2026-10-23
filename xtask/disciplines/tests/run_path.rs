// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The gate-run path end to end, in-process (DEFERRED D1): `execute_with`
//! on a scratch workspace with a gate of its own, two `command` proofs
//! (run together, `run_batch`) and a spine/tooth pair of Kani entries with
//! `spine = "contracts"` (contract keys, prerequisites, the second wave).
//! `cargo kani` is a stand-in that logs its package. atc is hidden: a
//! stand-in `atc` that is not available.
//!
//! The test re-runs itself as a child with that environment (`set_var` is
//! `unsafe`, which the workspace forbids); llvm-cov counts the child too.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command as Proc;

use xtask::{Command, Gate, Inputs, Runner, Scope, execute_with};

const MANIFEST: &str = r#"[workspace]
members = ["spine", "tooth"]
resolver = "3"

[workspace.metadata.disciplines]
haircomb = "handled"
bridge = "spine"
proof_memory_budget = "4G"

[[workspace.metadata.disciplines.proof]]
name = "spine"
kind = "kani"
package = "spine"
memory = "2G"
unstable = ["function-contracts"]

[[workspace.metadata.disciplines.proof]]
name = "tooth"
kind = "kani"
package = "tooth"
memory = "2G"
unstable = ["function-contracts", "stubbing"]
spine = "contracts"

[[workspace.metadata.disciplines.proof]]
name = "cmd-a"
kind = "command"
package = "spine"
command = ["sh", "-c", "echo cmd-a >> ../proofs.log"]
memory = "1G"

[[workspace.metadata.disciplines.proof]]
name = "cmd-b"
kind = "command"
package = "spine"
command = ["sh", "-c", "echo cmd-b >> ../proofs.log"]
memory = "1G"
"#;

const SPINE_LIB: &str = "#![no_std]\n#[cfg_attr(kani, kani::ensures(|r: &u8| *r >= x))]\npub fn up(x: u8) -> u8 {\n    x.saturating_add(1)\n}\n";

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn exe(path: &Path, text: &str) {
    write(path, text);
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
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

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch() -> Scratch {
    let root = std::env::temp_dir().join(format!("xtask-run-path-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    write(&root.join("Cargo.toml"), MANIFEST);
    for (name, layer, extra) in [("spine", "core", ""), ("tooth", "core", "tooth = \"t\"\n")] {
        let deps = if name == "tooth" {
            "spine = { path = \"../spine\" }\n"
        } else {
            ""
        };
        write(
            &root.join(name).join("Cargo.toml"),
            &format!(
                "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\n{deps}\n[package.metadata.disciplines]\nlayer = \"{layer}\"\n{extra}"
            ),
        );
    }
    write(&root.join("spine/src/lib.rs"), SPINE_LIB);
    write(
        &root.join("tooth/src/lib.rs"),
        "#![no_std]\npub use spine::up;\n",
    );
    let bin = root.join("bin");
    exe(
        &bin.join("cargo-kani"),
        "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = -p ] && echo \"$2\" >> \"$KANI_LOG\"; shift; done\nexit 0\n",
    );
    exe(&bin.join("atc"), "#!/bin/sh\nexit 1\n");
    let lock = Proc::new("cargo")
        .args(["generate-lockfile", "--offline"])
        .current_dir(&root)
        .status()
        .unwrap();
    assert!(lock.success());
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
    Scratch(root)
}

fn touch(root: &Path) -> Result<(), String> {
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("own.log"))
        .and_then(|mut f| std::io::Write::write_all(&mut f, b"run\n"))
        .map_err(|e| e.to_string())
}

fn registry() -> Vec<Gate> {
    vec![Gate {
        name: "own",
        run: Box::new(touch),
        inputs: Inputs::Globs(&["spine/**"]),
        env: &[],
        tools: &["sh"],
        extra_paths: &[],
        ignored_inputs: &[],
        cacheable: true,
        cache_on_main: true,
        blocked: None,
        decl: "",
    }]
}

fn lines(path: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect();
    v.sort();
    v
}

fn gate(root: &Path) -> bool {
    let runner = Runner {
        registry,
        dirs: vec![PathBuf::from(env!("CARGO_MANIFEST_DIR"))],
    };
    let cmd = Command::Gate {
        only: None,
        no_cache: false,
        scope: Scope::All,
    };
    execute_with(&runner, &cmd, root)
}

const CHILD: &str = "XTASK_RUN_PATH_ROOT";

#[test]
fn gates_run_then_cache_and_a_spine_body_edit_reruns_only_the_spine() {
    let Some(root) = std::env::var_os(CHILD).map(PathBuf::from) else {
        let s = scratch();
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut dirs = vec![s.0.join("bin")];
        dirs.extend(std::env::split_paths(&path));
        let out = Proc::new(std::env::current_exe().unwrap())
            .args([
                "gates_run_then_cache_and_a_spine_body_edit_reruns_only_the_spine",
                "--exact",
                "--nocapture",
            ])
            .env(CHILD, &s.0)
            .env("PATH", std::env::join_paths(dirs).unwrap())
            .env("KANI_LOG", s.0.join("kani.log"))
            .env_remove("DISCIPLINES_GATE_CONTEXT")
            .env_remove("DISCIPLINES_GATE_NO_CACHE")
            .env_remove("ATC_HELD")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    };
    let root = &root;
    let kani_log = root.join("kani.log");

    assert!(gate(root), "first run passes");
    assert_eq!(lines(&root.join("own.log")), ["run"]);
    assert_eq!(lines(&kani_log), ["spine", "tooth"]);
    assert_eq!(lines(&root.join("proofs.log")), ["cmd-a", "cmd-b"]);

    assert!(gate(root), "second run passes from the cache");
    assert_eq!(lines(&root.join("own.log")), ["run"], "own gate cached");
    assert_eq!(lines(&kani_log), ["spine", "tooth"], "proofs cached");
    assert_eq!(lines(&root.join("proofs.log")), ["cmd-a", "cmd-b"]);

    // A body edit that keeps the contract: the spine proof and the gate
    // keyed on spine/** rerun; the tooth stays cached by contracts.
    write(
        &root.join("spine/src/lib.rs"),
        &SPINE_LIB.replace("x.saturating_add(1)", "x.saturating_add(2)"),
    );
    assert!(gate(root), "third run passes");
    assert_eq!(lines(&root.join("own.log")), ["run", "run"]);
    assert_eq!(lines(&kani_log), ["spine", "spine", "tooth"]);
    assert_eq!(
        lines(&root.join("proofs.log")),
        ["cmd-a", "cmd-a", "cmd-b", "cmd-b"],
        "the command proofs key on the whole spine package"
    );
}
