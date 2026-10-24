// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Spawns the real binary: covers `main` and the exit codes hooks rely on.
use std::process::{Command, Output};

fn xtask(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .expect("spawn xtask")
}

#[test]
fn list_prints_the_registry_in_order() {
    let out = xtask(&["gate", "--list"]);
    assert!(out.status.success());
    // The binary's root is the project it was built in, which may declare
    // proofs: `--list` prints every gate there, proof gates included.
    let names: Vec<String> = xtask::all_gates(&xtask::workspace_root(), None)
        .unwrap()
        .iter()
        .map(|g| g.name.to_string())
        .collect();
    let listed: Vec<String> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(listed, names);
}

#[test]
fn unknown_only_name_fails_before_any_gate_runs() {
    let out = xtask(&["gate", "--only", "nope"]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("unknown gate `nope`"), "{err}");
    assert!(!err.contains("== "), "a gate ran: {err}");
}

#[test]
fn bad_usage_exits_2() {
    assert_eq!(xtask(&["frobnicate"]).status.code(), Some(2));
    assert_eq!(xtask(&[]).status.code(), Some(2));
}

#[test]
fn parse_only_accepts_registered_names() {
    let args = |a: &[&str]| a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
    assert_eq!(
        xtask::parse_args(&args(&["gate", "--only", "fmt"])),
        Ok(xtask::Command::Gate {
            only: Some("fmt".to_string()),
            no_cache: false,
            scope: xtask::Scope::All
        })
    );
    assert!(xtask::parse_args(&args(&["gate", "--only", "fmtt"])).is_err());
}

#[test]
fn gate_flags_and_cache_clear_parse() {
    let args = |a: &[&str]| a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
    assert_eq!(
        xtask::parse_args(&args(&["gate", "--no-cache"])),
        Ok(xtask::Command::Gate {
            only: None,
            no_cache: true,
            scope: xtask::Scope::All
        })
    );
    assert_eq!(
        xtask::parse_args(&args(&["gate", "--no-cache", "--only", "lint"])),
        Ok(xtask::Command::Gate {
            only: Some("lint".to_string()),
            no_cache: true,
            scope: xtask::Scope::All
        })
    );
    assert_eq!(
        xtask::parse_args(&args(&["cache", "clear"])),
        Ok(xtask::Command::CacheClear)
    );
    assert!(xtask::parse_args(&args(&["gate", "--list", "--no-cache"])).is_err());
    assert!(xtask::parse_args(&args(&["gate", "--only"])).is_err());
    assert!(xtask::parse_args(&args(&["cache"])).is_err());
}

#[test]
fn a_repeated_only_is_a_usage_error() {
    let first = xtask::registry()[0].name;
    let out = xtask(&["gate", "--only", first, "--only", first]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("--only given twice"), "{err}");
    assert!(!err.contains("== "), "a gate ran: {err}");
}

#[test]
fn main_context_is_the_variable_or_head_on_the_main_branch() {
    use std::ffi::OsStr;
    let var = |v| Some(OsStr::new(v));
    for (env, branch, want) in [
        (None, None, false),
        (var("main"), None, true),
        (var("1"), None, false),
        (var(""), Some("feat/x"), false),
        (var("main"), Some("feat/x"), true),
        (None, Some("main"), true),
        (None, Some("feat/x"), false),
        (None, Some("trunk"), false),
    ] {
        assert_eq!(
            xtask::is_main_context(env, branch, "main"),
            want,
            "{env:?} {branch:?}"
        );
    }
    assert!(xtask::is_main_context(None, Some("trunk"), "trunk"));
    assert!(xtask::is_main_context(None, Some("main"), "trunk"));
}

#[test]
fn an_empty_main_branch_variable_means_main() {
    use std::ffi::OsString;
    assert_eq!(xtask::main_branch_name(None), "main");
    assert_eq!(xtask::main_branch_name(Some(OsString::new())), "main");
    assert_eq!(xtask::main_branch_name(Some("trunk".into())), "trunk");
}

#[test]
fn proof_flags_and_the_proofs_subcommand_parse() {
    use xtask::{Command, Scope, USAGE};
    let args = |a: &[&str]| a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
    let gate = |only: Option<&str>, no_cache, scope| {
        Ok(Command::Gate {
            only: only.map(str::to_string),
            no_cache,
            scope,
        })
    };
    let parse = |a: &[&str]| xtask::parse_args(&args(a));
    assert_eq!(
        parse(&["gate", "--no-proofs"]),
        gate(None, false, Scope::NoProofs)
    );
    assert_eq!(
        parse(&["gate", "--only", "proof:core"]),
        gate(Some("proof:core"), false, Scope::All)
    );
    assert_eq!(parse(&["proofs"]), gate(None, false, Scope::ProofsOnly));
    assert_eq!(
        parse(&["proofs", "--only", "core"]),
        gate(Some("proof:core"), false, Scope::ProofsOnly)
    );
    assert_eq!(
        parse(&["proofs", "--only", "proof:core"]),
        gate(Some("proof:core"), false, Scope::ProofsOnly)
    );
    assert_eq!(
        parse(&["proofs", "--no-cache"]),
        gate(None, true, Scope::ProofsOnly)
    );
    assert_eq!(
        parse(&["gate", "--list", "--no-proofs"]),
        Err(USAGE.to_string())
    );
    assert_eq!(parse(&["proofs", "--list"]), Err(USAGE.to_string()));
    assert!(parse(&["proofs", "--only"]).is_err());
    assert!(
        parse(&["gate", "--only", "nope"])
            .unwrap_err()
            .starts_with("unknown gate `nope`")
    );
}

/// In process, on a scratch workspace: the binary's root is the project it
/// was built in, which may declare proofs.
#[test]
fn proofs_with_none_declared_passes() {
    let dir = std::env::temp_dir().join(format!("xtask-cli-noproofs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
    let cmd = xtask::parse_args(&["proofs".to_string()]).unwrap();
    let passed = xtask::execute(&cmd, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(passed);
}

#[test]
fn proofs_with_a_bad_declaration_fails() {
    let dir = std::env::temp_dir().join(format!("xtask-cli-badproofs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        "[workspace]\nmembers = []\n\n[[workspace.metadata.disciplines.proof]]\nname = \"x\"\nkind = \"coq\"\n",
    )
    .unwrap();
    let cmd = xtask::parse_args(&["proofs".to_string()]).unwrap();
    let passed = xtask::execute(&cmd, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!passed);
}

#[test]
fn proofs_only_given_twice_is_named() {
    let args: Vec<String> = ["proofs", "--only", "a", "--only", "b"]
        .map(String::from)
        .to_vec();
    assert_eq!(xtask::parse_args(&args).unwrap_err(), "--only given twice");
}

#[test]
fn ratchet_parses_alone() {
    assert_eq!(
        xtask::parse_args(&["ratchet".to_string()]),
        Ok(xtask::Command::Ratchet)
    );
    assert!(xtask::parse_args(&["ratchet".to_string(), "x".to_string()]).is_err());
}

/// A scratch workspace of one crate, `lib` its source; its build directory
/// stays inside it (`.cargo/config.toml`), whatever the user's cargo config.
fn ratchet_scratch(name: &str, lib: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("xtask-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("a/src")).unwrap();
    std::fs::create_dir_all(dir.join(".cargo")).unwrap();
    std::fs::write(
        dir.join(".cargo/config.toml"),
        "[build]\nbuild-dir = \"build\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        "[workspace]\nmembers = [\"a\"]\nresolver = \"3\"\n\n[workspace.lints.clippy]\ndoc_markdown = \"allow\"  # ratchet: 1\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("a/Cargo.toml"),
        "[package]\nname = \"a\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lints]\nworkspace = true\n",
    )
    .unwrap();
    std::fs::write(dir.join("a/src/lib.rs"), lib).unwrap();
    let lock = Command::new("cargo")
        .args(["generate-lockfile", "--offline"])
        .current_dir(&dir)
        .status()
        .unwrap();
    assert!(lock.success());
    dir
}

/// In process: `ratchet` measures a workspace that builds, and fails on one
/// that does not.
#[test]
fn ratchet_measures_a_workspace_and_fails_when_clippy_does() {
    let ok = ratchet_scratch("ratchet-ok", "/// Calls foo_bar.\npub fn f() {}\n");
    let passed = xtask::execute(&xtask::Command::Ratchet, &ok);
    let _ = std::fs::remove_dir_all(&ok);
    assert!(passed);
    let bad = ratchet_scratch("ratchet-bad", "pub fn f() -> u32 { \"x\" }\n");
    let passed = xtask::execute(&xtask::Command::Ratchet, &bad);
    let _ = std::fs::remove_dir_all(&bad);
    assert!(!passed);
}
