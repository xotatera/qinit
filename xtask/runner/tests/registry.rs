// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pins qinit's actual stages: the repository and its tooling workspace.

use std::process::Command;

use qinit_xtask::STAGES;
use xtask::Inputs;

#[test]
fn qinit_has_only_repository_and_tooling_stages() {
    let stages: Vec<(&str, &str)> = STAGES.iter().map(|s| (s.name, s.dir)).collect();
    assert_eq!(stages, [("repo", ""), ("xtask", "xtask")]);
}

#[test]
fn repository_gate_policy_is_pinned() {
    let gates = qinit_xtask::repo_registry();
    let names: Vec<&str> = gates.iter().map(|gate| gate.name).collect();
    assert_eq!(
        names,
        [
            "canary",
            "fmt",
            "placeholder-scan", // disciplines:allow-placeholder (the gate's name)
            "sleep-scan",
            "changelog",
            "lint",
            "layers",
            "no-std",
            "duplication",
            "test",
        ]
    );
    let declarations: Vec<(&str, Inputs, Option<&str>)> = gates
        .iter()
        .map(|gate| (gate.name, gate.inputs, gate.blocked))
        .collect();
    assert_eq!(
        declarations,
        [
            ("canary", Inputs::Globs(&["README.md"]), None),
            (
                "fmt",
                Inputs::Tree,
                Some("D3: no product package to format")
            ),
            ("placeholder-scan", Inputs::Tree, None), // disciplines:allow-placeholder (the gate's name)
            ("sleep-scan", Inputs::Tree, None),
            ("changelog", Inputs::Tree, None),
            ("lint", Inputs::Tree, Some("D3: no product package to lint")),
            (
                "layers",
                Inputs::Tree,
                Some("D3: no product package to check")
            ),
            (
                "no-std",
                Inputs::Tree,
                Some("D4: no kernel or core product crate"),
            ),
            (
                "duplication",
                Inputs::Globs(&["**/*.rs", "gates/duplication-baseline.txt"]),
                None
            ),
            ("test", Inputs::Tree, Some("D3: no product package to test")),
        ]
    );
}

#[test]
fn tooling_registry_blocks_only_repository_wide_checks() {
    let blocked: Vec<(&str, Option<&str>)> = qinit_xtask::xtask_registry()
        .iter()
        .map(|gate| (gate.name, gate.blocked))
        .collect();
    assert_eq!(
        blocked,
        [
            ("preflight", None),
            ("fmt", None),
            (
                "placeholder-scan", // disciplines:allow-placeholder (the gate's name)
                Some("D5: repository-wide scans run in the repo stage"),
            ),
            (
                "sleep-scan",
                Some("D5: repository-wide scans run in the repo stage")
            ),
            (
                "changelog",
                Some("D5: repository-wide scans run in the repo stage")
            ),
            ("lint", None),
            ("layers", None),
            ("no-std", Some("D4: no kernel or core product crate")),
            (
                "duplication",
                Some("D5: repository-wide scans run in the repo stage")
            ),
            ("test", None),
        ]
    );
}

#[test]
fn repository_declares_no_proofs_before_product_crates_exist() {
    let root = qinit_xtask::repo_root();
    let names = qinit_xtask::gate_names(&STAGES[0], &root).unwrap();
    assert!(names.iter().all(|name| !name.starts_with("proof:")));
}

#[test]
fn main_context_refuses_no_proofs_even_without_declared_proofs() {
    let output = Command::new(env!("CARGO_BIN_EXE_qinit-xtask"))
        .args(["gate", "--only", "repo/canary", "--no-proofs"])
        .env(xtask::CONTEXT_ENV, "main")
        .output()
        .expect("run qinit-xtask");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("--no-proofs is refused: this run decides what lands on main"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn canary_reports_the_human_review_instruction_only_on_main() {
    assert_eq!(qinit_xtask::canary(false, true), Ok(()));
    assert_eq!(qinit_xtask::canary(true, false), Ok(()));
    let failure = qinit_xtask::canary(true, true).unwrap_err();
    assert!(failure.contains("Remove these two lines to confirm"));
}
