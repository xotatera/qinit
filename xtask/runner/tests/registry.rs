// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pins qinit's actual stages: the repository and its tooling workspace.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use qinit_xtask::STAGES;
use xtask::Inputs;

const REVIEW_CANARY: &str = "> [!IMPORTANT]\n> Remove these two lines to confirm that a human has reviewed this change.\n\n";

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
            "reuse",
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
            ("reuse", Inputs::Tree, None),
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
    let reuse = gates
        .iter()
        .find(|gate| gate.name == "reuse")
        .expect("the repository stage runs REUSE");
    assert_eq!(reuse.tools, ["reuse"]);
    assert!(reuse.cacheable);
    assert!(reuse.cache_on_main);
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
            ("no-std", Some("D4: no tooling kernel or core crate")),
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

#[test]
fn tooling_no_std_blocker_has_an_independent_ledger_resolution_condition() {
    let ledger = std::fs::read_to_string(qinit_xtask::repo_root().join("DEFERRED.md")).unwrap();
    assert!(ledger.contains("tooling `no-std` gate is separately blocked"));
    assert!(ledger.contains("Unblock it only in the change that adds a"));
    assert!(ledger.contains("primitive, kernel, or core crate to the `xtask` workspace"));
}

#[test]
fn repository_canary_gate_accepts_a_reviewed_fixture_on_main() {
    let fixture = Fixture::new();
    let accepted = fixture.run_with_context(
        &["gate", "--only", "repo/canary", "--no-cache"],
        Some("main"),
    );
    assert_success(&accepted);
}

#[test]
fn repository_canary_gate_rejects_a_seeded_canary_in_main_context() {
    let fixture = Fixture::new();
    fixture.seed_review_canary();
    let clean = fixture.run(&["gate", "--only", "repo/canary", "--no-cache"]);
    assert_success(&clean);

    let rejected = fixture.run_with_context(
        &["gate", "--only", "repo/canary", "--no-cache"],
        Some("main"),
    );
    assert_failure_contains(&rejected, "review canary remains in README.md");
}

#[test]
fn repository_canary_gate_rejects_a_seeded_canary_on_configured_main_branch() {
    let fixture = Fixture::new();
    fixture.seed_review_canary();
    git(&fixture.root, &["symbolic-ref", "HEAD", "refs/heads/trunk"]);

    let without_override = fixture.run(&["gate", "--only", "repo/canary", "--no-cache"]);
    assert_success(&without_override);

    let rejected =
        fixture.run_with_main_branch(&["gate", "--only", "repo/canary", "--no-cache"], "trunk");
    assert_failure_contains(&rejected, "review canary remains in README.md");
}

#[test]
fn repository_canary_gate_rejects_git_launch_errors() {
    let fixture = Fixture::new();
    let rejected = fixture.run_without_git(&["gate", "--only", "repo/canary", "--no-cache"]);
    assert_failure_contains(&rejected, "git symbolic-ref --short -q HEAD");
}

#[test]
fn repository_canary_gate_accepts_a_detached_head() {
    let fixture = Fixture::new();
    git(
        &fixture.root,
        &[
            "-c",
            "user.name=qinit fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ],
    );
    git(&fixture.root, &["checkout", "--quiet", "--detach"]);
    let accepted = fixture.run(&["gate", "--only", "repo/canary", "--no-cache"]);
    assert_success(&accepted);
}

#[test]
fn readme_introduction_matches_the_approved_component_scope() {
    let readme = std::fs::read_to_string(qinit_xtask::repo_root().join("README.md")).unwrap();
    assert!(readme.contains("- **qctl**: the configuration compiler and administrative CLI."));
    assert!(readme.contains("- **client library**: the library for the control protocol."));
    assert!(readme.contains("- **zero**: one binary with early-boot and final-shutdown modes."));
    assert!(!readme.contains("Its role will be decided during design."));
}

#[test]
fn repository_placeholder_gate_rejects_a_temporary_violation() {
    let fixture = Fixture::new();
    let clean = fixture.run(&[
        "gate",
        "--only",
        concat!("repo/place", "holder-scan"),
        "--no-cache",
    ]);
    assert_success(&clean);

    fixture.write(
        concat!("place", "holder-violation.rs"),
        concat!("fn pending() { // TO", "DO: remove }\n"),
    );
    let rejected = fixture.run(&[
        "gate",
        "--only",
        concat!("repo/place", "holder-scan"),
        "--no-cache",
    ]);
    assert_failure_contains(&rejected, concat!("place", "holder-violation.rs:1"));
    assert_failure_contains(&rejected, concat!("TO", "DO: remove"));
}

#[test]
fn repository_sleep_gate_rejects_a_temporary_violation() {
    let fixture = Fixture::new();
    let clean = fixture.run(&["gate", "--only", "repo/sleep-scan", "--no-cache"]);
    assert_success(&clean);

    fixture.write(
        "sleep-violation.rs",
        concat!(
            "fn wait() { std::thread::",
            "sleep(std::time::Duration::ZERO); }\n"
        ),
    );
    let rejected = fixture.run(&["gate", "--only", "repo/sleep-scan", "--no-cache"]);
    assert_failure_contains(&rejected, "sleep-violation.rs:1");
    assert_failure_contains(&rejected, "wait on a handshake or an event");
}

#[test]
fn repository_reuse_gate_rejects_then_accepts_a_corrected_fixture() {
    let fixture = Fixture::new();
    fixture.write("reuse-violation.txt", "unlicensed fixture\n");
    let rejected = fixture.run(&["gate", "--only", "repo/reuse", "--no-cache"]);
    assert_failure_contains(&rejected, "MISSING COPYRIGHT AND LICENSING INFORMATION");

    fixture.write(
        "reuse-violation.txt",
        "SPDX-FileCopyrightText: 2026 Xota Tera\nSPDX-License-Identifier: GPL-3.0-or-later\n",
    );
    let corrected = fixture.run(&["gate", "--only", "repo/reuse", "--no-cache"]);
    assert_success(&corrected);
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("qinit-registry-{nonce}"));
        std::fs::create_dir_all(&root).unwrap();
        let source = qinit_xtask::repo_root();
        for path in [
            "Cargo.toml",
            "README.md",
            "DEFERRED.md",
            "REUSE.toml",
            ".gitignore",
        ] {
            std::fs::copy(source.join(path), root.join(path)).unwrap();
        }
        copy_tree(&source.join("xtask"), &root.join("xtask"));
        copy_tree(&source.join("gates"), &root.join("gates"));
        copy_tree(&source.join("LICENSES"), &root.join("LICENSES"));
        let readme = std::fs::read_to_string(root.join("README.md")).unwrap();
        let readme = readme.strip_prefix(REVIEW_CANARY).unwrap_or(&readme);
        std::fs::write(root.join("README.md"), readme).unwrap();
        let ignored = std::fs::read_to_string(root.join(".gitignore")).unwrap();
        std::fs::write(root.join(".gitignore"), format!("{ignored}\ntarget/\n")).unwrap();
        git(&root, &["init", "--initial-branch=fixture"]);
        git(&root, &["add", "--all"]);
        Self { root }
    }

    fn write(&self, path: &str, text: &str) {
        std::fs::write(self.root.join(path), text).unwrap();
    }

    fn seed_review_canary(&self) {
        let readme = std::fs::read_to_string(self.root.join("README.md")).unwrap();
        assert!(
            !readme.starts_with(REVIEW_CANARY),
            "fixture unexpectedly already contains the review canary"
        );
        std::fs::write(
            self.root.join("README.md"),
            format!("{REVIEW_CANARY}{readme}"),
        )
        .unwrap();
    }

    fn run(&self, arguments: &[&str]) -> Output {
        self.run_with_context_and_main_branch(arguments, None, None)
    }

    fn run_with_context(&self, arguments: &[&str], context: Option<&str>) -> Output {
        self.run_with_context_and_main_branch(arguments, context, None)
    }

    fn run_with_main_branch(&self, arguments: &[&str], main_branch: &str) -> Output {
        self.run_with_context_and_main_branch(arguments, None, Some(main_branch))
    }

    fn run_without_git(&self, arguments: &[&str]) -> Output {
        let no_git_path = self.root.join("no-git-on-path");
        std::fs::create_dir(&no_git_path).unwrap();
        for program in ["cargo", "rustc"] {
            let source = std::env::split_paths(&std::env::var_os("PATH").unwrap())
                .map(|directory| directory.join(program))
                .find(|candidate| candidate.is_file())
                .unwrap();
            std::os::unix::fs::symlink(source, no_git_path.join(program)).unwrap();
        }
        Command::new(env!("CARGO_BIN_EXE_qinit-xtask"))
            .args(arguments)
            .current_dir(&self.root)
            .env("PATH", no_git_path)
            .env_remove(xtask::CONTEXT_ENV)
            .env_remove(xtask::MAIN_BRANCH_ENV)
            .output()
            .expect("run qinit-xtask without git")
    }

    fn run_with_context_and_main_branch(
        &self,
        arguments: &[&str],
        context: Option<&str>,
        main_branch: Option<&str>,
    ) -> Output {
        let mut command = self.command(arguments);
        if let Some(context) = context {
            command.env(xtask::CONTEXT_ENV, context);
        }
        if let Some(main_branch) = main_branch {
            command.env(xtask::MAIN_BRANCH_ENV, main_branch);
        }
        command.output().expect("run isolated qinit-xtask fixture")
    }

    fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new("cargo");
        command
            .args([
                "run",
                "--manifest-path",
                self.root.join("xtask/Cargo.toml").to_str().unwrap(),
                "--package",
                "qinit-xtask",
                "--quiet",
                "--locked",
                "--offline",
                "--",
            ])
            .args(arguments)
            .current_dir(&self.root)
            .env("CARGO_TARGET_DIR", self.root.join("xtask/target"))
            .env_remove(xtask::CONTEXT_ENV)
            .env_remove(xtask::MAIN_BRANCH_ENV);
        command
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn copy_tree(source: &Path, destination: &Path) {
    std::fs::create_dir_all(destination).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if name == "target" {
            continue;
        }
        let destination = destination.join(&name);
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &destination);
        } else {
            std::fs::copy(entry.path(), destination).unwrap();
        }
    }
}

fn git(root: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .args(arguments)
        .current_dir(root)
        .status()
        .expect("run git for isolated fixture");
    assert!(status.success(), "git {} failed", arguments.join(" "));
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure_contains(output: &Output, expected: &str) {
    assert!(!output.status.success(), "fixture unexpectedly passed");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains(expected), "{text}");
}
