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

/// Measured with `cargo xtask gate --no-cache` on 2026-10-24/27 (seconds):
/// preflight, canary, placeholder-scan, sleep-scan, changelog, layers 0.0; // disciplines:allow-placeholder (the gate's name)
/// reuse 0.3; duplication 0.8; xtask fmt 1.8; xtask lint 2.8; xtask test
/// 42-56. Blocked gates (SKIP, 0.0 s now) sit where their work will cost
/// once unblocked; re-measure when one is. A new gate is placed by its
/// measured time; slow gates go last.
const GLOBAL_ORDER: &[(&str, &str)] = &[
    ("repo", "preflight"),
    ("xtask", "preflight"),
    ("repo", "canary"),
    ("repo", "placeholder-scan"), // disciplines:allow-placeholder (the gate's name)
    ("repo", "sleep-scan"),
    ("repo", "changelog"),
    ("xtask", "placeholder-scan"), // disciplines:allow-placeholder (the gate's name)
    ("xtask", "sleep-scan"),
    ("xtask", "changelog"),
    ("xtask", "duplication"),
    ("xtask", "no-std"),
    ("xtask", "layers"),
    ("repo", "layers"),
    ("repo", "reuse"),
    ("repo", "duplication"),
    ("xtask", "fmt"),
    ("repo", "fmt"),
    ("xtask", "lint"),
    ("repo", "lint"),
    ("repo", "no-std"),
    ("repo", "test"),
    ("xtask", "test"),
];

#[test]
fn global_gate_order_is_pinned_fastest_first() {
    assert_eq!(qinit_xtask::ORDER, GLOBAL_ORDER);
}

#[test]
fn global_order_names_every_static_gate_once() {
    for stage in STAGES {
        let mut registry: Vec<&str> = (stage.registry)().iter().map(|gate| gate.name).collect();
        let mut ordered: Vec<&str> = qinit_xtask::ORDER
            .iter()
            .filter(|(name, _)| *name == stage.name)
            .map(|(_, gate)| *gate)
            .collect();
        registry.sort_unstable();
        ordered.sort_unstable();
        assert_eq!(ordered, registry, "stage {}", stage.name);
    }
}

#[allow(clippy::unnecessary_wraps)] // signature fixed by the `plan` names callback
fn names_with_a_repo_proof(stage: &qinit_xtask::Stage) -> Result<Vec<String>, String> {
    let mut names: Vec<String> = (stage.registry)()
        .iter()
        .map(|gate| gate.name.to_string())
        .collect();
    if stage.name == "repo" {
        names.push("proof:example".to_string());
    }
    Ok(names)
}

fn planned(arguments: &[&str]) -> Vec<(&'static str, xtask::Command)> {
    let arguments: Vec<String> = arguments.iter().map(|a| (*a).to_string()).collect();
    match qinit_xtask::plan(&arguments, &names_with_a_repo_proof).unwrap() {
        qinit_xtask::Plan::Run(steps) => steps,
        other => panic!("not a run: {other:?}"),
    }
}

fn step(stage: &'static str, arguments: &[&str]) -> (&'static str, xtask::Command) {
    let registry = STAGES.iter().find(|s| s.name == stage).unwrap().registry;
    let arguments: Vec<String> = arguments.iter().map(|a| (*a).to_string()).collect();
    (stage, xtask::parse_args_with(registry, &arguments).unwrap())
}

#[test]
fn a_full_gate_run_follows_the_global_order_then_runs_proofs() {
    let mut expected: Vec<_> = GLOBAL_ORDER
        .iter()
        .map(|(stage, gate)| step(stage, &["gate", "--no-cache", "--only", gate]))
        .collect();
    expected.push(step("repo", &["proofs", "--no-cache"]));
    assert_eq!(planned(&["gate", "--no-cache"]), expected);
}

#[test]
fn no_proofs_forwards_to_every_step_and_drops_the_proof_steps() {
    let expected: Vec<_> = GLOBAL_ORDER
        .iter()
        .map(|(stage, gate)| step(stage, &["gate", "--no-proofs", "--only", gate]))
        .collect();
    assert_eq!(planned(&["gate", "--no-proofs"]), expected);
}

#[test]
fn gate_list_prints_the_global_order() {
    let fixture = Fixture::new();
    let output = fixture.run(&["gate", "--list"]);
    assert_success(&output);
    let listed: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_string)
        .collect();
    // Declared proofs follow the static gates (the fixture copies the root manifest).
    let expected: Vec<String> = GLOBAL_ORDER
        .iter()
        .map(|(stage, gate)| format!("{stage}/{gate}"))
        .chain(["repo/proof:qinit-event-core".to_string()])
        .collect();
    assert_eq!(listed, expected);
}

#[test]
fn the_first_failing_gate_stops_the_run() {
    let fixture = Fixture::new();
    fixture.seed_review_canary();
    let output = fixture.run_with_context(&["gate", "--no-cache"], Some("main"));
    assert_failure_contains(&output, "review canary remains in README.md");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("=== stopped at repo/canary"), "{stderr}");
    assert!(
        stderr.contains("not run: repo/placeholder-scan,"), // disciplines:allow-placeholder (the gate's name)
        "{stderr}"
    );
    assert!(stderr.contains("xtask/test"), "{stderr}");
    for later in ["== reuse", "== duplication", "== test", "PASS fmt"] {
        assert!(
            !stderr.contains(later),
            "{later} ran after the failure: {stderr}"
        );
    }
}

#[test]
fn repository_gate_policy_is_pinned() {
    let gates = qinit_xtask::repo_registry();
    let names: Vec<&str> = gates.iter().map(|gate| gate.name).collect();
    assert_eq!(
        names,
        [
            "preflight",
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
            ("preflight", Inputs::Globs(&["**/Cargo.toml"]), None),
            ("canary", Inputs::Globs(&["README.md"]), None),
            ("reuse", Inputs::Tree, None),
            ("fmt", Inputs::Tree, None),
            ("placeholder-scan", Inputs::Tree, None), // disciplines:allow-placeholder (the gate's name)
            ("sleep-scan", Inputs::Tree, None),
            ("changelog", Inputs::Tree, None),
            ("lint", Inputs::Tree, None),
            ("layers", Inputs::Tree, None),
            ("no-std", Inputs::Tree, None),
            (
                "duplication",
                Inputs::Globs(&["**/*.rs", "gates/duplication-baseline.txt"]),
                None
            ),
            ("test", Inputs::Tree, None),
        ]
    );
    let reuse = gates
        .iter()
        .find(|gate| gate.name == "reuse")
        .expect("the repository stage runs REUSE");
    assert_eq!(reuse.tools, ["reuse"]);
    assert!(reuse.cacheable);
    assert!(reuse.cache_on_main);
    let preflight = &gates[0];
    let template = xtask::registry();
    let template = template
        .iter()
        .find(|gate| gate.name == "preflight")
        .unwrap();
    let mut tools = template.tools.to_vec();
    tools.push("reuse");
    assert_eq!(preflight.tools, tools);
    assert!(preflight.cacheable);
    assert!(preflight.cache_on_main);
}

#[test]
fn repository_preflight_names_a_missing_repository_tool() {
    let scratch = Scratch::new("preflight-path");
    for program in ["cargo", "rustc", "rustfmt", "cargo-clippy", "git"] {
        let source = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|directory| directory.join(program))
            .find(|candidate| candidate.is_file())
            .unwrap();
        std::os::unix::fs::symlink(source, scratch.0.join(program)).unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_qinit-xtask"))
        .args(["gate", "--only", "repo/preflight", "--no-cache"])
        .env("PATH", &scratch.0)
        .env_remove(xtask::CONTEXT_ENV)
        .env_remove(xtask::MAIN_BRANCH_ENV)
        .output()
        .expect("run qinit-xtask without reuse");
    assert_failure_contains(&output, "missing: reuse");
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

/// Repository files outside `xtask/` that the tooling tests read.
const TOOLING_TEST_EXTRA_PATHS: &[&str] = &[
    "../.githooks",
    "../.cargo/config.toml",
    "../.gitignore",
    "../Cargo.lock",
    "../Cargo.toml",
    "../DEFERRED.md",
    "../LICENSES",
    "../crates",
    "../README.md",
    "../REUSE.toml",
    "../gates",
    "../rust-toolchain.toml",
];

#[test]
fn tooling_test_gate_declares_the_repository_files_its_tests_read() {
    let gates = qinit_xtask::xtask_registry();
    let test = gates
        .iter()
        .find(|gate| gate.name == "test")
        .expect("the tooling stage runs its tests");
    assert_eq!(test.inputs, Inputs::Tree);
    assert_eq!(test.extra_paths, TOOLING_TEST_EXTRA_PATHS);
    let others: Vec<&str> = gates
        .iter()
        .filter(|gate| gate.name != "test" && !gate.extra_paths.is_empty())
        .map(|gate| gate.name)
        .collect();
    assert!(others.is_empty(), "{others:?}");
}

#[test]
fn a_changed_hook_invalidates_the_tooling_test_cache_key() {
    use std::collections::HashMap;
    use std::ffi::OsString;

    let scratch = Scratch::new("hook-key");
    let root = scratch.0.join("repo");
    let stage = root.join("xtask");
    std::fs::create_dir_all(stage.join("src")).unwrap();
    std::fs::create_dir_all(root.join(".githooks")).unwrap();
    std::fs::write(stage.join("src/lib.rs"), "pub fn a() {}\n").unwrap();
    std::fs::write(root.join(".githooks/pre-push"), "#!/bin/sh\nexit 1\n").unwrap();
    git(&root, &["init", "-q", "--initial-branch=fixture"]);
    git(&root, &["add", "--all"]);
    let runner = scratch.0.join("runner");
    std::fs::create_dir_all(&runner).unwrap();
    let probe = xtask::cache::key::Probe {
        runner_dirs: vec![runner],
        path: Some(OsString::new()),
        sysroot: None,
        vars: HashMap::new(),
        home: Some(scratch.0.join("home")),
    };
    let gates = qinit_xtask::xtask_registry();
    let test = gates.iter().find(|gate| gate.name == "test").unwrap();
    let spec = test.key_spec();
    let before = xtask::cache::key::key(&stage, &spec, &probe).unwrap();
    assert_eq!(
        before,
        xtask::cache::key::key(&stage, &spec, &probe).unwrap()
    );
    std::fs::write(root.join(".githooks/pre-push"), "#!/bin/sh\nexit 0\n").unwrap();
    assert_ne!(
        before,
        xtask::cache::key::key(&stage, &spec, &probe).unwrap()
    );
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("qinit-registry-{name}-{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn repository_declares_exactly_the_core_crate_proofs() {
    let root = qinit_xtask::repo_root();
    let names = qinit_xtask::gate_names(&STAGES[0], &root).unwrap();
    let proofs: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|name| name.starts_with("proof:"))
        .collect();
    assert_eq!(proofs, ["proof:qinit-event-core"]);
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

const CANARY_LINE_1: &str = "> [!IMPORTANT]";
const CANARY_LINE_2: &str =
    "> Remove these two lines to confirm that a human has reviewed this change.";

#[test]
fn canary_detection_normalises_encoding_line_endings_and_spacing() {
    let plain = format!("{CANARY_LINE_1}\n{CANARY_LINE_2}\n\n# qinit\n");
    assert!(qinit_xtask::canary_present(&plain));
    for variant in [
        format!("{CANARY_LINE_1}\r\n{CANARY_LINE_2}\r\n\r\n# qinit\r\n"),
        format!("\u{feff}{CANARY_LINE_1}\n{CANARY_LINE_2}\n"),
        format!("\n  \n{CANARY_LINE_1}\n{CANARY_LINE_2}\n"),
        format!(" {CANARY_LINE_1}\n\t{CANARY_LINE_2}  \n"),
        format!("\u{feff}\r\n {CANARY_LINE_1} \r\n{CANARY_LINE_2}\t\r\n"),
        // pre-push reads the README through bash command substitution,
        // which drops NUL bytes.
        format!("{CANARY_LINE_1}\0\n{CANARY_LINE_2}\n"),
    ] {
        assert!(qinit_xtask::canary_present(&variant), "{variant:?}");
    }
    for absent in [
        String::new(),
        "# qinit\n".to_string(),
        format!("{CANARY_LINE_1}\n"),
        format!("{CANARY_LINE_1}\n\n{CANARY_LINE_2}\n"),
        format!("# qinit\n{CANARY_LINE_1}\n{CANARY_LINE_2}\n"),
    ] {
        assert!(!qinit_xtask::canary_present(&absent), "{absent:?}");
    }
}

#[test]
fn repository_canary_gate_rejects_a_crlf_bom_canary_in_main_context() {
    let fixture = Fixture::new();
    let readme = std::fs::read_to_string(fixture.root.join("README.md")).unwrap();
    fixture.write(
        "README.md",
        &format!("\u{feff}\r\n {CANARY_LINE_1}\r\n{CANARY_LINE_2} \r\n{readme}"),
    );
    let rejected = fixture.run_with_context(
        &["gate", "--only", "repo/canary", "--no-cache"],
        Some("main"),
    );
    assert_failure_contains(&rejected, "review canary remains in README.md");
}

#[test]
fn repository_canary_gate_rejects_a_symlinked_readme() {
    let fixture = Fixture::new();
    let readme = fixture.root.join("README.md");
    std::fs::rename(&readme, fixture.root.join("README.real.md")).unwrap();
    std::os::unix::fs::symlink("README.real.md", &readme).unwrap();
    let rejected = fixture.run(&["gate", "--only", "repo/canary", "--no-cache"]);
    assert_failure_contains(&rejected, "README.md is a symlink");
}

#[test]
fn repository_canary_gate_rejects_a_missing_readme() {
    let fixture = Fixture::new();
    std::fs::remove_file(fixture.root.join("README.md")).unwrap();
    let rejected = fixture.run(&["gate", "--only", "repo/canary", "--no-cache"]);
    assert_failure_contains(&rejected, "README.md is missing");
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
fn repository_canary_gate_ignores_a_leaked_git_dir() {
    let fixture = Fixture::new();
    fixture.seed_review_canary();
    let other = fixture.root.join("other-repository");
    std::fs::create_dir(&other).unwrap();
    git(&other, &["init", "--quiet", "--initial-branch=main"]);
    let mut command = fixture.command(&["gate", "--only", "repo/canary", "--no-cache"]);
    command.env("GIT_DIR", other.join(".git"));
    let accepted = command.output().expect("run qinit-xtask with GIT_DIR");
    assert_success(&accepted);
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
            "Cargo.lock",
            "README.md",
            "DEFERRED.md",
            "REUSE.toml",
            ".gitignore",
        ] {
            std::fs::copy(source.join(path), root.join(path)).unwrap();
        }
        copy_tree(&source.join("xtask"), &root.join("xtask"));
        copy_tree(&source.join("crates"), &root.join("crates"));
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
