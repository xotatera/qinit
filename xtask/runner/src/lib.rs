// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! qinit's gate runner runs repository gates before the tooling workspace.
//! The public product workspace remains empty until product work begins.

use std::path::{Path, PathBuf};

use xtask::{Command, Gate, Inputs, Runner};

/// One stage: a name, its root relative to the repository, and its gates.
pub struct Stage {
    pub name: &'static str,
    pub dir: &'static str,
    pub registry: fn() -> Vec<Gate>,
}

/// qinit's existing stages in run order. Product stages are added only when
/// their workspaces exist; the empty root workspace is the repository stage.
pub const STAGES: &[Stage] = &[
    Stage {
        name: "repo",
        dir: "",
        registry: repo_registry,
    },
    Stage {
        name: "xtask",
        dir: "xtask",
        registry: xtask_registry,
    },
];

/// The review canary's required instruction.
pub const CANARY_INSTRUCTION: &str =
    "Remove these two lines to confirm that a human has reviewed this change.";

/// Fails only when this run decides what reaches the main branch and the
/// review canary remains in the tree.
///
/// # Errors
/// When the review canary is still present in the main context.
pub fn canary(main: bool, present: bool) -> Result<(), String> {
    if main && present {
        Err(format!(
            "review canary remains in README.md. {CANARY_INSTRUCTION}"
        ))
    } else {
        Ok(())
    }
}

fn canary_gate(root: &Path) -> Result<(), String> {
    let main_branch = xtask::main_branch_name(std::env::var_os(xtask::MAIN_BRANCH_ENV));
    let branch = current_branch(root);
    let main = xtask::is_main_context(
        std::env::var_os(xtask::CONTEXT_ENV).as_deref(),
        branch.as_deref(),
        &main_branch,
    );
    let readme = std::fs::read_to_string(root.join("README.md"))
        .map_err(|error| format!("README.md: {error}"))?;
    let present = readme.lines().take(2).eq([
        "> [!IMPORTANT]",
        "> Remove these two lines to confirm that a human has reviewed this change.",
    ]);
    canary(main, present)
}

const NO_PRODUCT_FORMAT: &str = "D3: no product package to format";
const NO_PRODUCT_LINT: &str = "D3: no product package to lint";
const NO_PRODUCT_LAYERS: &str = "D3: no product package to check";
const NO_PRODUCT_NO_STD: &str = "D4: no kernel or core product crate";
const NO_TOOLING_NO_STD: &str = "D4: no tooling kernel or core crate";
const NO_PRODUCT_TEST: &str = "D3: no product package to test";
const TOOLING_REPOSITORY_SCANS: &str = "D5: repository-wide scans run in the repo stage";

/// Repository gates available before qinit has product packages.
#[must_use]
pub fn repo_registry() -> Vec<Gate> {
    vec![
        Gate {
            name: "canary",
            run: Box::new(canary_gate),
            inputs: Inputs::Globs(&["README.md"]),
            env: &[xtask::CONTEXT_ENV, xtask::MAIN_BRANCH_ENV],
            tools: &["git"],
            extra_paths: &[],
            cache_paths: &[],
            ignored_inputs: &[],
            cacheable: false,
            cache_on_main: false,
            blocked: None,
            decl: "",
        },
        Gate {
            name: "reuse",
            run: Box::new(reuse),
            inputs: Inputs::Tree,
            env: &[],
            tools: &["reuse"],
            extra_paths: &[],
            cache_paths: &[],
            ignored_inputs: &[],
            cacheable: true,
            cache_on_main: true,
            blocked: None,
            decl: "",
        },
        Gate {
            name: "fmt",
            run: Box::new(xtask::gates::fmt),
            inputs: Inputs::Tree,
            env: &["RUSTFMT"],
            tools: &["cargo", "rustfmt", "verusfmt"],
            extra_paths: &[],
            cache_paths: &[],
            ignored_inputs: &[],
            cacheable: true,
            cache_on_main: false,
            blocked: Some(NO_PRODUCT_FORMAT),
            decl: "",
        },
        repo_scan("placeholder-scan", xtask::gates::stub_scan, true), // disciplines:allow-placeholder (the gate's name)
        repo_scan("sleep-scan", xtask::gates::sleep_scan, true),
        repo_scan("changelog", xtask::gates::changelog, false),
        Gate {
            name: "lint",
            run: Box::new(xtask::gates::lint),
            inputs: Inputs::Tree,
            env: xtask::RUST_ENV,
            tools: &["cargo", "cargo-clippy", "rustc"],
            extra_paths: &[],
            cache_paths: &[],
            ignored_inputs: &[],
            cacheable: true,
            cache_on_main: false,
            blocked: Some(NO_PRODUCT_LINT),
            decl: "",
        },
        Gate {
            name: "layers",
            run: Box::new(xtask::gates::layers),
            inputs: Inputs::Tree,
            env: xtask::RUST_ENV,
            tools: &["cargo"],
            extra_paths: &[],
            cache_paths: &[],
            ignored_inputs: &[],
            cacheable: true,
            cache_on_main: false,
            blocked: Some(NO_PRODUCT_LAYERS),
            decl: "",
        },
        Gate {
            name: "no-std",
            run: Box::new(xtask::gates::no_std),
            inputs: Inputs::Tree,
            env: xtask::RUST_ENV,
            tools: &["cargo", "rustc"],
            extra_paths: &[],
            cache_paths: &[],
            ignored_inputs: &[],
            cacheable: true,
            cache_on_main: false,
            blocked: Some(NO_PRODUCT_NO_STD),
            decl: "",
        },
        Gate {
            name: "duplication",
            run: Box::new(xtask::gates::duplication),
            inputs: Inputs::Globs(&["**/*.rs", "gates/duplication-baseline.txt"]),
            env: &[],
            tools: &["git"],
            extra_paths: &[],
            cache_paths: &[],
            ignored_inputs: &[],
            cacheable: true,
            cache_on_main: true,
            blocked: None,
            decl: "",
        },
        Gate {
            name: "test",
            run: Box::new(xtask::gates::test),
            inputs: Inputs::Tree,
            env: xtask::RUST_ENV,
            tools: &["cargo", "rustc"],
            extra_paths: &[],
            cache_paths: &[],
            ignored_inputs: &[],
            cacheable: true,
            cache_on_main: false,
            blocked: Some(NO_PRODUCT_TEST),
            decl: "",
        },
    ]
}

fn reuse(root: &Path) -> Result<(), String> {
    xtask::gates::run(root, "reuse", &["lint"])
}

fn repo_scan(name: &'static str, run: fn(&Path) -> Result<(), String>, cacheable: bool) -> Gate {
    Gate {
        name,
        run: Box::new(run),
        inputs: Inputs::Tree,
        env: &[],
        tools: &["git"],
        extra_paths: &[],
        cache_paths: &[],
        ignored_inputs: &[],
        cacheable,
        cache_on_main: cacheable,
        blocked: None,
        decl: "",
    }
}

/// Tooling-only checks run in the xtask workspace. Repository-wide scans run
/// once in the repository stage, where their policy files and ledger live.
#[must_use]
pub fn xtask_registry() -> Vec<Gate> {
    let mut gates = xtask::registry();
    for gate in &mut gates {
        gate.blocked = match gate.name {
            "placeholder-scan" // disciplines:allow-placeholder (the gate's name)
            | "sleep-scan" | "changelog" | "duplication" => Some(TOOLING_REPOSITORY_SCANS),
            "no-std" => Some(NO_TOOLING_NO_STD),
            _ => None,
        };
    }
    gates
}

fn current_branch(root: &Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["symbolic-ref", "--short", "-q", "HEAD"])
        .current_dir(root)
        .output()
        .ok()?;
    let branch = String::from_utf8(output.stdout).ok()?;
    let branch = branch.trim();
    (output.status.success() && !branch.is_empty()).then(|| branch.to_string())
}

/// The repository root: this crate is `<root>/xtask/runner`.
#[must_use]
pub fn repo_root() -> PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::fs::canonicalize(&path).unwrap_or(path)
}

pub const USAGE: &str = "usage: cargo xtask gate [--only [<stage>/]<gate>] [--no-cache] [--no-proofs] | gate --list\n       cargo xtask proofs [--only [<stage>/]<name>] [--no-cache]\n       cargo xtask cache clear\n       cargo xtask dup <stage> report|sweep|bless …\n       cargo xtask ratchet <stage>\nstages: repo, xtask";

/// What a command line asks for.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// `gate --list`: every stage's gates, `<stage>/<gate>`.
    List,
    /// `cache clear`: the store is shared by every stage.
    CacheClear,
    /// `ratchet <stage>`: print the stage's pedantic findings per lint table.
    Ratchet(&'static str),
    /// The template command to run in each listed stage, in order.
    Run(Vec<(&'static str, Command)>),
}

/// Plans a command line. `names(stage)` lists its static and proof gates.
///
/// # Errors
/// For usage errors, an unknown stage, or a gate no selected stage has.
pub fn plan(
    args: &[String],
    names: &dyn Fn(&Stage) -> Result<Vec<String>, String>,
) -> Result<Plan, String> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["gate", "--list"] => Ok(Plan::List),
        ["cache", "clear"] => Ok(Plan::CacheClear),
        ["ratchet", stage] => Ok(Plan::Ratchet(stage_named(stage)?.name)),
        ["dup", stage, rest @ ..] => {
            let stage = stage_named(stage)?;
            let mut forwarded = vec!["dup".to_string()];
            forwarded.extend(rest.iter().map(|arg| (*arg).to_string()));
            Ok(Plan::Run(vec![(
                stage.name,
                xtask::parse_args_with(stage.registry, &forwarded)?,
            )]))
        }
        [verb @ ("gate" | "proofs"), rest @ ..] => plan_run(verb, rest, names),
        _ => Err(USAGE.to_string()),
    }
}

fn stage_named(name: &str) -> Result<&'static Stage, String> {
    STAGES
        .iter()
        .find(|stage| stage.name == name)
        .ok_or_else(|| {
            let known: Vec<&str> = STAGES.iter().map(|stage| stage.name).collect();
            format!("unknown stage `{name}`; stages: {}", known.join(", "))
        })
}

fn plan_run(
    verb: &str,
    rest: &[&str],
    names: &dyn Fn(&Stage) -> Result<Vec<String>, String>,
) -> Result<Plan, String> {
    let mut only = None;
    let mut forwarded = vec![verb.to_string()];
    let mut arguments = rest.iter();
    while let Some(argument) = arguments.next() {
        if *argument == "--only" {
            if only.is_some() {
                return Err("--only given twice".to_string());
            }
            only = Some(*arguments.next().ok_or_else(|| USAGE.to_string())?);
        } else {
            forwarded.push((*argument).to_string());
        }
    }
    let (stage, gate) = match only.map(|value| value.split_once('/')) {
        Some(Some((stage, gate))) => (Some(stage_named(stage)?), Some(gate)),
        Some(None) => (None, only),
        None => (None, None),
    };
    let gate = gate.map(|gate| {
        if verb == "proofs" && !gate.starts_with("proof:") {
            format!("proof:{gate}")
        } else {
            gate.to_string()
        }
    });
    let mut selected = Vec::new();
    for candidate in STAGES {
        if stage.is_some_and(|requested| requested.name != candidate.name) {
            continue;
        }
        let candidate_names =
            names(candidate).map_err(|error| format!("{} proofs: {error}", candidate.name))?;
        let has =
            |predicate: &dyn Fn(&str) -> bool| candidate_names.iter().any(|name| predicate(name));
        let wanted = match (&gate, verb) {
            (Some(gate), _) => has(&|name| name == gate),
            (None, "proofs") => has(&|name| name.starts_with("proof:")),
            (None, _) => true,
        };
        if !wanted {
            continue;
        }
        let mut arguments = forwarded.clone();
        if let Some(gate) = &gate {
            arguments.extend(["--only".to_string(), gate.clone()]);
        }
        selected.push((
            candidate.name,
            xtask::parse_args_with(candidate.registry, &arguments)?,
        ));
    }
    if selected.is_empty() {
        return match (verb, gate) {
            ("proofs", None) => Ok(Plan::Run(Vec::new())),
            (_, Some(gate)) => Err(format!(
                "unknown gate `{gate}`; `cargo xtask gate --list` names them all"
            )),
            _ => Err("no stage declares a proof gate".to_string()),
        };
    }
    Ok(Plan::Run(selected))
}

/// Every gate of `stage` at `root`, including declared proofs.
///
/// # Errors
/// A malformed proof declaration for the stage.
pub fn gate_names(stage: &Stage, root: &Path) -> Result<Vec<String>, String> {
    xtask::all_gates_with(stage.registry, &root.join(stage.dir), None)
        .map(|gates| gates.iter().map(|gate| gate.name.to_string()).collect())
}

/// Runs a plan; `true` only if every selected stage passes.
#[must_use]
pub fn execute(plan: Plan, root: &Path) -> bool {
    match plan {
        Plan::List => {
            for stage in STAGES {
                let names = match gate_names(stage, root) {
                    Ok(names) => names,
                    Err(error) => {
                        eprintln!("{} proofs: {error}", stage.name);
                        return false;
                    }
                };
                for name in names {
                    println!("{}/{name}", stage.name);
                }
            }
            true
        }
        Plan::Ratchet(name) => {
            let stage = stage_named(name).unwrap_or_else(|error| unreachable!("{error}"));
            match xtask::gates::ratchet_measure(&root.join(stage.dir)) {
                Ok(text) => {
                    print!("{text}");
                    true
                }
                Err(error) => {
                    eprintln!("{error}");
                    false
                }
            }
        }
        Plan::CacheClear => xtask::execute_with(
            &Runner::extending(repo_registry, PathBuf::from(env!("CARGO_MANIFEST_DIR"))),
            &Command::CacheClear,
            root,
        ),
        Plan::Run(steps) => {
            let mut failed = Vec::new();
            for (name, command) in steps {
                let stage = stage_named(name).unwrap_or_else(|error| unreachable!("{error}"));
                eprintln!("=== stage {name}");
                let runner =
                    Runner::extending(stage.registry, PathBuf::from(env!("CARGO_MANIFEST_DIR")));
                if !xtask::execute_with(&runner, &command, &root.join(stage.dir)) {
                    failed.push(name);
                }
            }
            if failed.is_empty() {
                eprintln!("=== every stage passed");
            } else {
                eprintln!("=== failed stages: {}", failed.join(", "));
            }
            failed.is_empty()
        }
    }
}
