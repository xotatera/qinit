// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Gate runner: an ordered registry of gates, run by `cargo xtask gate`.
//! Gate bodies (`gates.rs`) only spawn tools and read exit codes; all logic
//! lives in the other modules, which are unit-tested.
pub mod atc;
pub mod batch;
pub mod cache;
pub mod changelog;
pub mod duplication;
pub mod fmt_gate;
pub mod gates;
pub mod git;
pub mod layers;
pub mod listed;
pub mod proofs;
pub mod ratchet;
pub mod run_scope;
pub mod runner;
pub mod shell;
pub mod sleeps;
pub mod stubs;
pub mod timing;
pub mod tools;
pub mod trusted;
pub mod vir_trust;
pub mod watch;

pub use cache::key::Inputs;
pub use run_scope::{shared, will_run};

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A gate's body: `Err(message)` on failure.
pub type Body = Box<dyn Fn(&Path) -> Result<(), String>>;

/// One gate: a name, a body that returns `Err(message)` on failure, and what
/// its result depends on (for the cache). `tests/registry.rs` pins every
/// declaration, so narrowing a gate's inputs is a reviewed change.
pub struct Gate {
    pub name: &'static str,
    pub run: Body,
    pub inputs: Inputs,
    pub env: &'static [&'static str],
    pub tools: &'static [&'static str],
    /// Files or directories outside the repository that the gate reads
    /// (`build.rs`, `include_str!`): absolute, `~/`-prefixed or relative to
    /// the root.
    pub extra_paths: &'static [&'static str],
    /// Absolute paths added at runtime without losing non-UTF-8 bytes.
    pub cache_paths: &'static [PathBuf],
    /// Globs matched against ignored files, for generated inputs.
    pub ignored_inputs: &'static [&'static str],
    /// `false` for wall-clock benchmarks and network or supply-chain gates.
    pub cacheable: bool,
    /// `false` for gates driven by cargo, whose inputs the key cannot fully
    /// see: in the `main` context ([`CONTEXT_ENV`]) they run and record.
    pub cache_on_main: bool,
    /// `Some(reason)` prints `SKIP <gate>: <reason>` and never runs the gate.
    pub blocked: Option<&'static str>,
    /// Canonical text of a runtime declaration (proof entries), keyed so an
    /// edit re-runs the gate; empty for the static gates.
    pub decl: &'static str,
}

impl Gate {
    #[must_use]
    pub fn key_spec(&self) -> cache::key::KeySpec<'_> {
        cache::key::KeySpec {
            gate: self.name,
            inputs: self.inputs,
            env: self.env,
            tools: self.tools,
            extra_paths: self.extra_paths,
            cache_paths: self.cache_paths,
            ignored_inputs: self.ignored_inputs,
            decl: self.decl,
        }
    }
}

/// What rustc, rustdoc and clippy read from the environment: lint and test
/// declare them all.
pub const RUST_ENV: &[&str] = &[
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_RUSTFLAGS",
    "RUSTDOCFLAGS",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CLIPPY_CONF_DIR",
];

/// The gates in run order, cheapest first. The order is deliberate and is
/// pinned by `tests/registry.rs`.
#[must_use]
pub fn registry() -> Vec<Gate> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let preflight_cache_paths: Vec<PathBuf> = crate::tools::resolve_in(&path, "cargo-verus")
        .and_then(|cargo_verus| crate::tools::cargo_verus_sibling(&cargo_verus))
        .into_iter()
        .collect();
    vec![
        Gate {
            name: "preflight",
            run: Box::new(gates::preflight),
            inputs: Inputs::Globs(&["**/Cargo.toml"]),
            env: &[],
            // Verus, its cargo driver and verusfmt too: preflight checks
            // them once a Verus entry is declared, and is cached on main.
            tools: &[
                "cargo",
                "rustfmt",
                "cargo-clippy",
                "git",
                "verus",
                "cargo-verus",
                "verusfmt",
            ],
            // `cargo-verus` runs this sibling, not the unrelated `verus`
            // selected from PATH. Its contents decide the pin check.
            extra_paths: &[],
            cache_paths: Box::leak(preflight_cache_paths.into_boxed_slice()),
            ignored_inputs: &[],
            cacheable: true,
            cache_on_main: true,
            blocked: None,
            decl: "",
        },
        Gate {
            name: "fmt",
            run: Box::new(gates::fmt),
            inputs: Inputs::Globs(&[
                "**/*.rs",
                "**/rustfmt.toml",
                "**/.rustfmt.toml",
                "**/Cargo.toml",
            ]),
            env: &["RUSTFMT"],
            tools: &["cargo", "rustfmt", "verusfmt"],
            extra_paths: &[],
            cache_paths: &[],
            ignored_inputs: &[],
            cacheable: true,
            cache_on_main: false,
            blocked: fmt_gate::BLOCKED,
            decl: "",
        },
        // Whole-tree text scans: cheap, and they read every file git lists.
        scan("placeholder-scan", gates::stub_scan, true), // disciplines:allow-placeholder (the gate's documented name)
        scan("sleep-scan", gates::sleep_scan, true),
        // Decided by git refs, which no cache key sees.
        scan("changelog", gates::changelog, false),
        Gate {
            name: "lint",
            run: Box::new(gates::lint),
            inputs: Inputs::Tree,
            env: RUST_ENV,
            tools: &["cargo", "cargo-clippy", "rustc"],
            extra_paths: &[],
            cache_paths: &[],
            ignored_inputs: &[],
            cacheable: true,
            cache_on_main: false,
            blocked: None,
            decl: "",
        },
        Gate {
            name: "layers",
            run: Box::new(gates::layers),
            inputs: Inputs::Tree,
            env: RUST_ENV,
            tools: &["cargo"],
            extra_paths: &[],
            cache_paths: &[],
            ignored_inputs: &[],
            cacheable: true,
            cache_on_main: false,
            blocked: None,
            decl: "",
        },
        Gate {
            name: "no-std",
            run: Box::new(gates::no_std),
            inputs: Inputs::Tree,
            env: RUST_ENV,
            tools: &["cargo", "rustc"],
            extra_paths: &[],
            cache_paths: &[],
            ignored_inputs: &[],
            cacheable: true,
            cache_on_main: false,
            blocked: layers::NO_STD_BLOCKED,
            decl: "",
        },
        Gate {
            name: "duplication",
            run: Box::new(gates::duplication),
            inputs: Inputs::Globs(&["**/*.rs", duplication::BASELINE]),
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
            run: Box::new(gates::test),
            inputs: Inputs::Tree,
            env: RUST_ENV,
            tools: &["cargo", "rustc"],
            extra_paths: &[],
            cache_paths: &[],
            ignored_inputs: &[],
            cacheable: true,
            cache_on_main: false,
            blocked: None,
            decl: "",
        },
    ]
}

/// A whole-tree text scan: its input is the tree, its only tool git.
/// `cacheable: false` also keeps it off the cache on main. Public so a
/// repository stage declares its scans exactly like the template.
#[must_use]
pub fn scan(name: &'static str, run: fn(&Path) -> Result<(), String>, cacheable: bool) -> Gate {
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

/// Leaked: proof gates are built once per run of a short-lived CLI, and
/// `Gate` holds `'static` declarations like the static registry.
fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

/// The gate for one proof entry: keyed on its package and the members it
/// reaches, trusted on main (spec 2026-10-09, decision 1).
#[must_use]
pub fn proof_gate(p: proofs::Proof, budget: u64, skip: Option<&'static str>) -> Gate {
    let globs: Vec<&'static str> = p.globs().into_iter().map(leak).collect();
    let mut tools = vec!["cargo", "prlimit", "timeout"];
    tools.extend(p.tools.iter().cloned().map(leak));
    let extra_paths: Vec<&'static str> = p.extra_paths.iter().cloned().map(leak).collect();
    let mut cache_paths = Vec::new();
    let mut env: Vec<&'static str> = RUST_ENV.to_vec();
    if p.kind == proofs::Kind::Verus {
        env.extend(proofs::VERUS_ENV);
        let path = std::env::var_os("PATH").unwrap_or_default();
        if let Some(bin) = crate::tools::resolve_in(&path, "cargo-verus") {
            if let Some(verus) = crate::tools::cargo_verus_sibling(&bin) {
                cache_paths.push(verus);
            }
            cache_paths.extend(proofs::verus_install_files(&bin));
        }
    }
    Gate {
        name: leak(p.gate_name()),
        decl: leak(p.decl.clone()),
        run: Box::new(move |root| gates::proof(root, &p, budget)),
        inputs: Inputs::Globs(Box::leak(globs.into_boxed_slice())),
        env: Box::leak(env.into_boxed_slice()),
        tools: Box::leak(tools.into_boxed_slice()),
        extra_paths: Box::leak(extra_paths.into_boxed_slice()),
        cache_paths: Box::leak(cache_paths.into_boxed_slice()),
        ignored_inputs: &[],
        cacheable: true,
        cache_on_main: true,
        blocked: skip,
    }
}

/// A declared proof with the memory budget its gate runs under.
#[derive(Debug, Clone)]
pub struct ProofSpec {
    pub proof: proofs::Proof,
    pub budget: u64,
}

/// The declared proofs, each with its budget, in declaration order.
///
/// # Errors
/// As for `proof_gates`.
pub fn proof_specs(root: &Path) -> Result<Vec<ProofSpec>, String> {
    let declared = gates::declared_proofs(root)?;
    let mem = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|m| proofs::mem_total(&m));
    Ok(declared
        .proofs
        .into_iter()
        .map(|p| {
            let budget = proofs::budget(declared.budget, mem, p.memory);
            ProofSpec { proof: p, budget }
        })
        .collect())
}

/// The declared proof gates, in declaration order.
///
/// # Errors
/// `cargo metadata` failing, or a declaration error (preflight reports the
/// same).
pub fn proof_gates(root: &Path, skip: Option<&'static str>) -> Result<Vec<Gate>, String> {
    Ok(proof_specs(root)?
        .into_iter()
        .map(|s| proof_gate(s.proof, s.budget, skip))
        .collect())
}

/// The contract key of a `spine = "contracts"` gate: its normal key with
/// the tooth's globs, and each spine file's interface text in place of the
/// spine's files.
fn contract_key(
    root: &Path,
    gate: &Gate,
    contract: &proofs::Contract,
    probe: &cache::key::Probe,
) -> Result<String, String> {
    let mut decl = gate.decl.to_string();
    for dir in &contract.spine_dirs {
        let files = cache::contracts::spine_sources(root, dir)?;
        for file in files {
            let text =
                std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
            let shown = file
                .strip_prefix(root)
                .unwrap_or(&file)
                .display()
                .to_string();
            decl.push_str("\nspine-interface ");
            decl.push_str(&cache::contracts::interface_text(&shown, &text)?);
        }
    }
    let globs: Vec<&'static str> = contract.globs.iter().cloned().map(leak).collect();
    let spec = cache::key::KeySpec {
        inputs: cache::key::Inputs::Globs(Box::leak(globs.into_boxed_slice())),
        decl: &decl,
        ..gate.key_spec()
    };
    cache::key::key(root, &spec, probe)
}

/// The static registry, then the proof gates.
///
/// # Errors
/// A malformed proof declaration. It must fail the gate instead of leaving
/// the proof gates out.
pub fn all_gates(root: &Path, skip: Option<&'static str>) -> Result<Vec<Gate>, String> {
    all_gates_with(registry, root, skip)
}

/// [`all_gates`] for a project runner's own registry.
///
/// # Errors
/// As for [`all_gates`].
pub fn all_gates_with(
    registry: fn() -> Vec<Gate>,
    root: &Path,
    skip: Option<&'static str>,
) -> Result<Vec<Gate>, String> {
    let mut gates = registry();
    gates.extend(proof_gates(root, skip)?);
    Ok(gates)
}

/// From this crate's directory to the workspace root: `..` for
/// `<root>/xtask`, `../..` for `<root>/tools/xtask`.
pub const ROOT_FROM_MANIFEST: &str = "..";

#[must_use]
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(ROOT_FROM_MANIFEST)
}

/// The repository holding this crate: where `DEFERRED.md` and `gates/`
/// live. The workspace root when the runner is the repository's workspace;
/// above it when the runner is a separate tooling workspace.
///
/// # Panics
/// When this crate is not inside a git work tree.
#[must_use]
pub fn repository_root() -> PathBuf {
    toplevel(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap_or_else(|e| panic!("{e}"))
}

/// The top of the git work tree holding `dir`.
///
/// # Errors
/// When git fails or `dir` is outside a work tree.
pub fn toplevel(dir: &Path) -> Result<PathBuf, String> {
    let out = git::command()
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(dir)
        .output()
        .map_err(|e| format!("git rev-parse: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{}: not in a git work tree: {}",
            dir.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(PathBuf::from(
        String::from_utf8_lossy(&out.stdout).trim_end_matches('\n'),
    ))
}

pub const USAGE: &str = "usage: cargo xtask gate [--only <name>] [--no-cache] [--no-proofs] | gate --list\n       cargo xtask proofs [--only <name>] [--no-cache]\n       cargo xtask cache clear\n       cargo xtask dup report|sweep|bless …\n       cargo xtask ratchet";

/// Set (to `1`, or any non-empty value but `0`): like `--no-cache`, every
/// runnable gate runs (passes are still recorded).
pub const NO_CACHE_ENV: &str = "DISCIPLINES_GATE_NO_CACHE";

/// Set to exactly `main` by the merge hooks: the gate is deciding what lands
/// on main, so gates with `cache_on_main: false` run instead of reading the
/// cache.
pub const CONTEXT_ENV: &str = "DISCIPLINES_GATE_CONTEXT";

/// Whether this run decides what lands on a protected branch: the hooks say so
/// through [`CONTEXT_ENV`], and the runner also checks HEAD itself so hooks
/// copied before the variable existed are covered. Literal `main` is always
/// protected; `main_branch` may name one additional protected branch. With no
/// branch (detached HEAD, or `git` failed) only the variable decides.
#[must_use]
pub fn is_main_context(
    env_value: Option<&std::ffi::OsStr>,
    branch: Option<&str>,
    main_branch: &str,
) -> bool {
    env_value.is_some_and(|v| v == "main")
        || branch.is_some_and(|b| b == "main" || b == main_branch)
}

/// Names the main branch for the runner's own check, like the hooks'
/// `${DISCIPLINES_MAIN_BRANCH:-main}`.
pub const MAIN_BRANCH_ENV: &str = "DISCIPLINES_MAIN_BRANCH";

/// The main branch's name from [`MAIN_BRANCH_ENV`]'s value: unset and empty
/// both mean `main`. A non-UTF-8 value never equals a branch name
/// `current_branch` returns (those are UTF-8), so only the context variable
/// decides then.
#[must_use]
pub fn main_branch_name(value: Option<std::ffi::OsString>) -> String {
    value
        .filter(|v| !v.is_empty())
        .map_or_else(|| "main".to_string(), |v| v.to_string_lossy().into_owned())
}

fn current_branch(root: &Path) -> Option<String> {
    let out = git::command()
        .args(["symbolic-ref", "--short", "-q", "HEAD"])
        .current_dir(root)
        .output()
        .ok()?;
    let name = String::from_utf8(out.stdout).ok()?;
    let name = name.trim();
    (out.status.success() && !name.is_empty()).then(|| name.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Every gate.
    All,
    /// Every gate; proof gates print `SKIP proof:<name>: --no-proofs`.
    /// Refused in the main context.
    NoProofs,
    /// Proof gates only (`cargo xtask proofs`).
    ProofsOnly,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Gate {
        only: Option<String>,
        no_cache: bool,
        scope: Scope,
    },
    List,
    CacheClear,
    Dup(duplication::cli::DupArgs),
    /// Each lint table's clippy allows with their current counts.
    Ratchet,
}

/// # Errors
/// The usage text, or an unknown gate name with the known ones.
pub fn parse_args(args: &[String]) -> Result<Command, String> {
    parse_args_with(registry, args)
}

/// [`parse_args`] for a project runner's own registry: `--only` names are
/// checked against it.
///
/// # Errors
/// As for [`parse_args`].
pub fn parse_args_with(registry: fn() -> Vec<Gate>, args: &[String]) -> Result<Command, String> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["gate", rest @ ..] => parse_gate(registry, rest),
        ["proofs", rest @ ..] => parse_proofs(rest),
        ["cache", "clear"] => Ok(Command::CacheClear),
        ["dup", rest @ ..] => duplication::cli::parse(rest).map(Command::Dup),
        ["ratchet"] => Ok(Command::Ratchet),
        _ => Err(USAGE.to_string()),
    }
}

fn parse_gate(registry: fn() -> Vec<Gate>, rest: &[&str]) -> Result<Command, String> {
    let (mut only, mut list, mut no_cache, mut no_proofs) = (None, false, false, false);
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        match *arg {
            "--list" => list = true,
            "--no-cache" => no_cache = true,
            "--no-proofs" => no_proofs = true,
            "--only" => {
                if only.is_some() {
                    return Err("--only given twice".to_string());
                }
                let name = *it.next().ok_or_else(|| USAGE.to_string())?;
                let names: Vec<&str> = registry().iter().map(|g| g.name).collect();
                if !names.contains(&name) && !name.starts_with("proof:") {
                    return Err(format!(
                        "unknown gate `{name}`; known gates: {}",
                        names.join(", ")
                    ));
                }
                only = Some(name.to_string());
            }
            _ => return Err(USAGE.to_string()),
        }
    }
    match (list, only.is_some() || no_cache || no_proofs) {
        (true, true) => Err(USAGE.to_string()),
        (true, false) => Ok(Command::List),
        (false, _) => Ok(Command::Gate {
            only,
            no_cache,
            scope: if no_proofs {
                Scope::NoProofs
            } else {
                Scope::All
            },
        }),
    }
}

/// `proofs [--only <name>] [--no-cache]`: `<name>` with or without the
/// `proof:` prefix.
fn parse_proofs(rest: &[&str]) -> Result<Command, String> {
    let (mut only, mut no_cache) = (None, false);
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        match *arg {
            "--no-cache" => no_cache = true,
            "--only" => {
                if only.is_some() {
                    return Err("--only given twice".to_string());
                }
                let name = *it.next().ok_or_else(|| USAGE.to_string())?;
                only = Some(if name.starts_with("proof:") {
                    name.to_string()
                } else {
                    format!("proof:{name}")
                });
            }
            _ => return Err(USAGE.to_string()),
        }
    }
    Ok(Command::Gate {
        only,
        no_cache,
        scope: Scope::ProofsOnly,
    })
}

/// The gates a `gate`/`proofs` run covers, or the run's verdict when it ends
/// before any gate: `--no-proofs` on main, no proofs declared, a proof
/// declaration error under `proofs`, or an unknown `--only` name.
fn select(
    runner: &Runner,
    scope: Scope,
    only: Option<&str>,
    main: bool,
    root: &Path,
) -> Result<Vec<Gate>, bool> {
    if scope == Scope::NoProofs && main {
        eprintln!("--no-proofs is refused: this run decides what lands on main");
        return Err(false);
    }
    let gates = match scope {
        Scope::All => all_gates_with(runner.registry, root, None),
        Scope::NoProofs => all_gates_with(runner.registry, root, Some("--no-proofs")),
        Scope::ProofsOnly => match proof_gates(root, None) {
            Ok(g) if g.is_empty() => {
                eprintln!("no proofs declared");
                return Err(true);
            }
            result => result,
        },
    };
    let gates = match gates {
        Ok(gates) => gates,
        Err(error) => {
            eprintln!("proofs: {error}");
            return Err(false);
        }
    };
    if let Some(o) = only
        && !gates.iter().any(|g| g.name == o)
    {
        let names: Vec<&str> = gates.iter().map(|g| g.name).collect();
        eprintln!("unknown gate `{o}`; known gates: {}", names.join(", "));
        return Err(false);
    }
    Ok(gates)
}

/// What a gate run reads besides the gate itself.
struct RunCtx<'a> {
    root: &'a Path,
    store: Option<&'a cache::store::Store>,
    refresh: bool,
    main: bool,
    probe: Option<cache::key::Probe>,
    /// Proof gates by name, with their declarations; every declared one,
    /// since prerequisites count even when `--only` filters the run.
    specs: BTreeMap<&'static str, ProofSpec>,
    proof_gates: BTreeMap<&'static str, Gate>,
}

impl RunCtx<'_> {
    fn key(&self, g: &Gate) -> Result<String, String> {
        match &self.probe {
            Some(probe) => cache::key::key(self.root, &g.key_spec(), probe),
            None => Err("no key probe (cache off)".to_string()),
        }
    }

    fn cache_of(&self, g: &Gate) -> runner::Cache<'_> {
        runner::cache_for(g, self.store, self.refresh, self.main)
    }

    fn contract(&self, g: &Gate) -> Option<&proofs::Contract> {
        self.specs.get(g.name)?.proof.contract.as_ref()
    }

    fn contract_key_of(&self, g: &Gate) -> Result<String, String> {
        match (&self.probe, self.contract(g)) {
            (Some(probe), Some(c)) => contract_key(self.root, g, c, probe),
            _ => Err("no contract".to_string()),
        }
    }

    /// The spine proof `name` has a passing record for the spine as it is
    /// now.
    fn prerequisite_holds(&self, name: &str) -> bool {
        let Some(store) = self.store else {
            return false;
        };
        self.proof_gates.get(name).is_some_and(|g| {
            self.key(g)
                .is_ok_and(|k| store.hit(g.name, &k).is_ok_and(|h| h.is_some()))
        })
    }

    fn record_duration(&self, gate: &str, secs: u64) {
        if let Some(store) = self.store
            && let Err(e) = store.record_duration(gate, secs)
        {
            eprintln!("cache: {e}");
        }
    }
}

/// `cargo xtask gate` and `cargo xtask proofs`: every selected gate, with
/// the cache. Proof gates run last, together (`batch`).
fn run_gates(
    runner: &Runner,
    only: Option<&str>,
    no_cache: bool,
    scope: Scope,
    root: &Path,
) -> bool {
    let refresh =
        no_cache || std::env::var_os(NO_CACHE_ENV).is_some_and(|v| !v.is_empty() && v != "0");
    let store = match cache::store::Store::open(root) {
        Ok(store) => Some(store),
        Err(e) => {
            eprintln!("cache: {e}; running every gate");
            None
        }
    };
    let main_branch = main_branch_name(std::env::var_os(MAIN_BRANCH_ENV));
    let main = is_main_context(
        std::env::var_os(CONTEXT_ENV).as_deref(),
        current_branch(root).as_deref(),
        &main_branch,
    );
    run_scope::reset();
    let gates = match select(runner, scope, only, main, root) {
        Ok(gates) => gates,
        Err(verdict) => return verdict,
    };
    // The probe runs rustc, so build it only when some cache is in use.
    // `run_gate` never asks for a key under `Off`, so `key`'s `Err` is
    // unreachable; if it were reached the gate would just run.
    let specs: BTreeMap<&'static str, ProofSpec> = match proof_specs(root) {
        Ok(specs) => specs
            .into_iter()
            .map(|s| (leak(s.proof.gate_name()), s))
            .collect(),
        Err(error) => {
            eprintln!("proofs: {error}");
            return false;
        }
    };
    let proof_gates: BTreeMap<&'static str, Gate> = match proof_gates(root, None) {
        Ok(gates) => gates.into_iter().map(|gate| (gate.name, gate)).collect(),
        Err(error) => {
            eprintln!("proofs: {error}");
            return false;
        }
    };
    let ctx = RunCtx {
        root,
        store: store.as_ref(),
        refresh,
        main,
        probe: store
            .is_some()
            .then(|| cache::key::Probe::from_env(root, runner.dirs.clone())),
        proof_gates,
        specs,
    };
    let selected: Vec<Gate> = gates
        .into_iter()
        .filter(|g| only.is_none_or(|o| o == g.name))
        .collect();
    let position: Vec<&'static str> = selected.iter().map(|g| g.name).collect();
    let (proof_list, others): (Vec<Gate>, Vec<Gate>) = selected
        .into_iter()
        .partition(|g| ctx.specs.contains_key(g.name));
    let started = std::time::Instant::now();
    let mut run = Ran {
        started,
        failed: Vec::new(),
        not_run: Vec::new(),
        times: Vec::new(),
        spans: Vec::new(),
    };
    run_wave(&ctx, &others, &mut run);
    // Contract-keyed proofs go second, once the spine proofs they rely on
    // have recorded their passes.
    // A contract-keyed proof whose spine proofs already hold needs nothing
    // from the first wave, so it joins it.
    let (keyed, plain): (Vec<Gate>, Vec<Gate>) = proof_list.into_iter().partition(|g| {
        ctx.contract(g).is_some_and(|c| {
            !c.prerequisites
                .iter()
                .all(|name| ctx.prerequisite_holds(name))
        })
    });
    run_wave(&ctx, &plain, &mut run);
    run_wave(&ctx, &keyed, &mut run);
    let Ran {
        mut failed,
        not_run,
        times,
        spans,
        ..
    } = run;
    failed.sort_by_key(|n| position.iter().position(|p| p == n));
    for line in runner::summary(started.elapsed(), timing::held_total(&spans), &times) {
        eprintln!("{line}");
    }
    if failed.is_empty() {
        eprintln!("all gates passed");
    } else {
        eprintln!("failed: {}", failed.join(", "));
    }
    if !not_run.is_empty() {
        eprintln!("not run: {}", not_run.join(", "));
    }
    failed.is_empty()
}

/// What a gate run collects as its gates end.
struct Ran {
    started: std::time::Instant,
    failed: Vec<&'static str>,
    /// Gates left unstarted because an earlier gate failed (fail fast).
    not_run: Vec<&'static str>,
    /// Each gate that ran, with its time less atc's holds.
    times: Vec<(&'static str, Duration)>,
    spans: Vec<timing::Span>,
}

/// Runs `wave`: each gate is looked up first; what must run runs one at a
/// time, or, for two or more proofs, in parallel under the budget. Fail
/// fast: after a failure, in this wave or an earlier one, no gate starts.
fn run_wave(ctx: &RunCtx, wave: &[Gate], run: &mut Ran) {
    if !run.failed.is_empty() {
        run.not_run.extend(wave.iter().map(|g| g.name));
        return;
    }
    let key = |g: &Gate| ctx.key(g);
    let alt_keys: Vec<Box<dyn Fn() -> Result<String, String> + '_>> = wave
        .iter()
        .map(|g| Box::new(move || ctx.contract_key_of(g)) as Box<dyn Fn() -> _>)
        .collect();
    // Each prerequisite's answer is computed once per wave, and only when a
    // gate's full key missed.
    let held: std::cell::RefCell<BTreeMap<String, bool>> = std::cell::RefCell::default();
    let holds = |c: &proofs::Contract| {
        !ctx.main
            && c.prerequisites.iter().all(|name| {
                if let Some(h) = held.borrow().get(name) {
                    return *h;
                }
                let h = ctx.prerequisite_holds(name);
                held.borrow_mut().insert(name.clone(), h);
                h
            })
    };
    let lookups: Vec<Box<dyn Fn() -> bool + '_>> = wave
        .iter()
        .map(|g| Box::new(move || ctx.contract(g).is_some_and(holds)) as Box<dyn Fn() -> bool>)
        .collect();
    let alts: Vec<Option<runner::Alt>> = wave
        .iter()
        .zip(alt_keys.iter().zip(&lookups))
        .map(|(g, (k, l))| {
            ctx.contract(g).map(|_| runner::Alt {
                record_as: format!("{}~contracts", g.name),
                key: k.as_ref(),
                lookup: l.as_ref(),
            })
        })
        .collect();
    let Some(mut slots) = prepare_wave(ctx, wave, &key, &alts, run) else {
        return;
    };
    let waiting: Vec<usize> = (0..wave.len()).filter(|i| slots[*i].is_some()).collect();
    // Every gate of the wave was looked up before any runs.
    run_scope::add(waiting.iter().map(|i| wave[*i].name));
    // `header`: a captured run prints its `== gate` line with its log; a
    // streaming one printed it before running.
    let mut finish =
        |i: usize, result: Result<(), String>, log: &str, ended: Ended, header: bool| -> bool {
            let g = &wave[i];
            if header {
                eprintln!("== {}", g.name);
            }
            eprint!("{log}");
            let Some(pending) = slots[i].take() else {
                return true;
            };
            let steps: Vec<timing::Step> = ended.steps.iter().map(|(_, s)| s.clone()).collect();
            let parts = timing::Parts::of(ended.elapsed, &steps);
            run.spans.push(timing::span(
                run.started,
                ended.start,
                ended.elapsed,
                &ended.steps,
            ));
            let report = runner::conclude(g, pending, result, &key, alts[i].as_ref());
            if matches!(
                report.outcome,
                runner::Outcome::Passed | runner::Outcome::Failed(_)
            ) {
                run.times.push((g.name, parts.ran()));
            }
            let proof = ctx.specs.contains_key(g.name);
            // Proofs record their time: it orders the next batch.
            if proof {
                ctx.record_duration(g.name, parts.ran().as_secs());
            }
            let passed = print_report(g.name, &report, Some(parts.suffix(proof)));
            if !passed {
                run.failed.push(g.name);
            }
            passed
        };
    let batchable = waiting.len() > 1
        && waiting
            .iter()
            .all(|i| ctx.specs.contains_key(wave[*i].name));
    if !batchable {
        let mut rest = waiting.into_iter();
        for i in rest.by_ref() {
            eprintln!("== {}", wave[i].name);
            let (result, ended) = timed(&wave[i], ctx.root);
            if !finish(i, result, "", ended, false) {
                break;
            }
        }
        run.not_run.extend(rest.map(|i| wave[i].name));
        return;
    }
    let mut skipped = Vec::new();
    run_batch(ctx, wave, &waiting, &mut |d| {
        // The batch stops starting entries after a failure; those never ran,
        // so they are neither concluded nor timed.
        if !d.ran {
            skipped.push(wave[d.index].name);
            return;
        }
        let ended = Ended {
            start: d.start,
            elapsed: d.elapsed,
            steps: d.steps,
        };
        let _ = finish(d.index, d.result, &d.log, ended, true);
    });
    run.not_run.extend(skipped);
}

/// Looks up every gate of `wave` before any runs: `Some` slot for each gate
/// that must run. Fail fast: `None` once a lookup reports a failure, with
/// the wave's other gates recorded as not run.
fn prepare_wave<'c>(
    ctx: &'c RunCtx,
    wave: &[Gate],
    key: &dyn Fn(&Gate) -> Result<String, String>,
    alts: &[Option<runner::Alt>],
    run: &mut Ran,
) -> Option<Vec<Option<runner::Pending<'c>>>> {
    let mut slots = Vec::new();
    for (g, alt) in wave.iter().zip(alts) {
        if !run.failed.is_empty() {
            break;
        }
        match runner::prepare(g, &ctx.cache_of(g), key, alt.as_ref()) {
            Err(report) => {
                eprintln!("== {}", g.name);
                if !print_report(g.name, &report, None) {
                    run.failed.push(g.name);
                }
                slots.push(None);
            }
            Ok(pending) => slots.push(Some(pending)),
        }
    }
    if run.failed.is_empty() {
        Some(slots)
    } else {
        let looked_up = slots.len();
        let unfinished = wave
            .iter()
            .enumerate()
            .filter(|(i, _)| *i >= looked_up || slots[*i].is_some())
            .map(|(_, g)| g.name);
        run.not_run.extend(unfinished);
        None
    }
}

/// When a gate that ran started, its wall time, and its atc steps.
struct Ended {
    start: std::time::Instant,
    elapsed: Duration,
    steps: Vec<(std::time::Instant, timing::Step)>,
}

/// Runs `g` on this thread, with the atc steps it recorded.
fn timed(g: &Gate, root: &Path) -> (Result<(), String>, Ended) {
    let _ = timing::take();
    let start = std::time::Instant::now();
    let result = (g.run)(root);
    let ended = Ended {
        start,
        elapsed: start.elapsed(),
        steps: timing::take(),
    };
    (result, ended)
}

/// Two or more pending proofs of `wave` (`waiting`, by index) run in
/// parallel under the budget; `finish` concludes each as it ends.
fn run_batch(ctx: &RunCtx, wave: &[Gate], waiting: &[usize], finish: &mut dyn FnMut(batch::Done)) {
    let names: Vec<&str> = waiting.iter().map(|i| wave[*i].name).collect();
    let durations = ctx
        .store
        .map(cache::store::Store::durations)
        .unwrap_or_default();
    let order = proofs::schedule::order(&names, &durations);
    let budget = waiting
        .iter()
        .filter_map(|i| ctx.specs.get(wave[*i].name).map(|s| s.budget))
        .max()
        .unwrap_or(0);
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let entries: Vec<batch::Waiting> = waiting
        .iter()
        .filter_map(|i| {
            ctx.specs.get(wave[*i].name).map(|s| batch::Waiting {
                index: *i,
                proof: s.proof.clone(),
            })
        })
        .collect();
    let runner =
        |root: &Path, p: &proofs::Proof, jobs: usize| gates::proof_run(root, p, jobs, true);
    batch::run(ctx.root, entries, &order, cores, budget, &runner, finish);
}

/// Prints a gate's warnings and outcome, with its time when it ran
/// (`timing::Parts::suffix`); whether it did not fail.
fn print_report(name: &str, report: &runner::Report, took: Option<String>) -> bool {
    let took = took.unwrap_or_default();
    for warning in &report.warnings {
        eprintln!("{warning}");
    }
    let ago = |when| cache::store::ago(when, cache::store::now());
    match &report.outcome {
        runner::Outcome::Skipped(reason) => eprintln!("SKIP {name}: {reason}"),
        runner::Outcome::Cached(when) => {
            eprintln!("CACHED {name}: inputs unchanged since {}", ago(*when));
        }
        runner::Outcome::CachedByContracts(when) => eprintln!(
            "CACHED {name}: spine contracts and tooth inputs unchanged since {}",
            ago(*when)
        ),
        runner::Outcome::Passed => eprintln!("PASS {name}{took}"),
        runner::Outcome::Failed(msg) => {
            eprintln!("FAIL {name}{took}:\n{msg}");
            return false;
        }
    }
    true
}

/// Runs a parsed command. Failure policy: fail fast. Gates run in registry
/// order and the run stops at the first failure; the summary names the
/// gates that did not run.
#[must_use]
pub fn execute(cmd: &Command, root: &Path) -> bool {
    execute_with(&Runner::template(), cmd, root)
}

/// A gate runner: its registry, and the crate directories it is built from
/// (every one keys every gate, so a change to gate code re-runs them all).
pub struct Runner {
    pub registry: fn() -> Vec<Gate>,
    /// The crate holding `main` first.
    pub dirs: Vec<PathBuf>,
}

impl Runner {
    /// This crate, run as the project's runner.
    #[must_use]
    pub fn template() -> Runner {
        Runner {
            registry,
            dirs: vec![PathBuf::from(env!("CARGO_MANIFEST_DIR"))],
        }
    }

    /// A project runner that uses this crate as a library: `registry` is
    /// its own, `dir` its crate's `CARGO_MANIFEST_DIR`.
    #[must_use]
    pub fn extending(registry: fn() -> Vec<Gate>, dir: PathBuf) -> Runner {
        Runner {
            registry,
            dirs: vec![dir, PathBuf::from(env!("CARGO_MANIFEST_DIR"))],
        }
    }
}

/// [`execute`] for a project runner ([`Runner::extending`]).
#[must_use]
pub fn execute_with(runner: &Runner, cmd: &Command, root: &Path) -> bool {
    match cmd {
        Command::List => match all_gates_with(runner.registry, root, None) {
            Ok(gates) => {
                for gate in gates {
                    println!("{}", gate.name);
                }
                true
            }
            Err(error) => {
                eprintln!("proofs: {error}");
                false
            }
        },
        Command::Gate {
            only,
            no_cache,
            scope,
        } => run_gates(runner, only.as_deref(), *no_cache, *scope, root),
        Command::CacheClear => {
            match cache::store::Store::open(root).and_then(|s| s.clear().map(|()| s)) {
                Ok(store) => {
                    println!("cleared {}", store.dir().display());
                    true
                }
                Err(e) => {
                    eprintln!("cache: {e}");
                    false
                }
            }
        }
        Command::Dup(args) => print_or_fail(duplication::cli::run(args, root)),
        Command::Ratchet => print_or_fail(gates::ratchet_measure(root)),
    }
}

/// Prints a subcommand's output, or its error on stderr; whether it worked.
fn print_or_fail(result: Result<String, String>) -> bool {
    match result {
        Ok(out) => {
            print!("{out}");
            true
        }
        Err(msg) => {
            eprintln!("{msg}");
            false
        }
    }
}
