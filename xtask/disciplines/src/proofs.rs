// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The proof tier: `[[workspace.metadata.disciplines.proof]]` entries in the
//! root manifest become `proof:<name>` gates. Pure: parsing the
//! declarations out of `cargo metadata`, the job count, the argv, and
//! reading the verifier's output. `gates.rs` spawns; `lib.rs` registers.
use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

pub mod cgroup;
pub mod schedule;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// `cargo kani`, one run per entry, harnesses in parallel.
    Kani,
    /// `cargo verus focus` in the package directory: the package alone,
    /// against its dependencies' specs.
    Verus,
    /// Any other prover, run once as given, in the package directory.
    Command(Vec<String>),
}

impl Kind {
    /// A prover that can prove a tooth's kernel and core crates (layers
    /// gate, proof coverage). A command entry runs an arbitrary tool, so it
    /// does not count.
    #[must_use]
    pub fn is_core_prover(&self) -> bool {
        matches!(self, Kind::Kani | Kind::Verus)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub name: String,
    pub kind: Kind,
    pub package: String,
    /// The package directory relative to the workspace root, `/`-separated;
    /// empty for the root package.
    pub dir: String,
    /// The package's directory and those of every member it reaches through
    /// path dependencies (any kind), sorted and unique. Just the root (`""`,
    /// the whole tree) when it reaches a path dependency that is not a
    /// member, or the root manifest patches with paths: `cargo metadata
    /// --no-deps` cannot see what those depend on.
    pub dirs: Vec<String>,
    /// Extra tree globs the proof reads (`inputs`), e.g. `include_str!` data.
    pub extra_globs: Vec<String>,
    /// Files or directories outside the tree it reads (`extra_paths`).
    pub extra_paths: Vec<String>,
    /// Binaries fingerprinted in its key: `cargo-kani`, or the command's
    /// program (and `cargo-<sub>` for `cargo <sub>`), plus declared `tools`.
    pub tools: Vec<String>,
    /// Bytes: each process's address-space cap under prlimit; per harness
    /// (Kani) or for the whole run (command) under a cgroup.
    pub memory: u64,
    /// Kani: per harness, wall clock. Verus and command: CPU seconds per
    /// process ([`CPU_SH`]).
    pub timeout_s: u64,
    /// Kani only: the whole `cargo kani` run, compile included.
    pub run_timeout_s: u64,
    /// Kani only: `-Z` features (`UNSTABLE`), in declaration order.
    pub unstable: Vec<String>,
    /// `spine = "contracts"`: the narrowed key; `None` otherwise.
    pub contract: Option<Contract>,
    /// `spine = "contracts"`: also recorded under the contract key.
    pub spine: bool,
    /// Command only, `gpu = true`: atc learns its GPU use instead of being
    /// told it has none. Scheduling only, so not part of `decl`.
    pub gpu: bool,
    /// Kani: the longest one harness may take (`harness_budget`, default
    /// 60 s, `rust.md` §5). A harness over it is reported as a warning.
    pub harness_budget_s: u64,
    /// The entry's fields in canonical form: part of the key, so editing the
    /// entry re-runs it.
    pub decl: String,
    /// Where Verus entries build: `verus/<workspace>` under cargo's build
    /// directory (`build_directory` in `cargo metadata`, else
    /// `target_directory`), `<workspace>` a hash of the workspace root, so
    /// workspaces sharing a build or target directory never share one.
    pub verus_root: String,
}

/// The narrowed key of a `spine = "contracts"` entry (`runner.md`, Proof
/// tier): the tooth's own inputs, and the spine read through its contracts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contract {
    /// Tooth dirs (`<d>/**`), the entry's `inputs`, the lock and toolchain
    /// files, and each spine crate's `Cargo.toml`.
    pub globs: Vec<String>,
    /// The spine crates' directories, sorted.
    pub spine_dirs: Vec<String>,
    /// `proof:<name>` of every kani entry whose package is one of those
    /// spine crates.
    pub prerequisites: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Declared {
    pub budget: Option<u64>,
    /// `gpu = true`: the repository's cargo gates use the GPU (shaders, GPU
    /// tests), so atc learns their GPU use instead of being told none.
    pub gpu: bool,
    pub proofs: Vec<Proof>,
}

/// The kani compiler runs under the cap too: a cold compile fails at 512M.
pub const MIN_MEMORY: u64 = 1 << 30;
pub const KANI_TIMEOUT_S: u64 = 300;
pub const COMMAND_TIMEOUT_S: u64 = 30 * 60;
pub const VERUS_TIMEOUT_S: u64 = 10 * 60;
/// A Verus entry's driver, with the package as `$1` and the entry's own
/// build directory as `$2`. `focus` verifies the package only; each
/// dependency's own entry proves it. Cargo skips a package it considers
/// fresh, and Verus then prints no results, so the package's artifacts are
/// cleaned first. The build directory is the entry's alone: a shared one
/// lets a tooth's run rebuild the spine as a dependency between the spine
/// entry's clean and its verification, leaving nothing to verify. It is
/// exported absolute, so build scripts running elsewhere read it right. One
/// thread: the reservation is one CPU, and the spikes measured no gain from
/// more (notes/2026-10-13-verus-spike-s2.md).
///
/// The first pass runs with `--no-cheating`, which rejects every place
/// Verus takes something on trust; a package with none is verified by it.
/// Otherwise [`VERUS_SECOND_PASS`] is printed and a plain pass follows:
/// [`verus_trust`] then requires a marker on each line the first pass named.
/// Both passes verify the library alone: a failing library stops cargo
/// before the binaries, whose trusted code the first pass would not list.
/// Both verify every item, `verus!` or not (`--no-external-by-default`,
/// deprecated in Verus; its removal fails the gate): code outside the macro
/// is otherwise trusted, and a trait impl there may break the trait's
/// `ensures`. Colour is off, so error lines start with `error`. Both passes
/// write Verus's VIR and impl-name logs to `log/` in the build directory,
/// which the gate then judges ([`crate::vir_trust`]).
pub const VERUS_SH: &str = r#"d="$2"; export CARGO_TARGET_DIR="$d" CARGO_BUILD_BUILD_DIR="$d" CARGO_TERM_COLOR=never; rm -rf "$d/log"; cargo clean -q -p "$1" || exit; cargo verus focus --lib -- --no-cheating --no-external-by-default --num-threads 1 --log vir --log impl-names --log-dir "$d/log" && exit 0; echo "xtask-verus: second pass"; cargo clean -q -p "$1" && exec cargo verus focus --lib -- --no-external-by-default --num-threads 1 --log vir --log impl-names --log-dir "$d/log""#;
/// The line between a Verus entry's two passes.
pub const VERUS_SECOND_PASS: &str = "xtask-verus: second pass";
/// Variables Verus reads that change its result: the solver it runs.
pub const VERUS_ENV: &[&str] = &["VERUS_Z3_PATH"];
/// The files in Verus's install directory that decide a result: the
/// verifier, its bundled solver and the verified standard library. Hashed
/// rather than the whole directory (thousands of files, over a gigabyte).
pub const VERUS_INSTALL_FILES: &[&str] = &["rust_verify", "z3", "vstd.vir"];
pub const KANI_RUN_TIMEOUT_S: u64 = 2 * 60 * 60;
/// One Kani harness's budget unless the entry declares `harness_budget`.
pub const KANI_HARNESS_BUDGET_S: u64 = 60;
/// Removed from every proof's environment: Kani and Verus pin their own
/// toolchains, and the workspace's `rust-toolchain.toml` must not win.
pub const DROPPED_ENV: &[&str] = &["RUSTUP_TOOLCHAIN"];
/// Kani's `-Z` features a proof entry may turn on (`unstable`).
pub const UNSTABLE: &[&str] = &["function-contracts", "loop-contracts", "stubbing"];
const FIELDS: &[&str] = &[
    "name",
    "kind",
    "package",
    "command",
    "memory",
    "timeout",
    "run_timeout",
    "inputs",
    "extra_paths",
    "tools",
    "unstable",
    "spine",
    "gpu",
    "harness_budget",
];

impl Proof {
    #[must_use]
    pub fn gate_name(&self) -> String {
        format!("proof:{}", self.name)
    }

    /// The tree inputs of the gate's key.
    #[must_use]
    pub fn globs(&self) -> Vec<String> {
        let mut globs: Vec<String> = self
            .dirs
            .iter()
            .map(|d| {
                if d.is_empty() {
                    "**".to_string()
                } else {
                    format!("{d}/**")
                }
            })
            .collect();
        globs.extend(self.extra_globs.iter().cloned());
        globs.extend(["Cargo.lock", "rust-toolchain.toml", "rust-toolchain"].map(String::from));
        globs
    }

    /// Where the driver runs, relative to the root: Kani from the root,
    /// Verus and a command from the package.
    #[must_use]
    pub fn workdir(&self) -> &str {
        match self.kind {
            Kind::Kani => "",
            Kind::Verus | Kind::Command(_) => &self.dir,
        }
    }
}

/// The repository's `gpu` flag alone, leniently: `false` for anything but
/// `true`. Gates other than `preflight` read it, and must not fail on a
/// declaration error that is `preflight`'s to report.
#[must_use]
pub fn repo_gpu(json: &str) -> bool {
    serde_json::from_str::<Value>(json)
        .ok()
        .and_then(|doc| {
            doc.get("metadata")?
                .get("disciplines")?
                .get("gpu")?
                .as_bool()
        })
        .unwrap_or(false)
}

/// # Errors
/// Unparsable JSON, a malformed `cargo metadata` document, a bad
/// `proof_memory_budget`, or any entry error (prefixed `proof entry <name>:`).
pub fn parse(json: &str) -> Result<Declared, String> {
    let doc: Value = serde_json::from_str(json).map_err(|e| format!("cargo metadata: {e}"))?;
    let disciplines = doc.get("metadata").and_then(|m| m.get("disciplines"));
    let budget = match disciplines.and_then(|d| d.get("proof_memory_budget")) {
        None => None,
        Some(v) => Some(
            v.as_str()
                .ok_or_else(|| "expected a string such as \"24G\"".to_string())
                .and_then(parse_size)
                .map_err(|e| format!("proof_memory_budget: {e}"))?,
        ),
    };
    let gpu = match disciplines.and_then(|d| d.get("gpu")) {
        None => false,
        Some(v) => v.as_bool().ok_or("gpu: expected true or false")?,
    };
    let Some(entries) = disciplines.and_then(|d| d.get("proof")) else {
        return Ok(Declared {
            budget,
            gpu,
            proofs: Vec::new(),
        });
    };
    let entries = entries
        .as_array()
        .ok_or("proof: expected `[[workspace.metadata.disciplines.proof]]` tables")?;
    let members = members(&doc)?;
    let verus_root = ["build_directory", "target_directory"]
        .iter()
        .find_map(|k| doc.get(*k).and_then(Value::as_str))
        .map(|dir| format!("{dir}/verus/{}", workspace_key(&doc)))
        .unwrap_or_default();
    let mut proofs: Vec<Proof> = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let mut proof = entry_of(entry, &members)
            .map_err(|e| format!("proof entry {}: {e}", label(entry, i)))?;
        if proof.kind == Kind::Verus && verus_root.is_empty() {
            return Err(format!(
                "proof entry `{}`: cargo metadata names no build or target directory",
                proof.name
            ));
        }
        proof.verus_root.clone_from(&verus_root);
        if proofs.iter().any(|p| p.name == proof.name) {
            return Err(format!("proof entry `{}`: duplicate name", proof.name));
        }
        proofs.push(proof);
    }
    for i in 0..proofs.len() {
        if !proofs[i].spine {
            continue;
        }
        let c = contract_of(&proofs[i], &proofs, &members)
            .map_err(|e| format!("proof entry `{}`: {e}", proofs[i].name))?;
        proofs[i].contract = Some(c);
    }
    Ok(Declared {
        budget,
        gpu,
        proofs,
    })
}

struct Member {
    dir: String,
    /// `layer` and `tooth` from `[package.metadata.disciplines]`; wrong
    /// types are the `layers` gate's to report.
    layer: Option<String>,
    tooth: Option<String>,
    /// Names of members this one names as path dependencies.
    deps: Vec<String>,
    /// Whether it names a path dependency that is not a member.
    foreign: bool,
}

fn members(doc: &Value) -> Result<BTreeMap<String, Member>, String> {
    let root = doc
        .get("workspace_root")
        .and_then(Value::as_str)
        .ok_or("cargo metadata: no workspace_root")?;
    let packages = doc
        .get("packages")
        .and_then(Value::as_array)
        .ok_or("cargo metadata: no packages")?;
    let names: BTreeSet<&str> = packages
        .iter()
        .filter_map(|p| p.get("name")?.as_str())
        .collect();
    let mut out = BTreeMap::new();
    for p in packages {
        let name = p
            .get("name")
            .and_then(Value::as_str)
            .ok_or("cargo metadata: a package has no name")?;
        let manifest = p
            .get("manifest_path")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("cargo metadata: `{name}` has no manifest_path"))?;
        let dir = relative_dir(root, manifest).ok_or_else(|| {
            format!("cargo metadata: `{name}`'s manifest {manifest} is outside {root}")
        })?;
        let path_deps: Vec<&str> = p
            .get("dependencies")
            .and_then(Value::as_array)
            .map(|deps| {
                deps.iter()
                    .filter(|d| d.get("path").is_some())
                    .filter_map(|d| d.get("name")?.as_str())
                    .collect()
            })
            .unwrap_or_default();
        let foreign = path_deps.iter().any(|n| !names.contains(n));
        let deps = path_deps
            .into_iter()
            .filter(|n| names.contains(n))
            .map(str::to_string)
            .collect();
        let decl = p.get("metadata").and_then(|m| m.get("disciplines"));
        let field = |k: &str| {
            decl.and_then(|d| d.get(k))
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        out.insert(
            name.to_string(),
            Member {
                dir,
                layer: field("layer"),
                tooth: field("tooth"),
                deps,
                foreign,
            },
        );
    }
    Ok(out)
}

/// `/ws` + `/ws/crates/a/Cargo.toml` → `crates/a`; `/ws/Cargo.toml` → the empty string.
fn relative_dir(root: &str, manifest: &str) -> Option<String> {
    let dir = manifest.strip_suffix("Cargo.toml")?.trim_end_matches('/');
    let rel = dir.strip_prefix(root.trim_end_matches('/'))?;
    if !rel.is_empty() && !rel.starts_with('/') {
        return None;
    }
    Some(rel.trim_start_matches('/').to_string())
}

fn label(entry: &Value, i: usize) -> String {
    entry
        .get("name")
        .and_then(Value::as_str)
        .map_or_else(|| format!("#{}", i + 1), |n| format!("`{n}`"))
}

fn entry_of(entry: &Value, members: &BTreeMap<String, Member>) -> Result<Proof, String> {
    let table = entry.as_object().ok_or("expected a table")?;
    if let Some(key) = table.keys().find(|k| !FIELDS.contains(&k.as_str())) {
        return Err(format!("unknown field `{key}`"));
    }
    let text = |k: &str| -> Result<Option<&str>, String> {
        table.get(k).map_or(Ok(None), |v| {
            v.as_str()
                .map(Some)
                .ok_or_else(|| format!("`{k}` must be a string"))
        })
    };
    let name = text("name")?.ok_or("missing `name`")?;
    let valid = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_';
    if name.is_empty() || !name.chars().all(valid) {
        return Err(format!(
            "name `{name}`: use lowercase letters, digits, `-` and `_`"
        ));
    }
    let package = text("package")?.ok_or("missing `package`")?;
    let member = members
        .get(package)
        .ok_or_else(|| format!("package `{package}` is not a workspace member"))?;
    let kind = kind_of(table, text("kind")?.ok_or("missing `kind`")?)?;
    let memory = text("memory")?
        .ok_or("missing `memory` (the per-process cap, e.g. \"4G\")")
        .map_err(str::to_string)
        .and_then(parse_size)
        .map_err(|e| format!("memory: {e}"))?;
    if memory < MIN_MEMORY {
        return Err(
            "memory: below the 1G minimum (the compiler runs under the cap too)".to_string(),
        );
    }
    let timeout_s = match text("timeout")? {
        Some(t) => parse_duration(t).map_err(|e| format!("timeout: {e}"))?,
        None => match kind {
            Kind::Kani => KANI_TIMEOUT_S,
            Kind::Verus => VERUS_TIMEOUT_S,
            Kind::Command(_) => COMMAND_TIMEOUT_S,
        },
    };
    let run_timeout_s = match (text("run_timeout")?, &kind) {
        (Some(_), Kind::Command(_) | Kind::Verus) => {
            return Err("`run_timeout` is only for kind = \"kani\"".to_string());
        }
        (Some(t), Kind::Kani) => parse_duration(t).map_err(|e| format!("run_timeout: {e}"))?,
        (None, _) => KANI_RUN_TIMEOUT_S,
    };
    let extra_globs = strings(table, "inputs")?;
    let extra_paths = strings(table, "extra_paths")?;
    let tools = tools_of(&kind, strings(table, "tools")?);
    let unstable = unstable_of(table, &kind)?;
    let spine = spine_of(table, &kind, member)?;
    let gpu = gpu_of(table, &kind)?;
    let (harness_budget_s, budget_declared) = harness_budget_of(table, &kind)?;
    let unstable_decl = decl_suffix(
        &unstable,
        spine,
        budget_declared.then_some(harness_budget_s),
    );
    let decl = format!(
        "kind={kind:?} package={package} memory={memory} timeout={timeout_s} \
         run_timeout={run_timeout_s} inputs={extra_globs:?} extra_paths={extra_paths:?} \
         tools={tools:?}{unstable_decl}"
    );
    Ok(Proof {
        name: name.to_string(),
        kind,
        package: package.to_string(),
        dir: member.dir.clone(),
        dirs: reachable_dirs(package, members),
        extra_globs,
        extra_paths,
        tools,
        memory,
        timeout_s,
        run_timeout_s,
        unstable,
        contract: None,
        spine,
        gpu,
        harness_budget_s,
        decl,
        verus_root: String::new(),
    })
}

/// The entry's `kind`, with `command` for `kind = "command"` only.
fn kind_of(table: &serde_json::Map<String, Value>, kind: &str) -> Result<Kind, String> {
    let command = match table.get("command") {
        None => None,
        Some(v) => {
            let argv: Vec<String> = v
                .as_array()
                .and_then(|a| a.iter().map(|s| s.as_str().map(str::to_string)).collect())
                .ok_or("`command` must be an array of strings")?;
            if argv.is_empty() {
                return Err("`command` is empty".to_string());
            }
            Some(argv)
        }
    };
    Ok(match (kind, command) {
        ("kani", None) => Kind::Kani,
        ("kani" | "verus", Some(_)) => {
            return Err("`command` is only for kind = \"command\"".to_string());
        }
        ("verus", None) => Kind::Verus,
        ("command", Some(argv)) => Kind::Command(argv),
        ("command", None) => return Err("kind = \"command\" needs `command`".to_string()),
        (other, _) => {
            return Err(format!(
                "unknown kind `{other}`: use \"kani\", \"verus\" or \"command\""
            ));
        }
    })
}

/// Whether the entry declares `spine = "contracts"`, which needs a Kani
/// entry on a tooth crate.
fn spine_of(
    table: &serde_json::Map<String, Value>,
    kind: &Kind,
    member: &Member,
) -> Result<bool, String> {
    let spine = match table.get("spine") {
        None => false,
        Some(v) => match (v.as_str(), kind) {
            (Some("contracts"), Kind::Kani) => true,
            (Some("contracts"), Kind::Command(_) | Kind::Verus) => {
                return Err("`spine` is only for kind = \"kani\"".to_string());
            }
            _ => return Err("spine: use \"contracts\"".to_string()),
        },
    };
    if spine && member.tooth.is_none() {
        return Err("`spine = \"contracts\"` needs a package in a tooth".to_string());
    }
    Ok(spine)
}

/// The entry's `gpu`: a command's own say; Kani never uses the GPU.
fn gpu_of(table: &serde_json::Map<String, Value>, kind: &Kind) -> Result<bool, String> {
    match (table.get("gpu"), kind) {
        (None, _) => Ok(false),
        (Some(_), Kind::Kani | Kind::Verus) => Err(
            "`gpu` is only for kind = \"command\": Kani and Verus never use the GPU".to_string(),
        ),
        (Some(v), Kind::Command(_)) => v
            .as_bool()
            .ok_or_else(|| "`gpu` must be true or false".to_string()),
    }
}

/// The optional fields' part of `decl`: empty when unset, so existing keys
/// stay the same.
fn decl_suffix(unstable: &[String], spine: bool, harness_budget_s: Option<u64>) -> String {
    let mut out = String::new();
    if !unstable.is_empty() {
        out = format!(" unstable={unstable:?}");
    }
    if spine {
        out.push_str(r#" spine="contracts""#);
    }
    if let Some(s) = harness_budget_s {
        out = format!("{out} harness_budget={s}");
    }
    out
}

/// The entry's `harness_budget` in seconds, and whether it declared one.
fn harness_budget_of(
    table: &serde_json::Map<String, Value>,
    kind: &Kind,
) -> Result<(u64, bool), String> {
    match (table.get("harness_budget"), kind) {
        (None, _) => Ok((KANI_HARNESS_BUDGET_S, false)),
        (Some(_), Kind::Verus | Kind::Command(_)) => {
            Err("`harness_budget` is only for kind = \"kani\"".to_string())
        }
        (Some(v), Kind::Kani) => {
            let text = v.as_str().ok_or("`harness_budget` must be a string")?;
            let s = parse_duration(text).map_err(|e| format!("harness_budget: {e}"))?;
            Ok((s, true))
        }
    }
}

/// The entry's `unstable` Kani features, each one of `UNSTABLE`.
fn unstable_of(table: &serde_json::Map<String, Value>, kind: &Kind) -> Result<Vec<String>, String> {
    let unstable = strings(table, "unstable")?;
    if !unstable.is_empty() && *kind != Kind::Kani {
        return Err("`unstable` is only for kind = \"kani\"".to_string());
    }
    if let Some(bad) = unstable.iter().find(|u| !UNSTABLE.contains(&u.as_str())) {
        return Err(format!(
            "unstable: unknown `{bad}` (one of: {})",
            UNSTABLE.join(", ")
        ));
    }
    Ok(unstable)
}

/// The binaries a proof's key fingerprints: `cargo-kani`; Verus's `cargo`,
/// `cargo-verus` and `verus` (each fingerprinted through its symlinks, so a
/// new Verus install re-keys; its bundled solver ships with it); or the
/// command's program plus `cargo-<sub>` for `cargo [+toolchain] <sub> …`;
/// then the declared `tools`.
fn tools_of(kind: &Kind, declared: Vec<String>) -> Vec<String> {
    let mut tools = match kind {
        Kind::Kani => vec!["cargo-kani".to_string()],
        Kind::Verus => ["cargo", "cargo-verus", "verus"].map(String::from).to_vec(),
        Kind::Command(argv) => {
            let mut t = vec![argv[0].clone()];
            // `cargo +nightly miri …`: the subcommand follows the toolchain.
            if let Some(sub) = argv.iter().skip(1).find(|a| !a.starts_with('+'))
                && argv[0] == "cargo"
                && !sub.starts_with('-')
            {
                t.push(format!("cargo-{sub}"));
            }
            t
        }
    };
    for tool in declared {
        if !tools.contains(&tool) {
            tools.push(tool);
        }
    }
    tools
}

fn strings(table: &serde_json::Map<String, Value>, key: &str) -> Result<Vec<String>, String> {
    match table.get(key) {
        None => Ok(Vec::new()),
        Some(v) => v
            .as_array()
            .and_then(|a| a.iter().map(|s| s.as_str().map(str::to_string)).collect())
            .ok_or_else(|| format!("`{key}` must be an array of strings")),
    }
}

/// The cargo configuration files that may hold `[patch]` tables: every
/// ancestor's `.cargo/config{.toml,}` from `root` up, then `$CARGO_HOME`'s.
#[must_use]
pub fn cargo_config_paths(
    root: &std::path::Path,
    cargo_home: Option<&std::path::Path>,
) -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    for dir in root.ancestors() {
        paths.push(dir.join(".cargo/config.toml"));
        paths.push(dir.join(".cargo/config"));
    }
    if let Some(home) = cargo_home {
        paths.push(home.join("config.toml"));
        paths.push(home.join("config"));
    }
    paths
}

/// Every proof keys the whole tree when the root manifest has a `[patch…]`
/// or `[replace]` table: a patch may point at an in-tree path that is not a
/// member, and `cargo metadata --no-deps` does not report patches.
pub fn widen_for_patches(declared: &mut Declared, root_manifest: &str) {
    if patches(root_manifest) {
        for p in &mut declared.proofs {
            p.dirs = vec![String::new()];
            p.contract = None;
        }
    }
}

/// Whether a manifest or cargo config text has a `[patch…]`/`[replace]`
/// table or a dotted `patch.`/`replace.` key. A line-prefix match: it may
/// over-widen (costing re-runs), never under-widen on the usual forms.
#[must_use]
pub fn patches(text: &str) -> bool {
    text.lines().any(|l| {
        let l = l.trim_start();
        ["[patch", "[replace]", "patch.", "replace."]
            .iter()
            .any(|p| l.starts_with(p))
    })
}

/// The narrowed key's inputs for a `spine = "contracts"` entry.
fn contract_of(
    p: &Proof,
    all: &[Proof],
    members: &BTreeMap<String, Member>,
) -> Result<Contract, String> {
    if p.dirs.iter().any(String::is_empty) {
        return Err(format!(
            "`spine = \"contracts\"`: `{}` reaches a path dependency outside the workspace, so its key cannot be narrowed",
            p.package
        ));
    }
    let reached = reachable_names(&p.package, members);
    let spine_kind = |m: &Member| {
        m.tooth.is_none() && matches!(m.layer.as_deref(), Some("primitive" | "kernel" | "core"))
    };
    let kani_on = |name: &str| {
        all.iter()
            .any(|q| q.kind == Kind::Kani && q.package == name)
    };
    // Read through contracts: spine crates whose contracts a Kani entry of
    // their own proves. Every other reached crate is keyed by its files.
    let (digested, keyed_whole): (Vec<&str>, Vec<&str>) = reached
        .iter()
        .copied()
        .partition(|n| members.get(*n).is_some_and(spine_kind) && kani_on(n));
    let prerequisites: Vec<String> = all
        .iter()
        .filter(|q| q.kind == Kind::Kani && digested.contains(&q.package.as_str()))
        .map(Proof::gate_name)
        .collect();
    if prerequisites.is_empty() {
        return Err(format!(
            "`spine = \"contracts\"`: no kani proof entry covers a spine crate `{}` reaches",
            p.package
        ));
    }
    let mut spine_dirs: Vec<String> = digested
        .iter()
        .filter_map(|n| members.get(*n))
        .map(|m| m.dir.clone())
        .collect();
    spine_dirs.sort();
    if spine_dirs.iter().any(String::is_empty) {
        return Err("`spine = \"contracts\"`: a spine crate is the root package, so its key cannot be narrowed".to_string());
    }
    let mut globs: Vec<String> = keyed_whole
        .iter()
        .filter_map(|n| members.get(*n))
        .map(|m| {
            if m.dir.is_empty() {
                "**".to_string()
            } else {
                format!("{}/**", m.dir)
            }
        })
        .collect();
    globs.sort();
    globs.extend(p.extra_globs.iter().cloned());
    globs.extend(["Cargo.lock", "rust-toolchain.toml", "rust-toolchain"].map(String::from));
    globs.extend(spine_dirs.iter().map(|d| format!("{d}/Cargo.toml")));
    Ok(Contract {
        globs,
        spine_dirs,
        prerequisites,
    })
}

/// Every member `start` reaches through path dependencies, itself included.
fn reachable_names<'a>(start: &'a str, members: &'a BTreeMap<String, Member>) -> Vec<&'a str> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![start];
    while let Some(name) = stack.pop() {
        if seen.insert(name)
            && let Some(m) = members.get(name)
        {
            stack.extend(m.deps.iter().map(String::as_str));
        }
    }
    seen.into_iter().collect()
}

fn reachable_dirs(start: &str, members: &BTreeMap<String, Member>) -> Vec<String> {
    let seen = reachable_names(start, members);
    if seen
        .iter()
        .any(|n| members.get(*n).is_some_and(|m| m.foreign))
    {
        return vec![String::new()];
    }
    let dirs: BTreeSet<String> = seen
        .iter()
        .filter_map(|n| members.get(*n))
        .map(|m| m.dir.clone())
        .collect();
    dirs.into_iter().collect()
}

fn split_unit(text: &str) -> (&str, &str) {
    let at = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    text.split_at(at)
}

/// `1024`, `2K`, `3M`, `4G` (powers of 1024).
///
/// # Errors
/// Anything else, or a value that overflows `u64`.
pub fn parse_size(text: &str) -> Result<u64, String> {
    let bad = || format!("bad size `{text}`: use a number with K, M or G");
    let (digits, unit) = split_unit(text);
    let shift = match unit {
        "" => 0,
        "K" => 10,
        "M" => 20,
        "G" => 30,
        _ => return Err(bad()),
    };
    let n: u64 = digits.parse().map_err(|_| bad())?;
    n.checked_mul(1 << shift)
        .ok_or_else(|| format!("size `{text}` is too large"))
}

/// `90`, `90s`, `2m`, `1h`, in seconds; never zero.
///
/// # Errors
/// Anything else, zero, or an overflow.
pub fn parse_duration(text: &str) -> Result<u64, String> {
    let bad = || format!("bad duration `{text}`: use a whole number with s, m or h");
    let (digits, unit) = split_unit(text);
    let mul = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        _ => return Err(bad()),
    };
    let n: u64 = digits.parse().map_err(|_| bad())?;
    if n == 0 {
        return Err(bad());
    }
    n.checked_mul(mul).ok_or_else(bad)
}

/// `MemTotal` from `/proc/meminfo`, in bytes.
#[must_use]
pub fn mem_total(meminfo: &str) -> Option<u64> {
    meminfo
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))?
        .trim()
        .strip_suffix("kB")?
        .trim()
        .parse::<u64>()
        .ok()?
        .checked_mul(1024)
}

/// The declared budget, else half of RAM, else one process's cap.
#[must_use]
pub fn budget(declared: Option<u64>, mem_total: Option<u64>, memory: u64) -> u64 {
    declared.or(mem_total.map(|m| m / 2)).unwrap_or(memory)
}

/// Harnesses verified at once: as many as the budget holds at `memory`
/// each, at most one per core, at least one.
#[must_use]
pub fn jobs(cores: usize, budget: u64, memory: u64) -> usize {
    let by_memory = usize::try_from(budget / memory.max(1)).unwrap_or(usize::MAX);
    cores.min(by_memory).max(1)
}

/// How a run's memory is capped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cap {
    /// `prlimit --as=<memory>`: each process's address space.
    Prlimit,
    /// The run's cgroup (see `cgroup`), entered by `MOVE_SH`.
    Cgroup(std::path::PathBuf),
    /// `atc run --ram-max`: atc caps the job's own cgroup, named for `repo`;
    /// `never_pause` for every kind ([`crate::atc::NEVER_PAUSE_ENV`]), not
    /// only Kani.
    Atc { repo: String, never_pause: bool },
}

/// `bytes` in atc's size grammar (powers of 1024): `4G`, `512M`, `64K`, else
/// the plain number.
#[must_use]
pub fn size_arg(bytes: u64) -> String {
    match bytes {
        0 => "0".to_string(),
        b if b.is_multiple_of(1 << 30) => format!("{}G", b >> 30),
        b if b.is_multiple_of(1 << 20) => format!("{}M", b >> 20),
        b if b.is_multiple_of(1 << 10) => format!("{}K", b >> 10),
        b => b.to_string(),
    }
}

/// `sh -c MOVE_SH <cgroup> <argv…>`: moves the shell into the cgroup, then
/// becomes the rest of the argv.
pub const MOVE_SH: &str = r#"echo $$ > "$0/cgroup.procs" || { echo "xtask: cannot move into $0" >&2; exit 1; }; exec "$@""#;

/// How long `timeout` waits after its SIGTERM before it sends SIGKILL.
pub const KILL_AFTER: &str = "30s";
/// [`KILL_AFTER`] in seconds: how far a CPU limit's hard limit (SIGKILL)
/// lies past its soft one (SIGXCPU).
pub const KILL_AFTER_S: u64 = 30;
/// SIGXCPU's exit status (128 + 24): a process used its CPU limit.
pub const CPU_LIMIT_EXIT: i32 = 152;

/// `sh -c TIMEOUT_SH xtask-proof -k <grace> <secs> <driver…>`: runs
/// `timeout` in the background and waits for it. GNU `timeout` moves itself
/// and the driver into a process group of their own, which a terminal's
/// Ctrl-C or hangup never reaches. This shell stays in xtask's group, so it
/// gets the signal and passes SIGTERM on to timeout's whole group (its pgid
/// is its pid). On expiry `timeout` signals that group itself (exit 124).
/// The wrapper then exits 128 + the signal's number. `$!` rather than a
/// variable, so a signal between the fork and an assignment still finds
/// `timeout`. A run started with SIGINT ignored (a shell's background job)
/// gets no Ctrl-C to pass on; SIGTERM and SIGHUP still are.
pub const TIMEOUT_SH: &str = r#"stop() { kill -TERM -$! 2>/dev/null || kill -TERM $! 2>/dev/null; wait $!; exit "$1"; }
trap 'stop 130' INT
trap 'stop 143' TERM
trap 'stop 129' HUP
timeout "$@" &
wait $!"#;

/// `sh -c CPU_SH xtask-proof <soft> <hard> <driver…>`: [`TIMEOUT_SH`]'s
/// signal handling, with a CPU-time limit instead of a deadline (Verus and
/// command entries; plan `2026-10-13-pause-proof.md` R1). The limit is per
/// process (`RLIMIT_CPU`, summed over its threads): each process of the
/// run may use `<soft>` CPU seconds (SIGXCPU) and is killed at `<hard>`;
/// it bounds a runaway process, not the run. A frozen process uses none,
/// so a pause of the gate step cannot fail the run, and a run that only
/// waits is never stopped. `timeout -k <grace> 0` sets no deadline but
/// gives the driver a process group of its own and escalates a passed-on
/// signal to SIGKILL, as [`TIMEOUT_SH`] does. When the driver itself dies at its limit (152,
/// or 137 at the hard one), the rest of its group is stopped too; a
/// process deeper in the run that dies at its limit fails the driver in
/// the driver's own way (cargo's exit 101). A core limit of one byte
/// (`prlimit`) writes no core file and also stops a host's core-dump pipe
/// (the kernel's marker for "no pipe dump"); without `prlimit`,
/// `ulimit -c 0` keeps core files out of the package directory but a
/// piped handler still records one.
pub const CPU_SH: &str = r#"stop() { kill -TERM -$! 2>/dev/null || kill -TERM $! 2>/dev/null; wait $!; exit "$1"; }
trap 'stop 130' INT
trap 'stop 143' TERM
trap 'stop 129' HUP
prlimit --pid $$ --core=1 2>/dev/null || ulimit -c 0
ulimit -S -t "$1" && ulimit -H -t "$2" || { echo "xtask-proof: cannot set a CPU limit of $1 s" >&2; exit 70; }
shift 2
timeout -k 30s 0 "$@" &
wait $!
s=$?
case $s in 137|152) kill -KILL -$! 2>/dev/null ;; esac
exit $s"#;

/// The driver's exit code as reports read it: `timeout -k` SIGKILLs a
/// prover still running `KILL_AFTER` past its deadline, so 137 once
/// `limit_s` has passed is the timeout (124), not a kill from elsewhere.
/// `elapsed` leaves out what atc held the run: a long wait for admission
/// is not the prover's time.
#[must_use]
pub fn exit_after(code: Option<i32>, elapsed: std::time::Duration, limit_s: u64) -> Option<i32> {
    match code {
        Some(137) if elapsed.as_secs() >= limit_s => Some(124),
        c => c,
    }
}

/// The limit the wrapper gets: Kani's whole-run timeout (wall-clock, which
/// `exit_after` compares with), or a Verus or command entry's CPU seconds.
#[must_use]
pub fn deadline_s(p: &Proof) -> u64 {
    match p.kind {
        Kind::Kani => p.run_timeout_s,
        Kind::Verus | Kind::Command(_) => p.timeout_s,
    }
}

/// The run's `memory.max`: Kani's harnesses share `jobs × memory`; a
/// command gets `memory`.
#[must_use]
pub fn cgroup_cap(p: &Proof, jobs: usize) -> u64 {
    match p.kind {
        Kind::Kani => p
            .memory
            .saturating_mul(u64::try_from(jobs).unwrap_or(u64::MAX)),
        Kind::Verus | Kind::Command(_) => p.memory,
    }
}

/// A Verus entry's build directory, `verus/<workspace>/<name>` under
/// cargo's build directory: outside the tree when one is configured, so a
/// fresh checkout at the same path reuses its Verus library.
#[must_use]
pub fn verus_build_dir(p: &Proof) -> String {
    format!("{}/{}", p.verus_root, p.name)
}

/// FNV-1a of the workspace root, 16 hex digits: a stable name per checkout.
fn workspace_key(doc: &Value) -> String {
    let root = doc
        .get("workspace_root")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in root.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// The full argv: the cap (`prlimit`, which caps each process; the cgroup
/// move; or `atc run`, which reserves and caps), then the wrapper with the
/// limit (`TIMEOUT_SH` and Kani's run timeout; `CPU_SH` and the CPU limit
/// for Verus and command entries), then the driver.
#[must_use]
pub fn argv(p: &Proof, jobs: usize, cap: &Cap) -> Vec<String> {
    let mut v = Vec::new();
    match cap {
        Cap::Prlimit => v.extend([
            "prlimit".to_string(),
            format!("--as={}", p.memory),
            "--".to_string(),
        ]),
        Cap::Cgroup(path) => {
            v.extend(["sh", "-c", MOVE_SH].map(String::from));
            v.push(path.to_string_lossy().into_owned());
        }
        Cap::Atc { repo, never_pause } => {
            let cpus = match p.kind {
                Kind::Kani => jobs,
                Kind::Verus | Kind::Command(_) => 1,
            };
            v.extend(["atc", "run", "--name"].map(String::from));
            v.push(format!("{repo}/{}", p.gate_name()));
            v.extend(["--cpu-min".to_string(), cpus.to_string()]);
            // Reserve one job's memory: atc reserves the larger of this and
            // the learned p95 once a run has been measured, and `--ram-max`
            // stays the kernel cap. Without it a first run reserves the
            // whole cap, and waits while other load holds the host
            // (DEFERRED D16).
            v.extend(["--ram-min".to_string(), size_arg(p.memory)]);
            v.extend(["--ram-max".to_string(), size_arg(cgroup_cap(p, jobs))]);
            // No `--give-up-after`: a proof waits for atc as long as atc
            // needs, since a busy host is not a failure (user, 2026-10-13).
            // A job that can never fit fails at once (exit 77);
            // `ATC_MAX_WAIT`, when set, is the caller's own cap.
            if !p.gpu {
                v.extend(crate::atc::NO_GPU.map(String::from));
            }
            // Kani's limits are wall-clock (its run timeout and its own
            // per-harness timeout): a freeze would spend them, so atc never
            // pauses a Kani run (plan `2026-10-13-pause-proof.md` R2).
            if p.kind == Kind::Kani || *never_pause {
                v.push("--never-pause".to_string());
            }
            v.push("--".to_string());
        }
    }
    let secs = deadline_s(p);
    if p.kind == Kind::Kani {
        v.extend(["sh", "-c", TIMEOUT_SH, "xtask-proof", "-k", KILL_AFTER].map(String::from));
        v.push(secs.to_string());
    } else {
        v.extend(["sh", "-c", CPU_SH, "xtask-proof"].map(String::from));
        v.push(secs.to_string());
        v.push((secs + KILL_AFTER_S).to_string());
    }
    match &p.kind {
        Kind::Kani => {
            v.extend(["cargo", "kani", "-p"].map(String::from));
            v.push(p.package.clone());
            v.extend(["-j".to_string(), jobs.to_string()]);
            v.extend(["--output-format", "terse", "-Z", "unstable-options"].map(String::from));
            for feature in &p.unstable {
                v.extend(["-Z".to_string(), feature.clone()]);
            }
            v.push("--harness-timeout".to_string());
            v.push(format!("{}s", p.timeout_s));
        }
        Kind::Verus => {
            v.extend(["sh", "-c", VERUS_SH, "xtask-verus"].map(String::from));
            v.push(p.package.clone());
            v.push(verus_build_dir(p));
        }
        Kind::Command(cmd) => v.extend(cmd.iter().cloned()),
    }
    v
}

/// The failed harnesses from Kani's terse output, in summary order, each
/// with `(timed out)` or the cbmc exit status when the output says so. With
/// `-j`, lines are attributed to the last `Thread <n>:` prefix seen.
#[must_use]
pub fn kani_failures(output: &str) -> Vec<String> {
    failures_of(output, true)
}

/// `kani_failures`; `blame_cap` adds that a cbmc exit status may be the
/// memory cap (`prlimit` fails its allocations), which under atc's
/// `--ram-max` is an OOM kill instead (exit 76).
fn failures_of(output: &str, blame_cap: bool) -> Vec<String> {
    let mut current: BTreeMap<&str, &str> = BTreeMap::new();
    let mut reason: BTreeMap<&str, String> = BTreeMap::new();
    let mut failed = Vec::new();
    let mut last = "";
    for line in output.lines() {
        let prefixed = line.strip_prefix("Thread ").and_then(|r| {
            r.split_once(": ")
                .or_else(|| r.strip_suffix(':').map(|t| (t, "")))
        });
        let (thread, rest) = prefixed.unwrap_or((last, line));
        last = thread;
        if let Some(h) = rest
            .strip_prefix("Checking harness ")
            .and_then(|h| h.strip_suffix("..."))
        {
            current.insert(thread, h);
        } else if rest.starts_with("CBMC timed out") {
            if let Some(h) = current.get(thread) {
                reason.insert(h, "timed out".to_string());
            }
        } else if let Some(status) = rest.strip_prefix("CBMC failed with status ") {
            if let Some(h) = current.get(thread) {
                let cap = if blame_cap {
                    "; it may have hit the memory cap"
                } else {
                    ""
                };
                reason.insert(h, format!("CBMC exited with status {status}{cap}"));
            }
        } else if let Some(h) = rest.strip_prefix("Verification failed for - ") {
            failed.push(h.trim());
        }
    }
    failed
        .into_iter()
        .map(|h| match reason.get(h) {
            Some(r) => format!("{h} ({r})"),
            None => h.to_string(),
        })
        .collect()
}

/// # Errors
/// The failed harnesses, or, when none is named (a compile error), the
/// last 20 lines of output; under a cgroup, followed by any OOM kills.
/// Only under `prlimit` does a cbmc exit status suggest the cap: a cgroup
/// counts its OOM kills.
pub fn kani_report(
    p: &Proof,
    output: &str,
    code: Option<i32>,
    usage: Option<&cgroup::Usage>,
) -> Result<(), String> {
    kani_result(p, output, code, usage.is_none()).map_err(|e| match usage {
        Some(u) if u.oom_kills > 0 => format!(
            "{e}\nOOM-killed {} process(es) at the {} cgroup cap; raise memory or lower jobs",
            u.oom_kills,
            human(u.cap)
        ),
        _ => e,
    })
}

fn kani_result(p: &Proof, output: &str, code: Option<i32>, blame_cap: bool) -> Result<(), String> {
    match code {
        Some(0) => {
            return match unsatisfied_cover(output) {
                Some(line) => Err(format!(
                    "a harness of package `{}` is vacuous: {line}",
                    p.package
                )),
                None => Ok(()),
            };
        }
        Some(124) => {
            return Err(format!(
                "`cargo kani -p {}` timed out after {}s (run_timeout)",
                p.package, p.run_timeout_s
            ));
        }
        _ => {}
    }
    let failures = failures_of(output, blame_cap);
    if failures.is_empty() && blame_cap && output.contains("memory allocation of") {
        // Rust's allocation-failure abort, in the driver: `prlimit` caps it
        // like every cbmc, and it outgrows `memory` with many harnesses.
        return Err(format!(
            "the Kani driver of package `{}` ran out of its {} address space (prlimit caps \
             every process, the driver included); run the proof where a writable delegated \
             cgroup or atc caps the whole run instead",
            p.package,
            human(p.memory)
        ));
    }
    if failures.is_empty() {
        let lines: Vec<&str> = output.lines().collect();
        let tail = lines[lines.len().saturating_sub(20)..].join("\n");
        return Err(format!(
            "`cargo kani -p {}` failed before any harness result:\n{tail}",
            p.package
        ));
    }
    let count = if failures.len() == 1 {
        "1 harness".to_string()
    } else {
        format!("{} harnesses", failures.len())
    };
    let list: Vec<String> = failures.iter().map(|f| format!("  - {f}")).collect();
    Err(format!(
        "{count} of package `{}` failed:\n{}",
        p.package,
        list.join("\n")
    ))
}

/// A `** <n> of <m> cover properties satisfied` line with `n < m`: Kani
/// exits 0 with an unreachable `kani::cover!`, which marks a vacuous harness.
fn unsatisfied_cover(output: &str) -> Option<&str> {
    output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("** "))
        .find(|rest| {
            let Some((counts, _)) = rest.split_once(" cover properties satisfied") else {
                return false;
            };
            let mut n = counts.split(" of ").map(str::parse::<u64>);
            matches!((n.next(), n.next()), (Some(Ok(got)), Some(Ok(all))) if got < all)
        })
}

/// Each verified harness and its `Verification Time`, slowest first. With
/// `-j`, a time belongs to the harness its thread last started.
#[must_use]
pub fn kani_times(output: &str) -> Vec<(String, f64)> {
    let mut current: BTreeMap<&str, &str> = BTreeMap::new();
    let mut times = Vec::new();
    let mut last = "";
    for line in output.lines() {
        let prefixed = line.strip_prefix("Thread ").and_then(|r| {
            r.split_once(": ")
                .or_else(|| r.strip_suffix(':').map(|t| (t, "")))
        });
        let (thread, rest) = prefixed.unwrap_or((last, line));
        last = thread;
        if let Some(h) = rest
            .strip_prefix("Checking harness ")
            .and_then(|h| h.strip_suffix("..."))
        {
            current.insert(thread, h);
        } else if let Some(t) = rest
            .strip_prefix("Verification Time: ")
            .and_then(|t| t.trim().strip_suffix('s'))
            .and_then(|t| t.parse::<f64>().ok())
            && let Some(h) = current.get(thread)
        {
            times.push(((*h).to_string(), t));
        }
    }
    times.sort_by(|a, b| b.1.total_cmp(&a.1));
    times
}

/// Each harness whose verification time exceeds the entry's
/// `harness_budget`, slowest first, as a warning; or a warning that the
/// times cannot all be read (Kani's summary counts more verified harnesses
/// than times found). `None` when every harness fits. Never a failure: load
/// alone pushes short harnesses past their budget, and no reservation keeps
/// a run's CPUs to itself without waiting for a quiet host (user,
/// 2026-10-13); the rule is kept by review and DEFERRED entries.
#[must_use]
pub fn harness_budget_report(p: &Proof, output: &str) -> Option<String> {
    let budget = std::time::Duration::from_secs(p.harness_budget_s).as_secs_f64();
    let times = kani_times(output);
    let verified = output.lines().find_map(|l| {
        l.trim()
            .strip_prefix("Complete - ")
            .and_then(|r| r.split_whitespace().next())
            .and_then(|n| n.parse::<usize>().ok())
    });
    let mut warnings = Vec::new();
    if let Some(n) = verified.filter(|&n| times.len() < n) {
        warnings.push(format!(
            "warning: harness budget: read {} harness times, but Kani verified {n}; its output format may have changed",
            times.len()
        ));
    }
    let over: Vec<String> = times
        .into_iter()
        .filter(|(_, s)| *s > budget)
        .map(|(name, s)| format!("{name} {s:.1} s"))
        .collect();
    if !over.is_empty() {
        warnings.push(format!(
            "warning: harness over its {} s budget: {}; split it or bound its state (rust.md §5), or declare a larger `harness_budget` with a DEFERRED entry",
            p.harness_budget_s,
            over.join(", ")
        ));
    }
    (!warnings.is_empty()).then(|| warnings.join("\n"))
}

/// `slowest harnesses: a 372.5 s, b 12.0 s` for the first `n`; empty when
/// there are none.
#[must_use]
pub fn slowest(times: &[(String, f64)], n: usize) -> String {
    if times.is_empty() {
        return String::new();
    }
    let list: Vec<String> = times
        .iter()
        .take(n)
        .map(|(h, t)| format!("{h} {t:.1} s"))
        .collect();
    format!("slowest harnesses: {}", list.join(", "))
}

fn human(bytes: u64) -> String {
    if bytes.is_multiple_of(1 << 30) {
        format!("{}G", bytes >> 30)
    } else if bytes.is_multiple_of(1 << 20) {
        format!("{}M", bytes >> 20)
    } else {
        format!("{bytes} bytes")
    }
}

/// `could not start (exit 127: not found); is `x` installed and on PATH?`
/// for the shell's and `timeout`'s cannot-run codes.
fn could_not_start(p: &Proof, code: i32) -> Option<String> {
    let why = match code {
        126 => "not executable",
        127 => "not found",
        _ => return None,
    };
    let program = match &p.kind {
        Kind::Command(argv) => argv.first().map_or("", String::as_str),
        Kind::Kani => "cargo-kani",
        Kind::Verus => "cargo",
    };
    Some(format!(
        "`{}` could not start (exit {code}: {why}); is `{program}` installed and on PATH?",
        driver_text(p)
    ))
}

/// Whether a line of a proof's output is atc saying the run waits for
/// others: shown as it comes, even when the entry's output is captured.
#[must_use]
pub fn live_line(line: &str) -> bool {
    line.starts_with("atc: waiting for ")
}

/// The driver as reports name it.
fn driver_text(p: &Proof) -> String {
    match &p.kind {
        Kind::Command(argv) => argv.join(" "),
        Kind::Kani => format!("cargo kani -p {}", p.package),
        Kind::Verus => format!("cargo verus focus ({})", p.package),
    }
}

/// # Errors
/// Under `atc run`: atc's own exit codes (`atc::exit_message`; on 76 a Kani
/// entry keeps its failed harnesses), else the driver's timeout, failure or
/// kill. The cap is atc's to report, so a plain failure never blames it.
pub fn atc_report(
    p: &Proof,
    output: &str,
    code: Option<i32>,
    cap: u64,
    held: bool,
) -> Result<(), String> {
    let cmd = driver_text(p);
    let atc = code.and_then(|c| crate::atc::exit_message(c, Some(&size_arg(cap)), held));
    match (&p.kind, atc, code) {
        (Kind::Kani, Some(m), Some(76)) => {
            kani_result(p, output, code, false).map_err(|e| format!("{e}\n{m}"))
        }
        (_, Some(m), _) => Err(format!("`{cmd}`: {m}")),
        (Kind::Kani, None, _) => kani_result(p, output, code, false),
        (Kind::Verus, None, _) => verus_result(p, output, plain_atc(p, code)),
        (Kind::Command(_), None, _) => plain_atc(p, code),
    }
}

/// A Verus or command run whose driver used its CPU limit.
fn cpu_limit(cmd: &str, p: &Proof) -> String {
    format!(
        "`{cmd}` used its CPU limit: a process ran {}s of CPU (`timeout`)",
        p.timeout_s
    )
}

/// A Verus or command driver killed by SIGKILL: the hard CPU limit (a
/// process that ignored SIGXCPU) or a kill from elsewhere.
fn hard_kill(cmd: &str) -> String {
    format!(
        "`{cmd}` was killed by signal 9: a process may have reached its hard CPU limit ({KILL_AFTER_S}s past `timeout`)"
    )
}

/// A driver's own outcome under atc, once atc's codes are ruled out.
fn plain_atc(p: &Proof, code: Option<i32>) -> Result<(), String> {
    let cmd = driver_text(p);
    let start = code.and_then(|c| could_not_start(p, c));
    match code {
        Some(0) => Ok(()),
        Some(CPU_LIMIT_EXIT) => Err(cpu_limit(&cmd, p)),
        Some(137) => Err(hard_kill(&cmd)),
        Some(_) if start.is_some() => Err(start.unwrap_or_default()),
        // atc returns 128 + N when signal N killed the command.
        Some(c @ 129..=192) => Err(format!("`{cmd}` was killed by signal {}", c - 128)),
        Some(c) => Err(format!("`{cmd}` failed (exit {c})")),
        None => Err(format!("`{cmd}` was killed by a signal")),
    }
}

/// The `--no-cheating` rejections Verus lists in full before failing: one
/// of each kind does not hide the rest. Any other error in the first pass
/// (a rejection that stops the listing, a verification error, a build
/// failure) leaves the listing incomplete.
pub const VERUS_LISTED: &[&str] = &[
    "error: assume/admit not allowed with --no-cheating",
    "error: external_body/assume_specification not allowed with --no-cheating",
    "error: #[verifier::assume_termination] not allowed with --no-cheating",
];

/// # Errors
/// What a Verus run's first pass took on trust without
/// `disciplines:allow-trusted (<reason>)` on the line it names (read by
/// `line_of`, paths relative to the workspace root), each as
/// `<path>:<line>: <rejection>`; or, failing closed, a first pass whose
/// listing may be incomplete: another error, a rejection without its
/// location, or a failure that names nothing. Otherwise the output to
/// judge: the second pass when there is one, else the whole output.
pub fn verus_trust(
    output: &str,
    line_of: impl Fn(&str, usize) -> Option<String>,
) -> Result<&str, String> {
    // The separator is a line of its own; a source snippet Verus quotes
    // carries a `N |` prefix and cannot stand for it.
    let Some(at) = output
        .match_indices(VERUS_SECOND_PASS)
        .map(|(at, _)| at)
        .find(|&at| {
            (at == 0 || output[..at].ends_with('\n'))
                && output[at + VERUS_SECOND_PASS.len()..].starts_with('\n')
        })
    else {
        return Ok(output);
    };
    let (first, second) = (&output[..at], &output[at + VERUS_SECOND_PASS.len()..]);
    let (mut unmarked, mut other, mut named) = (Vec::new(), Vec::new(), 0usize);
    let lines: Vec<&str> = first.lines().collect();
    for (i, header) in lines.iter().enumerate() {
        if !header.starts_with("error") || header.starts_with("error: could not compile") {
            continue;
        }
        if !VERUS_LISTED.contains(&header.trim_end()) {
            other.push((*header).to_string());
            continue;
        }
        named += 1;
        let mut block = lines[i + 1..]
            .iter()
            .take_while(|l| !l.starts_with("error"));
        let at = block
            .find_map(|l| l.trim_start().strip_prefix("--> "))
            .map(str::trim);
        let place = at.and_then(|at| {
            let mut parts = at.rsplitn(3, ':');
            let (_col, number, path) = (parts.next(), parts.next(), parts.next());
            path.zip(number.and_then(|n| n.parse::<usize>().ok()))
        });
        let marked = place.is_some_and(|(path, number)| {
            line_of(path, number)
                .is_some_and(|l| crate::stubs::marked_with_reason(&l, crate::trusted::MARKER))
        });
        if !marked {
            let at = place.map_or_else(
                || "(no location)".to_string(),
                |(path, number)| format!("{path}:{number}"),
            );
            unmarked.push(format!("{at}: {}", header.trim()));
        }
    }
    if other.iter().any(|e| e.contains("no library targets found")) {
        return Err(
            "the package has no library target: a Verus entry verifies its library".to_string(),
        );
    }
    if !other.is_empty() || named == 0 {
        return Err(format!(
            "the `--no-cheating` pass failed for another reason, so its list of trusted code may be incomplete:\n{}\n{}",
            other.join("\n"),
            verus_diagnostics(first)
        ));
    }
    if unmarked.is_empty() {
        Ok(second)
    } else {
        Err(format!(
            "{}\nVerus takes these on trust. Prove them, or mark each line with `{} (<reason>)`.",
            unmarked.join("\n"),
            crate::trusted::MARKER
        ))
    }
}

/// Verus's `verification results:: N verified, M errors`, summed over every
/// such line: `focus` prints one per verified target (a lib and a bin give
/// two). `None` when there is none, or one does not parse.
#[must_use]
pub fn verus_results(output: &str) -> Option<(u64, u64)> {
    let mut total: Option<(u64, u64)> = None;
    for line in output
        .lines()
        .filter_map(|l| l.split_once("verification results::").map(|(_, r)| r))
    {
        let mut nums = line
            .split(|c: char| !c.is_ascii_digit())
            .filter(|w| !w.is_empty())
            .map(str::parse::<u64>);
        let (Some(Ok(verified)), Some(Ok(errors))) = (nums.next(), nums.next()) else {
            return None;
        };
        let (v, e) = total.unwrap_or((0, 0));
        total = Some((v + verified, e + errors));
    }
    total
}

/// # Errors
/// A Verus run: its errors with their diagnostics, a run that verified
/// nothing, a missing `cargo-verus`, or `plain` (the driver's exit, timeout
/// or kill, then the output) when Verus printed no results; an exit 0
/// without results is an error too.
pub fn verus_result(p: &Proof, output: &str, plain: Result<(), String>) -> Result<(), String> {
    let cmd = driver_text(p);
    if output.contains("no such command: `verus`") {
        return Err(format!(
            "`{cmd}`: `cargo-verus` is not installed or not on PATH (a Verus release provides it)"
        ));
    }
    match verus_results(output) {
        Some((_, errors)) if errors > 0 => Err(format!(
            "`{cmd}`: {errors} verification error(s)\n{}",
            verus_diagnostics(output)
        )),
        Some((0, _)) => Err(format!(
            "`{cmd}` verified nothing: is the code inside `verus!`, and is `[package.metadata.verus] verify = true` set?\n{}",
            verus_diagnostics(output)
        )),
        Some(_) => plain.map_err(|e| with_diagnostics(e, output)),
        None => {
            let head = match plain {
                Ok(()) => format!("`{cmd}` printed no `verification results` line"),
                Err(e) => e,
            };
            Err(with_diagnostics(head, output))
        }
    }
}

/// `head`, then the output's diagnostics when there are any.
fn with_diagnostics(head: String, output: &str) -> String {
    let diagnostics = verus_diagnostics(output);
    if diagnostics.is_empty() {
        head
    } else {
        format!("{head}\n{diagnostics}")
    }
}

/// The output from the first `error` or `WARNING` line on, at most 60
/// lines; without one, the last 40 lines.
fn verus_diagnostics(output: &str) -> String {
    let lines: Vec<&str> = output.lines().collect();
    let from = lines
        .iter()
        .position(|l| l.starts_with("error") || l.starts_with("WARNING"));
    let shown = match from {
        Some(i) => &lines[i..lines.len().min(i + 60)],
        None => &lines[lines.len().saturating_sub(40)..],
    };
    shown.join("\n")
}

/// # Errors
/// A Verus run outside atc: [`verus_result`] over [`command_report`].
pub fn verus_report(
    p: &Proof,
    output: &str,
    code: Option<i32>,
    usage: Option<&cgroup::Usage>,
) -> Result<(), String> {
    verus_result(p, output, command_report(p, code, usage))
}

/// # Errors
/// The CPU limit (exit 152, or 137 at the hard one), a failure or a kill. Under prlimit it
/// names the cap as a likely cause; under a cgroup the OOM count decides.
pub fn command_report(
    p: &Proof,
    code: Option<i32>,
    usage: Option<&cgroup::Usage>,
) -> Result<(), String> {
    let cmd = driver_text(p);
    let cap = human(p.memory);
    let start = code.and_then(|c| could_not_start(p, c));
    match (code, usage) {
        (Some(0), _) => Ok(()),
        (Some(CPU_LIMIT_EXIT), _) => Err(cpu_limit(&cmd, p)),
        (_, Some(u)) if u.oom_kills > 0 => Err(format!(
            "`{cmd}` was OOM-killed at the {} cgroup cap",
            human(u.cap)
        )),
        // prlimit fails allocations rather than killing: a SIGKILL is not
        // the memory cap.
        (Some(137), _) => Err(hard_kill(&cmd)),
        (Some(_), _) if start.is_some() => Err(start.unwrap_or_default()),
        // The wrapper shell reports a signal death as 128 + N.
        (Some(c @ 129..=192), Some(_)) => Err(format!("`{cmd}` was killed by signal {}", c - 128)),
        (Some(c @ 129..=192), None) => Err(format!(
            "`{cmd}` was killed by signal {}; a process may have hit the {cap} memory cap",
            c - 128
        )),
        (Some(c), Some(_)) => Err(format!("`{cmd}` failed (exit {c})")),
        (None, Some(_)) => Err(format!("`{cmd}` was killed by a signal")),
        (Some(c), None) => Err(format!(
            "`{cmd}` failed (exit {c}); a process may have hit the {cap} memory cap"
        )),
        (None, None) => Err(format!(
            "`{cmd}` was killed by a signal; a process may have hit the {cap} memory cap"
        )),
    }
}

/// `peak memory: 9.4G of 14G cap`; empty without a `memory.peak`.
#[must_use]
pub fn peak_line(u: &cgroup::Usage) -> String {
    u.peak.map_or_else(String::new, |peak| {
        format!("peak memory: {} of {} cap", approx(peak), human(u.cap))
    })
}

/// Tenths of a G at or above 1G, else whole M; rounded up.
fn approx(bytes: u64) -> String {
    if bytes >= 1 << 30 {
        let tenths = (bytes.saturating_mul(10)).div_ceil(1 << 30);
        format!("{}.{}G", tenths / 10, tenths % 10)
    } else {
        format!("{}M", bytes.div_ceil(1 << 20))
    }
}

/// The [`VERUS_INSTALL_FILES`] beside `cargo_verus` (resolved through its
/// symlinks), as absolute paths for a proof gate's `extra_paths`; empty when
/// it does not resolve.
#[must_use]
pub fn verus_install_files(cargo_verus: &std::path::Path) -> Vec<String> {
    let Some(dir) = cargo_verus
        .canonicalize()
        .ok()
        .and_then(|b| b.parent().map(std::path::Path::to_path_buf))
    else {
        return Vec::new();
    };
    VERUS_INSTALL_FILES
        .iter()
        .map(|f| dir.join(f).to_string_lossy().into_owned())
        .collect()
}

/// Tools `preflight` requires once a Verus proof is declared: the selected
/// `verus` release, the `cargo-verus` driver, and `verusfmt`, which formats
/// `verus!` bodies. The driver is version-checked separately; an empty
/// workspace does not require Verus.
#[must_use]
pub fn required_tools(proofs: &[Proof]) -> Vec<(&'static str, &'static str)> {
    if proofs.iter().any(|p| p.kind == Kind::Verus) {
        vec![
            ("verus", crate::tools::VERUS_INSTALL),
            ("cargo-verus", crate::tools::VERUS_INSTALL),
            ("verusfmt", "cargo install --locked verusfmt"),
        ]
    } else {
        Vec::new()
    }
}

/// Tools one proof gate checks before it runs, with install hints.
#[must_use]
pub fn gate_tools(p: &Proof) -> Vec<(&'static str, &'static str)> {
    let mut tools = vec![
        ("prlimit", "util-linux, from your package manager"),
        ("timeout", "coreutils, from your package manager"),
    ];
    match p.kind {
        Kind::Kani => tools.push((
            "cargo-kani",
            "cargo install --locked kani-verifier && cargo kani setup",
        )),
        Kind::Verus => {
            let release = "a Verus release from https://github.com/verus-lang/verus/releases, with `verus` and `cargo-verus` on PATH";
            tools.extend([("cargo-verus", release), ("verus", release)]);
        }
        Kind::Command(_) => {}
    }
    tools
}
