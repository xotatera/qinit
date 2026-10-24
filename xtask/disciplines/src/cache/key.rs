// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Cache keys. A manifest lists everything a gate's result depends on, one
//! sorted line per item. The key is git's hash of that manifest, so no
//! hashing dependency is needed.
//! - `file <path> <blob> <x|->`: each declared input (the whole tree by
//!   default) and, for gates using cargo, each listed file a `#[path]`
//!   attribute names.
//! - `runner <path> <blob> <x|->`: every source file of the runner crate
//!   (hidden directories and `target/` skipped), so a change to gate code or
//!   constants invalidates every entry. A project runner built on this crate
//!   as a library (`execute_with`) names both crates: the further ones show
//!   as `runner+<n> <path> …`.
//! - `ignored <path> <blob> <x|->`: ignored files matching `ignored_inputs`
//!   (at most `OUTSIDE_FILE_LIMIT` of them).
//! - `extra-path <path> <blob> <x|->`, `extra-path-missing <entry>`: each
//!   file under a declared `extra_paths` entry (see `outside::extra_path`).
//! - `outside <path> <blob> <x|->`, `outside-missing <value>`: path
//!   dependencies outside the repository (see `outside`): for every gate,
//!   those of the runner's own build chain (`outside::runner_manifests`);
//!   for gates using cargo, the whole tree's.
//! - `ignored-dep <path> <blob> <x|->`: for gates using cargo, ignored files
//!   below in-tree directories the manifests name (see `outside::scan`).
//! - `config <path> <blob>`: cargo configuration outside the tree (every
//!   gate: cargo builds the runner) and, for gates using cargo, rustfmt and
//!   clippy configuration (see `outside::config_files`), those cargo
//!   configuration includes, and rustfmt configuration above each outside
//!   directory. Also, for every gate, the runner chain's own files (root
//!   `Cargo.toml`, runner `Cargo.toml`, root `.cargo/config{,.toml}`) and
//!   tracked included configuration, shown relative to the root when in
//!   the tree: a narrowed gate does not list them among its inputs.
//! - `named-binary <path> <size> <mtime>`, `named-binary-missing <value>`:
//!   for every gate, the binaries variables (`names_binary`) and cargo
//!   configuration (`outside::NAMED_KEYS`, `runner`) name.
//! - `target-spec <path> <blob>`, `target-spec-missing <value>`: for every
//!   gate, a custom target specification (`CARGO_BUILD_TARGET` or a
//!   cargo configuration `target` ending in `.json`).
//! - `extra <path> <blob>`: `Cargo.lock`, the toolchain files and
//!   `gates/cache-env.txt`.
//! - `sysroot <path>`: the active toolchain.
//! - `tool <name> <path> <size> <mtime>`: the binary found on PATH (or
//!   `missing`, or `unreadable`) for each declared tool, and for `rustc`
//!   and `cargo` on every gate (`RUNNER_TOOLS`): they build the runner.
//! - `sysroot-tool …`: the same tool in the active rustup toolchain. A
//!   `rustup update` changes only this one.
//! - `env <NAME>=<value>`: each declared variable, each one listed in
//!   `gates/cache-env.txt` and, for every gate, each one present whose
//!   name starts with `CARGO_` or `RUST`, except those `cargo xtask` sets
//!   for the runner itself (`CARGO_RUN_ENV`) and those rustup's proxy sets
//!   to the toolchain the sysroot already keys (`RUSTUP_RESOLVED_ENV`).
//!   `CARGO_HOME` and `RUSTUP_HOME` are always keyed, by their effective
//!   value (`$HOME/.cargo`, `$HOME/.rustup` when unset). Values are
//!   `{:?}`-escaped, so a non-UTF-8 value is keyed byte for byte.
//! - `gate <name>`.
//!
//! Paths are shown as UTF-8 when they are, and `{:?}`-escaped otherwise.
use std::collections::{BTreeSet, HashMap};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use super::outside::{self, CanonicalRoot, OUTSIDE_FILE_LIMIT, Outside};
use super::{glob, not_inputs};
use crate::duplication::files::{self, Walk};
use crate::{git, tools};

/// What a gate reads from the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inputs {
    /// Every tracked file and every untracked file that is not ignored.
    Tree,
    /// Only the files matching these globs (see `glob`).
    Globs(&'static [&'static str]),
}

/// One gate's declaration, as the key needs it.
pub struct KeySpec<'a> {
    pub gate: &'a str,
    pub inputs: Inputs,
    pub env: &'a [&'a str],
    pub tools: &'a [&'a str],
    /// Files or directories outside the tree the gate reads.
    pub extra_paths: &'a [&'a str],
    /// Absolute runtime paths kept byte-for-byte in the cache key.
    pub cache_paths: &'a [PathBuf],
    /// Globs over ignored files the gate reads.
    pub ignored_inputs: &'a [&'a str],
    /// A runtime declaration's text; empty adds no line.
    pub decl: &'a str,
}

/// What the key reads from outside the tree. Tests build it by hand.
pub struct Probe {
    /// The runner's crate directories, the one holding `main` first.
    pub runner_dirs: Vec<PathBuf>,
    pub path: Option<OsString>,
    pub sysroot: Option<PathBuf>,
    /// The environment. Names that are not UTF-8 are dropped; values are
    /// kept byte for byte.
    pub vars: HashMap<String, OsString>,
    /// `$HOME`: expands `~/` in `extra_paths` and locates user configuration.
    pub home: Option<PathBuf>,
}

impl Probe {
    /// The real environment. `rustc --print sysroot` follows rustup proxies to
    /// the active toolchain. It is run once per gate run, in `root`, so a
    /// directory override or `rust-toolchain.toml` there applies.
    #[must_use]
    pub fn from_env(root: &Path, runner_dirs: Vec<PathBuf>) -> Probe {
        let sysroot = std::process::Command::new("rustc")
            .args(["--print", "sysroot"])
            .current_dir(root)
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| PathBuf::from(String::from_utf8_lossy(&out.stdout).trim()));
        Probe {
            runner_dirs,
            path: std::env::var_os("PATH"),
            sysroot,
            vars: std::env::vars_os()
                .filter_map(|(k, v)| Some((k.into_string().ok()?, v)))
                .collect(),
            home: home_from(std::env::var_os("HOME")),
        }
    }
}

/// Optional: variable names (one per line, `#` comments) every key includes.
pub const CACHE_ENV: &str = "gates/cache-env.txt";

/// `$HOME`'s value as a directory: unset and empty are both `None`.
fn home_from(value: Option<OsString>) -> Option<PathBuf> {
    value.filter(|v| !v.is_empty()).map(PathBuf::from)
}

const EXTRAS: &[&str] = &[
    "Cargo.lock",
    "rust-toolchain.toml",
    "rust-toolchain",
    CACHE_ENV,
];

/// Variables naming a binary cargo runs instead of its default one. Any
/// `CARGO_TARGET_<triple>_LINKER` or `_RUNNER` does too (see `names_binary`).
const NAMED_ENV: &[&str] = &[
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTFMT",
    "RUSTDOC",
    "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTDOC",
    "CARGO_HOST_LINKER",
];

/// Cargo gates key every variable present with one of these prefixes...
const CARGO_ENV_PREFIXES: &[&str] = &["CARGO_", "RUST"];

/// ...except those `cargo xtask` sets for the runner itself. Child cargo
/// sets its own values for its children, so they cannot change a verdict,
/// and `CARGO_MANIFEST_DIR` would tie every key to one worktree.
const CARGO_RUN_ENV: &[&str] = &[
    "CARGO_MANIFEST_DIR",
    "CARGO_MANIFEST_PATH",
    "CARGO_CRATE_NAME",
    "CARGO_BIN_NAME",
    "CARGO_PRIMARY_PACKAGE",
    "CARGO_TARGET_TMPDIR",
    "CARGO",
    "RUST_RECURSION_COUNT",
];
const CARGO_RUN_PREFIXES: &[&str] = &["CARGO_PKG_", "CARGO_BIN_EXE_"];

/// Set by rustup's proxy, so present under `cargo xtask` and usually not in
/// a shell (DEFERRED D13). The toolchain they select enters every key as
/// the sysroot (`rustc --print sysroot` follows them), so they are left out.
const RUSTUP_RESOLVED_ENV: &[&str] = &["RUSTUP_TOOLCHAIN", "RUSTUP_TOOLCHAIN_SOURCE"];

/// Homes the proxy also sets, to the default when unset: keyed by their
/// effective value (the variable, else `$HOME/<default>`), so a run
/// without the proxy keys the same, and a real relocation still re-keys.
const DEFAULTED_HOMES: &[(&str, &str)] = &[("CARGO_HOME", ".cargo"), ("RUSTUP_HOME", ".rustup")];

/// `name`'s value as cargo and rustup see it: a defaulted home is filled in.
fn effective(name: &str, probe: &Probe) -> Option<OsString> {
    let set = probe.vars.get(name).filter(|v| !v.is_empty()).cloned();
    match DEFAULTED_HOMES.iter().find(|(n, _)| *n == name) {
        Some((_, default)) => set.or_else(|| {
            probe
                .home
                .as_ref()
                .map(|h| h.join(default).into_os_string())
        }),
        None => probe.vars.get(name).cloned(),
    }
}

/// Whether every key holds the variable `name` without declaring it.
fn keyed_by_prefix(name: &str) -> bool {
    CARGO_ENV_PREFIXES.iter().any(|p| name.starts_with(p))
        && !CARGO_RUN_ENV.contains(&name)
        && !RUSTUP_RESOLVED_ENV.contains(&name)
        && !DEFAULTED_HOMES.iter().any(|(n, _)| *n == name)
        && !CARGO_RUN_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Whether the variable `name` names a binary cargo runs.
fn names_binary(name: &str) -> bool {
    NAMED_ENV.contains(&name)
        || name
            .strip_prefix("CARGO_TARGET_")
            .is_some_and(|rest| rest.ends_with("_LINKER") || rest.ends_with("_RUNNER"))
}

const HOME_UNSET: &str = "HOME is unset or empty; cargo still reads the user's config, so the cache cannot fingerprint it";

/// The toolchain that builds the runner: every key fingerprints it, so a
/// toolchain update invalidates even gates that do not run cargo.
const RUNNER_TOOLS: &[&str] = &["rustc", "cargo"];

/// Labels whose lines carry no execute flag.
const NO_EXEC_FLAG: &[&str] = &["extra", "config", "target-spec"];

/// # Errors
/// A git failure; an unreadable root, runner directory, manifest,
/// `gates/cache-env.txt`, extra path or outside directory; an outside
/// directory that contains the root or holds too many files; a glob member
/// pointing outside the root; no `HOME` (cargo reads the user's
/// configuration to build the runner); or a path that cannot be handed to git on one line.
pub fn manifest(root: &Path, spec: &KeySpec, probe: &Probe) -> Result<String, String> {
    let canonical = CanonicalRoot::new(root)?;
    let root = canonical.as_path();
    let listed = listed_files(root, &["--cached", "--others", "--exclude-standard"])?;
    let cargo = spec.tools.contains(&"cargo");
    if probe.home.is_none() {
        return Err(HOME_UNSET.to_string());
    }

    let (mut outside, config) = build_context(&canonical, &listed, probe, cargo)?;
    let (specs, specs_missing) = target_specs(root, &outside, probe);

    // (label, shown path, full path) for one `hash_files` batch.
    let mut entries: Vec<(&str, String, PathBuf)> = Vec::new();
    let mut relative = |label, base: &Path, rel: Vec<PathBuf>| {
        entries.extend(rel.into_iter().map(|p| (label, shown(&p), base.join(p))));
    };
    let mut inputs: BTreeSet<PathBuf> = tree_inputs(root, &listed, spec.inputs)?
        .into_iter()
        .collect();
    inputs.append(&mut outside.path_targets);
    relative("file", root, inputs.into_iter().collect());
    relative(
        "config",
        root,
        std::mem::take(&mut outside.tree_configs)
            .into_iter()
            .collect(),
    );
    let runner = runner_files(probe)?;
    for (label, dir, files) in &runner {
        relative(label, dir, files.clone());
    }
    relative(
        "ignored",
        root,
        ignored_inputs(root, spec.ignored_inputs, OUTSIDE_FILE_LIMIT)?,
    );
    relative(
        "ignored-dep",
        root,
        std::mem::take(&mut outside.ignored).into_iter().collect(),
    );
    relative(
        "extra",
        root,
        EXTRAS
            .iter()
            .map(PathBuf::from)
            .filter(|f| root.join(f).is_file())
            .collect(),
    );
    let mut absolute = |label, full: BTreeSet<PathBuf>| {
        entries.extend(full.into_iter().map(|f| (label, shown(&f), f)));
    };
    let (extra_files, extra_missing) = extra_paths(spec, &canonical, probe)?;
    absolute("extra-path", extra_files);
    absolute("config", config);
    absolute("outside", std::mem::take(&mut outside.files));
    absolute("target-spec", specs);

    let paths: Vec<&Path> = entries.iter().map(|(_, _, full)| full.as_path()).collect();
    let blobs = hash_files(root, &paths)?;
    let mut lines = vec![format!("gate {}", spec.gate)];
    for ((label, shown, full), blob) in entries.iter().zip(blobs) {
        if NO_EXEC_FLAG.contains(label) {
            lines.push(format!("{label} {shown} {blob}"));
        } else {
            lines.push(format!("{label} {shown} {blob} {}", exec_flag(full)));
        }
    }
    lines.extend(extra_missing);
    lines.extend(specs_missing);
    lines.extend(
        outside
            .missing
            .iter()
            .map(|v| format!("outside-missing {v}")),
    );
    lines.push(format!("sysroot {:?}", probe.sysroot));
    let mut tools: BTreeSet<&str> = spec.tools.iter().copied().collect();
    tools.extend(RUNNER_TOOLS);
    for tool in tools {
        lines.extend(tool_lines(tool, probe));
    }
    let mut names = env_names(root, spec.env)?;
    lines.extend(named_binary_lines(root, &outside, probe));
    names.extend(probe.vars.keys().filter(|k| keyed_by_prefix(k)).cloned());
    names.extend(DEFAULTED_HOMES.iter().map(|(n, _)| (*n).to_string()));
    for var in names {
        lines.push(format!("env {var}={:?}", effective(&var, probe)));
    }
    if !spec.decl.is_empty() {
        lines.push(format!("decl {}", spec.decl));
    }
    lines.sort();
    Ok(lines.join("\n") + "\n")
}

/// (label, directory, source files relative to it) per runner directory.
type RunnerFiles<'a> = Vec<(String, &'a Path, Vec<PathBuf>)>;

/// Each runner directory's source files, with the label its manifest lines
/// carry: `runner` for the first, `runner+<n>` for the further ones.
fn runner_files(probe: &Probe) -> Result<RunnerFiles<'_>, String> {
    let mut out = Vec::new();
    for (i, dir) in probe.runner_dirs.iter().enumerate() {
        let mut files = Vec::new();
        files::walk_paths(dir, Path::new(""), Walk::Source, &mut |p| {
            files.push(p);
            Ok(())
        })?;
        let label = match i {
            0 => "runner".to_string(),
            n => format!("runner+{n}"),
        };
        out.push((label, dir.as_path(), files));
    }
    Ok(out)
}

/// Cargo builds the runner, so every key holds the runner's build context:
/// cargo configuration (with the runner chain's own content, whatever the
/// gate's inputs), the paths it and the runner's manifests name, and, in
/// `manifest`, the binaries it runs and the `CARGO_`/`RUST` environment.
/// Only cargo gates (`cargo`) follow the whole tree and the rustfmt and
/// clippy configuration. Returns the scan and the `config` files outside
/// the tree; in-tree configuration is left in `Outside::tree_configs`.
fn build_context(
    canonical: &CanonicalRoot,
    listed: &[PathBuf],
    probe: &Probe,
    cargo: bool,
) -> Result<(Outside, BTreeSet<PathBuf>), String> {
    let found = outside::config_files(canonical, probe);
    let runner = outside::runner_manifests(canonical, &probe.runner_dirs);
    let mut seeds = runner.clone();
    seeds.extend(found.cargo);
    let mut config = if cargo {
        found.files
    } else {
        found.cargo_files
    };
    let manifest = canonical.as_path().join("Cargo.toml");
    let not_inputs = match std::fs::read(&manifest) {
        Ok(text) => not_inputs::from_manifest(&String::from_utf8_lossy(&text))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(format!("{}: {e}", manifest.display())),
    };
    let mut outside = outside::scan(canonical, listed, &seeds, cargo, &not_inputs)?;
    // In-tree ones are shown relative to the root, so worktrees still share
    // keys.
    for (seed, _) in runner {
        let Some(seed) = seed.canonicalize().ok().filter(|p| p.is_file()) else {
            continue;
        };
        match seed.strip_prefix(canonical.as_path()) {
            Ok(rel) => {
                outside.tree_configs.insert(rel.to_path_buf());
            }
            Err(_) => {
                config.insert(seed);
            }
        }
    }
    config.append(&mut outside.rustfmt);
    config.append(&mut outside.configs);
    Ok((outside, config))
}

/// # Errors
/// As for `manifest`, or git failing to hash it.
pub fn key(root: &Path, spec: &KeySpec, probe: &Probe) -> Result<String, String> {
    let manifest = manifest(root, spec, probe)?;
    Ok(
        git_with_stdin(root, &["hash-object", "--stdin"], manifest.into_bytes())?
            .trim()
            .to_string(),
    )
}

/// The files under the declared `extra_paths`, canonical, and an
/// `extra-path-missing <entry>` line for each entry that does not exist.
fn extra_paths(
    spec: &KeySpec,
    canonical: &CanonicalRoot,
    probe: &Probe,
) -> Result<(BTreeSet<PathBuf>, Vec<String>), String> {
    let mut missing = Vec::new();
    let mut files = BTreeSet::new();
    for entry in spec
        .extra_paths
        .iter()
        .map(PathBuf::from)
        .chain(spec.cache_paths.iter().cloned())
    {
        match outside::extra_path(&entry, canonical, probe.home.as_deref())? {
            Some(found) => files.extend(found),
            None => missing.push(format!("extra-path-missing {}", shown(&entry))),
        }
    }
    Ok((files, missing))
}

/// A path as a manifest shows it: as is when it is UTF-8 and does not start
/// with `"`, else `{:?}`-escaped (which always starts with `"`), so a
/// non-UTF-8 name can never show like a UTF-8 one.
fn shown(path: &Path) -> String {
    match path.to_str() {
        Some(text) if !text.starts_with('"') => text.to_string(),
        _ => escaped(path),
    }
}

// Debug formatting is the point: it escapes non-UTF-8 bytes and newlines.
#[allow(clippy::unnecessary_debug_formatting)]
fn escaped(path: &Path) -> String {
    format!("{:?}", path.as_os_str())
}

/// The listed files the gate declares, each a regular file (deleted ones
/// skipped). A listed directory (a submodule or nested repository) is an
/// error under narrowed inputs too: it holds files git does not list that a
/// glob such as `**/*.rs` would match. Listed symlinks to directories are
/// left to the scan of the tree's symlinks.
fn tree_inputs(root: &Path, listed: &[PathBuf], inputs: Inputs) -> Result<Vec<PathBuf>, String> {
    let real_dir = |p: &Path| {
        root.join(p)
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_dir())
    };
    let selected: Vec<&PathBuf> = listed
        .iter()
        .filter(|p| match inputs {
            Inputs::Tree => true,
            Inputs::Globs(globs) => matches_any(globs, p) || real_dir(p),
        })
        .collect();
    for p in &selected {
        require_regular(root, p)?;
    }
    Ok(selected
        .into_iter()
        .filter(|p| root.join(p).is_file())
        .cloned()
        .collect())
}

fn matches_any(globs: &[&str], path: &Path) -> bool {
    let path = path.to_string_lossy();
    globs.iter().any(|g| glob::matches(g, &path))
}

/// Ignored files matching `globs`, at most `limit` of them. The listing can
/// be huge (`target/`), so it only runs when the gate declares any, and only
/// below the globs' literal leading directories when every glob has one.
fn ignored_inputs(root: &Path, globs: &[&str], limit: usize) -> Result<Vec<PathBuf>, String> {
    if globs.is_empty() {
        return Ok(Vec::new());
    }
    let mut args: Vec<String> = ["--others", "--ignored", "--exclude-standard"]
        .map(String::from)
        .to_vec();
    if let Some(prefixes) = literal_prefixes(globs) {
        args.push("--".to_string());
        args.extend(prefixes.iter().map(|p| format!(":(literal){p}")));
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let matched: Vec<PathBuf> = listed_files(root, &args)?
        .into_iter()
        .filter(|p| matches_any(globs, p) && root.join(p).is_file())
        .collect();
    if matched.len() > limit {
        return Err(format!(
            "ignored_inputs: more than {limit} files; the cache cannot fingerprint them"
        ));
    }
    Ok(matched)
}

/// Each glob's literal leading directories (`gen` for `gen/**`, `out/a` for
/// `out/a/*.rs`), or `None` when any glob starts with a wildcard or has no
/// directory part.
fn literal_prefixes(globs: &[&str]) -> Option<Vec<String>> {
    globs
        .iter()
        .map(|glob| {
            let dirs = glob.rsplit_once('/')?.0;
            let literal: Vec<&str> = dirs
                .split('/')
                .take_while(|seg| !seg.is_empty() && !seg.contains('*'))
                .collect();
            (!literal.is_empty()).then(|| literal.join("/"))
        })
        .collect()
}

/// The declared variables plus those listed in `gates/cache-env.txt`.
fn env_names(root: &Path, declared: &[&str]) -> Result<BTreeSet<String>, String> {
    let mut names: BTreeSet<String> = declared.iter().map(|v| (*v).to_string()).collect();
    let list = root.join(CACHE_ENV);
    if list.is_file() {
        let text = std::fs::read_to_string(&list).map_err(|e| format!("{CACHE_ENV}: {e}"))?;
        names.extend(
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string),
        );
    }
    Ok(names)
}

/// `git ls-files -z <which>`, sorted and deduplicated, names kept byte for
/// byte.
pub(crate) fn listed_files<S: AsRef<OsStr>>(
    root: &Path,
    which: &[S],
) -> Result<Vec<PathBuf>, String> {
    let out = git::command()
        .args(["ls-files", "-z"])
        .args(which)
        .current_dir(root)
        .output()
        .map_err(|e| format!("git ls-files: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git ls-files: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let mut found: Vec<PathBuf> = out
        .stdout
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| PathBuf::from(OsStr::from_bytes(p)))
        .collect();
    found.sort();
    found.dedup();
    Ok(found)
}

/// Deleted entries are skipped. Anything else that is not a regular file
/// (submodule, directory symlink, nested repository) cannot be fingerprinted.
fn require_regular(root: &Path, rel: &Path) -> Result<(), String> {
    let path = root.join(rel);
    if path.is_file() || path.symlink_metadata().is_err() {
        Ok(())
    } else {
        Err(format!(
            "{}: not a regular file (submodule, directory symlink or nested repository); the cache cannot fingerprint it",
            shown(rel)
        ))
    }
}

/// `x` when any execute bit is set (following symlinks, like the hash), else `-`.
fn exec_flag(path: &Path) -> char {
    match path.metadata() {
        Ok(meta) if meta.permissions().mode() & 0o111 != 0 => 'x',
        _ => '-',
    }
}

/// Every path must be absolute: `--stdin-paths` would unquote a line
/// starting with `"`.
fn hash_files(root: &Path, paths: &[&Path]) -> Result<Vec<String>, String> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let mut input = Vec::new();
    for path in paths {
        let bytes = path.as_os_str().as_bytes();
        if bytes.contains(&b'\n') {
            return Err(format!(
                "{}: a newline in a path cannot be hashed",
                escaped(path)
            ));
        }
        if !path.is_absolute() {
            return Err(format!(
                "{}: a relative path cannot be hashed",
                escaped(path)
            ));
        }
        input.extend_from_slice(bytes);
        input.push(b'\n');
    }
    let out = git_with_stdin(
        root,
        &["hash-object", "--no-filters", "--stdin-paths"],
        input,
    )?;
    let mut blobs: Vec<String> = out.lines().map(str::to_string).collect();
    if blobs.len() != paths.len() {
        return Err(format!(
            "git hash-object: {} hashes for {} paths",
            blobs.len(),
            paths.len()
        ));
    }
    // git reads as many bytes as stat reports, and virtual files (/proc,
    // /sys) report 0: hash those from what a read returns.
    for (path, blob) in paths.iter().zip(&mut blobs) {
        if path.metadata().is_ok_and(|m| m.is_file() && m.len() == 0) {
            let content = std::fs::read(path).map_err(|e| format!("{}: {e}", escaped(path)))?;
            if !content.is_empty() {
                *blob = git_with_stdin(root, &["hash-object", "--no-filters", "--stdin"], content)?
                    .trim()
                    .to_string();
            }
        }
    }
    Ok(blobs)
}

/// `git::with_stdin`, failing on a non-zero exit.
fn git_with_stdin(root: &Path, args: &[&str], input: Vec<u8>) -> Result<String, String> {
    let out = git::with_stdin(root, args, input)?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "git {}: {}",
            args[0],
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

fn tool_lines(tool: &str, probe: &Probe) -> Vec<String> {
    let found = probe
        .path
        .as_deref()
        .and_then(|p| tools::resolve_in(p, tool));
    let mut lines = vec![match found {
        Some(path) => format!("tool {tool} {}", fingerprint(&path)),
        None => format!("tool {tool} missing"),
    }];
    if let Some(bin) = probe
        .sysroot
        .as_ref()
        .map(|s| s.join("bin").join(tool))
        .filter(|b| b.is_file())
    {
        lines.push(format!("sysroot-tool {tool} {}", fingerprint(&bin)));
    }
    lines
}

/// The binaries cargo runs instead of its defaults: those variables name
/// (`names_binary`, resolved against the root; a `_RUNNER` value split at
/// whitespace, as cargo splits it) and those cargo configuration names
/// (resolved from the configuration's base).
fn named_binary_lines(root: &Path, outside: &Outside, probe: &Probe) -> Vec<String> {
    let search = probe.path.as_deref();
    let from_env = probe
        .vars
        .iter()
        .filter(|(name, _)| names_binary(name))
        .map(|(name, value)| {
            let program = if name.ends_with("_RUNNER") {
                first_word(value)
            } else {
                value.as_os_str()
            };
            named_binary(program, root, search)
        });
    let from_config = outside
        .named
        .iter()
        .map(|(value, base)| named_binary(OsStr::new(value), base, search));
    from_env.chain(from_config).flatten().collect()
}

/// Custom target specifications: `CARGO_BUILD_TARGET` (resolved against the
/// root) and cargo configuration `target` values (resolved from their base)
/// ending in `.json`. Returns the files found, canonical, and a
/// `target-spec-missing <value>` line for each one that is not a file.
fn target_specs(root: &Path, outside: &Outside, probe: &Probe) -> (BTreeSet<PathBuf>, Vec<String>) {
    let from_env = probe
        .vars
        .get("CARGO_BUILD_TARGET")
        .filter(|v| outside::has_suffix(v.as_bytes(), ".json"))
        .map(|v| (v.clone(), root.to_path_buf()));
    let from_config = outside
        .target_specs
        .iter()
        .map(|(value, base)| (OsString::from(value), base.clone()));
    let (mut found, mut missing) = (BTreeSet::new(), Vec::new());
    for (value, base) in from_env.into_iter().chain(from_config) {
        match base
            .join(&value)
            .canonicalize()
            .ok()
            .filter(|p| p.is_file())
        {
            Some(path) => {
                found.insert(path);
            }
            None => missing.push(format!("target-spec-missing {}", shown(Path::new(&value)))),
        }
    }
    (found, missing)
}

/// The first whitespace-separated word of `value`, or empty.
fn first_word(value: &OsStr) -> &OsStr {
    OsStr::from_bytes(
        value
            .as_bytes()
            .split(u8::is_ascii_whitespace)
            .find(|w| !w.is_empty())
            .unwrap_or_default(),
    )
}

/// A value naming a binary: a path (it contains `/`) resolves from `base`,
/// a bare name through `search`. `None` for an empty value.
fn named_binary(value: &OsStr, base: &Path, search: Option<&OsStr>) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    let found = if value.as_bytes().contains(&b'/') {
        Some(base.join(value))
    } else {
        value
            .to_str()
            .and_then(|name| search.and_then(|s| tools::resolve_in(s, name)))
    };
    Some(
        match found
            .and_then(|p| p.canonicalize().ok())
            .filter(|p| p.is_file())
        {
            Some(path) => format!("named-binary {}", fingerprint(&path)),
            None => format!("named-binary-missing {}", shown(Path::new(value))),
        },
    )
}

fn fingerprint(path: &Path) -> String {
    match path.metadata() {
        Ok(meta) => {
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_nanos());
            format!("{} {} {mtime}", path.display(), meta.len())
        }
        Err(_) => format!("{} unreadable", path.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::{home_from, ignored_inputs, literal_prefixes};
    use std::ffi::OsString;
    use std::path::PathBuf;

    #[test]
    fn an_empty_home_is_unset() {
        assert_eq!(home_from(None), None);
        assert_eq!(home_from(Some(OsString::new())), None);
        assert_eq!(home_from(Some("/h".into())), Some(PathBuf::from("/h")));
    }

    #[test]
    fn literal_prefixes_need_a_literal_directory_on_every_glob() {
        assert_eq!(
            literal_prefixes(&["gen/**", "out/a/*.rs"]),
            Some(vec!["gen".to_string(), "out/a".to_string()])
        );
        assert_eq!(literal_prefixes(&["gen/**", "**/*.gen"]), None);
        assert_eq!(literal_prefixes(&["a.gen"]), None);
        assert_eq!(literal_prefixes(&["*/x/y.rs"]), None);
    }

    #[test]
    fn more_matched_ignored_files_than_the_limit_is_an_error() {
        let dir = std::env::temp_dir().join(format!("xtask-ignored-limit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("gen")).unwrap();
        std::fs::write(dir.join(".gitignore"), "gen/\n").unwrap();
        for f in ["a.gen", "b.gen", "c.txt"] {
            std::fs::write(dir.join("gen").join(f), f).unwrap();
        }
        let init = crate::git::command()
            .args(["init", "-q"])
            .current_dir(&dir)
            .status();
        let at_limit = ignored_inputs(&dir, &["gen/*.gen"], 2).map(|f| f.len());
        let over = ignored_inputs(&dir, &["gen/*.gen"], 1);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(init.is_ok_and(|s| s.success()));
        assert_eq!(at_limit, Ok(2));
        let err = over.unwrap_err();
        assert!(err.contains("more than 1 files"), "{err}");
    }
}
