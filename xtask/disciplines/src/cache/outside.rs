// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Inputs outside the repository. Git does not list them, so the key
//! fingerprints them separately.
//!
//! - Path dependencies (`scan`, cargo gates): every `Cargo.toml` and
//!   `.cargo/config{,.toml}` in the tree, and every cargo configuration file
//!   `config_files` finds outside it, is scanned as text for string values
//!   of `PATH_KEYS`, bare or quoted. A value resolving outside the root names
//!   a directory whose files join the key (a file names its whole parent
//!   directory), and that directory's own manifests are scanned in turn,
//!   along with the rustfmt configuration in its ancestors. A value resolving
//!   inside the root adds what git does not list: the ignored files below a
//!   directory, or below an ignored file's directory, plus ignored rustfmt
//!   configuration above it. A root manifest with a `[package]` table names
//!   the root itself, as `members = ["."]` does. A glob value (`members = ["../x/*"]`) whose
//!   literal prefix is outside the root is an error; inside, its prefix is
//!   treated as an in-tree directory. A false positive only costs a cache
//!   miss.
//! - Directory symlinks (`scan`): every listed symlink resolving to a
//!   directory outside the root is followed, one resolving inside it adds
//!   that directory's ignored files, and a dangling one is an error.
//! - Included cargo configuration (`include`, `[[include]] path`, `scan`):
//!   resolved from the including file's directory, fingerprinted and read
//!   as cargo configuration in turn.
//! - `#[path]` attributes in the tree's and ignored dependencies' `.rs`
//!   files (`scan`): the files they name.
//! - Custom target specifications (`target` values ending in `.json`,
//!   `scan`).
//! - Binaries named by cargo configuration (`NAMED_KEYS` and `runner`,
//!   `scan`).
//! - Declared `extra_paths` (`extra_path`).
//! - Configuration cargo, rustfmt and clippy read from outside the tree
//!   (`config_files`): cargo's for every gate (cargo builds the runner),
//!   rustfmt's and clippy's for cargo gates.
//!
//! Outside directories, and the ignored files below in-tree ones, skip only
//! `.git` and directories holding cargo's `CACHEDIR.TAG` (build output);
//! in-tree walks also skip the declared `not_inputs` directories below
//! their start;
//! extra directories are walked whole. Both follow symlinked files. An
//! outside or extra directory that contains the repository, holds more than
//! `OUTSIDE_FILE_LIMIT` files or holds a symlinked directory is an error: the
//! gate runs.
use std::collections::{BTreeSet, HashMap};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::key::{self, Probe};
use crate::duplication::files::{self, Walk};

/// The most files one outside directory may hold before the cache gives up.
pub const OUTSIDE_FILE_LIMIT: usize = 20_000;

/// The repository root, canonicalized. Only `new` builds one, so the
/// contains-the-root bound and the ancestor walk always see the real path,
/// however the root was spelled (`./`, `..`, a symlink).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalRoot(PathBuf);

impl CanonicalRoot {
    /// # Errors
    /// `root` cannot be canonicalized (it does not exist, or is unreadable).
    pub fn new(root: &Path) -> Result<CanonicalRoot, String> {
        root.canonicalize()
            .map(CanonicalRoot)
            .map_err(|e| format!("{}: {e}", root.display()))
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// What the scan found.
#[derive(Default)]
pub struct Outside {
    /// Every file below each outside directory (`.git` and build output
    /// skipped), as canonical absolute paths.
    pub files: BTreeSet<PathBuf>,
    /// Values that resolve to nothing: their later appearance changes the key.
    pub missing: BTreeSet<String>,
    /// Ignored files below each in-tree directory a value names (build
    /// output skipped), relative to the root.
    pub ignored: BTreeSet<PathBuf>,
    /// `rustfmt.toml` and `.rustfmt.toml` in each outside directory's
    /// ancestors, canonical.
    pub rustfmt: BTreeSet<PathBuf>,
    /// The first string of each `NAMED_KEYS` or `runner` value in a cargo
    /// configuration file, with the directory a relative path resolves from.
    pub named: BTreeSet<(String, PathBuf)>,
    /// Cargo configuration files outside the tree that another one
    /// includes, canonical.
    pub configs: BTreeSet<PathBuf>,
    /// Listed cargo configuration files that another one includes, relative
    /// to the root.
    pub tree_configs: BTreeSet<PathBuf>,
    /// Listed files a `#[path]` attribute names, relative to the root: the
    /// gate reads them whatever its declared inputs.
    pub path_targets: BTreeSet<PathBuf>,
    /// Each `target` value ending in `.json` in a cargo configuration file
    /// (a custom target specification), with the directory it resolves from.
    pub target_specs: BTreeSet<(String, PathBuf)>,
}

/// `listed` are the tree's files, relative to `root`. `seeds` are the
/// manifests to start from, each with the directory its paths resolve from:
/// cargo configuration outside the tree (see `Config::cargo`) and the
/// runner's own chain (`runner_manifests`). With `whole_tree` (cargo gates),
/// the tree's manifests, directory symlinks and `#[path]` attributes are
/// followed too.
///
/// # Errors
/// An unreadable manifest, root or outside directory; an outside directory
/// that contains the root, holds too many files or holds a symlinked
/// directory; a glob value pointing outside the root; a dangling listed
/// symlink; or more than
/// `OUTSIDE_FILE_LIMIT` ignored in-tree files.
pub fn scan(
    canonical: &CanonicalRoot,
    listed: &[PathBuf],
    seeds: &[(PathBuf, PathBuf)],
    whole_tree: bool,
    not_inputs: &[PathBuf],
) -> Result<Outside, String> {
    let root = canonical.as_path();
    let mut scan = Scan {
        canonical,
        listed,
        not_inputs,
        queue: seeds.to_vec(),
        sources: Vec::new(),
        seen: BTreeSet::new(),
        found: Outside::default(),
    };
    if whole_tree {
        scan.sources
            .extend(listed.iter().filter(|p| is_rust(p)).map(|p| root.join(p)));
        scan.queue.extend(
            listed
                .iter()
                .filter(|p| is_manifest(&p.to_string_lossy()))
                .map(|p| with_base(root.join(p))),
        );
        scan.tree_symlinks()?;
        // A root package is a member whose directory is the root: its ignored
        // files count, as a member's do (`members = ["."]` names it explicitly).
        if root_is_package(root) {
            let root_dir = root.to_path_buf();
            scan.inside_dir(&root_dir)?;
        }
    }
    loop {
        if let Some((manifest, base)) = scan.queue.pop() {
            scan.manifest(&manifest, &base)?;
        } else if let Some(source) = scan.sources.pop() {
            scan.source(&source)?;
        } else {
            break;
        }
    }
    if scan.found.ignored.len() > OUTSIDE_FILE_LIMIT {
        return Err(format!(
            "ignored path dependencies: more than {OUTSIDE_FILE_LIMIT} files; the cache cannot fingerprint them (list ignored directories no build step reads under [workspace.metadata.disciplines] not_inputs)"
        ));
    }
    Ok(scan.found)
}

/// The state of one `scan`.
struct Scan<'a> {
    canonical: &'a CanonicalRoot,
    /// The tree's files, sorted: anything else in the tree is ignored.
    listed: &'a [PathBuf],
    /// Directories whose ignored files a walk from above them leaves out.
    not_inputs: &'a [PathBuf],
    /// Manifests still to read, each with its base.
    queue: Vec<(PathBuf, PathBuf)>,
    /// Rust sources still to read for `#[path]` attributes: the listed ones,
    /// then the ignored ones found.
    sources: Vec<PathBuf>,
    /// Directories and included configuration files already followed.
    seen: BTreeSet<PathBuf>,
    found: Outside,
}

impl Scan<'_> {
    fn root(&self) -> &Path {
        self.canonical.as_path()
    }

    /// A `Cargo.toml` or cargo configuration file: its `PATH_KEYS` values,
    /// and for a configuration file also its binaries, target
    /// specifications and includes.
    fn manifest(&mut self, manifest: &Path, base: &Path) -> Result<(), String> {
        if !manifest.is_file() {
            return Ok(());
        }
        let text = std::fs::read(manifest).map_err(|e| format!("{}: {e}", manifest.display()))?;
        let text = String::from_utf8_lossy(&text);
        if manifest.file_name().is_some_and(|n| n != "Cargo.toml") {
            self.named_values(&text, base);
            self.includes(&text, manifest);
        }
        for value in assignments(&text, PATH_KEYS)
            .into_iter()
            .flat_map(|a| a.strings)
        {
            self.value(value, base)?;
        }
        Ok(())
    }

    /// The files a cargo configuration file includes (`include = "…"`,
    /// `include = ["…", { path = "…" }]`, `[[include]] path = "…"`; any
    /// `path` ending in `.toml` counts), resolved from its own directory.
    /// Each is fingerprinted (an outside one as configuration, an ignored
    /// in-tree one as an ignored dependency, a listed one as in-tree
    /// configuration: narrowed gates do not list it among their inputs)
    /// and read as configuration in turn; its own paths resolve from the
    /// parent of its directory, as cargo resolves any configuration file's.
    /// A missing one is recorded, so an optional include appearing changes
    /// the key.
    fn includes(&mut self, text: &str, config: &Path) {
        let dir = config.parent().unwrap_or(config);
        let strings = |keys| assignments(text, keys).into_iter().flat_map(|a| a.strings);
        let values = strings(&["include"])
            .chain(strings(&["path"]).filter(|v| has_suffix(v.as_bytes(), ".toml")));
        for value in values.collect::<Vec<_>>() {
            let Ok(file) = dir.join(&value).canonicalize() else {
                self.found.missing.insert(value);
                continue;
            };
            if !file.is_file() || !self.seen.insert(file.clone()) {
                continue;
            }
            match file.strip_prefix(self.root()).map(Path::to_path_buf) {
                Ok(rel) if self.listed.binary_search(&rel).is_ok() => {
                    self.found.tree_configs.insert(rel);
                }
                Ok(rel) => {
                    self.found.ignored.insert(rel);
                }
                Err(_) => {
                    self.found.configs.insert(file.clone());
                }
            }
            let base = file
                .parent()
                .and_then(Path::parent)
                .unwrap_or(&file)
                .to_path_buf();
            self.queue.push((file, base));
        }
    }

    /// Every listed symlink resolving to a directory: one outside the root is
    /// followed, one inside it adds that directory's ignored files (a tracked
    /// `m/src/gen -> ../../ext` puts `ext`'s files into `m`). A dangling one
    /// is an error.
    fn tree_symlinks(&mut self) -> Result<(), String> {
        let links: Vec<PathBuf> = self
            .listed
            .iter()
            .map(|p| self.root().join(p))
            .filter(|full| full.symlink_metadata().is_ok_and(|m| m.is_symlink()))
            .collect();
        for link in links {
            let Ok(resolved) = link.canonicalize() else {
                return Err(format!(
                    "{}: dangling symlink; the cache cannot follow it",
                    link.display()
                ));
            };
            if !resolved.is_dir() {
                continue;
            }
            if resolved.starts_with(self.root()) {
                self.inside_dir(&resolved)?;
            } else {
                self.outside_dir(&resolved)?;
            }
        }
        Ok(())
    }

    /// A Rust source's `#[path = "…"]` attributes (also inside `cfg_attr`),
    /// each resolved from the source's directory. A listed target is
    /// recorded for the key, an ignored or outside one is followed as a file
    /// value is, and a missing one is recorded.
    fn source(&mut self, source: &Path) -> Result<(), String> {
        let text = match std::fs::read(source) {
            Ok(text) => text,
            // A listed source that was deleted: nothing to read.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("{}: {e}", source.display())),
        };
        let dir = source.parent().unwrap_or(source);
        for value in path_attributes(&String::from_utf8_lossy(&text)) {
            let Ok(target) = dir.join(&value).canonicalize() else {
                self.found.missing.insert(value);
                continue;
            };
            if !target.is_file() {
                continue;
            }
            match target.strip_prefix(self.root()).map(Path::to_path_buf) {
                Ok(rel) if self.listed.binary_search(&rel).is_ok() => {
                    self.found.path_targets.insert(rel);
                }
                Ok(_) => self.inside_file(&target)?,
                Err(_) => {
                    let parent = target.parent().unwrap_or(&target).to_path_buf();
                    self.outside_dir(&parent)?;
                }
            }
        }
        Ok(())
    }

    /// `NAMED_KEYS` values of a cargo configuration file: the first string
    /// of each; `runner`'s split at whitespace, as cargo splits it. Also its
    /// `target` values ending in `.json`.
    fn named_values(&mut self, text: &str, base: &Path) {
        for (keys, split) in [(NAMED_KEYS, false), (&["runner"][..], true)] {
            for assigned in assignments(text, keys) {
                let Some(first) = assigned.strings.into_iter().next() else {
                    continue;
                };
                // Cargo splits only the plain-string form.
                let value = if split && !assigned.array {
                    first.split_whitespace().next().unwrap_or("").to_string()
                } else {
                    first
                };
                self.found.named.insert((value, base.to_path_buf()));
            }
        }
        for value in assignments(text, &["target"])
            .into_iter()
            .flat_map(|a| a.strings)
            .filter(|v| has_suffix(v.as_bytes(), ".json"))
        {
            self.found.target_specs.insert((value, base.to_path_buf()));
        }
    }

    /// One `PATH_KEYS` string, resolved from `base`.
    fn value(&mut self, value: String, base: &Path) -> Result<(), String> {
        let pattern = glob_prefix(&value);
        let Ok(target) = base.join(pattern.unwrap_or(&value)).canonicalize() else {
            self.found.missing.insert(value);
            return Ok(());
        };
        let inside = target.starts_with(self.root());
        match pattern {
            Some(_) if !inside => Err(format!(
                "{value}: glob pointing outside the repository; the cache cannot follow it"
            )),
            Some(_) => self.inside_glob(&target),
            None if inside && target.is_dir() => self.inside_dir(&target),
            None if inside => self.inside_file(&target),
            None if target.is_dir() => self.outside_dir(&target),
            None => {
                let dir = target.parent().unwrap_or(&target).to_path_buf();
                self.outside_dir(&dir)
            }
        }
    }

    /// A glob's literal prefix inside the root: its ignored files. The
    /// listed symlinks below it (a tracked `crates/a/x -> ../../ext` matches
    /// `crates/*/x`) are followed by `tree_symlinks`, like every other.
    fn inside_glob(&mut self, prefix: &Path) -> Result<(), String> {
        if prefix.is_dir() {
            self.inside_dir(prefix)
        } else {
            Ok(())
        }
    }

    /// An in-tree directory: the ignored files below it, and the ignored
    /// rustfmt configuration above it.
    fn inside_dir(&mut self, dir: &Path) -> Result<(), String> {
        if !self.seen.insert(dir.to_path_buf()) {
            return Ok(());
        }
        let rel = dir.strip_prefix(self.root()).unwrap_or(Path::new(""));
        for file in ignored_below(self.root(), rel, self.not_inputs)? {
            self.add_ignored(file);
        }
        self.ignored_rustfmt_above(rel);
        Ok(())
    }

    /// An in-tree file. An ignored one names its directory's ignored files,
    /// as an outside file names its whole directory; a listed one adds only
    /// the ignored rustfmt configuration above it (its listed siblings are
    /// tree inputs already).
    fn inside_file(&mut self, file: &Path) -> Result<(), String> {
        let Ok(rel) = file.strip_prefix(self.root()).map(Path::to_path_buf) else {
            return Ok(());
        };
        let parent = file.parent().unwrap_or(file);
        if self.listed.binary_search(&rel).is_err() {
            self.inside_dir(parent)
        } else {
            self.ignored_rustfmt_above(rel.parent().unwrap_or(Path::new("")));
            Ok(())
        }
    }

    /// `rustfmt.toml` and `.rustfmt.toml` that git does not list, in
    /// `rel_dir` and each in-tree ancestor.
    fn ignored_rustfmt_above(&mut self, rel_dir: &Path) {
        for dir in rel_dir.ancestors() {
            for name in ["rustfmt.toml", ".rustfmt.toml"] {
                let rel = dir.join(name);
                if self.listed.binary_search(&rel).is_err() && self.root().join(&rel).is_file() {
                    self.add_ignored(rel);
                }
            }
        }
    }

    fn add_ignored(&mut self, rel: PathBuf) {
        if is_manifest(&rel.to_string_lossy()) {
            self.queue.push(with_base(self.root().join(&rel)));
        }
        if is_rust(&rel) && !self.found.ignored.contains(&rel) {
            self.sources.push(self.root().join(&rel));
        }
        self.found.ignored.insert(rel);
    }

    /// An outside directory: its files, its manifests and the rustfmt
    /// configuration above it.
    fn outside_dir(&mut self, dir: &Path) -> Result<(), String> {
        if !self.seen.insert(dir.to_path_buf()) {
            return Ok(());
        }
        self.found.rustfmt.extend(rustfmt_above(dir));
        let manifests = collect(dir, self.canonical, &mut self.found.files)?;
        self.queue.extend(manifests.into_iter().map(with_base));
        Ok(())
    }
}

/// A glob value's literal prefix: the segments before the first one holding
/// `*`, `?` or `[` (`../x` for `../x/*`, empty for `*`). `None` when `value`
/// is not a glob.
fn glob_prefix(value: &str) -> Option<&str> {
    let glob = |seg: &str| seg.contains(['*', '?', '[']);
    if !glob(value) {
        return None;
    }
    let mut end = 0;
    for seg in value.split('/') {
        if glob(seg) {
            break;
        }
        end += seg.len() + 1;
    }
    Some(&value[..end.saturating_sub(1)])
}

/// The ignored files below the in-tree directory `rel`, skipping those
/// under a directory (at or below `rel`) that holds `CACHEDIR.TAG`, and
/// those under a `not_inputs` directory `rel` is not itself in: a value
/// naming a directory there is evidence the build reads it.
///
/// # Errors
/// git fails, or an ignored entry is a directory (a symlinked directory or a
/// nested repository) whose files cannot be listed.
fn ignored_below(root: &Path, rel: &Path, not_inputs: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut pathspec = OsString::from(":(literal)");
    pathspec.push(rel);
    let listed = key::listed_files(
        root,
        &[
            OsString::from("--others"),
            OsString::from("--ignored"),
            OsString::from("--exclude-standard"),
            OsString::from("--"),
            pathspec,
        ],
    )?;
    let mut tagged: HashMap<PathBuf, bool> = HashMap::new();
    let mut is_tagged = |dir: &Path| {
        *tagged
            .entry(dir.to_path_buf())
            .or_insert_with(|| root.join(dir).join(CACHEDIR_TAG).is_file())
    };
    let skipped: Vec<&PathBuf> = not_inputs.iter().filter(|d| !rel.starts_with(d)).collect();
    let mut kept = Vec::new();
    for file in listed {
        if skipped.iter().any(|d| file.starts_with(d)) {
            continue;
        }
        let parent = file.parent().unwrap_or(Path::new(""));
        if parent
            .ancestors()
            .take_while(|a| a.starts_with(rel))
            .any(&mut is_tagged)
        {
            continue;
        }
        let full = root.join(&file);
        if full.is_file() {
            kept.push(file);
        } else if full.is_dir() {
            return Err(format!(
                "{}: ignored directory (symlink or nested repository); the cache cannot fingerprint it (list ignored directories no build step reads under [workspace.metadata.disciplines] not_inputs)",
                full.display()
            ));
        }
    }
    Ok(kept)
}

/// The rustfmt configuration files in `dir`'s strict ancestors, canonical.
fn rustfmt_above(dir: &Path) -> Vec<PathBuf> {
    dir.ancestors()
        .skip(1)
        .flat_map(|a| ["rustfmt.toml", ".rustfmt.toml"].map(|n| a.join(n)))
        .filter(|f| f.is_file())
        .filter_map(|f| f.canonicalize().ok())
        .collect()
}

/// Adds the files of `dir` to `files`; returns the manifests among them.
fn collect(
    dir: &Path,
    root: &CanonicalRoot,
    files: &mut BTreeSet<PathBuf>,
) -> Result<Vec<PathBuf>, String> {
    let mut manifests: Vec<PathBuf> = [".cargo/config.toml", ".cargo/config"]
        .iter()
        .map(|c| dir.join(c))
        .collect();
    for rel in dir_files(dir, root, OUTSIDE_FILE_LIMIT, Walk::Outside)? {
        if is_manifest(&rel.to_string_lossy()) {
            manifests.push(dir.join(&rel));
        }
        files.insert(dir.join(rel));
    }
    Ok(manifests)
}

/// The files below `dir`, walked as `mode` says, relative to it, names kept
/// byte for byte.
///
/// # Errors
/// `dir` contains `root`, holds more than `limit` files or a
/// symlinked directory, or cannot be read.
pub(crate) fn dir_files(
    dir: &Path,
    root: &CanonicalRoot,
    limit: usize,
    mode: Walk,
) -> Result<Vec<PathBuf>, String> {
    if root.as_path().starts_with(dir) {
        return Err(format!(
            "{}: contains the repository; the cache cannot fingerprint it",
            dir.display()
        ));
    }
    let mut found = Vec::new();
    files::walk_paths(dir, Path::new(""), mode, &mut |rel| {
        if found.len() == limit {
            return Err(format!(
                "{}: more than {limit} files; the cache cannot fingerprint it",
                dir.display()
            ));
        }
        found.push(rel);
        Ok(())
    })?;
    Ok(found)
}

/// One declared `extra_paths` entry: absolute, `~/`-prefixed (against
/// `home`, an error without one) or relative to `root`. `Ok(None)` when it does not
/// exist; otherwise its canonical files (the entry itself, or every file
/// below it, hidden, `target` and symlinked files included).
///
/// # Errors
/// A `~/` entry without a home, an unreadable entry, one that is neither a regular file nor a directory
/// (hashing a FIFO would block), or a directory `dir_files` refuses.
pub fn extra_path(
    entry: &str,
    root: &CanonicalRoot,
    home: Option<&Path>,
) -> Result<Option<Vec<PathBuf>>, String> {
    let path = match entry.strip_prefix("~/") {
        Some(rest) => match home {
            Some(home) => home.join(rest),
            None => {
                return Err(format!(
                    "{entry}: HOME is unset or empty; the cache cannot resolve it"
                ));
            }
        },
        None => root.as_path().join(entry),
    };
    let path = match path.canonicalize() {
        Ok(path) => path,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{entry}: {e}")),
    };
    if path.is_file() {
        return Ok(Some(vec![path]));
    }
    if !path.is_dir() {
        return Err(format!(
            "{entry}: not a regular file or directory; the cache cannot fingerprint it"
        ));
    }
    let files = dir_files(&path, root, OUTSIDE_FILE_LIMIT, Walk::Full)?;
    Ok(Some(files.into_iter().map(|rel| path.join(rel)).collect()))
}

/// The manifests the runner itself is built from: its crates' `Cargo.toml`
/// and the workspace root's `Cargo.toml` and `.cargo/config{,.toml}`, each
/// with its base. Every gate's key follows them, so a path dependency,
/// `[patch]` path or include of the runner's build counts even for gates
/// that do not use cargo (duplication is served from the cache on main).
#[must_use]
pub fn runner_manifests(root: &CanonicalRoot, runner_dirs: &[PathBuf]) -> Vec<(PathBuf, PathBuf)> {
    let root = root.as_path();
    runner_dirs
        .iter()
        .map(|dir| dir.join("Cargo.toml"))
        .chain([
            root.join("Cargo.toml"),
            root.join(".cargo/config.toml"),
            root.join(".cargo/config"),
        ])
        .map(with_base)
        .collect()
}

/// Configuration files in every strict ancestor of the root.
const ANCESTOR_CONFIG: &[&str] = &[
    ".cargo/config",
    ".cargo/config.toml",
    "rustfmt.toml",
    ".rustfmt.toml",
    "clippy.toml",
    ".clippy.toml",
];

/// The configuration found outside the tree.
pub struct Config {
    /// Every configuration file that exists, canonical.
    pub files: BTreeSet<PathBuf>,
    /// The cargo configuration files among them, canonical: every gate's
    /// key holds these, since cargo builds the runner.
    pub cargo_files: BTreeSet<PathBuf>,
    /// The cargo configuration files among them, each with the directory its
    /// paths resolve from: the directory holding `.cargo` for an ancestor's,
    /// `$CARGO_HOME`'s parent for cargo home's. `scan` follows their paths.
    pub cargo: Vec<(PathBuf, PathBuf)>,
}

/// The configuration files outside the tree that cargo, rustfmt and clippy
/// read: `ANCESTOR_CONFIG` above the root, `$CARGO_HOME/config{,.toml}`
/// (default `<home>/.cargo`), `$XDG_CONFIG_HOME/rustfmt/{rustfmt,.rustfmt}.toml`
/// (default `<home>/.config`) and `<home>/{rustfmt,.rustfmt}.toml`.
#[must_use]
pub fn config_files(root: &CanonicalRoot, probe: &Probe) -> Config {
    let home = probe.home.as_deref();
    let dir_from = |var: &str, default: &str| {
        probe
            .vars
            .get(var)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| home.map(|h| h.join(default)))
    };
    // (file, base directory when it is a cargo configuration file)
    let mut candidates: Vec<(PathBuf, Option<PathBuf>)> = Vec::new();
    for dir in root.as_path().ancestors().skip(1) {
        for name in ANCESTOR_CONFIG {
            let base = name.starts_with(".cargo/").then(|| dir.to_path_buf());
            candidates.push((dir.join(name), base));
        }
    }
    if let Some(cargo_home) = dir_from("CARGO_HOME", ".cargo") {
        let base = cargo_home.parent().unwrap_or(&cargo_home).to_path_buf();
        for name in ["config", "config.toml"] {
            candidates.push((cargo_home.join(name), Some(base.clone())));
        }
    }
    let rustfmt_dirs = dir_from("XDG_CONFIG_HOME", ".config")
        .map(|c| c.join("rustfmt"))
        .into_iter()
        .chain(home.map(Path::to_path_buf));
    for dir in rustfmt_dirs {
        for name in ["rustfmt.toml", ".rustfmt.toml"] {
            candidates.push((dir.join(name), None));
        }
    }
    let mut config = Config {
        files: BTreeSet::new(),
        cargo_files: BTreeSet::new(),
        cargo: Vec::new(),
    };
    for (file, base) in candidates {
        let Some(canonical) = file.is_file().then(|| file.canonicalize().ok()).flatten() else {
            continue;
        };
        if let Some(base) = base {
            config.cargo_files.insert(canonical.clone());
            config.cargo.push((file, base));
        }
        config.files.insert(canonical);
    }
    config
}

/// Whether `value` ends with `suffix`, ignoring ASCII case (cargo does not,
/// so this only widens what the key follows).
pub(crate) fn has_suffix(value: &[u8], suffix: &str) -> bool {
    value.len() >= suffix.len()
        && value[value.len() - suffix.len()..].eq_ignore_ascii_case(suffix.as_bytes())
}

/// Whether the root manifest has a `[package]` table.
fn root_is_package(root: &Path) -> bool {
    std::fs::read_to_string(root.join("Cargo.toml"))
        .is_ok_and(|text| text.lines().any(|l| l.trim() == "[package]"))
}

fn is_rust(path: &Path) -> bool {
    path.extension().is_some_and(|e| e == "rs")
}

/// The `path` strings of each attribute (`#[path = "…"]`,
/// `#[cfg_attr(…, path = "…")]`), found as text like the TOML values: a
/// false positive only costs a cache miss.
fn path_attributes(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (start, _) in text.match_indices("#[") {
        let body = &text[start + 2..];
        let body = &body[..body.find(']').unwrap_or(body.len())];
        let name = body.trim_start();
        if name.starts_with("path") || name.starts_with("cfg_attr") {
            found.extend(
                assignments(body, &["path"])
                    .into_iter()
                    .flat_map(|a| a.strings),
            );
        }
    }
    found
}

fn is_manifest(rel: &str) -> bool {
    let (dir, name) = rel.rsplit_once('/').unwrap_or(("", rel));
    name == "Cargo.toml"
        || ((dir == ".cargo" || dir.ends_with("/.cargo"))
            && (name == "config.toml" || name == "config"))
}

/// A manifest found in the tree or an outside directory, with its base.
fn with_base(manifest: PathBuf) -> (PathBuf, PathBuf) {
    let base = base_dir(&manifest).to_path_buf();
    (manifest, base)
}

/// Cargo resolves a manifest's paths from its directory, and a config file's
/// from the directory holding `.cargo`.
fn base_dir(manifest: &Path) -> &Path {
    let dir = manifest.parent().unwrap_or(manifest);
    if dir.file_name().is_some_and(|n| n == ".cargo") {
        dir.parent().unwrap_or(dir)
    } else {
        dir
    }
}

/// Cargo writes this file into every build directory it creates.
const CACHEDIR_TAG: &str = "CACHEDIR.TAG";

/// Keys whose string values may name a path.
const PATH_KEYS: &[&str] = &[
    "path",
    "paths",
    "build",
    "workspace",
    "directory",
    "members",
    "default-members",
    "local-registry",
];

/// Cargo configuration keys naming a binary cargo runs, besides `runner`
/// (whose string form cargo splits at whitespace).
pub const NAMED_KEYS: &[&str] = &[
    "rustc",
    "rustc-wrapper",
    "rustc-workspace-wrapper",
    "rustdoc",
    "linker",
];

/// The strings of each assignment to one of `keys` (`path = "…"`,
/// `"path"="…"`, `paths = ["…", …]`), including dotted keys and inline
/// tables. Non-string values (`workspace = true`) give no strings.
pub(crate) fn assignments(text: &str, keys: &[&str]) -> Vec<Assignment> {
    let mut out = Vec::new();
    for (eq, _) in text.match_indices('=') {
        if !key_before(&text[..eq]).is_some_and(|k| keys.contains(&k)) {
            continue;
        }
        let value = text[eq + 1..].trim_start_matches([' ', '\t']);
        let mut strings = Vec::new();
        let array = value.starts_with('[');
        if let Some(array) = value.strip_prefix('[') {
            let mut rest = array.split(']').next().unwrap_or("");
            while let Some((s, tail)) = rest.find(['"', '\'']).and_then(|i| quoted(&rest[i..])) {
                strings.push(s.to_string());
                rest = tail;
            }
        } else if let Some((s, _)) = quoted(value) {
            strings.push(s.to_string());
        }
        out.push(Assignment { array, strings });
    }
    out
}

/// One assignment `assignments` found.
pub(crate) struct Assignment {
    /// The value is an array (`["…", …]`), not a plain string.
    pub(crate) array: bool,
    /// Its strings, in order.
    pub(crate) strings: Vec<String>,
}

/// The key ending `text`, trailing blanks skipped: the body of a `"…"` or
/// `'…'` key, or the last run of bare-key characters.
fn key_before(text: &str) -> Option<&str> {
    let text = text.trim_end_matches([' ', '\t']);
    if let Some(quote) = text.chars().next_back().filter(|c| *c == '"' || *c == '\'') {
        let body = &text[..text.len() - 1];
        return body.rfind(quote).map(|start| &body[start + 1..]);
    }
    let bare = |c: char| c.is_alphanumeric() || c == '_' || c == '-';
    let start = text
        .char_indices()
        .rev()
        .take_while(|(_, c)| bare(*c))
        .last()
        .map(|(i, _)| i)?;
    Some(&text[start..])
}

/// A string opening `text`, and the text after it: a multi-line `"""…"""`
/// or `'''…'''`, or a single-line `"…"` or `'…'`.
fn quoted(text: &str) -> Option<(&str, &str)> {
    for fence in ["\"\"\"", "'''"] {
        if let Some(body) = text.strip_prefix(fence) {
            let end = body.find(fence)?;
            // TOML trims a newline right after the opening delimiter.
            let value = &body[..end];
            let value = value
                .strip_prefix("\r\n")
                .or_else(|| value.strip_prefix('\n'))
                .unwrap_or(value);
            return Some((value, &body[end + fence.len()..]));
        }
    }
    let quote = text.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let body = &text[1..];
    let end = body.find(quote)?;
    Some((&body[..end], &body[end + 1..]))
}

#[cfg(test)]
mod tests {
    use super::{CanonicalRoot, dir_files};
    use crate::duplication::files::Walk;
    use std::path::Path;

    #[test]
    fn a_directory_over_the_file_limit_is_an_error() {
        let dir = std::env::temp_dir().join(format!("xtask-outside-limit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        for f in ["a", "b", "sub/c"] {
            std::fs::write(dir.join(f), f).unwrap();
        }
        let root = CanonicalRoot::new(Path::new("/")).unwrap();
        let at_limit = dir_files(&dir, &root, 3, Walk::Full).map(|f| f.len());
        let over = dir_files(&dir, &root, 2, Walk::Full);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(at_limit, Ok(3));
        let err = over.unwrap_err();
        assert!(err.contains("more than 2 files"), "{err}");
    }
}
