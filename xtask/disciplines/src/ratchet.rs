// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The lint ratchet (the skill's `gates.md`, lint):
//! a clippy lint a project still violates is allowed in its lint table with
//! the exact number of findings, `<lint> = "allow"  # ratchet: <n>`. `lint`
//! runs clippy once per group of packages whose tables ratchet the same
//! lints ([`groups`]), warning on those lints there only, and [`judge`] fails
//! on every finding no ratchet budgets and on every count that moved, so the
//! list only shrinks. Every allow in a lint table carries a justification
//! comment (a ratchet count is one), and every package has a lint policy.
//! Pure: the gate body in `gates.rs` runs cargo.
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde_json::Value;

use crate::layers;

/// A lint table: the workspace's (`[workspace.lints.*]`), or a package's own
/// (`[lints.*]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Table {
    Workspace,
    Package,
}

/// One `allow` in a lint table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allow {
    /// As rustc names it: `-` written in the manifest becomes `_`.
    pub lint: String,
    /// A clippy lint (`[*.lints.clippy]`), not a rustc one.
    pub clippy: bool,
    /// `Some(n)` for `# ratchet: <n>`; `None` for a permanent allow, whose
    /// comment is its justification.
    pub ratchet: Option<usize>,
    /// 1-based line in the manifest.
    pub line: usize,
}

/// A manifest key line's full dotted key (its table header's path, then
/// the key) with quotes removed, and its value.
fn full_key(k: &layers::KeyLine) -> Option<(String, &str)> {
    let (key, value) = k.line.split_once('=')?;
    let header = k
        .header
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or_default();
    let full = if header.is_empty() {
        unquote_path(key)
    } else {
        format!("{}.{}", unquote_path(header), unquote_path(key))
    };
    Some((full, value))
}

/// The allows of `table` in a manifest's text, and an error per allow
/// without a justification comment, per malformed ratchet comment, per
/// ratchet on a rustc lint, per allow of the `warnings` group (it would
/// hide every warning from the gate), and per allow inside an inline table
/// (which one comment cannot justify). A comment starting with `ratchet`,
/// in any case, is a ratchet: `ratchet: <n>` or `ratchet <n>`.
#[must_use]
pub fn allows(manifest: &str, table: Table) -> (Vec<Allow>, Vec<String>) {
    let root = match table {
        Table::Workspace => "workspace.lints",
        Table::Package => "lints",
    };
    let mut out = Vec::new();
    let mut errors = Vec::new();
    for k in layers::key_lines_full(manifest) {
        let Some((full, value)) = full_key(&k) else {
            continue;
        };
        let n = k.number;
        // `lints = { … }` or `clippy = { … }`: an inline table above the lint.
        if full == root || full == format!("{root}.clippy") || full == format!("{root}.rust") {
            if value.contains("allow") {
                errors.push(format!(
                    "line {n}: an allow inside an inline table: give it its own line and a justification comment"
                ));
            }
            continue;
        }
        for (group, clippy) in [("clippy", true), ("rust", false)] {
            let Some(rest) = full.strip_prefix(&format!("{root}.{group}.")) else {
                continue;
            };
            // `[*.lints.clippy.<lint>]` with `level = …`: the lint is the
            // table's last part; its other keys (`priority`) are no level.
            let (lint, level) = match rest.split_once('.') {
                Some((lint, "level")) => (lint, value),
                Some(_) => continue,
                None => (rest, value),
            };
            if !is_allow(level) {
                continue;
            }
            let lint = lint.replace('-', "_");
            if lint == "warnings" {
                errors.push(format!(
                    "line {n}: allowing `warnings` hides every warning from the lint gate"
                ));
                continue;
            }
            match ratchet_of(k.comment.as_deref()) {
                Comment::Missing => errors.push(format!(
                    "line {n}: `{lint}` is allowed without a justification comment"
                )),
                Comment::Ratchet(_) if !clippy => {
                    errors.push(format!("line {n}: `{lint}`: ratchets are for clippy lints"));
                }
                Comment::Malformed(c) => {
                    errors.push(format!("line {n}: `{lint}`: bad ratchet count `{c}`"));
                }
                Comment::Ratchet(0) => errors.push(format!(
                    "line {n}: `{lint}`: a ratchet of 0 is a fixed lint: delete the allow line"
                )),
                Comment::Ratchet(_) if CLIPPY_GROUPS.contains(&lint.as_str()) => {
                    errors.push(format!(
                        "line {n}: `{lint}` is a lint group: ratchet its lints one by one (clippy reports each by name)"
                    ));
                }
                Comment::Ratchet(count) => out.push(Allow {
                    lint,
                    clippy,
                    ratchet: Some(count),
                    line: n,
                }),
                Comment::Justified => out.push(Allow {
                    lint,
                    clippy,
                    ratchet: None,
                    line: n,
                }),
            }
        }
    }
    (out, errors)
}

/// Clippy's lint groups: findings are reported by lint, never by group.
const CLIPPY_GROUPS: [&str; 10] = [
    "all",
    "cargo",
    "complexity",
    "correctness",
    "nursery",
    "pedantic",
    "perf",
    "restriction",
    "style",
    "suspicious",
];

enum Comment {
    Missing,
    Justified,
    Ratchet(usize),
    Malformed(String),
}

fn ratchet_of(comment: Option<&str>) -> Comment {
    let Some(c) = comment.filter(|c| !c.is_empty()) else {
        return Comment::Missing;
    };
    let lower = c.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("ratchet") else {
        return Comment::Justified;
    };
    let count = rest.strip_prefix(':').unwrap_or(rest).trim();
    count
        .parse()
        .map_or_else(|_| Comment::Malformed(c.to_string()), Comment::Ratchet)
}

/// A dotted key with each part's quotes removed (`"a"."b"` → `a.b`).
fn unquote_path(key: &str) -> String {
    key.split('.')
        .map(|p| p.trim_matches(|c| c == '"' || c == '\''))
        .collect::<Vec<_>>()
        .join(".")
}

/// Whether a lint value (whitespace removed) is the `allow` level, plain or
/// as an inline table's `level`.
fn is_allow(value: &str) -> bool {
    let level = if value.starts_with('{') {
        layers::inline_value(value, "level").unwrap_or_default()
    } else {
        value
    };
    matches!(level, "\"allow\"" | "'allow'")
}

/// Which table governs a package's manifest: the workspace's (`[lints]
/// workspace = true`), its own (`[lints.clippy]`, or `clippy` inside an
/// inline `lints` table), or none.
#[must_use]
pub fn governed_by(manifest: &str) -> Option<Table> {
    if layers::opts_into_workspace_lints(manifest) {
        return Some(Table::Workspace);
    }
    let own = layers::key_lines_full(manifest).iter().any(|k| {
        full_key(k).is_some_and(|(full, value)| {
            full == "lints.clippy"
                || full.starts_with("lints.clippy.")
                || (full == "lints" && layers::inline_value(value, "clippy").is_some())
        })
    });
    own.then_some(Table::Package)
}

/// One lint table and the packages it governs; `what` names it in messages
/// (the manifest's path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Governed {
    pub what: String,
    pub allows: Vec<Allow>,
    pub packages: BTreeSet<String>,
}

impl Governed {
    /// The clippy lints this table ratchets.
    fn ratcheted(&self) -> BTreeSet<String> {
        self.allows
            .iter()
            .filter(|a| a.clippy && a.ratchet.is_some())
            .map(|a| a.lint.clone())
            .collect()
    }

    /// Every clippy lint this table allows, ratcheted or not.
    fn allowed(&self) -> BTreeSet<String> {
        self.allows
            .iter()
            .filter(|a| a.clippy)
            .map(|a| a.lint.clone())
            .collect()
    }
}

/// A workspace's lint policy: its tables, the members no table governs, and
/// the errors found reading them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub tables: Vec<Governed>,
    pub ungoverned: BTreeSet<String>,
    pub errors: Vec<String>,
    /// Cargo's build directory (`build_directory`, else `target_directory`):
    /// several runs each build under it ([`run_dir`]).
    pub build_root: String,
}

impl Policy {
    fn members(&self) -> BTreeSet<&str> {
        self.tables
            .iter()
            .flat_map(|t| &t.packages)
            .chain(&self.ungoverned)
            .map(String::as_str)
            .collect()
    }
}

/// One clippy run: its packages and the lints it warns on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub packages: Vec<String>,
    pub warn: BTreeSet<String>,
}

/// The clippy runs `lint` needs: packages grouped by the lints their table
/// ratchets (`measuring`: every clippy lint it allows, for `cargo xtask
/// ratchet`), so `-W` never reaches a package whose table did not ask for
/// it. Members no table governs join the group that warns on nothing. One
/// group, the usual case, is one run over the whole workspace.
#[must_use]
pub fn groups(policy: &Policy, measuring: bool) -> Vec<Run> {
    let mut by: BTreeMap<BTreeSet<String>, Vec<String>> = BTreeMap::new();
    for t in &policy.tables {
        let warn = if measuring {
            t.allowed()
        } else {
            t.ratcheted()
        };
        by.entry(warn)
            .or_default()
            .extend(t.packages.iter().cloned());
    }
    if !policy.ungoverned.is_empty() {
        by.entry(BTreeSet::new())
            .or_default()
            .extend(policy.ungoverned.iter().cloned());
    }
    by.retain(|_, packages| !packages.is_empty());
    by.into_iter()
        .map(|(warn, packages)| Run { packages, warn })
        .collect()
}

/// Where a run builds when there are several: `lint/<key>` under cargo's
/// build directory, `<key>` a hash of the run's packages, so each run's
/// fingerprints (clippy's arguments among them) stay warm across gate runs.
#[must_use]
pub fn run_dir(build_root: &str, run: &Run) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in run.packages.join(",").bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{build_root}/lint/{h:016x}")
}

/// The package name in a cargo package id: `path+file:///…/x#0.1.0` (name
/// from the path) or `path+file:///…/dir#name@0.1.0`.
#[must_use]
pub fn package_name(id: &str) -> String {
    let (path, fragment) = id.split_once('#').unwrap_or((id, ""));
    match fragment.split_once('@') {
        Some((name, _)) => name.to_string(),
        None => path.rsplit('/').next().unwrap_or(path).to_string(),
    }
}

/// A finding's place: file, line and column of its primary span.
type Place = (String, Option<u64>, Option<u64>);

/// The warnings and errors of workspace members in clippy's JSON lines, as
/// (package, clippy lint if any, place, rendered message).
fn findings<'a>(
    members: &BTreeSet<&str>,
    json: &'a str,
) -> impl Iterator<Item = (String, Option<String>, Place, String)> + 'a {
    let members: BTreeSet<String> = members.iter().map(|m| (*m).to_string()).collect();
    json.lines().filter_map(move |line| {
        let m = serde_json::from_str::<Value>(line).ok()?;
        let msg = &m["message"];
        if m["reason"] != "compiler-message"
            || !matches!(msg["level"].as_str(), Some("warning" | "error"))
        {
            return None;
        }
        let package = package_name(m["package_id"].as_str()?);
        if !members.contains(&package) {
            return None;
        }
        let lint = msg["code"]["code"]
            .as_str()
            .and_then(|c| c.strip_prefix("clippy::"))
            .map(str::to_string);
        let span = &msg["spans"][0];
        let place = (
            span["file_name"].as_str().unwrap_or_default().to_string(),
            span["line_start"].as_u64(),
            span["column_start"].as_u64(),
        );
        let rendered = msg["rendered"]
            .as_str()
            .map_or_else(|| msg["message"].to_string(), str::to_string);
        Some((package, lint, place, rendered))
    })
}

/// The lines of one run's JSON about its own packages: a run also lints
/// the members its packages depend on, with its flags, and those are judged
/// in their own run.
#[must_use]
pub fn own(run: &Run, json: &str) -> String {
    json.lines()
        .filter(|line| {
            serde_json::from_str::<Value>(line).is_ok_and(|m| {
                m["package_id"]
                    .as_str()
                    .is_some_and(|id| run.packages.contains(&package_name(id)))
            })
        })
        .flat_map(|line| [line, "\n"])
        .collect()
}

/// What [`judge`] finds: each member's warning or error its table does not
/// ratchet (rendered, once each), and each ratchet whose count differs from
/// its findings. Counts mean nothing when a run failed (clippy stopped).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Verdict {
    pub findings: Vec<String>,
    pub counts: Vec<String>,
}

/// Clippy's JSON lines (every run's, each kept to its own packages with
/// [`own`]) judged against the policy; findings counted once per lint and
/// place (each target reports a finding). Packages outside the workspace
/// are not judged.
#[must_use]
pub fn judge(policy: &Policy, json: &str) -> Verdict {
    let mut failures = Vec::new();
    let mut counts = Vec::new();
    let mut seen_failures = BTreeSet::new();
    let mut counted: BTreeMap<(usize, String), BTreeSet<Place>> = BTreeMap::new();
    for (package, lint, place, rendered) in findings(&policy.members(), json) {
        let table = policy
            .tables
            .iter()
            .position(|t| t.packages.contains(&package));
        if let (Some(t), Some(lint)) = (table, &lint)
            && policy.tables[t].ratcheted().contains(lint)
        {
            counted.entry((t, lint.clone())).or_default().insert(place);
            continue;
        }
        if seen_failures.insert(rendered.clone()) {
            failures.push(rendered.trim_end().to_string());
        }
    }
    for (t, table) in policy.tables.iter().enumerate() {
        for a in table.allows.iter().filter(|a| a.clippy) {
            let Some(want) = a.ratchet else {
                continue;
            };
            let have = counted.get(&(t, a.lint.clone())).map_or(0, BTreeSet::len);
            let what = &table.what;
            let (at, lint) = (a.line, &a.lint);
            match have.cmp(&want) {
                std::cmp::Ordering::Equal => {}
                std::cmp::Ordering::Greater => counts.push(format!(
                    "{what}:{at}: `{lint}` has {have} findings, the ratchet allows {want}: fix the new ones"
                )),
                std::cmp::Ordering::Less if have == 0 => counts.push(format!(
                    "{what}:{at}: `{lint}` has no findings left: delete its allow line"
                )),
                std::cmp::Ordering::Less => counts.push(format!(
                    "{what}:{at}: `{lint}` is down to {have} findings: lower its ratchet from {want} to {have}"
                )),
            }
        }
    }
    Verdict {
        findings: failures,
        counts,
    }
}

/// What `cargo xtask ratchet` prints: per table, each clippy lint it allows
/// with its count in `json` (from runs warning on all of them), as lines
/// ready to paste.
#[must_use]
pub fn measure(policy: &Policy, json: &str) -> String {
    let members = policy.members();
    let mut counted: BTreeMap<(String, String), BTreeSet<Place>> = BTreeMap::new();
    for (package, lint, place, _) in findings(&members, json) {
        if let Some(lint) = lint {
            counted.entry((package, lint)).or_default().insert(place);
        }
    }
    let mut text = String::new();
    for table in &policy.tables {
        let _ = writeln!(text, "# {}", table.what);
        for lint in table.allowed() {
            let n: BTreeSet<&Place> = table
                .packages
                .iter()
                .filter_map(|p| counted.get(&(p.clone(), lint.clone())))
                .flatten()
                .collect();
            let _ = writeln!(text, "{lint} = \"allow\"  # ratchet: {}", n.len());
        }
    }
    text
}

/// The lint policy of the workspace `cargo metadata --no-deps` describes:
/// its tables, the members none governs (each also an error), and every
/// allow's justification ([`allows`]). `read` reads a manifest. Each table
/// is named by its manifest's path relative to the workspace root.
///
/// # Errors
/// Malformed metadata, or a manifest that cannot be read.
pub fn policy(
    metadata: &str,
    read: &dyn Fn(&std::path::Path) -> std::io::Result<String>,
) -> Result<Policy, String> {
    let doc: Value = serde_json::from_str(metadata).map_err(|e| format!("cargo metadata: {e}"))?;
    let root = doc["workspace_root"]
        .as_str()
        .ok_or("cargo metadata: no `workspace_root`")?;
    let root = std::path::Path::new(root);
    let relative = |p: &std::path::Path| p.strip_prefix(root).unwrap_or(p).display().to_string();
    let load =
        |p: &std::path::Path| read(p).map_err(|e| format!("cannot read {}: {e}", p.display()));
    let label = |p: &std::path::Path, e: &str| format!("{}: {e}", relative(p));
    let root_manifest = root.join("Cargo.toml");
    let (allows_ws, errs) = allows(&load(&root_manifest)?, Table::Workspace);
    let mut errors: Vec<String> = errs.iter().map(|e| label(&root_manifest, e)).collect();
    let mut workspace = Governed {
        what: relative(&root_manifest),
        allows: allows_ws,
        packages: BTreeSet::new(),
    };
    let mut own = Vec::new();
    let mut ungoverned = BTreeSet::new();
    let packages = doc["packages"]
        .as_array()
        .ok_or("cargo metadata: no `packages` array")?;
    for p in packages {
        let name = p["name"]
            .as_str()
            .ok_or("cargo metadata: a package without a name")?;
        let path = std::path::Path::new(
            p["manifest_path"]
                .as_str()
                .ok_or("cargo metadata: a package without a manifest_path")?,
        );
        let text = load(path)?;
        match governed_by(&text) {
            Some(Table::Workspace) => {
                workspace.packages.insert(name.to_string());
            }
            Some(Table::Package) => {
                let (allows, errs) = allows(&text, Table::Package);
                errors.extend(errs.iter().map(|e| label(path, e)));
                own.push(Governed {
                    what: relative(path),
                    allows,
                    packages: BTreeSet::from([name.to_string()]),
                });
            }
            None => {
                ungoverned.insert(name.to_string());
                errors.push(format!(
                    "{}: package `{name}` has no lint policy: set `[lints] workspace = true`, or give it its own `[lints.clippy]`",
                    relative(path)
                ));
            }
        }
    }
    own.insert(0, workspace);
    let build_root = ["build_directory", "target_directory"]
        .iter()
        .find_map(|k| doc[*k].as_str())
        .unwrap_or_default()
        .to_string();
    Ok(Policy {
        tables: own,
        ungoverned,
        errors,
        build_root,
    })
}
