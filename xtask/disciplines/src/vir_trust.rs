// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a Verus crate takes on trust, from Verus's own logs (the skill's
//! `runner.md`, Proof tier). The judged pass's `--log vir` lists every
//! function Verus takes as external (`(external_fn (Fun :path …))`);
//! `--log impl-names` maps each trait impl to its trait and span. Each of the package's own entries must be
//! explained (a standard derive, an item the log declares with a verified
//! body, an accessor `verus!` generates) or carry
//! `disciplines:allow-trusted (<reason>)`; external free functions and
//! inherent methods, which verified code cannot call, are listed. Pure: the
//! gate reads the logs, the sources and `cargo metadata`.
use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::{stubs, trusted};

/// core's derivable traits, by path, with the name a derive spells.
const DERIVABLE: [(&str, &str); 8] = [
    ("core::fmt::Debug", "Debug"),
    ("core::cmp::PartialEq", "PartialEq"),
    ("core::cmp::Eq", "Eq"),
    ("core::cmp::PartialOrd", "PartialOrd"),
    ("core::cmp::Ord", "Ord"),
    ("core::hash::Hash", "Hash"),
    ("core::default::Default", "Default"),
    ("core::clone::Clone", "Clone"),
];

/// Verus's own proc-macro crates; no derive of theirs is a standard one.
pub const VERUS_MACROS: [&str; 2] = ["verus_builtin_macros", "verus_state_machines_macros"];

/// What the logs show: entries that fail, and those listed only.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Outcome {
    pub failures: Vec<String>,
    pub listed: Vec<String>,
}

/// A trait impl from `crate.impl_names`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Impl {
    trait_path: String,
    types: String,
    file: String,
    line: usize,
    col: usize,
    end_line: usize,
    end_col: usize,
    /// The span's macro context: 0 for code as written.
    ctx: u64,
}

/// The log with every run of whitespace one space and every quoted
/// string's contents blanked to `_`: a string literal in verified code is
/// written into the log verbatim, and must never read as a record.
fn squeeze(text: &str) -> String {
    let squeezed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let (mut out, mut quoted, mut escaped) = (String::with_capacity(squeezed.len()), false, false);
    for c in squeezed.chars() {
        if quoted {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                quoted = false;
                out.push('"');
                continue;
            }
            out.push('_');
        } else {
            quoted = c == '"';
            out.push(c);
        }
    }
    out
}

/// Whether `path` is the crate's or inside it.
fn owned(path: &str, krate: &str) -> bool {
    path == krate
        || path
            .strip_prefix(krate)
            .is_some_and(|r| r.starts_with("::"))
}

/// The paths following `prefix` in `text`, each up to a space or `)`.
fn paths_after<'a>(text: &'a str, prefix: &'a str) -> impl Iterator<Item = (usize, &'a str)> + 'a {
    text.match_indices(prefix).map(move |(i, _)| {
        let rest = &text[i + prefix.len()..];
        let end = rest.find([' ', ')']).unwrap_or(rest.len());
        (i, &rest[..end])
    })
}

/// Each declared function's path and whether it has a body: the `:body`
/// key at the top level of its `(Function …)` record is not `None`. From a
/// squeezed log; quoted strings (spans) are skipped when matching
/// parentheses.
fn declarations(vir: &str) -> BTreeMap<String, bool> {
    let mut out = BTreeMap::new();
    for (at, path) in paths_after(vir, "(Function :name (Fun :path ") {
        let body = top_level_value(&vir[at..], ":body ").is_some_and(|v| !v.starts_with("None"));
        let known = out.entry(path.to_string()).or_insert(false);
        *known |= body;
    }
    out
}

/// What follows `key` at depth 1 of the record `record` starts with (its
/// first `(` opens it), before the record closes.
fn top_level_value<'a>(record: &'a str, key: &str) -> Option<&'a str> {
    let bytes = record.as_bytes();
    let (mut depth, mut i, mut quoted) = (0usize, 0, false);
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if quoted => i += 1,
            b'"' => quoted = !quoted,
            b'(' if !quoted => depth += 1,
            b')' if !quoted => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return None;
                }
            }
            _ if !quoted && depth == 1 && record[i..].starts_with(key) => {
                return Some(&record[i + key.len()..]);
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// The crate's trait impls from `crate.impl_names`, by `<crate>::…::impl&%N`.
fn impls(text: &str, krate: &str) -> Result<BTreeMap<String, Impl>, String> {
    let mut out = BTreeMap::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let parts: Vec<&str> = line.split("###").map(str::trim).collect();
        let [name, trait_path, types, span] = parts[..] else {
            return Err(format!("impl names: unreadable line `{line}`"));
        };
        if !owned(name, krate) {
            continue;
        }
        let bad = || format!("impl names: unreadable span `{span}`");
        let (place, ctx) = span.rsplit_once(" (#").ok_or_else(bad)?;
        let ctx = ctx.trim_end_matches(')').parse().map_err(|_| bad())?;
        let (start, end) = place.split_once(": ").ok_or_else(bad)?;
        let mut s = start.rsplitn(3, ':');
        let (col, line_no, file) = (s.next(), s.next(), s.next());
        let mut e = end.split(':');
        let num = |v: Option<&str>| v.and_then(|v| v.parse::<usize>().ok()).ok_or_else(bad);
        out.insert(
            name.to_string(),
            Impl {
                trait_path: trait_path.to_string(),
                types: types.to_string(),
                file: file.ok_or_else(bad)?.to_string(),
                line: num(line_no)?,
                col: num(col)?,
                end_line: num(e.next())?,
                end_col: num(e.next())?,
                ctx,
            },
        );
    }
    Ok(out)
}

/// Whether the impl is a standard derive as written: a derivable trait by
/// path, a macro span, and the source text there that trait's name inside
/// `#[derive(…)]`.
fn is_derive(i: &Impl, read_line: &dyn Fn(&str, usize) -> Option<String>) -> bool {
    let Some((_, name)) = DERIVABLE.iter().find(|(path, _)| *path == i.trait_path) else {
        return false;
    };
    if i.ctx == 0 || i.line != i.end_line {
        return false;
    }
    let Some(text) = read_line(&i.file, i.line) else {
        return false;
    };
    let (from, to) = (i.col.saturating_sub(1), i.end_col.saturating_sub(1));
    if text.get(from..to) != Some(*name) {
        return false;
    }
    // The nearest `#[derive(` before the name, on this line or up to five
    // lines above it, with no `]` between.
    let mut before = text[..from].to_string();
    for back in 1..=6 {
        if let Some(open) = before.rfind("#[derive(") {
            return !before[open..].contains(']');
        }
        match i.line.checked_sub(back).and_then(|l| read_line(&i.file, l)) {
            Some(prev) if back <= 5 && (!prev.contains(']') || prev.contains("#[derive(")) => {
                before = format!("{prev}\n{before}");
            }
            _ => return false,
        }
    }
    false
}

/// Whether a marker with a reason sits on the impl's first line or on the
/// lines that lead into it ([`trusted::leads_in`]: comment lines and
/// attributes). The walk stops at anything else, so a previous item's
/// marker never counts; a macro-built impl takes its marker on its header
/// line.
fn marked(i: &Impl, read_line: &dyn Fn(&str, usize) -> Option<String>) -> bool {
    let mut n = i.line;
    for _ in 0..32 {
        let Some(text) = read_line(&i.file, n) else {
            return false;
        };
        if stubs::marked_with_reason(&text, trusted::MARKER) {
            return true;
        }
        let Some(prev) = n.checked_sub(1).filter(|p| *p >= 1) else {
            return false;
        };
        match read_line(&i.file, prev) {
            Some(p) if trusted::leads_in(&p) => n = prev,
            _ => return false,
        }
    }
    false
}

/// The judgement of crate `krate`'s own external entries. `proc_macros`
/// names the proc-macro crates in the package's dependency closure other
/// than Verus's ([`proc_macros`]): any is a failure, since one could forge
/// a standard derive the log cannot tell apart, or emit a `cfg` no text scan
/// sees. `read_line` reads a 1-based line of a file named relative to the
/// workspace root.
///
/// # Errors
/// An unreadable `impl_names` line, or a log with nothing of the crate (the
/// wrong log, or a renamed library).
pub fn judge(
    krate: &str,
    vir: &str,
    impl_names: &str,
    proc_macros: &[String],
    read_line: &dyn Fn(&str, usize) -> Option<String>,
) -> Result<Outcome, String> {
    let vir = squeeze(vir);
    let declared = declarations(&vir);
    if !declared.keys().any(|p| owned(p, krate)) {
        return Err(format!("the VIR log declares nothing of crate `{krate}`"));
    }
    let impls = impls(impl_names, krate)?;
    let externals: BTreeSet<&str> = paths_after(&vir, "(external_fn (Fun :path ")
        .map(|(_, p)| p)
        .filter(|p| owned(p, krate))
        .collect();
    let mut out = Outcome::default();
    if !proc_macros.is_empty() {
        out.failures.push(format!(
            "proc-macro crates in the dependencies of a proved crate: {} (one could forge a standard derive, or emit code built differently from how Verus verified it); only Verus's own are allowed",
            proc_macros.join(", ")
        ));
    }
    for path in externals {
        let (owner, item) = path.rsplit_once("::").unwrap_or(("", path));
        if declared.get(path).copied().unwrap_or(false) {
            continue; // a constant or const fn, verified where declared
        }
        if let Some(i) = impls.get(owner) {
            let at = format!("{}:{}", i.file, i.line);
            let what = format!("`impl {} for {}`", i.trait_path, i.types);
            if !is_derive(i, read_line) && !marked(i, read_line) {
                out.failures.push(format!(
                    "{at}: {what} is external (trusted; `{item}`) with no `{} (<reason>)` on it",
                    trusted::MARKER
                ));
            }
            continue;
        }
        if let Some(field) = item.strip_prefix("arrow_") {
            let siblings = declared
                .iter()
                .filter(|(p, body)| {
                    **body
                        && p.strip_prefix(&format!("{owner}::arrow_"))
                            .and_then(|r| r.strip_suffix(&format!("_{field}")))
                            .is_some_and(|variant| !variant.is_empty())
                })
                .count();
            if siblings >= 2 {
                continue; // the accessor `verus!` generates for a shared field
            }
        }
        out.listed.push(path.to_string());
    }
    Ok(out)
}

/// The proc-macro crates other than Verus's in `package`'s dependency
/// closure (normal dependencies, through libraries; a proc macro's own
/// dependencies run on the host and are not followed), from `cargo
/// metadata` with dependencies.
///
/// # Errors
/// Malformed metadata, or no workspace member named `package`.
pub fn proc_macros(metadata: &str, package: &str) -> Result<Vec<String>, String> {
    let doc: Value = serde_json::from_str(metadata).map_err(|e| format!("cargo metadata: {e}"))?;
    let packages = doc["packages"]
        .as_array()
        .ok_or("cargo metadata: no `packages`")?;
    let by_id: BTreeMap<&str, &Value> = packages
        .iter()
        .filter_map(|p| Some((p["id"].as_str()?, p)))
        .collect();
    let is_macro = |p: &Value| {
        p["targets"].as_array().is_some_and(|ts| {
            ts.iter().any(|t| {
                t["kind"]
                    .as_array()
                    .is_some_and(|k| k.iter().any(|k| k == "proc-macro"))
            })
        })
    };
    let members: BTreeSet<&str> = doc["workspace_members"]
        .as_array()
        .ok_or("cargo metadata: no `workspace_members`")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let start = members
        .iter()
        .find(|id| by_id.get(*id).is_some_and(|p| p["name"] == package))
        .ok_or_else(|| format!("cargo metadata: no workspace member `{package}`"))?;
    let nodes: BTreeMap<&str, &Value> = doc["resolve"]["nodes"]
        .as_array()
        .ok_or("cargo metadata: no `resolve` graph (run it with dependencies)")?
        .iter()
        .filter_map(|n| Some((n["id"].as_str()?, n)))
        .collect();
    let mut seen = BTreeSet::from([*start]);
    let mut queue = vec![*start];
    let mut found = BTreeSet::new();
    while let Some(id) = queue.pop() {
        let Some(node) = nodes.get(id) else { continue };
        for dep in node["deps"].as_array().into_iter().flatten() {
            let normal = dep["dep_kinds"]
                .as_array()
                .is_some_and(|ks| ks.iter().any(|k| k["kind"].is_null()));
            let Some(dep_id) = dep["pkg"].as_str() else {
                continue;
            };
            if !normal || !seen.insert(dep_id) {
                continue;
            }
            match by_id.get(dep_id) {
                Some(p) if is_macro(p) => {
                    let name = p["name"].as_str().unwrap_or_default();
                    if !VERUS_MACROS.contains(&name) {
                        found.insert(name.to_string());
                    }
                }
                _ => queue.push(dep_id),
            }
        }
    }
    Ok(found.into_iter().collect())
}

/// Whether `package` has a build script (a `custom-build` target), from
/// `cargo metadata`: one can set `cfg`s that build the code differently
/// from how Verus verified it.
///
/// # Errors
/// Malformed metadata, or no package named `package`.
pub fn has_build_script(metadata: &str, package: &str) -> Result<bool, String> {
    let doc: Value = serde_json::from_str(metadata).map_err(|e| format!("cargo metadata: {e}"))?;
    let p = doc["packages"]
        .as_array()
        .ok_or("cargo metadata: no `packages`")?
        .iter()
        .find(|p| p["name"] == package)
        .ok_or_else(|| format!("cargo metadata: no package `{package}`"))?;
    Ok(p["targets"].as_array().is_some_and(|ts| {
        ts.iter().any(|t| {
            t["kind"]
                .as_array()
                .is_some_and(|k| k.iter().any(|k| k == "custom-build"))
        })
    }))
}

/// The name the package's library is compiled under (its `lib` target,
/// `-` read as `_`), from `cargo metadata`: the crate the VIR log names.
///
/// # Errors
/// Malformed metadata, no package named `package`, or no library target.
pub fn lib_name(metadata: &str, package: &str) -> Result<String, String> {
    let doc: Value = serde_json::from_str(metadata).map_err(|e| format!("cargo metadata: {e}"))?;
    let p = doc["packages"]
        .as_array()
        .ok_or("cargo metadata: no `packages`")?
        .iter()
        .find(|p| p["name"] == package)
        .ok_or_else(|| format!("cargo metadata: no package `{package}`"))?;
    p["targets"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|t| {
            t["kind"]
                .as_array()
                .is_some_and(|k| k.iter().any(|k| k == "lib" || k == "rlib"))
        })
        .and_then(|t| t["name"].as_str())
        .map(|n| n.replace('-', "_"))
        .ok_or_else(|| format!("package `{package}` has no library target"))
}

/// Verus's own crates: what a proved crate may depend on besides other
/// proved crates.
pub const VERUS_CRATES: [&str; 4] = [
    "vstd",
    "verus_builtin",
    "verus_builtin_macros",
    "verus_state_machines_macros",
];

/// The direct normal dependencies of `package` that are neither Verus's
/// crates nor among `proved` (workspace packages with their own Verus
/// entry, whose sources their entries scan) nor exempted with a reason in
/// the package's manifest (`[package.metadata.disciplines] trusted_deps =
/// { <name> = "<reason>" }`): such a dependency's macros and re-exports
/// reach the proved code unscanned (a `cfg!` behind a macro, `pub use
/// core::cfg`).
///
/// # Errors
/// Malformed metadata, or no workspace member named `package`.
pub fn foreign_deps(
    metadata: &str,
    package: &str,
    proved: &[String],
) -> Result<Vec<String>, String> {
    let doc: Value = serde_json::from_str(metadata).map_err(|e| format!("cargo metadata: {e}"))?;
    let packages = doc["packages"]
        .as_array()
        .ok_or("cargo metadata: no `packages`")?;
    let name_of: BTreeMap<&str, &str> = packages
        .iter()
        .filter_map(|p| Some((p["id"].as_str()?, p["name"].as_str()?)))
        .collect();
    let members: BTreeSet<&str> = doc["workspace_members"]
        .as_array()
        .ok_or("cargo metadata: no `workspace_members`")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let me = packages
        .iter()
        .find(|p| p["name"] == package && p["id"].as_str().is_some_and(|id| members.contains(id)))
        .ok_or_else(|| format!("cargo metadata: no workspace member `{package}`"))?;
    let exempt = &me["metadata"]["disciplines"]["trusted_deps"];
    let node = doc["resolve"]["nodes"]
        .as_array()
        .ok_or("cargo metadata: no `resolve` graph (run it with dependencies)")?
        .iter()
        .find(|n| n["id"] == me["id"])
        .ok_or_else(|| format!("cargo metadata: `{package}` is not in the resolve graph"))?;
    let mut out = BTreeSet::new();
    for dep in node["deps"].as_array().into_iter().flatten() {
        let normal = dep["dep_kinds"]
            .as_array()
            .is_some_and(|ks| ks.iter().any(|k| k["kind"].is_null()));
        let Some(name) = dep["pkg"].as_str().and_then(|id| name_of.get(id)) else {
            continue;
        };
        if !normal || VERUS_CRATES.contains(name) || proved.iter().any(|p| p == name) {
            continue;
        }
        if exempt[*name]
            .as_str()
            .is_none_or(|reason| reason.trim().is_empty())
        {
            out.insert((*name).to_string());
        }
    }
    Ok(out.into_iter().collect())
}
