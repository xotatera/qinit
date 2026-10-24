// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Logic of the `layers` and `no-std` gates. Each workspace crate declares a
//! layer and an allowlist of its direct dependencies under
//! `[package.metadata.disciplines]` in its own `Cargo.toml`. This module
//! checks those declarations against the dependency direction between
//! layers, the workspace lint opt-in and the `no_std` attribute. It is pure:
//! the gate bodies in `gates.rs` run `cargo metadata` and read the files.
use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::proofs::Kind;

pub mod primitive;

/// `Some(reason)` keeps `no-std` registered but skipping until the project
/// has a kernel or core crate. Bootstrap then sets it to `None` and changes
/// `tests/layers.rs` to assert `None`.
pub const NO_STD_BLOCKED: Option<&str> = Some("no kernel or core crate yet");

/// Every valid `layer` value.
pub const LAYER_NAMES: &[&str] = &[
    "primitive",
    "kernel",
    "core",
    "runtime",
    "edge",
    "unsafe",
    "tooling",
];

/// Target kinds that make a lib target.
const LIB_KINDS: &[&str] = &["lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepKind {
    Normal,
    Build,
    Dev,
}

/// One direct dependency, by its real package name (a rename is ignored).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dep {
    pub name: String,
    pub kind: DepKind,
    /// Whether the dependency is another package of this workspace.
    pub member: bool,
}

/// One workspace package, with the texts the checks read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub manifest: String,
    /// The lib target's root source file, if the package has a lib target.
    pub lib_source: Option<String>,
    /// The lib target's root source file path, if any.
    pub lib_path: Option<PathBuf>,
    pub layer: Option<String>,
    /// The feature slice (`tooth`) the crate belongs to; `None` for the
    /// spine, the handle and tooling.
    pub tooth: Option<String>,
    /// `data_only = "<reason>"`: a tooth whose code is data a proved spine
    /// runs (a script, a table), so it has no decision logic of its own
    /// for a Kani entry to prove. The reason says what proves it.
    pub data_only: Option<String>,
    pub allow: Option<Vec<String>>,
    pub deps: Vec<Dep>,
    /// Whether the lib target is a proc-macro, built for the host.
    pub proc_macro: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// The package, or `workspace` for the root manifest and an empty workspace.
    pub package: String,
    pub message: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.package, self.message)
    }
}

fn violation(package: &str, message: String) -> Violation {
    Violation {
        package: package.to_string(),
        message,
    }
}

/// Whether a crate in layer `from` may depend on a crate in layer `to`:
/// edge → runtime → core → kernel → primitive, every layer but tooling may
/// reach primitive, only the runtime reaches the unsafe zone, tooling
/// reaches everything and only tooling reaches tooling.
#[must_use]
pub fn may_depend(from: &str, to: &str) -> bool {
    if from == "tooling" {
        return true;
    }
    if to == "tooling" {
        return false;
    }
    from == to
        || matches!(
            (from, to),
            (
                "kernel" | "core" | "runtime" | "edge" | "unsafe",
                "primitive"
            ) | ("core", "kernel")
                | ("unsafe", "kernel" | "core")
                | ("runtime", "kernel" | "core" | "unsafe")
                | ("edge", "kernel" | "core" | "runtime")
        )
}

/// Which haircomb variant the workspace follows (`rust.md` §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// Teeth are pure; effects cross the bridge to the handle.
    Handled,
    /// Teeth carry their own effectful layers.
    Plain,
}

/// `[workspace.metadata.disciplines] haircomb` and `bridge`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comb {
    pub variant: Variant,
    pub bridge: Option<String>,
}

/// The workspace's haircomb declaration; handled when absent.
///
/// # Errors
/// On malformed JSON, an unknown `haircomb` or a non-string `bridge`.
pub fn comb(json: &str) -> Result<Comb, String> {
    let doc = parse(json)?;
    let decl = doc.get("metadata").and_then(|m| m.get("disciplines"));
    let variant = match decl.and_then(|d| d.get("haircomb")) {
        None => Variant::Handled,
        Some(v) => match v.as_str() {
            Some("handled") => Variant::Handled,
            Some("plain") => Variant::Plain,
            _ => {
                return Err(format!(
                    "`haircomb` must be \"handled\" or \"plain\", not {v}"
                ));
            }
        },
    };
    let bridge = decl
        .and_then(|d| d.get("bridge"))
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| "`bridge` must be a string (a crate name)".to_string())
        })
        .transpose()?;
    Ok(Comb { variant, bridge })
}

/// A tooth name: a lowercase ASCII letter, then lowercase letters, digits,
/// `-` or `_`.
#[must_use]
pub fn valid_tooth(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// Every haircomb violation: teeth reaching other teeth, the spine reaching
/// a tooth, teeth on layers that may not have one, and (handled) effectful
/// teeth and a missing or wrong bridge. Without teeth nothing applies.
#[must_use]
pub fn check_comb(packages: &[Package], comb: &Comb) -> Vec<Violation> {
    let mut out = Vec::new();
    let handled = comb.variant == Variant::Handled;
    for p in packages {
        let name = p.name.as_str();
        let layer = p.layer.as_deref().unwrap_or("");
        if let Some(t) = p.tooth.as_deref() {
            if !valid_tooth(t) {
                out.push(violation(
                    name,
                    format!("tooth `{t}`: use lowercase letters, digits, `-` and `_`, starting with a letter"),
                ));
            }
            if matches!(layer, "tooling" | "primitive") {
                out.push(violation(
                    name,
                    format!("a `{layer}` crate may not declare a tooth"),
                ));
            } else if handled && valid_layer(p).is_some() && !matches!(layer, "kernel" | "core") {
                out.push(violation(
                    name,
                    format!("handled haircomb: tooth `{t}` crate is `{layer}`; teeth are kernel or core (their effects go through the bridge)"),
                ));
            }
        }
        let spine = p.tooth.is_none() && matches!(layer, "primitive" | "kernel" | "core");
        let edges: BTreeSet<&str> = p
            .deps
            .iter()
            .filter(|d| d.kind == DepKind::Normal && d.member)
            .map(|d| d.name.as_str())
            .collect();
        for dep in edges {
            let Some(target) = packages.iter().find(|q| q.name == dep) else {
                continue;
            };
            if target.proc_macro {
                continue;
            }
            let Some(to) = target.tooth.as_deref() else {
                continue;
            };
            match p.tooth.as_deref() {
                Some(from) if from != to => out.push(violation(
                    name,
                    format!("tooth `{from}` may not depend on tooth `{to}` crate `{dep}`"),
                )),
                None if spine => out.push(violation(
                    name,
                    format!("the spine may not depend on tooth `{to}` crate `{dep}`"),
                )),
                _ => {}
            }
        }
    }
    let teeth = packages.iter().any(|p| p.tooth.is_some());
    // `haircomb` and `bridge` apply once any crate declares a tooth.
    if !teeth {
        return out;
    }
    match (&comb.bridge, handled) {
        (Some(_), false) => out.push(violation(
            "workspace",
            "`bridge` applies only to handled haircomb: plain teeth perform their own effects".to_string(),
        )),
        (None, true) => out.push(violation(
            "workspace",
            "handled haircomb needs `bridge` under [workspace.metadata.disciplines]: the core crate holding effects, results and protocol rules".to_string(),
        )),
        (Some(b), true) => match packages.iter().find(|p| p.name == *b) {
            None => out.push(violation(
                "workspace",
                format!("bridge `{b}` is not a workspace member"),
            )),
            Some(p) if p.layer.as_deref() != Some("core") || p.tooth.is_some() => {
                out.push(violation(
                    "workspace",
                    format!("bridge `{b}` must be a core crate with no tooth"),
                ));
            }
            Some(_) => {}
        },
        _ => {}
    }
    out
}

/// Proof coverage: every primitive is the package of some proof entry, and
/// (handled, once any proof exists) every tooth's kernel and core crates of
/// a core-prover entry ([`crate::proofs::Kind::is_core_prover`]), unless the
/// crate declares `data_only` with a reason (and then has none), or depends
/// directly on a crate of its tooth with a `verus` entry: the text around a
/// proved core, which Verus, verifying whole libraries, cannot take (a Kani
/// tooth keeps its text beside its harnesses). `proofs` is `(package, kind)`
/// per entry.
#[must_use]
pub fn coverage(packages: &[Package], comb: &Comb, proofs: &[(&str, &Kind)]) -> Vec<Violation> {
    let mut out = Vec::new();
    for p in packages {
        let layer = p.layer.as_deref().unwrap_or("");
        if layer == "primitive" && !proofs.iter().any(|(pkg, _)| *pkg == p.name) {
            out.push(violation(
                &p.name,
                "primitive crate has no proof entry (Kani for its contracts, Miri for undefined behaviour)".to_string(),
            ));
        }
        let proved = proofs
            .iter()
            .any(|(pkg, kind)| kind.is_core_prover() && *pkg == p.name);
        let verus = |name: &str| {
            proofs
                .iter()
                .any(|(pkg, kind)| **kind == Kind::Verus && *pkg == name)
        };
        if let Some(why) = p.data_only.as_deref() {
            let problem = if p.tooth.is_none() {
                Some("`data_only` is only for tooth crates")
            } else if why.trim().is_empty() {
                Some("`data_only` needs a reason: what proves the code this data drives")
            } else if proved {
                Some("`data_only` with a core-prover entry (kani or verus): drop one of them")
            } else {
                None
            };
            if let Some(problem) = problem {
                out.push(violation(&p.name, problem.to_string()));
            }
            continue;
        }
        if let Some(t) = p.tooth.as_deref()
            && comb.variant == Variant::Handled
            && !proofs.is_empty()
            && matches!(layer, "kernel" | "core")
            && !proved
            && !p.deps.iter().any(|d| {
                d.kind == DepKind::Normal
                    && d.member
                    && verus(&d.name)
                    && packages
                        .iter()
                        .any(|q| q.name == d.name && q.tooth.as_deref() == Some(t))
            })
        {
            out.push(violation(
                &p.name,
                format!("tooth `{t}` crate has no core-prover entry, kani or verus, and depends on no crate of its tooth with a verus entry (handled haircomb: every tooth is proved once proofs exist; a crate holding the text around a Verus-proved core depends on it; a tooth that is only data a proved spine runs declares `data_only = \"<reason>\"`)"),
            ));
        }
    }
    out
}

/// Every violation in the workspace, never only the first.
#[must_use]
pub fn check(packages: &[Package], root_manifest: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    if packages.is_empty() {
        out.push(violation(
            "workspace",
            "no packages: nothing to check".to_string(),
        ));
    }
    if !root_forbids_unsafe(root_manifest) {
        out.push(violation(
            "workspace",
            "the root Cargo.toml does not forbid unsafe code: add `unsafe_code = \"forbid\"` under [workspace.lints.rust]"
                .to_string(),
        ));
    }
    for p in packages {
        check_package(p, packages, &mut out);
    }
    out
}

fn valid_layer(p: &Package) -> Option<&str> {
    p.layer.as_deref().filter(|l| LAYER_NAMES.contains(l))
}

fn check_package(p: &Package, all: &[Package], out: &mut Vec<Violation>) {
    let name = p.name.as_str();
    match p.layer.as_deref() {
        None => out.push(violation(
            name,
            "no `layer` in [package.metadata.disciplines]".to_string(),
        )),
        Some(l) if !LAYER_NAMES.contains(&l) => out.push(violation(
            name,
            format!("unknown layer `{l}` (one of: {})", LAYER_NAMES.join(", ")),
        )),
        Some(_) => {}
    }
    let layer = valid_layer(p);
    let names: BTreeSet<&str> = all.iter().map(|q| q.name.as_str()).collect();
    let redirected: BTreeSet<&str> = p
        .deps
        .iter()
        .filter(|d| d.kind != DepKind::Dev && !d.member && names.contains(d.name.as_str()))
        .map(|d| d.name.as_str())
        .collect();
    for dep in redirected {
        out.push(violation(
            name,
            format!(
                "dependency `{dep}` has a workspace member's name but is not a path dependency on it (e.g. redirected through [patch]); depend on the member by path"
            ),
        ));
    }
    let counted: BTreeSet<&str> = p
        .deps
        .iter()
        .filter(|d| d.kind != DepKind::Dev)
        .map(|d| d.name.as_str())
        .collect();
    let allow: BTreeSet<&str> = p.allow.iter().flatten().map(String::as_str).collect();
    for dep in counted.difference(&allow) {
        out.push(violation(
            name,
            format!("dependency `{dep}` is not in `allow`"),
        ));
    }
    for stale in allow.difference(&counted) {
        out.push(violation(
            name,
            format!("stale `allow` entry `{stale}`: no normal or build dependency has that name"),
        ));
    }
    if let Some(from) = layer {
        check_direction(p, from, all, out);
    }
    if !matches!(layer, Some("unsafe" | "primitive")) && !opts_into_workspace_lints(&p.manifest) {
        out.push(violation(
            name,
            "Cargo.toml does not set `lints.workspace = true`".to_string(),
        ));
    }
    if layer == Some("primitive") {
        for (group, lint) in [
            ("rust", "unsafe_op_in_unsafe_fn"),
            ("clippy", "undocumented_unsafe_blocks"),
        ] {
            if !sets_lint(&p.manifest, group, lint) {
                out.push(violation(
                    name,
                    format!(
                        "a primitive crate must set `{lint} = \"deny\"` under [lints.{group}] (as `[lints.{group}]` with `{lint} = \"deny\"`, or `[lints]` with `{group}.{lint} = \"deny\"` or `{group} = {{ {lint} = \"deny\" }}`)"
                    ),
                ));
            }
        }
    }
    if matches!(layer, Some("primitive" | "kernel" | "core")) && !p.proc_macro {
        match &p.lib_source {
            None => out.push(violation(
                name,
                "a primitive, kernel or core crate needs a lib target".to_string(),
            )),
            Some(src) if !declares_no_std(src) => out.push(violation(
                name,
                "the lib root lacks `#![no_std]` or `#![cfg_attr(<cfg>, no_std)]`".to_string(),
            )),
            Some(_) => {}
        }
    }
}

fn check_direction(p: &Package, from: &str, all: &[Package], out: &mut Vec<Violation>) {
    let members: BTreeSet<&str> = p
        .deps
        .iter()
        .filter(|d| d.kind == DepKind::Normal && d.member)
        .map(|d| d.name.as_str())
        .collect();
    for dep in members {
        let Some(target) = all.iter().find(|q| q.name == dep) else {
            continue;
        };
        if target.proc_macro {
            continue;
        }
        if let Some(to) = valid_layer(target)
            && !may_depend(from, to)
        {
            out.push(violation(
                &p.name,
                format!("a `{from}` crate may not depend on `{to}` crate `{dep}`"),
            ));
        }
    }
}

/// One key line of a manifest: the header of its table (empty before the
/// first), the line without comment and whitespace, its comment (after the
/// `#`, trimmed; `None` without one), and its 1-based number.
pub(crate) struct KeyLine {
    pub header: String,
    pub line: String,
    pub comment: Option<String>,
    pub number: usize,
}

/// [`key_lines`] with each line's comment and number.
pub(crate) fn key_lines_full(manifest: &str) -> Vec<KeyLine> {
    let mut header = String::new();
    let mut out = Vec::new();
    let mut open = None;
    for (i, raw) in manifest.lines().enumerate() {
        let Some(code) = code_of(raw, &mut open) else {
            continue;
        };
        let comment = raw[code.len()..]
            .strip_prefix('#')
            .map(|c| c.trim().to_string());
        let line: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        if line.starts_with('[') {
            header = line;
        } else if !line.is_empty() {
            out.push(KeyLine {
                header: header.clone(),
                line,
                comment,
                number: i + 1,
            });
        }
    }
    out
}

/// Each key line of a TOML manifest, with comments and all whitespace
/// removed, paired with the header of the table it sits in (empty before the
/// first header). A `#` inside a string is not a comment, and lines inside a
/// multi-line string are not key lines.
fn key_lines(manifest: &str) -> Vec<(String, String)> {
    let mut header = String::new();
    let mut out = Vec::new();
    let mut open = None;
    for raw in manifest.lines() {
        let Some(code) = code_of(raw, &mut open) else {
            continue;
        };
        let line: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        if line.starts_with('[') {
            header = line;
        } else if !line.is_empty() {
            out.push((header.clone(), line));
        }
    }
    out
}

/// One manifest line without its comment. `open` holds the closing delimiter
/// of a multi-line string left open by an earlier line, and is updated. A
/// line that starts inside such a string gives `None`: whatever follows its
/// closing delimiter still belongs to the earlier key's value.
fn code_of<'a>(line: &'a str, open: &mut Option<&'static str>) -> Option<&'a str> {
    if let Some(delim) = *open {
        if line.contains(delim) {
            *open = None;
        }
        return None;
    }
    let mut i = 0;
    while let Some(c) = line[i..].chars().next() {
        let rest = &line[i..];
        if c == '#' {
            return Some(&line[..i]);
        }
        if let Some(delim) = [r#"""""#, "'''"].into_iter().find(|d| rest.starts_with(d)) {
            if let Some(end) = rest[3..].find(delim) {
                i += 3 + end + 3;
            } else {
                *open = Some(delim);
                return Some(line);
            }
        } else if c == '"' {
            i += 1 + basic_string_len(&rest[1..]);
        } else if c == '\'' {
            i += 1 + rest[1..].find('\'').map_or(rest.len() - 1, |end| end + 1);
        } else {
            i += c.len_utf8();
        }
    }
    Some(line)
}

/// The length of a basic string's body plus its closing quote (or of the
/// whole rest, if the quote is missing), honouring backslash escapes.
fn basic_string_len(body: &str) -> usize {
    let mut escaped = false;
    for (i, c) in body.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => return i + 1,
            _ => {}
        }
    }
    body.len()
}

pub(crate) fn opts_into_workspace_lints(manifest: &str) -> bool {
    key_lines(manifest).iter().any(|(header, line)| {
        (header == "[lints]" && line == "workspace=true")
            || (header.is_empty()
                && (line == "lints.workspace=true" || line == "lints={workspace=true}"))
    })
}

fn root_forbids_unsafe(manifest: &str) -> bool {
    key_lines(manifest).iter().any(|(header, line)| {
        let value = match header.as_str() {
            "[workspace.lints.rust]" => line.strip_prefix("unsafe_code="),
            "[workspace.lints]" => line
                .strip_prefix("rust.unsafe_code=")
                .or_else(|| line.strip_prefix("rust=").and_then(inline_unsafe_code)),
            "[workspace]" => line.strip_prefix("lints.rust.unsafe_code="),
            "" => line.strip_prefix("workspace.lints.rust.unsafe_code="),
            _ => None,
        };
        value.is_some_and(is_forbid)
    })
}

/// The value of `unsafe_code` among the top-level keys of an inline `{…}`
/// table of lint levels (whitespace already removed). A key of the same name
/// inside a nested table is not the lint.
fn inline_unsafe_code(table: &str) -> Option<&str> {
    inline_value(table, "unsafe_code")
}

/// The value of `key` among the top-level keys of an inline `{…}` table
/// (whitespace already removed); a key of that name in a nested table is
/// not it.
pub(crate) fn inline_value<'a>(table: &'a str, key: &str) -> Option<&'a str> {
    let body = table.strip_prefix('{')?;
    let keys = [
        format!("{key}="),
        format!("\"{key}\"="),
        format!("'{key}'="),
    ];
    let mut depth = 0usize;
    let mut quote = None;
    let mut key_start = true;
    for (i, c) in body.char_indices() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            continue;
        }
        if key_start
            && depth == 0
            && let Some(value) = keys.iter().find_map(|k| body[i..].strip_prefix(k.as_str()))
        {
            return if value.starts_with('{') {
                value.find('}').map(|end| &value[..=end])
            } else {
                value.split([',', '}']).next()
            };
        }
        key_start = false;
        match c {
            '"' | '\'' => quote = Some(c),
            '{' | '[' => depth += 1,
            '}' | ']' if depth == 0 => return None,
            '}' | ']' => depth -= 1,
            ',' if depth == 0 => key_start = true,
            _ => {}
        }
    }
    None
}

fn is_forbid(value: &str) -> bool {
    value == "\"forbid\""
        || value == "'forbid'"
        || (value.starts_with('{')
            && (value.contains("level=\"forbid\"") || value.contains("level='forbid'")))
}

/// Whether the manifest sets `lint` in `[lints.<group>]` to deny or forbid:
/// `[lints.<group>]` with `lint = …`, `[lints]` with `<group>.lint = …` or
/// `<group> = { lint = … }`, or top-level `lints.<group>.lint = …`. Keys may
/// be quoted.
fn sets_lint(manifest: &str, group: &str, lint: &str) -> bool {
    let key = format!("{lint}=");
    let dotted = format!("{group}.{lint}=");
    let as_table = format!("{group}=");
    let top = format!("lints.{group}.{lint}=");
    key_lines(manifest).iter().any(|(header, raw)| {
        let unquoted = unquote_key(raw);
        let value = if *header == format!("[lints.{group}]") {
            unquoted.strip_prefix(&key)
        } else if header == "[lints]" {
            unquoted.strip_prefix(&dotted).or_else(|| {
                unquoted
                    .strip_prefix(&as_table)
                    .and_then(|t| inline_value(t, lint))
            })
        } else if header.is_empty() {
            unquoted.strip_prefix(&top)
        } else {
            None
        };
        value.is_some_and(is_deny_or_forbid)
    })
}

/// A key line with quotes around its key's segments removed:
/// `"a".b="x"` → `a.b="x"`. A quoted segment holding a `.` is one literal
/// key, so it keeps its quotes and matches no dotted form. The value is
/// untouched.
fn unquote_key(line: &str) -> String {
    let Some(eq) = key_end(line) else {
        return line.to_string();
    };
    let mut key = String::new();
    let mut quoted: Option<(char, String)> = None;
    for c in line[..eq].chars() {
        match &mut quoted {
            Some((q, seg)) if c == *q => {
                if seg.contains('.') {
                    key.push(*q);
                    key.push_str(seg);
                    key.push(*q);
                } else {
                    key.push_str(seg);
                }
                quoted = None;
            }
            Some((_, seg)) => seg.push(c),
            None if matches!(c, '"' | '\'') => quoted = Some((c, String::new())),
            None => key.push(c),
        }
    }
    format!("{key}{}", &line[eq..])
}

/// The index of the `=` that ends a line's key, skipping quoted segments.
fn key_end(line: &str) -> Option<usize> {
    let mut quote = None;
    for (i, c) in line.char_indices() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (None, '"' | '\'') => quote = Some(c),
            (None, '=') => return Some(i),
            _ => {}
        }
    }
    None
}

fn is_deny_or_forbid(value: &str) -> bool {
    is_forbid(value)
        || value == "\"deny\""
        || value == "'deny'"
        || (value.starts_with('{')
            && (value.contains("level=\"deny\"") || value.contains("level='deny'")))
}

fn declares_no_std(source: &str) -> bool {
    inner_attributes(source)
        .iter()
        .any(|a| a == "[no_std]" || (a.starts_with("[cfg_attr(") && a.ends_with(",no_std)]")))
}

/// The crate-level inner attributes (`#![…]`) at the top of a source file,
/// from the `[` on and with whitespace removed. Comments between them are
/// skipped; scanning stops at the first item, so text in later comments or
/// in strings never counts.
fn inner_attributes(source: &str) -> Vec<String> {
    let mut rest = source;
    let mut out = Vec::new();
    loop {
        rest = rest.trim_start();
        if let Some(after) = rest.strip_prefix("//") {
            rest = after.split_once('\n').map_or("", |(_, next)| next);
        } else if rest.starts_with("/*") {
            let Some(end) = block_comment_len(rest) else {
                return out;
            };
            rest = &rest[end..];
        } else if let Some(after) = rest.strip_prefix("#!") {
            let after = after.trim_start();
            let Some(end) = attribute_len(after) else {
                return out;
            };
            out.push(
                after[..end]
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect(),
            );
            rest = &after[end..];
        } else {
            return out;
        }
    }
}

/// The length of the (possibly nested) block comment `source` starts with.
fn block_comment_len(source: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = 0;
    while let Some(c) = source[i..].chars().next() {
        let rest = &source[i..];
        if rest.starts_with("/*") {
            depth += 1;
            i += 2;
        } else if rest.starts_with("*/") {
            depth -= 1;
            i += 2;
            if depth == 0 {
                return Some(i);
            }
        } else {
            i += c.len_utf8();
        }
    }
    None
}

/// The length of the bracketed attribute `source` starts with (`[` up to its
/// matching `]`), skipping brackets inside string literals.
fn attribute_len(source: &str) -> Option<usize> {
    if !source.starts_with('[') {
        return None;
    }
    let mut depth = 0usize;
    let mut i = 0;
    while let Some(c) = source[i..].chars().next() {
        match c {
            '"' => {
                i += 1 + basic_string_len(&source[i + 1..]);
                continue;
            }
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += c.len_utf8();
    }
    None
}

/// # Errors
/// One line per violation.
pub fn report(violations: &[Violation]) -> Result<(), String> {
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n"))
    }
}

fn parse(json: &str) -> Result<Value, String> {
    serde_json::from_str(json).map_err(|e| format!("cargo metadata: {e}"))
}

fn str_field<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("cargo metadata: missing string `{key}`"))
}

fn manifest_dir(p: &Value) -> Result<PathBuf, String> {
    let manifest = Path::new(str_field(p, "manifest_path")?);
    manifest
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("cargo metadata: {} has no parent", manifest.display()))
}

/// The packages of `cargo metadata --format-version 1 --no-deps` output, with
/// each manifest and lib root read through `read`.
///
/// # Errors
/// On malformed JSON, a wrongly typed declaration (naming the package) or a
/// file `read` cannot read: never an empty or partial list.
pub fn parse_metadata(
    json: &str,
    read: &dyn Fn(&Path) -> io::Result<String>,
) -> Result<Vec<Package>, String> {
    let doc = parse(json)?;
    let raw = doc
        .get("packages")
        .and_then(Value::as_array)
        .ok_or("cargo metadata: no `packages` array")?;
    let dirs = raw
        .iter()
        .map(|p| Ok((str_field(p, "name")?.to_string(), manifest_dir(p)?)))
        .collect::<Result<Vec<_>, String>>()?;
    raw.iter().map(|p| package(p, &dirs, read)).collect()
}

fn package(
    p: &Value,
    dirs: &[(String, PathBuf)],
    read: &dyn Fn(&Path) -> io::Result<String>,
) -> Result<Package, String> {
    let name = str_field(p, "name")?.to_string();
    let load = |path: &Path| {
        read(path).map_err(|e| format!("{name}: cannot read {}: {e}", path.display()))
    };
    let manifest = load(Path::new(str_field(p, "manifest_path")?))?;
    let lib = lib_path(p);
    let lib_source = lib.as_deref().map(load).transpose()?;
    let decl = p.get("metadata").and_then(|m| m.get("disciplines"));
    let layer = decl
        .and_then(|d| d.get("layer"))
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{name}: `layer` must be a string"))
        })
        .transpose()?;
    let tooth = decl
        .and_then(|d| d.get("tooth"))
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{name}: `tooth` must be a string"))
        })
        .transpose()?;
    let data_only = decl
        .and_then(|d| d.get("data_only"))
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{name}: `data_only` must be a string (the reason)"))
        })
        .transpose()?;
    let allow = decl
        .and_then(|d| d.get("allow"))
        .map(|v| {
            v.as_array()
                .and_then(|a| a.iter().map(|x| x.as_str().map(str::to_string)).collect())
                .ok_or_else(|| format!("{name}: `allow` must be an array of strings"))
        })
        .transpose()?;
    let deps = p
        .get("dependencies")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{name}: cargo metadata gave no `dependencies` array"))?
        .iter()
        .map(|d| dep(d, dirs))
        .collect::<Result<Vec<_>, String>>()?;
    Ok(Package {
        name,
        manifest,
        lib_source,
        lib_path: lib,
        layer,
        tooth,
        data_only,
        allow,
        deps,
        proc_macro: is_proc_macro(p),
    })
}

fn is_proc_macro(p: &Value) -> bool {
    p.get("targets")
        .and_then(Value::as_array)
        .is_some_and(|targets| {
            targets.iter().any(|t| {
                t.get("kind")
                    .and_then(Value::as_array)
                    .is_some_and(|kinds| kinds.iter().any(|k| k.as_str() == Some("proc-macro")))
            })
        })
}

fn lib_path(p: &Value) -> Option<PathBuf> {
    p.get("targets")?
        .as_array()?
        .iter()
        .find(|t| {
            t.get("kind")
                .and_then(Value::as_array)
                .is_some_and(|kinds| {
                    kinds
                        .iter()
                        .any(|k| k.as_str().is_some_and(|k| LIB_KINDS.contains(&k)))
                })
        })
        .and_then(|t| t.get("src_path")?.as_str())
        .map(PathBuf::from)
}

fn dep(d: &Value, dirs: &[(String, PathBuf)]) -> Result<Dep, String> {
    let name = str_field(d, "name")?.to_string();
    let kind = match d.get("kind").and_then(Value::as_str) {
        None => DepKind::Normal,
        Some("build") => DepKind::Build,
        Some("dev") => DepKind::Dev,
        Some(other) => {
            return Err(format!(
                "cargo metadata: dependency `{name}` has unknown kind `{other}`"
            ));
        }
    };
    let member = d.get("path").and_then(Value::as_str).is_some_and(|path| {
        dirs.iter()
            .any(|(n, dir)| *n == name && dir == Path::new(path))
    });
    Ok(Dep { name, kind, member })
}

/// The target `no-std` builds for.
///
/// # Errors
/// On malformed JSON, or when `[workspace.metadata.disciplines]
/// no_std_target` is not set.
pub fn no_std_target(json: &str) -> Result<String, String> {
    parse(json)?
        .get("metadata")
        .and_then(|m| m.get("disciplines"))
        .and_then(|d| d.get("no_std_target"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            "set `no_std_target` under [workspace.metadata.disciplines] in the root Cargo.toml (e.g. \"x86_64-unknown-none\")".to_string()
        })
}

/// The primitive, kernel and core crates, in workspace order.
///
/// # Errors
/// When there are none: the gate would build nothing.
pub fn no_std_crates(packages: &[Package]) -> Result<Vec<&str>, String> {
    let names: Vec<&str> = packages
        .iter()
        .filter(|p| {
            matches!(p.layer.as_deref(), Some("primitive" | "kernel" | "core")) && !p.proc_macro
        })
        .map(|p| p.name.as_str())
        .collect();
    if names.is_empty() {
        Err(
            "no primitive, kernel or core crate: nothing to build for the no_std target"
                .to_string(),
        )
    } else {
        Ok(names)
    }
}
