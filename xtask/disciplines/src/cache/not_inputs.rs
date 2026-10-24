// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! `not_inputs` in the root manifest's `[workspace.metadata.disciplines]`:
//! ignored directories no build step reads (a fuzz corpus, recorded data).
//! A path value naming an in-tree directory makes every ignored file below
//! it a possible input (`outside::scan`); files below these directories are
//! left out of that walk. Tracked files there stay inputs, and a gate's own
//! `ignored_inputs` globs still match there.
//!
//! The key reads the list from the manifest's text (`from_manifest`), with
//! no `cargo metadata` call per gate; preflight checks that text against
//! `cargo metadata` (`check`), so a list cargo would place elsewhere is
//! refused. The manifest is part of every key, so editing the list
//! invalidates every gate.
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use super::outside::assignments;

const TABLE: &str = "[workspace.metadata.disciplines]";
const EXPECTED: &str =
    "not_inputs: expected an array of directory paths, such as [\"fuzz/corpus\"]";

/// The list, sorted, from the root manifest's text. None is an empty list.
///
/// # Errors
/// More than one `not_inputs` assignment, a value that is not an array of
/// strings, or an invalid entry (see `entry`).
pub fn from_manifest(text: &str) -> Result<Vec<PathBuf>, String> {
    // Whole-line comments only: the template's own example is one.
    let text: String = text
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .flat_map(|l| [l, "\n"])
        .collect();
    let found = assignments(&text, &["not_inputs"]);
    match found.as_slice() {
        [] => Ok(Vec::new()),
        [one] if one.array => entries(one.strings.iter().map(String::as_str)),
        [_] => Err(EXPECTED.to_string()),
        _ => Err("not_inputs: assigned more than once".to_string()),
    }
}

/// The list, sorted, from `cargo metadata` output.
///
/// # Errors
/// Invalid JSON, a value that is not an array of strings, or an invalid
/// entry.
pub fn from_metadata(json: &str) -> Result<Vec<PathBuf>, String> {
    let doc: Value = serde_json::from_str(json).map_err(|e| format!("cargo metadata: {e}"))?;
    let Some(value) = doc
        .get("metadata")
        .and_then(|m| m.get("disciplines"))
        .and_then(|d| d.get("not_inputs"))
    else {
        return Ok(Vec::new());
    };
    let strings: Option<Vec<&str>> = value
        .as_array()
        .and_then(|a| a.iter().map(Value::as_str).collect());
    let strings = strings.ok_or(EXPECTED)?;
    entries(strings.into_iter())
}

/// Preflight: the list the key reads from the text is the one cargo sees.
///
/// # Errors
/// Either reading fails, or they differ.
pub fn check(json: &str, manifest: &str) -> Result<(), String> {
    let declared = from_metadata(json)?;
    if from_manifest(manifest)? == declared {
        Ok(())
    } else {
        Err(format!(
            "not_inputs: write it once, as an array of strings under {TABLE} in the root Cargo.toml"
        ))
    }
}

fn entries<'a>(values: impl Iterator<Item = &'a str>) -> Result<Vec<PathBuf>, String> {
    let mut out = values.map(entry).collect::<Result<Vec<_>, _>>()?;
    out.sort();
    out.dedup();
    Ok(out)
}

/// A literal relative directory path inside the root: no glob characters,
/// no `.`/`..` or root components, not empty.
fn entry(value: &str) -> Result<PathBuf, String> {
    let bad = |why: &str| Err(format!("not_inputs: `{value}`: {why}"));
    if value.contains(['*', '?', '[', ']']) {
        return bad("globs are not accepted; name the directory");
    }
    let path = Path::new(value);
    let mut parts = path.components().peekable();
    if parts.peek().is_none() {
        return bad("empty; the whole tree cannot be excluded");
    }
    if !parts.all(|c| matches!(c, Component::Normal(_))) {
        return bad("expected a relative path inside the repository, without `.` or `..`");
    }
    Ok(path.components().collect())
}
