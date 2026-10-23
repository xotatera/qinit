// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! `gates/duplication-baseline.txt`: accepted duplicate groups, shrink-only.
//!
//! One group per line, members sorted, each with a reason:
//! `src/a.rs::f | src/b.rs::Type::g  # why this stays`
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use super::Group;

pub const HEADER: &str = "# Accepted duplicate groups. Shrink-only: a group not covered here fails the\n\
# duplication gate; `cargo xtask dup bless` removes entries that no longer match.\n\
# One group per line, members sorted:  <member> | <member>  # reason\n";

/// Sorted member keys → reason.
pub type Baseline = BTreeMap<Vec<String>, String>;

/// # Errors
/// The first malformed line, by number.
pub fn parse(text: &str) -> Result<Baseline, String> {
    let mut out = Baseline::new();
    let mut seen = std::collections::HashSet::new();
    for (i, line) in text.lines().enumerate() {
        let n = i + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (members, reason) = line
            .split_once("  #")
            .ok_or(format!("line {n}: missing `  # reason`"))?;
        let reason = reason.trim();
        if reason.is_empty() {
            return Err(format!("line {n}: empty reason"));
        }
        let members: Vec<String> = members.split(" | ").map(|m| m.trim().to_string()).collect();
        if members.len() < 2 || members.iter().any(String::is_empty) {
            return Err(format!("line {n}: a group needs at least two members"));
        }
        if !members.windows(2).all(|w| w[0] < w[1]) {
            return Err(format!("line {n}: members must be sorted and distinct"));
        }
        if out.contains_key(&members) {
            return Err(format!("line {n}: duplicate group"));
        }
        if let Some(m) = members.iter().find(|m| !seen.insert((*m).clone())) {
            return Err(format!(
                "line {n}: member {m} already appears in another entry"
            ));
        }
        out.insert(members, reason.to_string());
    }
    Ok(out)
}

/// A missing file is an empty baseline.
///
/// # Errors
/// An unreadable or malformed file.
pub fn load(path: &Path) -> Result<Baseline, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Baseline::new()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

pub struct Diff<'a> {
    /// Current groups no baseline entry covers: these fail.
    pub new: Vec<&'a Group>,
    /// Baseline entries that are not exactly a current group (shrunk or gone).
    pub stale: Vec<Vec<String>>,
}

fn covered_by(group: &[String], entry: &[String]) -> bool {
    group.iter().all(|k| entry.contains(k))
}

#[must_use]
pub fn compare<'a>(base: &Baseline, current: &'a [Group]) -> Diff<'a> {
    let keys: Vec<Vec<String>> = current.iter().map(Group::keys).collect();
    Diff {
        new: current
            .iter()
            .zip(&keys)
            .filter(|(_, k)| !base.keys().any(|e| covered_by(k, e)))
            .map(|(g, _)| g)
            .collect(),
        stale: base.keys().filter(|e| !keys.contains(e)).cloned().collect(),
    }
}

/// The baseline narrowed to the current groups it covers, reasons kept.
/// Never adds a member: each line written is a current group inside an
/// existing entry, so one entry can become several lines when its group
/// split. Accepting new duplication is a decision made by hand.
#[must_use]
pub fn bless(base: &Baseline, current: &[Group]) -> String {
    let mut out = HEADER.to_string();
    for (entry, reason) in base {
        for group in current
            .iter()
            .map(Group::keys)
            .filter(|k| covered_by(k, entry))
        {
            let _ = writeln!(out, "{}  # {reason}", group.join(" | "));
        }
    }
    out
}
