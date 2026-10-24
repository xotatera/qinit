// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Duplication gate: functions whose bodies are identical after
//! normalisation (see `extract`). Two tiers:
//! - strict (the gate): local names and string literals ignored;
//! - loose (`dup report --loose`, advisory only): every name and literal ignored.
//!
//! Similarity-score detectors were measured at about 17 % precision; an exact
//! match on the strict normalisation had no false positive on the same sample.
pub mod baseline;
pub mod cli;
pub mod extract;
pub mod files;

use std::collections::BTreeMap;
use std::path::Path;

use extract::Function;

/// Smallest body, in strict tokens, that counts. Re-measure per project with
/// `cargo xtask dup sweep` and a classified sample (SKILL.md step 3).
///
/// Measured by the disciplines skill, 2026-10-08, 44 Rust repositories, with
/// `skill/tools/dup-measure.sh <repo> sweep` and `report --min-tokens 30`
/// (in a consuming project the equivalent is `cargo xtask dup sweep`):
/// - 254 gate-tier groups at 20, 174 at 30.
/// - At 30 the gate flags every exact TRUE pair of the earlier sample and no
///   FALSE pair. One true duplicate in that sample differs only in a returned
///   type name; that shape is advisory-only.
/// - Fresh 20-group sample at 20: 11 TRUE, 6 WEAK, 3 FALSE. Failed the limit
///   of 2 FALSE.
/// - Fresh 20-group sample at 30: 11 TRUE, 7 WEAK, 2 FALSE. Passed.
pub const MIN_TOKENS: usize = 30;

pub const BASELINE: &str = "gates/duplication-baseline.txt";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Strict,
    Loose,
}

/// Functions with identical normalised bodies. Members are `(key, line)`,
/// sorted by key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub tokens: usize,
    pub members: Vec<(String, usize)>,
}

impl Group {
    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        self.members.iter().map(|(k, _)| k.clone()).collect()
    }
}

#[must_use]
pub fn groups(fns: &[Function], tier: Tier, min_tokens: usize, include_tests: bool) -> Vec<Group> {
    let mut by_body: BTreeMap<String, Vec<&Function>> = BTreeMap::new();
    for f in fns {
        if (f.is_test && !include_tests) || f.strict.len() < min_tokens {
            continue;
        }
        let tokens = match tier {
            Tier::Strict => &f.strict,
            Tier::Loose => &f.loose,
        };
        by_body.entry(tokens.join("\u{1f}")).or_default().push(f);
    }
    let mut out: Vec<Group> = by_body
        .into_values()
        .filter(|fs| fs.len() > 1)
        .map(|fs| {
            let mut members: Vec<(String, usize)> =
                fs.iter().map(|f| (f.key.clone(), f.line)).collect();
            members.sort();
            Group {
                tokens: fs[0].strict.len(),
                members,
            }
        })
        .collect();
    out.sort_by(|a, b| a.members.cmp(&b.members));
    out
}

/// Every function in the Rust files under `root`.
///
/// # Errors
/// An unreadable file or directory, or a file the parser gives up on.
pub fn scan(root: &Path) -> Result<Vec<Function>, String> {
    let mut all = Vec::new();
    for rel in files::rust_files(root)? {
        let source = std::fs::read_to_string(root.join(&rel)).map_err(|e| format!("{rel}: {e}"))?;
        all.extend(extract::functions(&rel, &source)?);
    }
    Ok(all)
}

#[must_use]
pub fn describe(group: &Group) -> String {
    group
        .members
        .iter()
        .map(|(key, line)| format!("{key} (line {line})"))
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Refusal when a scan finds nothing: such a run checks nothing.
pub const NO_INPUT: &str = "no Rust functions found: a gate with no input checks nothing";

/// The gate. A strict group the baseline does not cover fails. A baseline
/// entry that shrank or vanished passes and is printed for `dup bless`.
///
/// # Errors
/// The new groups, with what to do about them; or no input at all.
pub fn gate(root: &Path) -> Result<(), String> {
    let fns = scan(root)?;
    if fns.is_empty() {
        return Err(NO_INPUT.to_string());
    }
    let base = baseline::load(&root.join(BASELINE))?;
    let current = groups(&fns, Tier::Strict, MIN_TOKENS, false);
    let diff = baseline::compare(&base, &current);
    for stale in &diff.stale {
        eprintln!(
            "duplication: baseline entry no longer matches (run `cargo xtask dup bless`): {}",
            stale.join(" | ")
        );
    }
    if diff.new.is_empty() {
        return Ok(());
    }
    let mut msg: Vec<String> = diff
        .new
        .iter()
        .map(|g| format!("new duplicate group ({} tokens): {}", g.tokens, describe(g)))
        .collect();
    msg.push(format!(
        "Extract the shared code. If the duplication is deliberate, add the group to {BASELINE} with a reason. \
         If you renamed or moved a function that is in the baseline, update its entry in the baseline."
    ));
    Err(msg.join("\n"))
}
