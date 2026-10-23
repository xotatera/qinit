// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The logic of the gate that requires every merge into main to add an
//! entry under `## [Unreleased]` in `CHANGELOG.md` (Keep a Changelog), or
//! a release section. It compares two texts of the file; which two depends
//! on where the gate runs ([`context`]).

/// Where the gate runs, which decides the two texts it compares.
#[derive(Debug, PartialEq, Eq)]
pub enum Context {
    /// A hook gating a merge into main: `HEAD` against the merged tree on
    /// disk. `pre-merge-commit` has no `MERGE_HEAD`, so the merged commits
    /// are not known, only the tree.
    Merging,
    /// On main, outside a hook: the merge at `HEAD`, first parent against
    /// the merge.
    MainTip,
    /// On a branch: its merge base with main against the working tree.
    Branch,
}

/// # Errors
/// With no branch (detached `HEAD`) outside a hook: there is nothing to
/// compare against.
pub fn context(hook_main: bool, branch: Option<&str>, main: &str) -> Result<Context, String> {
    match branch {
        _ if hook_main => Ok(Context::Merging),
        Some(b) if b == main => Ok(Context::MainTip),
        Some(_) => Ok(Context::Branch),
        None => Err("detached HEAD: check out a branch".to_string()),
    }
}

/// The non-blank lines of the `## [Unreleased]` section; `None` without one.
#[must_use]
pub fn unreleased(text: &str) -> Option<Vec<&str>> {
    let mut lines = text.lines().skip_while(|l| l.trim() != "## [Unreleased]");
    lines.next()?;
    Some(
        lines
            .take_while(|l| !l.starts_with("## "))
            .filter(|l| !l.trim().is_empty())
            .collect(),
    )
}

/// The release headings: `## [` sections other than `[Unreleased]`.
#[must_use]
pub fn releases(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|l| l.starts_with("## [") && l.trim() != "## [Unreleased]")
        .collect()
}

/// Passes when `new` has an entry (a `- ` or `* ` line) under
/// `[Unreleased]` that `old` lacks, or a release section `old` lacks.
/// Lines are compared as text: a reworded entry counts as new, and a new
/// entry identical to an existing one counts too (each copy is matched
/// once).
///
/// # Errors
/// When `new` has no `[Unreleased]` section, or neither changed.
pub fn check(old: &str, new: &str) -> Result<(), String> {
    let Some(now) = unreleased(new) else {
        return Err("CHANGELOG.md has no `## [Unreleased]` section".to_string());
    };
    let mut before = unreleased(old).unwrap_or_default();
    let added = now.iter().any(|line| {
        if let Some(at) = before.iter().position(|b| b == line) {
            before.remove(at);
            return false;
        }
        let t = line.trim_start();
        t.starts_with("- ") || t.starts_with("* ")
    });
    let released = releases(new).iter().any(|r| !releases(old).contains(r));
    if added || released {
        Ok(())
    } else {
        Err(
            "no new entry under `## [Unreleased]` in CHANGELOG.md: say what this branch \
             changes (Keep a Changelog: Added, Changed, Fixed, Removed …)"
                .to_string(),
        )
    }
}
