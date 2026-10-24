// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The matcher of the gate that rejects waiting by sleeping in Rust sources
//! (`principles.md` §7: handshakes and injected clocks, never sleeps). A
//! sleep the project chose to keep carries [`MARKER`] and `(D<n>)` on its
//! line, where `D<n>` is an `ACCEPTED` entry of `DEFERRED.md`.
use std::collections::BTreeMap;

/// The marker that exempts one line. Built from parts so this file does
/// not match itself.
pub const MARKER: &str = concat!("disciplines:allow-", "sleep");

/// A call or path to the standard library's sleep.
pub const PATTERN: &str = concat!("thread::", "sleep");

/// Extensions scanned.
pub const EXTENSIONS: &[&str] = &["rs"];

/// One finding: 1-based line number, the line, and why it fails.
#[derive(Debug, PartialEq, Eq)]
pub struct Hit {
    pub line: usize,
    pub text: String,
    pub why: String,
}

/// The statuses a ledger entry can have.
pub const STATUSES: &[&str] = &["OPEN", "DECISION", "ACCEPTED", "RESOLVED"];

/// Each entry of a `DEFERRED.md` text by number, with its status. Both
/// heading forms in use are read: ``### D<n> — <title> · `STATUS` `` (the
/// backticked status wins over words in the title) and the scaffold's
/// `### D<n> · STATUS · <title>` (the first status word).
#[must_use]
pub fn ledger(text: &str) -> BTreeMap<u32, String> {
    text.lines()
        .filter_map(|l| {
            let rest = l.strip_prefix("### D")?;
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            let id = digits.parse().ok()?;
            // The last piece between backticks that is exactly a status: a
            // stray backtick in the title cannot shift it, as pairing would.
            let ticked = l.split('`').rfind(|w| STATUSES.contains(w));
            let word = || {
                l.split(|c: char| !c.is_ascii_alphabetic())
                    .find(|w| STATUSES.contains(w))
            };
            Some((id, ticked.or_else(word)?.to_string()))
        })
        .collect()
}

/// The lines of `text` that sleep without a valid marker, and the markers
/// that are invalid or exempt nothing (a stale marker is cover for the next
/// sleep). `ledger` is the result of [`ledger`].
///
/// Any line holding the pattern counts, comments included: reword a comment
/// that names it, since the marker exempts only a line that sleeps.
#[must_use]
pub fn scan(text: &str, ledger: &BTreeMap<u32, String>) -> Vec<Hit> {
    // The braces a `use` over several lines leaves open, innermost last:
    // whether each is a `thread::{` group, where a bare `sleep` is the import.
    let mut open: Vec<bool> = Vec::new();
    text.lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let sleeps = if open.is_empty() {
                if strip_use(line).is_some() {
                    braces(line, &mut open);
                }
                is_sleep(line)
            } else {
                let thread = open.last() == Some(&true);
                braces(line, &mut open);
                is_sleep(line) || is_sleep_import(line) || (thread && contains_word(line, "sleep"))
            };
            let why = judge(line, sleeps, ledger)?;
            Some(Hit {
                line: i + 1,
                text: line.trim().to_string(),
                why,
            })
        })
        .collect()
}

fn judge(line: &str, sleeps: bool, ledger: &BTreeMap<u32, String>) -> Option<String> {
    let Some(at) = line.find(MARKER) else {
        return sleeps.then(|| "a sleep: wait on a handshake or an event instead".to_string());
    };
    let cited = line[at + MARKER.len()..]
        .trim_start()
        .strip_prefix('(')
        .and_then(|r| r.split_once(')'))
        .map(|(id, _)| id.trim());
    let Some(id) = cited.and_then(|c| c.strip_prefix('D')?.parse::<u32>().ok()) else {
        return Some(format!(
            "the marker must cite a ledger entry: `{MARKER} (D<n>)`"
        ));
    };
    match ledger.get(&id).map(String::as_str) {
        None => Some(format!("D{id} is not in DEFERRED.md")),
        Some("ACCEPTED") if sleeps => None,
        Some("ACCEPTED") => Some("a marker on a line that does not sleep".to_string()),
        Some(other) => Some(format!("D{id} is {other}, not ACCEPTED")),
    }
}

/// Follows the braces of `line` on `open`: each `{` pushes whether it opens
/// a `thread::{` group, each `}` pops.
fn braces(line: &str, open: &mut Vec<bool>) {
    for (at, c) in line.char_indices() {
        match c {
            '{' => open.push(line[..at].trim_end().ends_with("thread::")),
            '}' => {
                open.pop();
            }
            _ => {}
        }
    }
}

/// The pattern anywhere on the line, or `sleep` imported from
/// `std::thread` in a braced `use` on one line ([`scan`] follows a braced
/// `use` over several lines).
#[must_use]
pub fn is_sleep(line: &str) -> bool {
    line.contains(PATTERN) || (strip_use(line).is_some() && is_sleep_import(line))
}

/// `thread::{` on the line with `sleep` as a word after it.
fn is_sleep_import(line: &str) -> bool {
    line.find("thread::{")
        .is_some_and(|at| contains_word(&line[at..], "sleep"))
}

/// The line after `use `, with any `pub`, `pub(crate)` … before it; `None`
/// when the line is not a `use`.
fn strip_use(line: &str) -> Option<&str> {
    let t = line.trim();
    let t = match t.strip_prefix("pub") {
        Some(rest) if rest.starts_with('(') => rest.split_once(')').map_or(rest, |(_, r)| r),
        Some(rest) => rest,
        None => t,
    };
    t.trim_start().strip_prefix("use ")
}

fn contains_word(hay: &str, needle: &str) -> bool {
    let word = |c: char| c.is_alphanumeric() || c == '_';
    hay.match_indices(needle).any(|(at, _)| {
        !hay[..at].chars().next_back().is_some_and(word)
            && !hay[at + needle.len()..].chars().next().is_some_and(word)
    })
}
