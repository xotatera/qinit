// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The matcher of the gate that rejects unfinished code and promises in
//! source files. A genuine false positive carries
//! `disciplines:allow-placeholder (<reason>)` on its line.

/// The marker that exempts one line; it must be followed by a reason in
/// parentheses.
pub const MARKER: &str = "disciplines:allow-placeholder"; // disciplines:allow-placeholder (the marker itself)

/// Extensions scanned. Docs, specs and plans quote stubs on purpose; they
/// are out of scope. Extensionless files are scanned when they are shell
/// scripts (`shell::is_shell_script`).
pub const EXTENSIONS: &[&str] = &["rs", "in", "sh", "py", "toml"];

const ANYWHERE: &[&str] = &[
    "todo",                // disciplines:allow-placeholder (pattern definition)
    "fixme",               // disciplines:allow-placeholder (pattern definition)
    "hack",                // disciplines:allow-placeholder (pattern definition)
    "xxx",                 // disciplines:allow-placeholder (pattern definition)
    "unimplemented!(",     // disciplines:allow-placeholder (pattern definition)
    "is a follow-up",      // disciplines:allow-placeholder (pattern definition)
    "not implemented",     // disciplines:allow-placeholder (pattern definition)
    "not yet implemented", // disciplines:allow-placeholder (pattern definition)
];
const WORDS: &[&str] = &[
    "stub",        // disciplines:allow-placeholder (pattern definition)
    "placeholder", // disciplines:allow-placeholder (pattern definition)
    "for now",     // disciplines:allow-placeholder (pattern definition)
    "simplified:", // disciplines:allow-placeholder (pattern definition)
];
const QUALIFIERS: &[&str] = &["full", "real", "proper", "complete", "future"];

/// One finding: 1-based line number and the line.
#[derive(Debug, PartialEq, Eq)]
pub struct Hit {
    pub line: usize,
    pub text: String,
}

/// The project's declared vocabulary, relative to the repository root:
/// terms that collide with a pattern (`stub` for test doubles, a // disciplines:allow-placeholder (example terms)
/// `NothingToDo` variant), one per line as `<term>  # <reason>`. // disciplines:allow-placeholder (example terms)
pub const VOCABULARY: &str = "gates/scan-vocabulary.txt";

/// The terms of a vocabulary file. Blank lines and whole-line comments are
/// skipped. A term cannot hold `#`: the first one starts the reason.
///
/// # Errors
/// A line with no reason, or whose term is empty or holds whitespace.
pub fn parse_vocabulary(text: &str) -> Result<Vec<String>, String> {
    let mut terms = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (term, reason) = line.split_once('#').unwrap_or((line, ""));
        let term = term.trim();
        if reason.trim().is_empty() || term.is_empty() || term.contains(char::is_whitespace) {
            return Err(format!(
                "{VOCABULARY}:{}: expected `<term>  # <reason>`: {line}",
                i + 1
            ));
        }
        terms.push(term.to_string());
    }
    Ok(terms)
}

/// The lines of `text` that match a pattern and hold no valid marker.
/// A marker without a reason is itself a hit.
#[must_use]
pub fn scan(text: &str) -> Vec<Hit> {
    scan_with(text, &[], &mut [])
}

/// [`scan`], with each of `terms` blanked first wherever it stands as a
/// word (exact case, the patterns' word rule). `used[i]` is set when
/// `terms[i]` exempts a hit: the line is clean with every term blanked, and
/// hits again without that one. When those needed terms alone don't clean
/// the line (overlapping terms share a hit), every term that touched it
/// counts.
#[must_use]
pub fn scan_with(text: &str, terms: &[String], used: &mut [bool]) -> Vec<Hit> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| {
            if has_valid_marker(line) {
                return false;
            }
            if line.contains(MARKER) {
                return true;
            }
            if !is_placeholder(line) {
                return false;
            }
            let mask = |keep: &dyn Fn(usize) -> bool| {
                terms
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| keep(*i))
                    .fold((*line).to_string(), |m, (_, t)| blank_word(&m, t))
            };
            if is_placeholder(&mask(&|_| true)) {
                return true;
            }
            let touched: Vec<usize> = (0..terms.len())
                .filter(|&i| blank_word(line, &terms[i]) != *line)
                .collect();
            let needed: Vec<usize> = touched
                .iter()
                .copied()
                .filter(|&i| is_placeholder(&mask(&|j| j != i)))
                .collect();
            let enough = !needed.is_empty() && !is_placeholder(&mask(&|j| needed.contains(&j)));
            for i in if enough { needed } else { touched } {
                used[i] = true;
            }
            false
        })
        .map(|(i, line)| Hit {
            line: i + 1,
            text: line.trim().to_string(),
        })
        .collect()
}

/// `line` with every word occurrence of `term` replaced by spaces.
fn blank_word(line: &str, term: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut last = 0;
    for (at, _) in line.match_indices(term) {
        if stands_alone(line, at, term) {
            out.push_str(&line[last..at]);
            out.push_str(&" ".repeat(term.len()));
            last = at + term.len();
        }
    }
    out.push_str(&line[last..]);
    out
}

fn has_valid_marker(line: &str) -> bool {
    marked_with_reason(line, MARKER)
}

/// Whether `line` holds `marker` followed by a non-empty reason in
/// parentheses. Shared by the scans that take a marker.
#[must_use]
pub fn marked_with_reason(line: &str, marker: &str) -> bool {
    line.match_indices(marker).any(|(at, _)| {
        let rest = line[at + marker.len()..].trim_start();
        rest.strip_prefix('(')
            .and_then(|r| r.split_once(')'))
            .is_some_and(|(reason, _)| !reason.trim().is_empty())
    })
}

/// Case-insensitive, as the `grep -i` pattern in `gates.md`.
#[must_use]
pub fn is_placeholder(line: &str) -> bool {
    let lower = line.to_lowercase();
    ANYWHERE.iter().any(|p| lower.contains(p))
        || WORDS.iter().any(|w| contains_word(&lower, w))
        || QUALIFIERS
            .iter()
            .any(|q| lower.contains(&format!("in a {q} implementation")))
        || temporary_comment(&lower)
}

/// `needle` with no word character on either side.
fn contains_word(hay: &str, needle: &str) -> bool {
    hay.match_indices(needle)
        .any(|(at, _)| stands_alone(hay, at, needle))
}

/// `needle` at `at` in `hay` has no word character before it, nor after
/// it when it ends in one.
fn stands_alone(hay: &str, at: usize, needle: &str) -> bool {
    let word = |c: char| c.is_alphanumeric() || c == '_';
    let before = hay[..at].chars().next_back();
    let after = hay[at + needle.len()..].chars().next();
    !(before.is_some_and(word) || (needle.ends_with(word) && after.is_some_and(word)))
}

/// A line comment opening with `Temporary` and a colon (any number of
/// slashes, any spaces).
fn temporary_comment(lower: &str) -> bool {
    lower.match_indices("//").any(|(at, _)| {
        lower[at..]
            .trim_start_matches('/')
            .trim_start()
            .starts_with("temporary:")
    })
}
