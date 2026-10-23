// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The marker for code a Verus proof takes on trust, and the one construct
//! the gate finds by text. Verus's `--no-cheating` rejects the rest (assume,
//! admit, `external_body`, `assume_specification`, `axiom` functions,
//! `assume_termination`) and names their
//! lines; `#[verifier::external]` it accepts, yet on a trait impl (such as // disciplines:allow-trusted (documents the construct)
//! `unsafe impl Send`) it is trusted. Each needs
//! `disciplines:allow-trusted (<reason>)` on its line.

/// The marker that accepts one trusted line; it must be followed by a
/// reason in parentheses.
pub const MARKER: &str = "disciplines:allow-trusted"; // disciplines:allow-trusted (the marker itself)

/// `verifier::external` and `verifier(external)`, not followed by a word // disciplines:allow-trusted (documents the construct)
/// character (`external_body` is `--no-cheating`'s).
const EXTERNAL: &[&str] = &["verifier::external", "verifier(external"]; // disciplines:allow-trusted (pattern definition)

/// One finding: 1-based line number and the line.
#[derive(Debug, PartialEq, Eq)]
pub struct Hit {
    pub line: usize,
    pub text: String,
}

/// The lines of `text` where `#[verifier::external]` starts and carries no // disciplines:allow-trusted (documents the construct)
/// marker with a reason, found across the whole file (comments, whitespace
/// and line breaks ignored, `r#` dropped, as Verus reads the attribute). A
/// marker without a reason is itself a hit.
#[must_use]
pub fn scan(text: &str) -> Vec<Hit> {
    let lines: Vec<&str> = text.lines().collect();
    let (flat, line_of) = flatten(text);
    let mut hit_lines: Vec<usize> = external_at(&flat)
        .into_iter()
        .map(|at| line_of[at])
        .filter(|&n| {
            !lines
                .get(n)
                .is_some_and(|l| crate::stubs::marked_with_reason(l, MARKER))
        })
        .collect();
    hit_lines.extend(lines.iter().enumerate().filter_map(|(n, l)| {
        (l.contains(MARKER) && !crate::stubs::marked_with_reason(l, MARKER)).then_some(n)
    }));
    hit_lines.sort_unstable();
    hit_lines.dedup();
    hit_lines
        .into_iter()
        .map(|n| Hit {
            line: n + 1,
            text: lines.get(n).map_or("", |l| l.trim()).to_string(),
        })
        .collect()
}

/// Whether `line` names `verifier::external` (or `verifier(external)`), // disciplines:allow-trusted (documents the construct)
/// as [`scan`] reads it.
#[must_use]
pub fn is_external(line: &str) -> bool {
    !external_at(&flatten(line).0).is_empty()
}

/// Where [`EXTERNAL`] starts in flattened text, not followed by a word
/// character (`external_body` is `--no-cheating`'s).
fn external_at(flat: &str) -> Vec<usize> {
    EXTERNAL
        .iter()
        .flat_map(|p| {
            flat.match_indices(p).filter_map(|(at, _)| {
                let next = flat[at + p.len()..].chars().next();
                (!next.is_some_and(|c| c.is_alphanumeric() || c == '_')).then_some(at)
            })
        })
        .collect()
}

/// `text` without comments, whitespace or raw-identifier prefixes, and the
/// 0-based line each kept byte came from.
fn flatten(text: &str) -> (String, Vec<usize>) {
    let (mut flat, mut line_of) = (String::new(), Vec::new());
    let (mut line, mut chars) = (0usize, text.chars().peekable());
    while let Some(c) = chars.next() {
        match c {
            '\n' => line += 1,
            '/' if chars.peek() == Some(&'/') => {
                for d in chars.by_ref() {
                    if d == '\n' {
                        line += 1;
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut last = ' ';
                for d in chars.by_ref() {
                    if d == '\n' {
                        line += 1;
                    }
                    if last == '*' && d == '/' {
                        break;
                    }
                    last = d;
                }
            }
            c if c.is_whitespace() => {}
            'r' if chars.peek() == Some(&'#')
                && !flat.ends_with(|p: char| p.is_alphanumeric() || p == '_') =>
            {
                chars.next();
            }
            c => {
                for _ in 0..c.len_utf8() {
                    line_of.push(line);
                }
                flat.push(c);
            }
        }
    }
    (flat, line_of)
}

/// A token of Rust source: an identifier, or one punctuation character,
/// with its 0-based line. Comments, whitespace and literals are dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Token {
    line: usize,
    text: String,
}

/// The identifier and punctuation tokens of `text`, comments (nested block
/// ones included), string, byte-string, raw-string and char literals
/// skipped; `r#ident` is read as `ident`.
fn tokens(text: &str) -> Vec<Token> {
    let chars: Vec<char> = text.chars().collect();
    let (mut out, mut line, mut i) = (Vec::new(), 0usize, 0usize);
    let at = |i: usize| chars.get(i).copied().unwrap_or('\0');
    while i < chars.len() {
        let c = chars[i];
        if c == '\n' {
            line += 1;
            i += 1;
        } else if c.is_whitespace() {
            i += 1;
        } else if c == '/' && at(i + 1) == '/' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && at(i + 1) == '*' {
            let mut depth = 0usize;
            while i < chars.len() {
                if chars[i] == '/' && at(i + 1) == '*' {
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && at(i + 1) == '/' {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    line += usize::from(chars[i] == '\n');
                    i += 1;
                }
            }
        } else if let Some(end) = raw_string_end(&chars, i) {
            line += chars[i..end].iter().filter(|&&c| c == '\n').count();
            i = end;
        } else if c == '"' || (matches!(c, 'b' | 'c') && at(i + 1) == '"') {
            i += if c == '"' { 1 } else { 2 };
            while i < chars.len() && chars[i] != '"' {
                i += escape_or_char(&chars, i, &mut line);
            }
            i += 1;
        } else if c == '\'' && (at(i + 1) == '\\' || at(i + 2) == '\'') {
            // A char literal; `'a` without a closing quote is a lifetime.
            i += 1;
            while i < chars.len() && chars[i] != '\'' {
                i += escape_or_char(&chars, i, &mut line);
            }
            i += 1;
        } else if c.is_alphanumeric() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            if word == "r" && at(i) == '#' && (at(i + 1).is_alphabetic() || at(i + 1) == '_') {
                i += 1; // `r#ident`: the identifier follows
            } else {
                out.push(Token { line, text: word });
            }
        } else {
            out.push(Token {
                line,
                text: c.to_string(),
            });
            i += 1;
        }
    }
    out
}

/// How far one character of a literal's body reaches: two for an escape,
/// counting the newline a `\` line continuation skips.
fn escape_or_char(chars: &[char], i: usize, line: &mut usize) -> usize {
    if chars[i] == '\\' {
        *line += usize::from(chars.get(i + 1) == Some(&'\n'));
        2
    } else {
        *line += usize::from(chars[i] == '\n');
        1
    }
}

/// Where a raw string (`r"…"`, `r#"…"#`, `br"…"`, `cr"…"`) starting at `i`
/// ends.
fn raw_string_end(chars: &[char], i: usize) -> Option<usize> {
    let mut j = i;
    if matches!(chars.get(j), Some('b' | 'c')) {
        j += 1;
    }
    if chars.get(j) != Some(&'r') {
        return None;
    }
    j += 1;
    let hashes = chars[j..].iter().take_while(|&&c| c == '#').count();
    j += hashes;
    if chars.get(j) != Some(&'"')
        || (i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '_'))
    {
        return None;
    }
    j += 1;
    while j < chars.len() {
        if chars[j] == '"'
            && chars[j + 1..]
                .iter()
                .take(hashes)
                .filter(|&&c| c == '#')
                .count()
                == hashes
        {
            return Some(j + 1 + hashes);
        }
        j += 1;
    }
    Some(chars.len())
}

/// The names that make built code differ from verified code: configuration
/// (`cfg`, `cfg_attr`, `cfg!`, `cfg_select!`), code from another file
/// (`include!`), the build environment (`option_env!`), and `debug_assert!`
/// and its kin (a side effect in one runs only in debug builds).
const DIVERGENT: &[&str] = &[
    "cfg",
    "cfg_attr",
    "cfg_select",
    "include",
    "option_env",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
];

/// The configuration a proved crate may use, as tokens: the verified build
/// and a shipped one agree on `test` (neither is a test build).
const SAME_IN_BOTH: &[&[&str]] = &[
    &[
        "#", "!", "[", "cfg_attr", "(", "not", "(", "test", ")", ",", "no_std", ")", "]",
    ],
    &["#", "[", "cfg", "(", "test", ")", "]"],
    &["#", "[", "cfg", "(", "not", "(", "test", ")", ")", "]"],
];

/// The lines of `text` that may build differently from how Verus verified
/// them, without a marker with a reason: any `cfg`, `cfg_attr`,
/// `cfg_select`, `include` or `option_env` token outside the
/// [`SAME_IN_BOTH`] forms (as a token, so a macro taking `cfg` as an
/// argument, `cfg![…]` and an alias are all seen); `env` invoked, imported
/// or named by path; and `#[path = …]`. A proved crate's source holds every
/// token it compiles: proc macros are refused, and `macro_rules!` cannot
/// assemble an identifier.
#[must_use]
pub fn cfg_scan(text: &str) -> Vec<Hit> {
    let lines: Vec<&str> = text.lines().collect();
    let toks = tokens(text);
    let word = |k: usize| toks.get(k).map_or("", |t| t.text.as_str());
    let allowed = |k: usize| {
        SAME_IN_BOTH.iter().any(|form| {
            let pos = form.iter().position(|w| *w == word(k)).unwrap_or(0);
            k >= pos
                && form
                    .iter()
                    .enumerate()
                    .all(|(j, w)| word(k - pos + j) == *w)
        })
    };
    let mut in_use = false;
    let mut hit_lines = Vec::new();
    for (k, t) in toks.iter().enumerate() {
        let w = t.text.as_str();
        match w {
            "use" => in_use = true,
            ";" => in_use = false,
            _ => {}
        }
        let divergent = (DIVERGENT.contains(&w) && !allowed(k))
            || (w == "env"
                && (word(k + 1) == "!"
                    || (word(k.wrapping_sub(1)) == ":" && word(k + 1) != "(")
                    || in_use))
            || (w == "path" && word(k.wrapping_sub(1)) == "[" && word(k + 1) == "=");
        if divergent {
            hit_lines.push(t.line);
        }
    }
    hit_lines.retain(|&n| {
        !lines
            .get(n)
            .is_some_and(|l| crate::stubs::marked_with_reason(l, MARKER))
    });
    hit_lines.sort_unstable();
    hit_lines.dedup();
    hit_lines
        .into_iter()
        .map(|n| Hit {
            line: n + 1,
            text: lines.get(n).map_or("", |l| l.trim()).to_string(),
        })
        .collect()
}

/// Whether a line, with strings and comments stripped, leads into the item
/// below it: a comment-only line; attributes only (`#[…]`, each closed,
/// nothing after the last), or one left open; or the rest of an attribute
/// (path segments, then `]`). A one-line item after an attribute
/// (`#[derive(…)] struct X;`) does not lead in.
#[must_use]
pub fn leads_in(line: &str) -> bool {
    let toks = tokens(line);
    if toks.is_empty() {
        return line.trim_start().starts_with("//") || line.trim_start().starts_with("/*");
    }
    let words: Vec<&str> = toks.iter().map(|t| t.text.as_str()).collect();
    if words[0] == "#" {
        return attributes_only(&words);
    }
    words
        .iter()
        .all(|w| *w == ":" || *w == "]" || w.chars().all(|c| c.is_alphanumeric() || c == '_'))
        && words.last() == Some(&"]")
}

/// Whether `words` are attributes and nothing else, the last possibly left
/// open (it continues on the next line).
fn attributes_only(words: &[&str]) -> bool {
    let mut k = 0;
    while words.get(k) == Some(&"#") {
        k += 1;
        if words.get(k) == Some(&"!") {
            k += 1;
        }
        if words.get(k) != Some(&"[") {
            return false;
        }
        let mut depth = 0usize;
        loop {
            match words.get(k) {
                None => return true,
                Some(&("[" | "(" | "{")) => depth += 1,
                Some(&("]" | ")" | "}")) => depth = depth.saturating_sub(1),
                _ => {}
            }
            k += 1;
            if depth == 0 {
                break;
            }
        }
    }
    k == words.len()
}

/// What the gate finds by text in a Verus package before the prover runs,
/// in each of `files` (its Rust sources, relative to the root): lines
/// [`scan`] finds, and lines [`cfg_scan`] finds, each as `<file>:<line>:
/// <text>`. `read` reads a file relative to the root.
///
/// # Errors
/// A file `read` cannot read.
pub fn package_hits(
    files: &[String],
    read: &dyn Fn(&str) -> Result<String, String>,
) -> Result<(Vec<String>, Vec<String>), String> {
    let (mut trusted, mut configuration) = (Vec::new(), Vec::new());
    for file in files {
        let text = read(file)?;
        let label = |h: Hit| format!("{file}:{}: {}", h.line, h.text);
        trusted.extend(scan(&text).into_iter().map(label));
        configuration.extend(cfg_scan(&text).into_iter().map(label));
    }
    Ok((trusted, configuration))
}
