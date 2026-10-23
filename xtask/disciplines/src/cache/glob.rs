// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Glob matching for gate input declarations. Paths are relative and
//! `/`-separated:
//! - `**` matches any number of path segments, including none;
//! - `*` matches within one segment;
//! - everything else is literal.

#[must_use]
pub fn matches(pattern: &str, path: &str) -> bool {
    matches_counting(pattern, path).0
}

/// [`matches`], with the steps it took: table cells plus byte comparisons
/// within segments. Bounded by a polynomial in the inputs' lengths, which
/// tests check instead of timing the match.
#[must_use]
pub fn matches_counting(pattern: &str, path: &str) -> (bool, u64) {
    let mut pattern: Vec<&str> = pattern.split('/').collect();
    pattern.dedup_by(|a, b| *a == "**" && *b == "**");
    let path: Vec<&str> = path.split('/').collect();
    let mut steps = 0;
    let matched = segments(&pattern, &path, &mut steps);
    (matched, steps)
}

/// Dynamic programming over (pattern index, path index): `ok[i][j]` is
/// whether `pattern[i..]` matches `path[j..]`. Cost is bounded by the
/// pattern length times the path length, however many `**` there are.
fn segments(pattern: &[&str], path: &[&str], steps: &mut u64) -> bool {
    let width = path.len() + 1;
    let mut ok = vec![false; (pattern.len() + 1) * width];
    ok[pattern.len() * width + path.len()] = true;
    for i in (0..pattern.len()).rev() {
        for j in (0..=path.len()).rev() {
            *steps += 1;
            ok[i * width + j] = if pattern[i] == "**" {
                ok[(i + 1) * width + j] || (j < path.len() && ok[i * width + j + 1])
            } else {
                j < path.len() && ok[(i + 1) * width + j + 1] && segment(pattern[i], path[j], steps)
            };
        }
    }
    ok[0]
}

/// `*` within one segment: the iterative two-pointer match that remembers
/// the last `*` and retries from one byte further on. Bytes give the same
/// result as chars: `*` is ASCII, so each literal run between stars is whole
/// UTF-8 chars starting with a non-continuation byte, which can only match
/// at a char boundary; every `*` therefore covers whole chars.
fn segment(pattern: &str, name: &str, steps: &mut u64) -> bool {
    let (pattern, name) = (pattern.as_bytes(), name.as_bytes());
    let (mut p, mut n) = (0, 0);
    let mut backtrack: Option<(usize, usize)> = None;
    while n < name.len() {
        *steps += 1;
        if pattern.get(p) == Some(&b'*') {
            backtrack = Some((p, n));
            p += 1;
        } else if pattern.get(p) == Some(&name[n]) {
            p += 1;
            n += 1;
        } else if let Some((star, resume)) = backtrack {
            p = star + 1;
            n = resume + 1;
            backtrack = Some((star, resume + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}
