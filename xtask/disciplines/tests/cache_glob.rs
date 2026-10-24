// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use xtask::cache::glob::{matches, matches_counting};

#[test]
fn double_star_matches_any_depth_including_none() {
    for path in ["a.rs", "src/a.rs", "a/b/c.rs", "ö/ü.rs"] {
        assert!(matches("**/*.rs", path), "{path}");
    }
    for path in ["a.rsx", "a/b.txt", "rs", "a/.rs/b"] {
        assert!(!matches("**/*.rs", path), "{path}");
    }
}

#[test]
fn literal_and_single_star_stay_within_their_segment() {
    assert!(matches("Cargo.toml", "Cargo.toml"));
    assert!(!matches("Cargo.toml", "crates/a/Cargo.toml"));
    assert!(matches("**/Cargo.toml", "crates/a/Cargo.toml"));
    assert!(matches(
        "gates/duplication-baseline.txt",
        "gates/duplication-baseline.txt"
    ));
    assert!(!matches("*.rs", "src/a.rs"));
    assert!(matches("src/*_test.rs", "src/a_test.rs"));
    assert!(!matches("src/*_test.rs", "src/a_test.rs.bak"));
}

#[test]
fn edge_cases() {
    for path in ["src", "src/a", "src/a/b"] {
        assert!(matches("src/**", path), "{path}");
    }
    assert!(!matches("src/**", "srcx"));
    assert!(matches("**/**/*.rs", "a.rs"));
    assert!(matches("**/**/*.rs", "x/y/a.rs"));
    assert!(matches("*", ""));
    assert!(matches("a*", "a"));
    assert!(matches("a*b*c", "abc"));
    assert!(matches("a*b*c", "aXbYc"));
    assert!(!matches("a*b*c", "acb"));
    assert!(matches("ö*", "öü"));
    assert!(matches("", ""));
    assert!(!matches("", "a"));
}

/// The match, checked to take steps polynomial in the inputs: the table's
/// cells times the longest segment comparison, generously. Exponential
/// backtracking on these inputs would take billions. Counted, not timed:
/// a gate step can be paused or loaded.
fn fast(pattern: &str, path: &str) -> bool {
    let (got, steps) = matches_counting(pattern, path);
    let (p, n) = (pattern.len() as u64 + 1, path.len() as u64 + 1);
    let bound = 4 * p * n * p.max(n);
    assert!(steps <= bound, "{pattern}: {steps} steps, bound {bound}");
    got
}

#[test]
fn pathological_patterns_do_not_backtrack_exponentially() {
    assert!(!fast("a*a*a*a*a*a*a*a*b", &"a".repeat(60)));
    let deep = format!("{}y", "d/".repeat(39));
    assert!(!fast("**/**/**/**/**/x", &deep));
    assert!(!fast(
        "**/a*a*a*a*a*b/**/x",
        &format!("{}/x", "a".repeat(60))
    ));
}

#[test]
fn multibyte_names_match_by_whole_chars() {
    assert!(matches("a*ü.rs", "aéü.rs"));
    assert!(matches("*é*", "xéy"));
    assert!(!matches("a*é", "aü"));
    assert!(matches("ü*", "ü"));
}
