// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use xtask::trusted::{is_external, scan};

// disciplines:allow-trusted (every line below quotes a pattern under test)
const HITS: &[&str] = &[
    "#[verifier::external]",  // disciplines:allow-trusted (test input)
    "#[verifier(external)]",  // disciplines:allow-trusted (test input)
    "#[verifier::external ]", // disciplines:allow-trusted (test input)
    "#[cfg_attr(verus_keep_ghost, verifier::external)]", // disciplines:allow-trusted (test input)
    "#[verifier :: external]", // disciplines:allow-trusted (test input)
    "#[verifier( external )]", // disciplines:allow-trusted (test input)
];

#[test]
fn every_pattern_hits() {
    for line in HITS {
        let quoted = line.split(" //").next().unwrap();
        assert!(is_external(quoted), "missed: {quoted}");
    }
}

#[test]
fn near_misses_pass() {
    for line in [
        "#[verifier::external_body]",
        "#[verifier::external_fn_specification]",
        "#[verifier(external_body)]",
        "fn external() {}",
        "pub fn admit(x: u8) {}",
    ] {
        assert!(!is_external(line), "false positive: {line}");
    }
}

#[test]
fn a_marker_with_a_reason_accepts_its_line_only() {
    let text = "ok\n#[verifier::external] // disciplines:allow-trusted (Send impl)\n#[verifier::external]\n"; // disciplines:allow-trusted (test input)
    let hits = scan(text);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].line, 3);
}

#[test]
fn a_marker_without_a_reason_is_a_hit() {
    for text in [
        "#[verifier::external] // disciplines:allow-trusted", // disciplines:allow-trusted (test input)
        "#[verifier::external] // disciplines:allow-trusted ()", // disciplines:allow-trusted (test input)
        "fine // disciplines:allow-trusted", // disciplines:allow-trusted (test input)
    ] {
        assert_eq!(scan(text).len(), 1, "{text}");
    }
}

/// A copied project whose Verus entry is its root package scans this source
/// too.
#[test]
fn the_matcher_source_is_clean() {
    assert_eq!(scan(include_str!("../src/trusted.rs")), Vec::new());
}

#[test]
fn spellings_verus_accepts_are_found_across_lines() {
    for text in [
        "#[verifier::\nexternal]\nimpl T for U {}\n", // disciplines:allow-trusted (test input)
        "#[verifier:: /* x */ external]\nimpl T for U {}\n", // disciplines:allow-trusted (test input)
        "#[verifier::r#external]\nimpl T for U {}\n", // disciplines:allow-trusted (test input)
        "#[verifier // why\n  ::external]\nimpl T for U {}\n", // disciplines:allow-trusted (test input)
    ] {
        let hits = scan(text);
        assert_eq!(hits.len(), 1, "{text}");
        assert_eq!(
            hits[0].line, 1,
            "reported where the attribute starts: {text}"
        );
    }
    let marked = "#[verifier:: // disciplines:allow-trusted (Send impl)\nexternal]\n"; // disciplines:allow-trusted (test input)
    assert_eq!(scan(marked), Vec::new());
    let marked_late = "#[verifier::\nexternal] // disciplines:allow-trusted (Send impl)\n"; // disciplines:allow-trusted (test input)
    assert_eq!(
        scan(marked_late).len(),
        1,
        "the marker belongs on the first line"
    );
    assert_eq!(scan("let s = r#\"text\"#;\n"), Vec::new());
}

#[test]
fn configuration_predicates_may_name_only_test() {
    use xtask::trusted::cfg_scan;
    for ok in [
        "#![cfg_attr(not(test), no_std)]",
        "#[cfg(test)]\nmod tests {}",
        "#[cfg(not(test))]\nfn f() {}",
        "fn mycfg(x: u8) {}\nlet c = notcfg!(x);",
        "let s = \"cfg(feature) include!(x) env!(Y)\";\nlet c = '\"';",
        "// cfg(feature = \"x\")\n/* include!(\"y\") /* nested */ */\nfn f() {}",
        "let r = r#\"cfg(feature)\"#;\nlet env = 3;\nlet b = br\"include\";",
        "#[doc = \"cfg\"]\nfn f<'a>(x: &'a u8) {}",
    ] {
        assert_eq!(cfg_scan(ok), Vec::new(), "{ok}");
    }
    for (bad, line) in [
        ("#[cfg(feature = \"fast\")]\nfn f() {}", 1),
        ("#[cfg(verus_keep_ghost)]\nimpl A for B {}", 1),
        ("#[cfg_attr(debug_assertions, inline)]", 1),
        ("fn f() -> bool {\n    cfg!(debug_assertions)\n}", 2),
        ("#[cfg(\n    not(verus_keep_ghost)\n)]", 1),
        ("#[cfg( /* hidden */ target_os = \"linux\")]", 1),
        ("#[cfg_attr(test, cfg(feature = \"x\"))]", 1),
        ("#[cfg(all(test, feature = \"x\"))]", 1),
        (
            "macro_rules! gate { ($c:ident, $i:item) => { #[$c(feature = \"x\")] $i }; }\ngate!(cfg, pub fn hidden() {});",
            2,
        ),
        ("fn f() -> bool { cfg![feature = \"x\"] }", 1),
        ("fn f() -> bool { cfg!{debug_assertions} }", 1),
        ("cfg_select! { feature = \"x\" => { fn f() {} } }", 1),
        ("include![\"part.inc\"];", 1),
        ("use core::include as inc;\ninc!(\"part.inc\");", 1),
        ("const X: &str = env!(\"X\");", 1),
        ("use core::{env as e};", 1),
        ("const X: Option<&str> = option_env!(\"X\");", 1),
        ("#[path = \"elsewhere.rs\"]\nmod m;", 1),
        ("r#cfg!(feature = \"x\");", 1),
        (
            "skip!(cr#\"\"\"#);\n#[cfg(debug_assertions)]\nfn one() {}",
            2,
        ),
        ("skip!(cr\"\\\");\n#[cfg(debug_assertions)]\nfn one() {}", 2),
        ("let n = c\"x\";\n#[cfg(feature = \"y\")]", 2),
        (
            "fn f() { let mut x = 6; debug_assert!({ x = 1; true }); }",
            1,
        ),
        ("fn f() { debug_assert_eq!(1, 1); }", 1),
    ] {
        let hits = cfg_scan(bad);
        assert_eq!(hits.len(), 1, "{bad}: {hits:?}");
        assert_eq!(hits[0].line, line, "{bad}");
    }
    let marked = "#[cfg(feature = \"fast\")] // disciplines:allow-trusted (same code either way)";
    assert_eq!(cfg_scan(marked), Vec::new());
    // A `\` line continuation inside a string keeps the lines counted: the
    // marker on the string's last line does not reach the next line.
    let drift =
        "let s = \"a\\\nb\"; // disciplines:allow-trusted (string tail)\n#[cfg(feature = \"y\")]\n";
    let hits = cfg_scan(drift);
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].line, 3);
    assert_eq!(
        cfg_scan("fn f() { Self::env(); }"),
        Vec::new(),
        "a method named env"
    );
}

#[test]
fn a_line_leads_into_an_item_only_as_a_comment_or_an_attribute() {
    use xtask::trusted::leads_in;
    for yes in [
        "// note",
        "/* note */",
        "#[verifier::external]",
        "#[verifier::",
        "external]",
        "  verifier::external]",
    ] {
        assert!(leads_in(yes), "{yes}");
    }
    for yes in ["#[inline] #[must_use]", "#[doc = \"x\""] {
        assert!(leads_in(yes), "{yes}");
    }
    for no in [
        "#[derive(Clone, Copy)] pub struct Unrelated; // marker",
        "#[inline] fn f() {}",
        "pub fn helper() -> u32 { 0 } // marker",
        "mark!(external,",
        "impl A for S { fn one(&self) -> u32 { 1 } },",
        "pub fn a() -> &'static str { \"(//\" }",
        "",
        "x",
    ] {
        assert!(!leads_in(no), "{no}");
    }
}

#[test]
fn a_package_s_files_are_scanned() {
    use std::collections::BTreeMap;
    let files: BTreeMap<&str, &str> = BTreeMap::from([
        ("p/src/lib.rs", "#![cfg_attr(not(test), no_std)]\nmod m;\n"),
        (
            "p/src/m.rs",
            "#[cfg(feature = \"x\")]\n#[verifier::external]\nimpl A for B {}\n",
        ), // disciplines:allow-trusted (test input)
    ]);
    let read = |f: &str| {
        files
            .get(f)
            .map(|t| (*t).to_string())
            .ok_or_else(|| format!("{f}: missing"))
    };
    let all = ["p/src/lib.rs".to_string(), "p/src/m.rs".to_string()];
    let (trusted, cfgs) = xtask::trusted::package_hits(&all, &read).unwrap();
    assert_eq!(cfgs, ["p/src/m.rs:1: #[cfg(feature = \"x\")]"]);
    assert_eq!(trusted, ["p/src/m.rs:2: #[verifier::external]"]); // disciplines:allow-trusted (test input)
    assert_eq!(
        xtask::trusted::package_hits(&["p/src/gone.rs".to_string()], &read).unwrap_err(),
        "p/src/gone.rs: missing"
    );
}
