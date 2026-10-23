// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use xtask::stubs::{is_placeholder, parse_vocabulary, scan, scan_with};

// disciplines:allow-placeholder (every line below quotes a pattern under test)
const HITS: &[&str] = &[
    "// TODO: later",                    // disciplines:allow-placeholder (test input)
    "fixme",                             // disciplines:allow-placeholder (test input)
    "a hack",                            // disciplines:allow-placeholder (test input)
    "mktemp foo.XXXXXX",                 // disciplines:allow-placeholder (test input)
    "todo!()",                           // disciplines:allow-placeholder (test input)
    "unimplemented!()",                  // disciplines:allow-placeholder (test input)
    "a STUB here",                       // disciplines:allow-placeholder (test input)
    "in a real implementation we would", // disciplines:allow-placeholder (test input)
    "a placeholder value",               // disciplines:allow-placeholder (test input)
    "fine For now",                      // disciplines:allow-placeholder (test input)
    "not yet implemented",               // disciplines:allow-placeholder (test input)
    "/// Temporary: drop me",            // disciplines:allow-placeholder (test input)
    "Simplified: no retries",            // disciplines:allow-placeholder (test input)
    "that is a follow-up",               // disciplines:allow-placeholder (test input)
    "<placeholder-scan>",                // disciplines:allow-placeholder (test input)
];

#[test]
fn every_pattern_hits() {
    for line in HITS {
        let quoted = line.split(" //").next().unwrap();
        assert!(is_placeholder(quoted), "missed: {quoted}");
    }
}

#[test]
fn near_misses_pass() {
    for line in [
        "stubborn",
        "placeholders_are_words",
        "formatted",
        "fork now",
        "a temporary file",
        "simplified",
        "fully implemented",
    ] {
        assert!(!is_placeholder(line), "false positive: {line}");
    }
}

#[test]
fn a_marker_with_a_reason_exempts_its_line_only() {
    let text = "ok\nTODO x // disciplines:allow-placeholder (quoted)\nTODO y\n"; // disciplines:allow-placeholder (test input)
    let hits = scan(text);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].line, 3);
}

#[test]
fn a_marker_without_a_reason_is_a_hit() {
    for text in [
        "TODO // disciplines:allow-placeholder", // disciplines:allow-placeholder (test input)
        "TODO // disciplines:allow-placeholder ()", // disciplines:allow-placeholder (test input)
        "fine // disciplines:allow-placeholder", // disciplines:allow-placeholder (test input)
    ] {
        assert_eq!(scan(text).len(), 1, "{text}");
    }
}

fn terms(list: &[&str]) -> Vec<String> {
    list.iter().map(ToString::to_string).collect()
}

#[test]
fn a_vocabulary_term_blanks_its_word_only() {
    let t = terms(&["stub"]); // disciplines:allow-placeholder (test input)
    let mut used = [false];
    for line in [
        "sb-test-stub",  // disciplines:allow-placeholder (test input)
        "my-guest-stub", // disciplines:allow-placeholder (test input)
        "a stub double", // disciplines:allow-placeholder (test input)
    ] {
        let quoted = line.split(" //").next().unwrap();
        assert!(scan_with(quoted, &t, &mut used).is_empty(), "{quoted}");
    }
    assert!(used[0]);
    // Another pattern on the same line still hits.
    let line = "a stub TODO"; // disciplines:allow-placeholder (test input)
    assert_eq!(scan_with(line, &t, &mut used).len(), 1);
}

#[test]
fn a_vocabulary_term_matches_its_exact_case() {
    let t = terms(&["NothingToDo"]); // disciplines:allow-placeholder (test input)
    let mut used = [false];
    let line = "Event::NothingToDo =>"; // disciplines:allow-placeholder (test input)
    assert_eq!(scan_with(line, &t, &mut used), vec![]);
    assert!(used[0]);
    let line = "// nothingtodo"; // disciplines:allow-placeholder (test input)
    assert_eq!(scan_with(line, &t, &mut used).len(), 1);
    let line = "MyNothingToDo"; // disciplines:allow-placeholder (test input)
    assert_eq!(scan_with(line, &t, &mut used).len(), 1);
}

#[test]
fn a_term_counts_only_where_it_exempts_the_hit() {
    let t = terms(&["Event", "NothingToDo"]); // disciplines:allow-placeholder (test input)
    let mut used = [false, false];
    let line = "Event::NothingToDo =>"; // disciplines:allow-placeholder (test input)
    assert_eq!(scan_with(line, &t, &mut used), vec![]);
    assert_eq!(used, [false, true]);
    let t = terms(&["Foo"]);
    let mut used = [false];
    let line = "Foo TODO"; // disciplines:allow-placeholder (test input)
    assert_eq!(scan_with(line, &t, &mut used).len(), 1);
    assert!(!used[0]);
    // `stub` and `x.stub` share a hit: neither alone is needed, both count. // disciplines:allow-placeholder (test input)
    let t = terms(&["NothingToDo", "stub", "x.stub"]); // disciplines:allow-placeholder (test input)
    let mut used = [false; 3];
    let line = "NothingToDo x.stub"; // disciplines:allow-placeholder (test input)
    assert_eq!(scan_with(line, &t, &mut used), vec![]);
    assert_eq!(used, [true; 3]);
}

#[test]
fn a_term_on_a_clean_line_is_unused() {
    let t = terms(&["stub"]); // disciplines:allow-placeholder (test input)
    let mut used = [false];
    assert_eq!(scan_with("stubborn and clean", &t, &mut used), vec![]);
    assert!(!used[0]);
}

#[test]
fn vocabulary_lines_need_a_reason() {
    let text = "# comment\n\nstub  # test doubles\nNothingToDo # an event\n"; // disciplines:allow-placeholder (test input)
    assert_eq!(
        parse_vocabulary(text),
        Ok(terms(&["stub", "NothingToDo"])) // disciplines:allow-placeholder (test input)
    );
    let malformed = ["stub", "stub  #", "stub  #  ", "two words # r"]; // disciplines:allow-placeholder (test input)
    for bad in malformed {
        assert!(parse_vocabulary(bad).is_err(), "{bad}");
    }
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("xtask-stubs-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    assert!(
        xtask::git::command()
            .args(["init", "-q"])
            .current_dir(&dir)
            .status()
            .unwrap()
            .success()
    );
    dir
}

#[test]
fn the_gate_reads_the_vocabulary_and_fails_a_stale_term() {
    let dir = scratch("vocab");
    std::fs::create_dir_all(dir.join("gates")).unwrap();
    std::fs::write(dir.join("a.rs"), "struct GuestStub; // a stub double\n").unwrap(); // disciplines:allow-placeholder (test input)
    let hit = xtask::gates::stub_scan(&dir);
    std::fs::write(
        dir.join("gates/scan-vocabulary.txt"),
        "stub  # test doubles\n", // disciplines:allow-placeholder (test input)
    )
    .unwrap();
    let clean = xtask::gates::stub_scan(&dir);
    std::fs::write(
        dir.join("gates/scan-vocabulary.txt"),
        "stub  # test doubles\nNothingToDo  # gone\n", // disciplines:allow-placeholder (test input)
    )
    .unwrap();
    let stale = xtask::gates::stub_scan(&dir);
    std::fs::write(dir.join("gates/scan-vocabulary.txt"), "stub\n").unwrap(); // disciplines:allow-placeholder (test input)
    let malformed = xtask::gates::stub_scan(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(hit.unwrap_err().contains("a.rs:1"));
    assert_eq!(clean, Ok(()));
    let stale = stale.unwrap_err();
    assert!(stale.contains("stale term `NothingToDo`"), "{stale}"); // disciplines:allow-placeholder (test input)
    assert!(!stale.contains("`stub`"), "{stale}"); // disciplines:allow-placeholder (test input)
    assert!(
        malformed
            .unwrap_err()
            .contains("expected `<term>  # <reason>`")
    );
}

#[test]
fn the_repository_root_is_the_git_toplevel_above_a_nested_runner() {
    let dir = scratch("toplevel");
    std::fs::create_dir_all(dir.join("tools/xtask")).unwrap();
    let nested = xtask::toplevel(&dir.join("tools/xtask"));
    let outside = xtask::toplevel(std::path::Path::new("/"));
    let found = nested.unwrap().canonicalize().unwrap();
    let expected = dir.canonicalize().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(found, expected);
    assert!(outside.is_err());
}
