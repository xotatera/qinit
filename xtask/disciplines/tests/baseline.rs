// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use xtask::duplication::Group;
use xtask::duplication::baseline::{HEADER, bless, compare, parse};

fn group(keys: &[&str]) -> Group {
    Group {
        tokens: 50,
        members: keys.iter().map(|k| ((*k).to_string(), 1)).collect(),
    }
}

#[test]
fn parses_sorted_groups_with_reasons() {
    let b = parse(&format!(
        "{HEADER}a.rs::f | b.rs::g  # kept: platform twins\n\n"
    ))
    .unwrap();
    assert_eq!(
        b.get(&vec!["a.rs::f".to_string(), "b.rs::g".to_string()])
            .map(String::as_str),
        Some("kept: platform twins")
    );
}

#[test]
fn rejects_malformed_lines_with_their_number() {
    for (bad, why) in [
        ("a.rs::f | b.rs::g", "missing"),
        ("a.rs::f | b.rs::g  #   ", "empty reason"),
        ("a.rs::f  # alone", "at least two"),
        ("b.rs::g | a.rs::f  # r", "sorted"),
        ("a.rs::f | a.rs::f  # r", "sorted"),
    ] {
        let err = parse(&format!("# header\n{bad}\n")).unwrap_err();
        assert!(err.contains("line 2") && err.contains(why), "{bad}: {err}");
    }
    let err = parse("a.rs::f | b.rs::g  # r\na.rs::f | b.rs::g  # again\n").unwrap_err();
    assert!(err.contains("line 2") && err.contains("duplicate"), "{err}");
}

#[test]
fn new_groups_fail_vanished_ones_are_stale() {
    let base = parse("a.rs::f | b.rs::g  # r\nc.rs::h | d.rs::i  # r\n").unwrap();
    let current = [
        group(&["a.rs::f", "b.rs::g"]),
        group(&["e.rs::j", "f.rs::k"]),
    ];
    let diff = compare(&base, &current);
    assert_eq!(
        diff.new.iter().map(|g| g.keys()).collect::<Vec<_>>(),
        [vec!["e.rs::j".to_string(), "f.rs::k".to_string()]]
    );
    assert_eq!(
        diff.stale,
        [vec!["c.rs::h".to_string(), "d.rs::i".to_string()]]
    );
}

#[test]
fn a_shrunk_group_passes_and_is_stale() {
    let base = parse("a.rs::f | b.rs::g | c.rs::h  # r\n").unwrap();
    let current = [group(&["a.rs::f", "b.rs::g"])];
    let diff = compare(&base, &current);
    assert_eq!(diff.new.len(), 0);
    assert_eq!(diff.stale.len(), 1);
}

#[test]
fn a_grown_group_fails() {
    let base = parse("a.rs::f | b.rs::g  # r\n").unwrap();
    let current = [group(&["a.rs::f", "b.rs::g", "c.rs::h"])];
    let diff = compare(&base, &current);
    assert_eq!(diff.new.len(), 1);
}

#[test]
fn bless_only_removes_and_keeps_reasons() {
    let base =
        parse("a.rs::f | b.rs::g | c.rs::h  # shared reason\nx.rs::p | y.rs::q  # gone\n").unwrap();
    let text = bless(
        &base,
        &[
            group(&["a.rs::f", "b.rs::g"]),
            group(&["new.rs::n", "new.rs::o"]),
        ],
    );
    assert_eq!(
        text,
        format!("{HEADER}a.rs::f | b.rs::g  # shared reason\n")
    );
}

#[test]
fn rejects_a_member_listed_in_two_entries() {
    let err = parse("a.rs::f | b.rs::g  # r\na.rs::f | c.rs::h  # r\n").unwrap_err();
    assert!(
        err.contains("line 2") && err.contains("a.rs::f") && err.contains("another entry"),
        "{err}"
    );
}
