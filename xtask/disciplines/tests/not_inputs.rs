// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::PathBuf;

use xtask::cache::not_inputs::{check, from_manifest, from_metadata};

fn paths(v: &[&str]) -> Vec<PathBuf> {
    v.iter().map(PathBuf::from).collect()
}

const TABLE: &str = "[workspace.metadata.disciplines]\n";

#[test]
fn a_manifest_without_not_inputs_lists_none() {
    assert_eq!(from_manifest("[package]\nname = \"a\"\n"), Ok(vec![]));
}

#[test]
fn entries_are_read_sorted_from_a_multi_line_array() {
    let text = format!("{TABLE}not_inputs = [\n  \"gen\",\n  \"fuzz/corpus/\",\n]\n");
    assert_eq!(from_manifest(&text), Ok(paths(&["fuzz/corpus", "gen"])));
}

#[test]
fn invalid_entries_are_errors() {
    for bad in ["../x", "a/../b", "/abs", "fuzz/*", "a?", ".", "", "./a"] {
        let text = format!("{TABLE}not_inputs = [\"{bad}\"]\n");
        let Err(err) = from_manifest(&text) else {
            panic!("{bad} accepted")
        };
        assert!(err.starts_with("not_inputs"), "{bad}: {err}");
    }
}

#[test]
fn a_bracket_inside_an_entry_is_refused_by_preflight() {
    // The text scan ends the array at the first `]`, so the key sees no
    // list (more inputs, never fewer); preflight refuses the entry.
    let text = format!("{TABLE}not_inputs = [\"[ab]\"]\n");
    assert_eq!(from_manifest(&text), Ok(vec![]));
    let json = r#"{"metadata":{"disciplines":{"not_inputs":["[ab]"]}}}"#;
    assert!(check(json, &text).unwrap_err().starts_with("not_inputs"));
}

#[test]
fn a_plain_string_or_a_second_assignment_is_an_error() {
    assert!(from_manifest(&format!("{TABLE}not_inputs = \"gen\"\n")).is_err());
    let twice = format!("{TABLE}not_inputs = [\"a\"]\n[x]\nnot_inputs = [\"b\"]\n");
    assert!(from_manifest(&twice).is_err());
}

#[test]
fn metadata_reads_the_workspace_table() {
    let json = r#"{"metadata":{"disciplines":{"not_inputs":["gen","fuzz/corpus"]}}}"#;
    assert_eq!(from_metadata(json), Ok(paths(&["fuzz/corpus", "gen"])));
    assert_eq!(from_metadata(r#"{"metadata":null}"#), Ok(vec![]));
    let wrong = r#"{"metadata":{"disciplines":{"not_inputs":"gen"}}}"#;
    assert!(from_metadata(wrong).unwrap_err().starts_with("not_inputs"));
}

#[test]
fn check_accepts_agreement_and_refuses_a_misplaced_list() {
    let json = r#"{"metadata":{"disciplines":{"not_inputs":["gen"]}}}"#;
    assert_eq!(
        check(json, &format!("{TABLE}not_inputs = [\"gen\"]\n")),
        Ok(())
    );
    // Under another table: cargo metadata does not see it, the key would.
    let misplaced = "[package.metadata.x]\nnot_inputs = [\"gen\"]\n";
    let err = check(r#"{"metadata":null}"#, misplaced).unwrap_err();
    assert!(err.contains("[workspace.metadata.disciplines]"), "{err}");
}

#[test]
fn commented_out_lines_are_not_assignments() {
    let text = format!(
        "{TABLE}# not_inputs = [\"x\"]\n  # not_inputs = [\"y\"]\nnot_inputs = [\"gen\"]\n"
    );
    assert_eq!(from_manifest(&text), Ok(paths(&["gen"])));
}
