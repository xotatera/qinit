// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

/// A fmt skip registered during a migration must not outlive it.
#[test]
fn fmt_is_not_blocked() {
    assert_eq!(xtask::fmt_gate::BLOCKED, None);
}

#[test]
fn verusfmt_sees_every_file_invoking_the_macro() {
    use xtask::fmt_gate::invokes_verus;
    assert!(invokes_verus(
        "use vstd::prelude::*;\nverus! {\nfn f() {}\n}\n"
    ));
    assert!(invokes_verus("vstd::prelude::verus! {\nfn f() {}\n}\n"));
    assert!(invokes_verus("mod m {\n    verus! {\n    }\n}\n"));
    assert!(invokes_verus("r#verus! {\nfn f() {}\n}\n"));
    assert!(!invokes_verus("fn plain() {}\n"));
}

/// Read from the parsed source: a mention in a comment or a string is not
/// an invocation, so it does not make verusfmt a requirement.
#[test]
fn a_mention_in_a_comment_or_string_is_not_an_invocation() {
    use xtask::fmt_gate::invokes_verus;
    assert!(!invokes_verus("//! code inside `verus!` is verified\n"));
    assert!(!invokes_verus("/* verus! { } */\nfn f() {}\n"));
    assert!(!invokes_verus(
        "const HINT: &str = \"verus! {\";\nfn f() {}\n"
    ));
    assert!(!invokes_verus("macro_rules! verus { () => {}; }\n"));
}

/// A file the parser cannot read whole still goes to verusfmt when it names
/// the macro: fail closed.
#[test]
fn an_unparsable_file_naming_the_macro_counts_as_invoking_it() {
    use xtask::fmt_gate::invokes_verus;
    assert!(invokes_verus("fn broken( {\nverus! {}\n"));
}

#[test]
fn an_indented_verus_block_is_found() {
    use xtask::fmt_gate::indented_verus;
    assert_eq!(
        indented_verus("verus! {\nfn f() {}\n}\n"),
        Vec::<usize>::new()
    );
    assert_eq!(indented_verus("mod m {\n    verus! {\n    }\n}\n"), vec![2]);
    assert_eq!(
        indented_verus("mod m {\n    vstd::prelude::verus! {}\n}\n"),
        vec![2]
    );
    assert_eq!(
        indented_verus("    // code inside verus! is verified\n    let s = \"x::verus! {\";\n"),
        Vec::<usize>::new()
    );
}

/// A file tree-sitter cannot read whole (valid edition-2024 Rust its grammar
/// rejects) keeps the indented check: the line rule, failing closed.
#[test]
fn an_unparsable_file_still_has_its_indented_block_found() {
    use xtask::fmt_gate::{indented_verus, invokes_verus};
    let text =
        "unsafe extern \"C\" { pub safe fn abs(x: i32) -> i32; }\nmod m {\n    verus! {}\n}\n";
    assert!(invokes_verus(text));
    assert_eq!(indented_verus(text), vec![3]);
}

/// A `verus!` inside another macro's body is a token tree, not a parsed
/// invocation; it still counts, and an indented one is still found.
#[test]
fn a_verus_block_inside_another_macro_counts() {
    use xtask::fmt_gate::{indented_verus, invokes_verus};
    let nested = "cfg_if::cfg_if! {\n    if #[cfg(verus_keep_ghost)] {\n        verus! {\n        }\n    }\n}\n";
    assert!(invokes_verus(nested));
    assert_eq!(indented_verus(nested), vec![3]);
    let rules = "macro_rules! m {\n    () => { vstd::prelude::verus! {} };\n}\n";
    assert!(invokes_verus(rules));
    assert!(!invokes_verus(
        "cfg_if::cfg_if! { if #[cfg(x)] { fn verus() {} } }\n"
    ));
}
