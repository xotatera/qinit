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
