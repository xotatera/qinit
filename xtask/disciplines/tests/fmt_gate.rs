// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

/// A fmt skip registered during a migration must not outlive it.
#[test]
fn fmt_is_not_blocked() {
    assert_eq!(xtask::fmt_gate::BLOCKED, None);
}

#[test]
fn verusfmt_sees_every_file_naming_the_macro() {
    use xtask::fmt_gate::invokes_verus;
    assert!(invokes_verus(
        "use vstd::prelude::*;\nverus! {\nfn f() {}\n}\n"
    ));
    assert!(invokes_verus("vstd::prelude::verus! {\nfn f() {}\n}\n"));
    assert!(invokes_verus("//! code inside `verus!` is verified\n"));
    assert!(!invokes_verus("fn plain() {}\n"));
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
