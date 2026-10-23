// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a Verus crate trusts, judged from its logs. The fixtures under
//! `fixtures/vir/<case>/` are real Verus 0.2026.10.04 logs of honest crates
//! and of disguised external impls, trimmed to what the judge reads: every `external_fn` entry (the log repeats its dependencies'),
//! the crate's declarations cut to their `:body`, its `impl_names` lines,
//! and under `root/` the sources those spans name, each with `.txt`
//! appended so no Rust tool of a copied project reads them.
//! `metadata.json` is the disguise workspace's `cargo metadata`, trimmed
//! to packages, targets'
//! kinds and the resolve graph; `dis-k` depends on `fakederive`, a
//! proc-macro crate whose derive `PartialEq` forges the standard one.
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use xtask::vir_trust::{self, Outcome};

fn case(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/vir")
        .join(name)
}

/// Judges a case; `strip` removes every marker from the sources first.
fn judge(name: &str, krate: &str, proc_macros: &[&str], strip: bool) -> Result<Outcome, String> {
    let dir = case(name);
    let vir = std::fs::read_to_string(dir.join("crate.vir")).unwrap();
    let names = std::fs::read_to_string(dir.join("crate.impl_names")).unwrap();
    let read = |file: &str, n: usize| {
        let text = std::fs::read_to_string(dir.join("root").join(format!("{file}.txt"))).ok()?;
        let line = text.lines().nth(n.checked_sub(1)?)?;
        Some(if strip {
            line.replace("disciplines:allow-trusted", "removed")
        } else {
            line.to_string()
        })
    };
    let pm: Vec<String> = proc_macros.iter().map(|s| (*s).to_string()).collect();
    vir_trust::judge(krate, &vir, &names, &pm, &read)
}

#[test]
fn honest_crates_pass() {
    // Derives (Debug, PartialEq, Eq, PartialOrd, Ord, Hash) and a constant.
    assert_eq!(
        judge("bridge-core", "suite_bridge_core", &[], false),
        Ok(Outcome::default())
    );
    // A `verus!` accessor for a field two variants share, and `Default`.
    assert_eq!(
        judge("spine-core", "suite_spine_core", &[], false),
        Ok(Outcome::default())
    );
    // A `const fn`, declared with a verified body.
    assert_eq!(
        judge("gen-optional-proto", "optional_proto", &[], false),
        Ok(Outcome::default())
    );
    // Every derivable trait.
    assert_eq!(judge("dis-h", "dis_h", &[], false), Ok(Outcome::default()));
}

#[test]
fn an_external_trait_impl_needs_a_marker_where_it_is_written() {
    for (name, krate, at) in [
        ("dis-a", "dis_a", "a/src/lib.rs:22"),
        // The attribute split over two lines: the marker is two lines up.
        ("dis-b", "dis_b", "b/src/lib.rs:23"),
        // `include!`d from a file that is not `.rs`.
        ("dis-f", "dis_f", "f/src/lie.txt:2"),
    ] {
        assert_eq!(
            judge(name, krate, &[], false),
            Ok(Outcome::default()),
            "{name}"
        );
        let failures = judge(name, krate, &[], true).unwrap().failures;
        assert_eq!(failures.len(), 1, "{name}: {failures:#?}");
        assert!(
            failures[0].starts_with(&format!(
                "{at}: `impl {krate}::One for {krate}::S` is external"
            )),
            "{name}: {failures:#?}"
        );
    }
}

#[test]
fn an_impl_a_macro_assembles_fails_with_its_marker_on_the_invocation() {
    let failures = judge("dis-e", "dis_e", &[], false).unwrap().failures;
    assert_eq!(failures.len(), 1, "{failures:#?}");
    assert!(
        failures[0].starts_with("e/src/lib.rs:26: "),
        "{failures:#?}"
    );
}

#[test]
fn external_free_functions_and_inherent_methods_are_listed() {
    assert_eq!(
        judge("dis-i", "dis_i", &[], false),
        Ok(Outcome {
            failures: Vec::new(),
            listed: vec![
                "dis_i::impl&%0::lie_method".to_string(),
                "dis_i::lie".to_string()
            ],
        })
    );
}

#[test]
fn a_forged_derive_is_caught_by_the_proc_macro_rule_and_a_custom_one_always() {
    let custom = "k/src/lib.rs:22: `impl dis_k::One for dis_k::S` is external";
    let without = judge("dis-k", "dis_k", &[], false).unwrap().failures;
    assert_eq!(
        without.len(),
        1,
        "the log alone passes the forged `PartialEq`"
    );
    assert!(without[0].starts_with(custom), "{without:#?}");
    let with = judge("dis-k", "dis_k", &["fakederive"], false)
        .unwrap()
        .failures;
    assert_eq!(with.len(), 2, "{with:#?}");
    assert!(
        with[0].starts_with("proc-macro crates in the dependencies of a proved crate: fakederive"),
        "{with:#?}"
    );
    assert!(with[1].starts_with(custom), "{with:#?}");
}

#[test]
fn a_log_without_the_crate_or_with_a_bad_line_is_an_error() {
    assert_eq!(
        judge("bridge-core", "renamed_lib", &[], false),
        Err("the VIR log declares nothing of crate `renamed_lib`".to_string())
    );
    let vir = std::fs::read_to_string(case("bridge-core").join("crate.vir")).unwrap();
    let read = |_: &str, _: usize| None;
    assert!(
        vir_trust::judge(
            "suite_bridge_core",
            &vir,
            "suite_bridge_core::impl&%0 ### x",
            &[],
            &read
        )
        .unwrap_err()
        .starts_with("impl names: unreadable line")
    );
    assert!(
        vir_trust::judge(
            "suite_bridge_core",
            &vir,
            "suite_bridge_core::impl&%0 ### t ### u ### nowhere",
            &[],
            &read
        )
        .unwrap_err()
        .starts_with("impl names: unreadable span")
    );
}

#[test]
fn derives_need_their_source_to_be_explained() {
    // Without the source a derive cannot be checked, so it counts as a
    // hand-written external impl and needs a marker.
    let dir = case("bridge-core");
    let vir = std::fs::read_to_string(dir.join("crate.vir")).unwrap();
    let names = std::fs::read_to_string(dir.join("crate.impl_names")).unwrap();
    let blind = |_: &str, _: usize| None;
    let out = vir_trust::judge("suite_bridge_core", &vir, &names, &[], &blind).unwrap();
    assert_ne!(out.failures.len(), 0);
    assert!(
        out.failures.iter().all(|f| f.contains("is external")),
        "{out:#?}"
    );
}

#[test]
fn proc_macros_in_the_closure_are_found_and_verus_s_are_not() {
    let metadata = std::fs::read_to_string(case("metadata.json")).unwrap();
    assert_eq!(
        vir_trust::proc_macros(&metadata, "dis-k"),
        Ok(vec!["fakederive".to_string()])
    );
    assert_eq!(vir_trust::proc_macros(&metadata, "dis-a"), Ok(Vec::new()));
    assert_eq!(
        vir_trust::proc_macros(&metadata, "nope"),
        Err("cargo metadata: no workspace member `nope`".to_string())
    );
    let no_resolve = metadata.replace("\"resolve\"", "\"unresolved\"");
    assert!(
        vir_trust::proc_macros(&no_resolve, "dis-k")
            .unwrap_err()
            .contains("no `resolve` graph")
    );
    assert!(vir_trust::proc_macros("{}", "dis-k").is_err());
    assert!(vir_trust::proc_macros("nope", "dis-k").is_err());
}

#[test]
fn build_scripts_are_found_in_metadata() {
    let metadata = std::fs::read_to_string(case("metadata.json")).unwrap();
    assert_eq!(vir_trust::has_build_script(&metadata, "vstd"), Ok(true));
    assert_eq!(vir_trust::has_build_script(&metadata, "dis-k"), Ok(false));
    assert_eq!(
        vir_trust::has_build_script(&metadata, "nope"),
        Err("cargo metadata: no package `nope`".to_string())
    );
    assert!(vir_trust::has_build_script("{}", "x").is_err());
    assert!(vir_trust::has_build_script("nope", "x").is_err());
}

/// A small log: `decls` as `(path, has body)`, `externals`, and impl
/// names; sources as `(file, text)`.
fn synthetic(
    decls: &[(&str, bool)],
    externals: &[&str],
    names: &str,
    sources: &[(&str, &str)],
) -> Result<Outcome, String> {
    let mut vir = String::new();
    for (path, body) in decls {
        let body = if *body { "(@@ v)" } else { "None" };
        let _ = writeln!(vir, "(Function :name (Fun :path {path}) :body {body})");
    }
    for path in externals {
        let _ = writeln!(vir, "(external_fn (Fun :path {path}))");
    }
    let read = |file: &str, n: usize| {
        let (_, text) = sources.iter().find(|(f, _)| *f == file)?;
        text.lines().nth(n.checked_sub(1)?).map(str::to_string)
    };
    vir_trust::judge("c", &vir, names, &[], &read)
}

const DERIVED: &str = "#[derive(Debug)]\npub struct S;\n";

fn names(trait_path: &str, span: &str) -> String {
    format!("c::impl&%0   ###   {trait_path}   ###   c::S   ###   {span}\n")
}

#[test]
fn a_derive_needs_a_macro_span_on_one_line_at_its_name_in_a_derive() {
    let run = |trait_path: &str, span: &str, src: &str| {
        synthetic(
            &[("c::f", true)],
            &["c::impl&%0::fmt"],
            &names(trait_path, span),
            &[("src/lib.rs", src)],
        )
        .unwrap()
        .failures
        .len()
    };
    assert_eq!(
        run("core::fmt::Debug", "src/lib.rs:1:10: 1:15 (#3)", DERIVED),
        0
    );
    assert_eq!(
        run("core::fmt::Debug", "src/lib.rs:1:10: 1:15 (#0)", DERIVED),
        1,
        "code as written"
    );
    assert_eq!(
        run("core::fmt::Debug", "src/lib.rs:1:10: 2:15 (#3)", DERIVED),
        1,
        "two lines"
    );
    assert_eq!(
        run("my::Debug", "src/lib.rs:1:10: 1:15 (#3)", DERIVED),
        1,
        "not core's trait"
    );
    let outside = "#[derive(Clone)] #[my(Debug)]\npub struct S;\n";
    assert_eq!(
        run("core::fmt::Debug", "src/lib.rs:1:23: 1:28 (#3)", outside),
        1,
        "not inside the derive"
    );
    let vertical = "#[derive(\n    Clone,\n    Copy,\n    PartialEq,\n    Eq,\n    Debug,\n)]\npub struct S;\n";
    assert_eq!(
        run("core::fmt::Debug", "src/lib.rs:6:5: 6:10 (#3)", vertical),
        0,
        "five lines up"
    );
    let far = format!("#[derive(\n{}    Debug,\n)]\n", "    Clone,\n".repeat(6));
    assert_eq!(
        run("core::fmt::Debug", "src/lib.rs:8:5: 8:10 (#3)", &far),
        1,
        "past the look-back"
    );
}

#[test]
fn only_a_verified_body_explains_an_entry() {
    let impl_names = names("c::One", "src/lib.rs:2:1: 2:16 (#0)");
    let src = [("src/lib.rs", "// plain\nimpl One for S {}\n")];
    let declared = |body| {
        synthetic(
            &[("c::f", true), ("c::impl&%0::one", body)],
            &["c::impl&%0::one"],
            &impl_names,
            &src,
        )
        .unwrap()
        .failures
        .len()
    };
    assert_eq!(declared(true), 0);
    assert_eq!(declared(false), 1, "declared without a body");
}

#[test]
fn an_accessor_needs_two_verified_siblings() {
    let run = |siblings: &[(&str, bool)]| {
        let mut decls = vec![("c::f", true)];
        decls.extend_from_slice(siblings);
        synthetic(&decls, &["c::impl&%1::arrow_x"], "", &[])
            .unwrap()
            .listed
    };
    assert_eq!(
        run(&[
            ("c::impl&%1::arrow_A_x", true),
            ("c::impl&%1::arrow_B_x", true)
        ]),
        Vec::<String>::new()
    );
    assert_eq!(
        run(&[("c::impl&%1::arrow_A_x", true)]),
        ["c::impl&%1::arrow_x"]
    );
    assert_eq!(
        run(&[
            ("c::impl&%1::arrow_A_x", true),
            ("c::impl&%1::arrow_B_x", false)
        ]),
        ["c::impl&%1::arrow_x"]
    );
}

#[test]
fn another_crate_s_entries_and_quoted_text_are_not_the_crate_s() {
    // `cc` shares a prefix with `c`, and a string literal in verified code
    // reads like a record once Verus writes it into the log.
    let vir = "(Function :name (Fun :path c::f) :body (@@ v))\n\
               (Constant StrSlice \"(Function :name (Fun :path c::impl&%0::one) :body (@@ x))\")\n\
               (external_fn (Fun :path c::impl&%0::one))\n\
               (external_fn (Fun :path cc::g))\n";
    let impl_names = names("c::One", "src/lib.rs:2:1: 2:16 (#0)");
    let src = "// plain\nimpl One for S {}\n";
    let read = |_: &str, n: usize| src.lines().nth(n.checked_sub(1)?).map(str::to_string);
    let out = vir_trust::judge("c", vir, &impl_names, &[], &read).unwrap();
    assert_eq!(
        out.failures.len(),
        1,
        "the forged record explains nothing: {out:#?}"
    );
    assert_eq!(out.listed, Vec::<String>::new(), "`cc::g` is not `c`'s");
}

#[test]
fn a_marker_must_lead_into_the_impl() {
    let impl_names = names("c::One", "src/lib.rs:4:1: 4:16 (#0)");
    let run = |src: &str| {
        synthetic(
            &[("c::f", true)],
            &["c::impl&%0::one"],
            &impl_names,
            &[("src/lib.rs", src)],
        )
        .unwrap()
        .failures
        .len()
    };
    let previous = "pub fn helper() -> u32 { 0 } // disciplines:allow-trusted (helper)\n\nmark!(external,\nimpl One for S {}\n";
    assert_eq!(run(previous), 1, "the previous item's marker");
    let previous_adjacent = "x\npub fn helper() -> u32 { 0 } // disciplines:allow-trusted (helper)\nmark!(external,\nimpl One for S {}\n";
    assert_eq!(run(previous_adjacent), 1, "an adjacent item's marker");
    let split = "x\n#[verifier:: // disciplines:allow-trusted (split attribute)\nexternal]\nimpl One for S {}\n";
    assert_eq!(run(split), 0, "a split attribute's first line");
    let comment = "x\n// disciplines:allow-trusted (above, as a comment)\n#[verifier::external]\nimpl One for S {}\n";
    assert_eq!(run(comment), 0, "a comment line above the attribute");
    let listed = "x\nimpl A for S { fn one(&self) -> u32 { 1 } }, // disciplines:allow-trusted (A)\n\nimpl One for S {}\n";
    assert_eq!(run(listed), 1, "an item before it in a macro's list");
    let quoted = "x\npub fn a() -> &'static str { \"(//\" } // disciplines:allow-trusted (a)\nmark!(\nimpl One for S {}\n";
    assert_eq!(run(quoted), 1, "a `//` inside a string");
    let header =
        "x\nmark!(external,\n\nimpl One for S {} // disciplines:allow-trusted (built by mark!)\n";
    assert_eq!(run(header), 0, "a macro-built impl's own header line");
}

#[test]
fn only_normal_dependencies_bring_proc_macros() {
    let metadata = r#"{"workspace_members": ["m"],
      "packages": [
        {"id": "m", "name": "m", "targets": [{"kind": ["lib"]}]},
        {"id": "dev", "name": "dev", "targets": [{"kind": ["proc-macro"]}]},
        {"id": "build", "name": "build", "targets": [{"kind": ["proc-macro"]}]},
        {"id": "lib", "name": "lib", "targets": [{"kind": ["lib"]}]},
        {"id": "deep", "name": "deep", "targets": [{"kind": ["proc-macro"]}]}],
      "resolve": {"nodes": [
        {"id": "m", "deps": [
          {"pkg": "dev", "dep_kinds": [{"kind": "dev"}]},
          {"pkg": "build", "dep_kinds": [{"kind": "build"}]},
          {"pkg": "lib", "dep_kinds": [{"kind": null}]}]},
        {"id": "lib", "deps": [{"pkg": "deep", "dep_kinds": [{"kind": null}]}]}]}}"#;
    assert_eq!(
        vir_trust::proc_macros(metadata, "m"),
        Ok(vec!["deep".to_string()])
    );
}

#[test]
fn the_crate_is_named_by_its_library_target() {
    let metadata = r#"{"packages": [
        {"name": "my-pkg", "targets": [{"kind": ["bin"], "name": "tool"}, {"kind": ["lib"], "name": "renamed-lib"}]},
        {"name": "bins", "targets": [{"kind": ["bin"], "name": "b"}]}]}"#;
    assert_eq!(
        vir_trust::lib_name(metadata, "my-pkg"),
        Ok("renamed_lib".to_string())
    );
    assert_eq!(
        vir_trust::lib_name(metadata, "bins"),
        Err("package `bins` has no library target".to_string())
    );
    assert!(vir_trust::lib_name(metadata, "nope").is_err());
    assert!(vir_trust::lib_name("nope", "x").is_err());
}

#[test]
fn a_proved_crate_depends_only_on_verus_and_proved_crates() {
    let metadata = r#"{"workspace_members": ["m", "p2"],
      "packages": [
        {"id": "m", "name": "m", "targets": [{"kind": ["lib"]}],
         "metadata": {"disciplines": {"trusted_deps": {"bar": "a pure table, reviewed", "baz": " "}}}},
        {"id": "p2", "name": "p2", "targets": [{"kind": ["lib"]}]},
        {"id": "vstd", "name": "vstd", "targets": [{"kind": ["lib"]}]},
        {"id": "foo", "name": "foo", "targets": [{"kind": ["lib"]}]},
        {"id": "bar", "name": "bar", "targets": [{"kind": ["lib"]}]},
        {"id": "baz", "name": "baz", "targets": [{"kind": ["lib"]}]},
        {"id": "dev", "name": "dev", "targets": [{"kind": ["lib"]}]}],
      "resolve": {"nodes": [
        {"id": "m", "deps": [
          {"pkg": "vstd", "dep_kinds": [{"kind": null}]},
          {"pkg": "p2", "dep_kinds": [{"kind": null}]},
          {"pkg": "foo", "dep_kinds": [{"kind": null}]},
          {"pkg": "bar", "dep_kinds": [{"kind": null}]},
          {"pkg": "baz", "dep_kinds": [{"kind": null}]},
          {"pkg": "dev", "dep_kinds": [{"kind": "dev"}]}]}]}}"#;
    let proved = vec!["m".to_string(), "p2".to_string()];
    assert_eq!(
        vir_trust::foreign_deps(metadata, "m", &proved),
        Ok(vec!["baz".to_string(), "foo".to_string()])
    );
    assert_eq!(
        vir_trust::foreign_deps(metadata, "m", &["m".to_string()]),
        Ok(vec!["baz".to_string(), "foo".to_string(), "p2".to_string()]),
        "an unproved workspace crate is foreign"
    );
    assert!(vir_trust::foreign_deps(metadata, "nope", &proved).is_err());
    assert!(vir_trust::foreign_deps("{}", "m", &proved).is_err());
    let unresolved = metadata.replace("\"resolve\"", "\"other\"");
    assert!(vir_trust::foreign_deps(&unresolved, "m", &proved).is_err());
}
