// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `layers` and `no-std` gates' logic, on hand-built packages: each rule
//! has a minimal bad case that yields exactly one violation.
use std::io;
use std::path::Path;

use xtask::layers::{self, Comb, Dep, DepKind, Package, Variant};
use xtask::proofs::Kind;

const ROOT: &str =
    "[workspace]\nmembers = []\n\n[workspace.lints.rust]\nunsafe_code = \"forbid\"\n";
const OPTED_IN: &str = "[package]\nname = \"x\"\n\n[lints]\nworkspace = true\n";
const FIXTURE: &str = include_str!("fixtures/metadata.json");

fn pkg(name: &str, layer: &str, allow: &[&str], deps: Vec<Dep>) -> Package {
    Package {
        name: name.to_string(),
        manifest: if layer == "primitive" {
            PRIMITIVE_MANIFEST
        } else {
            OPTED_IN
        }
        .to_string(),
        lib_source: Some("#![cfg_attr(not(test), no_std)]\n".to_string()),
        lib_path: None,
        layer: Some(layer.to_string()),
        tooth: None,
        data_only: None,
        allow: Some(allow.iter().map(|s| (*s).to_string()).collect()),
        deps,
        proc_macro: false,
    }
}

fn ext(name: &str, kind: DepKind) -> Dep {
    Dep {
        name: name.to_string(),
        kind,
        member: false,
    }
}

fn build_member(name: &str) -> Dep {
    Dep {
        kind: DepKind::Build,
        ..member(name)
    }
}

fn member(name: &str) -> Dep {
    Dep {
        name: name.to_string(),
        kind: DepKind::Normal,
        member: true,
    }
}

fn messages(packages: &[Package]) -> Vec<String> {
    layers::check(packages, ROOT)
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn one(packages: &[Package], needle: &str) {
    let got = messages(packages);
    assert_eq!(got.len(), 1, "{got:#?}");
    assert!(got[0].contains(needle), "{got:#?}");
}

/// Serves manifests and lib roots for the fixture: every manifest opts in,
/// every lib root is `no_std`.
fn fixture_read(path: &Path) -> io::Result<String> {
    if path.ends_with("Cargo.toml") {
        Ok(OPTED_IN.to_string())
    } else if path.extension().is_some_and(|e| e == "rs") {
        Ok("#![no_std]\n".to_string())
    } else {
        Err(io::Error::other(format!(
            "unexpected read {}",
            path.display()
        )))
    }
}

fn find<'a>(packages: &'a [Package], name: &str) -> &'a Package {
    packages.iter().find(|p| p.name == name).unwrap()
}

#[test]
fn a_clean_workspace_passes() {
    let ps = [
        pkg("kernel", "kernel", &[], vec![]),
        pkg(
            "rules",
            "core",
            &["kernel", "heapless"],
            vec![member("kernel"), ext("heapless", DepKind::Normal)],
        ),
        pkg("rt", "runtime", &["rules"], vec![member("rules")]),
        pkg("app", "edge", &["rt"], vec![member("rt")]),
        pkg("xtask", "tooling", &["app"], vec![member("app")]),
    ];
    assert_eq!(messages(&ps), Vec::<String>::new());
}

#[test]
fn the_direction_table_is_exact() {
    let allowed = [
        ("core", "kernel"),
        ("unsafe", "kernel"),
        ("unsafe", "core"),
        ("runtime", "core"),
        ("runtime", "kernel"),
        ("runtime", "unsafe"),
        ("edge", "runtime"),
        ("edge", "core"),
        ("edge", "kernel"),
        ("kernel", "primitive"),
        ("core", "primitive"),
        ("runtime", "primitive"),
        ("edge", "primitive"),
        ("unsafe", "primitive"),
    ];
    for from in layers::LAYER_NAMES {
        for to in layers::LAYER_NAMES {
            let want = *from == "tooling" || from == to || allowed.contains(&(*from, *to));
            assert_eq!(layers::may_depend(from, to), want, "{from} -> {to}");
            let ps = [
                pkg("a", from, &["b"], vec![member("b")]),
                pkg("b", to, &[], vec![]),
            ];
            let got = messages(&ps);
            if want {
                assert!(got.is_empty(), "{from} -> {to}: {got:#?}");
            } else {
                assert_eq!(got.len(), 1, "{from} -> {to}: {got:#?}");
                assert!(got[0].contains("may not depend"), "{got:#?}");
            }
        }
    }
}

#[test]
fn named_forbidden_edges_fail() {
    for (from, to) in [
        ("edge", "unsafe"),
        ("core", "runtime"),
        ("runtime", "tooling"),
    ] {
        one(
            &[
                pkg("a", from, &["b"], vec![member("b")]),
                pkg("b", to, &[], vec![]),
            ],
            "may not depend",
        );
    }
}

#[test]
fn a_missing_layer_fails() {
    let mut p = pkg("a", "core", &[], vec![]);
    p.layer = None;
    one(&[p], "no `layer`");
}

#[test]
fn an_unknown_layer_fails() {
    one(&[pkg("a", "domain", &[], vec![])], "unknown layer `domain`");
}

#[test]
fn normal_build_and_target_deps_need_allow() {
    let target = Dep {
        name: "libc".to_string(),
        kind: DepKind::Normal,
        member: false,
    };
    for dep in [
        ext("serde", DepKind::Normal),
        ext("cc", DepKind::Build),
        target,
    ] {
        let name = dep.name.clone();
        one(
            &[pkg("a", "edge", &[], vec![dep])],
            &format!("dependency `{name}` is not in `allow`"),
        );
    }
}

#[test]
fn a_missing_allow_means_empty() {
    let mut p = pkg("a", "edge", &[], vec![ext("serde", DepKind::Normal)]);
    p.allow = None;
    one(&[p], "dependency `serde` is not in `allow`");
}

#[test]
fn dev_dependencies_are_free() {
    assert_eq!(
        messages(&[pkg("a", "core", &[], vec![ext("proptest", DepKind::Dev)])]),
        Vec::<String>::new()
    );
}

#[test]
fn a_stale_allow_entry_fails() {
    one(
        &[pkg("a", "edge", &["serde"], vec![])],
        "stale `allow` entry `serde`",
    );
}

#[test]
fn an_allow_entry_matching_only_a_dev_dependency_is_stale() {
    one(
        &[pkg(
            "a",
            "edge",
            &["proptest"],
            vec![ext("proptest", DepKind::Dev)],
        )],
        "stale `allow` entry `proptest`",
    );
}

#[test]
fn a_dependency_listed_twice_is_reported_once() {
    let target = Dep {
        name: "serde".to_string(),
        kind: DepKind::Normal,
        member: false,
    };
    one(
        &[pkg(
            "a",
            "edge",
            &[],
            vec![ext("serde", DepKind::Normal), target.clone()],
        )],
        "dependency `serde`",
    );
    let ps = [pkg(
        "a",
        "edge",
        &["serde"],
        vec![ext("serde", DepKind::Normal), target],
    )];
    assert_eq!(messages(&ps), Vec::<String>::new());
}

#[test]
fn a_missing_lints_opt_in_fails() {
    let mut p = pkg("a", "edge", &[], vec![]);
    p.manifest = "[package]\nname = \"a\"\n".to_string();
    one(&[p], "lints.workspace = true");
}

#[test]
fn a_commented_out_opt_in_fails() {
    let mut p = pkg("a", "edge", &[], vec![]);
    p.manifest = "[package]\nname = \"a\"\n\n[lints]\n# workspace = true\n".to_string();
    one(&[p], "lints.workspace = true");
}

#[test]
fn inline_opt_in_forms_pass() {
    for manifest in [
        "lints.workspace = true\n[package]\nname = \"a\"\n",
        "lints = { workspace = true }\n[package]\n",
    ] {
        let mut p = pkg("a", "edge", &[], vec![]);
        p.manifest = manifest.to_string();
        assert!(messages(&[p]).is_empty(), "{manifest}");
    }
}

#[test]
fn a_hash_inside_a_value_does_not_hide_the_opt_in() {
    let mut p = pkg("a", "edge", &[], vec![]);
    p.manifest = "[package]\ndescription = \"C# bindings\"\n\n[lints] # policy\nworkspace = true\n"
        .to_string();
    assert_eq!(messages(&[p]), Vec::<String>::new());
}

#[test]
fn the_unsafe_zone_needs_no_opt_in() {
    let mut p = pkg("ffi", "unsafe", &[], vec![]);
    p.manifest = "[package]\nname = \"ffi\"\n\n[lints.rust]\nunsafe_code = \"allow\"\n".to_string();
    assert_eq!(messages(&[p]), Vec::<String>::new());
}

#[test]
fn a_root_without_forbid_fails() {
    let got: Vec<String> = layers::check(&[pkg("a", "edge", &[], vec![])], "[workspace]\n")
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(got.len(), 1, "{got:#?}");
    assert!(
        got[0].starts_with("workspace: ") && got[0].contains("unsafe_code"),
        "{got:#?}"
    );
}

#[test]
fn root_forbid_table_forms_pass() {
    for root in [
        "[workspace.lints.rust]\nunsafe_code = { level = \"forbid\", priority = -1 }\n",
        "[workspace.lints]\nrust.unsafe_code = \"forbid\"\n",
    ] {
        assert!(
            layers::check(&[pkg("a", "edge", &[], vec![])], root).is_empty(),
            "{root}"
        );
    }
}

#[test]
fn kernel_and_core_need_the_no_std_attribute() {
    for layer in ["kernel", "core"] {
        let mut p = pkg("a", layer, &[], vec![]);
        p.lib_source = Some("pub fn f() {}\n".to_string());
        one(&[p], "no_std");
    }
}

#[test]
fn no_std_attribute_spellings_pass() {
    for src in ["#![no_std]\n", "#![cfg_attr( not(test), no_std )]\n"] {
        let mut p = pkg("a", "core", &[], vec![]);
        p.lib_source = Some(src.to_string());
        assert!(messages(&[p]).is_empty(), "{src}");
    }
}

#[test]
fn kernel_or_core_without_a_lib_target_fails() {
    let mut p = pkg("a", "kernel", &[], vec![]);
    p.lib_source = None;
    one(&[p], "lib target");
}

#[test]
fn an_empty_workspace_fails() {
    one(&[], "no packages");
}

#[test]
fn every_violation_is_reported() {
    let mut p = pkg("a", "edge", &["serde"], vec![]);
    p.layer = None;
    p.manifest = "[package]\n".to_string();
    assert_eq!(messages(&[p]).len(), 3);
}

#[test]
fn report_joins_violations_one_per_line() {
    assert_eq!(layers::report(&[]), Ok(()));
    let vs = layers::check(&[], "[workspace]\n");
    let err = layers::report(&vs).unwrap_err();
    assert_eq!(err.lines().count(), 2, "{err}");
}

#[test]
fn parse_reads_the_recorded_fixture() {
    let ps = layers::parse_metadata(FIXTURE, &fixture_read).unwrap();
    assert_eq!(ps.len(), 3);
    let core = find(&ps, "core-rules");
    assert_eq!(core.layer.as_deref(), Some("core"));
    assert_eq!(core.allow, Some(vec!["kernel".to_string()]));
    assert_eq!(core.deps.len(), 2);
    assert!(
        core.deps
            .iter()
            .all(|d| d.name == "kernel" && d.member && d.kind == DepKind::Normal)
    );
    let app = find(&ps, "app");
    assert_eq!(app.lib_source, None);
    assert!(
        app.deps
            .iter()
            .any(|d| d.name == "core-rules" && d.member && d.kind == DepKind::Normal)
    );
    assert!(
        app.deps
            .iter()
            .any(|d| d.name == "kernel" && d.kind == DepKind::Dev)
    );
    assert_eq!(
        find(&ps, "kernel").lib_source.as_deref(),
        Some("#![no_std]\n")
    );
    assert_eq!(find(&ps, "kernel").allow, None);
    assert!(
        layers::check(&ps, ROOT).is_empty(),
        "{:#?}",
        layers::check(&ps, ROOT)
    );
}

#[test]
fn parse_rejects_malformed_json() {
    assert!(layers::parse_metadata("{", &fixture_read).is_err());
    assert!(layers::parse_metadata("{\"packages\": \"x\"}", &fixture_read).is_err());
}

#[test]
fn parse_fails_when_a_file_cannot_be_read() {
    let err = layers::parse_metadata(FIXTURE, &|_| Err(io::Error::other("denied"))).unwrap_err();
    assert!(err.contains("cannot read"), "{err}");
}

fn one_package_json(metadata: &str, deps: &str) -> String {
    format!(
        "{{\"packages\":[{{\"name\":\"a\",\"manifest_path\":\"/w/a/Cargo.toml\",\"targets\":[],\"metadata\":{metadata},\"dependencies\":[{deps}]}},\
         {{\"name\":\"b\",\"manifest_path\":\"/w/b/Cargo.toml\",\"targets\":[],\"metadata\":null,\"dependencies\":[]}}],\"metadata\":null}}"
    )
}

#[test]
fn parse_rejects_wrongly_typed_declarations() {
    for metadata in [
        "{\"disciplines\":{\"layer\":3}}",
        "{\"disciplines\":{\"layer\":\"core\",\"allow\":\"x\"}}",
    ] {
        let err =
            layers::parse_metadata(&one_package_json(metadata, ""), &fixture_read).unwrap_err();
        assert!(err.starts_with("a: "), "{err}");
    }
}

#[test]
fn parse_rejects_an_unknown_dependency_kind() {
    let dep = "{\"name\":\"b\",\"kind\":\"weird\",\"target\":null,\"path\":\"/w/b\"}";
    assert!(layers::parse_metadata(&one_package_json("null", dep), &fixture_read).is_err());
}

#[test]
fn parse_an_outside_path_dep_with_a_member_name_is_not_a_member() {
    let inside = "{\"name\":\"b\",\"kind\":null,\"target\":null,\"path\":\"/w/b\"}";
    let outside = "{\"name\":\"b\",\"kind\":null,\"target\":null,\"path\":\"/elsewhere/b\"}";
    for (dep, want) in [(inside, true), (outside, false)] {
        let ps = layers::parse_metadata(&one_package_json("null", dep), &fixture_read).unwrap();
        assert_eq!(find(&ps, "a").deps[0].member, want, "{dep}");
    }
}

#[test]
fn no_std_target_is_read_from_workspace_metadata() {
    assert_eq!(
        layers::no_std_target(FIXTURE),
        Ok("x86_64-unknown-none".to_string())
    );
    assert!(layers::no_std_target("{\"packages\":[],\"metadata\":null}").is_err());
}

#[test]
fn no_std_crates_are_kernel_and_core() {
    let ps = [
        pkg("k", "kernel", &[], vec![]),
        pkg("c", "core", &[], vec![]),
        pkg("e", "edge", &[], vec![]),
    ];
    assert_eq!(layers::no_std_crates(&ps), Ok(vec!["k", "c"]));
    assert!(layers::no_std_crates(&[pkg("e", "edge", &[], vec![])]).is_err());
}

/// The template ships `no-std` blocked: there is no kernel or core crate to
/// build. Bootstrap sets `NO_STD_BLOCKED` to `None` once one exists and
/// changes this test to assert `None`.
#[test]
fn no_std_is_blocked_until_a_kernel_or_core_crate_exists() {
    assert_eq!(layers::NO_STD_BLOCKED, Some("no kernel or core crate yet"));
}

#[test]
fn a_patched_dependency_with_a_member_name_fails() {
    let ps = [
        pkg(
            "core",
            "core",
            &["edge"],
            vec![ext("edge", DepKind::Normal)],
        ),
        pkg("edge", "edge", &[], vec![]),
    ];
    one(&ps, "workspace member's name");
}

#[test]
fn root_forbid_other_spellings_pass() {
    for root in [
        "[workspace]\nlints.rust.unsafe_code = \"forbid\"\n",
        "[workspace]\nlints.rust.unsafe_code = { level = \"forbid\" }\n",
        "workspace.lints.rust.unsafe_code = \"forbid\"\n",
        "[workspace.lints]\nrust = { unsafe_code = \"forbid\" }\n",
        "[workspace.lints]\nrust = { unsafe_code = { level = \"forbid\", priority = -1 } }\n",
    ] {
        assert!(
            layers::check(&[pkg("a", "edge", &[], vec![])], root).is_empty(),
            "{root}"
        );
    }
}

#[test]
fn a_root_that_denies_unsafe_fails_and_names_the_form() {
    let root = "[workspace.lints.rust]\nunsafe_code = \"deny\"\n";
    let got = layers::check(&[pkg("a", "edge", &[], vec![])], root);
    assert_eq!(got.len(), 1, "{got:#?}");
    assert!(
        got[0]
            .message
            .contains("add `unsafe_code = \"forbid\"` under [workspace.lints.rust]"),
        "{got:#?}"
    );
}

#[test]
fn the_conditional_no_std_idiom_passes() {
    for src in [
        "#![cfg_attr(not(feature = \"std\"), no_std)]\n",
        "#![cfg_attr(test, allow(dead_code))]\n#![cfg_attr(not(feature = \"std\"), no_std)]\n",
    ] {
        let mut p = pkg("a", "core", &[], vec![]);
        p.lib_source = Some(src.to_string());
        assert!(messages(&[p]).is_empty(), "{src}");
    }
}

#[test]
fn an_unrelated_cfg_attr_is_not_no_std() {
    let mut p = pkg("a", "core", &[], vec![]);
    p.lib_source = Some("#![cfg_attr(test, allow(dead_code))]\n".to_string());
    one(&[p], "cfg_attr(<cfg>, no_std)");
}

fn proc_macro_pkg(name: &str, layer: &str) -> Package {
    Package {
        proc_macro: true,
        ..pkg(name, layer, &[], vec![])
    }
}

#[test]
fn build_dependency_edges_skip_the_direction_table() {
    let ps = [
        pkg("core", "core", &["edge"], vec![build_member("edge")]),
        pkg("edge", "edge", &[], vec![]),
    ];
    assert_eq!(messages(&ps), Vec::<String>::new());
}

#[test]
fn edges_to_proc_macro_packages_skip_the_direction_table() {
    for layer in ["edge", "tooling"] {
        let ps = [
            pkg("core", "core", &["pm"], vec![member("pm")]),
            proc_macro_pkg("pm", layer),
        ];
        assert_eq!(messages(&ps), Vec::<String>::new(), "{layer}");
    }
}

#[test]
fn a_core_proc_macro_needs_no_no_std_attribute() {
    let mut p = proc_macro_pkg("pm", "core");
    p.lib_source = Some("pub fn f() {}\n".to_string());
    assert_eq!(messages(&[p]), Vec::<String>::new());
}

#[test]
fn no_std_crates_omit_proc_macros() {
    let ps = [
        pkg("k", "kernel", &[], vec![]),
        proc_macro_pkg("pm", "core"),
    ];
    assert_eq!(layers::no_std_crates(&ps), Ok(vec!["k"]));
    assert!(layers::no_std_crates(&[proc_macro_pkg("pm", "core")]).is_err());
}

#[test]
fn parse_marks_proc_macro_packages() {
    let json = "{\"packages\":[{\"name\":\"a\",\"manifest_path\":\"/w/a/Cargo.toml\",\"targets\":[{\"kind\":[\"proc-macro\"],\"src_path\":\"/w/a/src/lib.rs\",\"name\":\"a\"}],\"metadata\":null,\"dependencies\":[]},\
        {\"name\":\"b\",\"manifest_path\":\"/w/b/Cargo.toml\",\"targets\":[{\"kind\":[\"lib\"],\"src_path\":\"/w/b/src/lib.rs\",\"name\":\"b\"}],\"metadata\":null,\"dependencies\":[]}],\"metadata\":null}";
    let ps = layers::parse_metadata(json, &fixture_read).unwrap();
    assert!(find(&ps, "a").proc_macro);
    assert!(!find(&ps, "b").proc_macro);
}

#[test]
fn no_std_in_a_comment_or_string_does_not_count() {
    for src in [
        "// #![no_std]\npub fn f() {}\n",
        "/* #![no_std] */\npub fn f() {}\n",
        "pub const S: &str = \"#![no_std]\";\n",
        "pub fn f() {}\n// #![cfg_attr(not(test), no_std)]\n",
    ] {
        let mut p = pkg("a", "core", &[], vec![]);
        p.lib_source = Some(src.to_string());
        one(&[p], "no_std");
    }
}

#[test]
fn no_std_after_doc_comments_and_other_attributes_passes() {
    let src = "//! Crate docs.\n/* a /* nested */ comment */\n#![warn(missing_docs)]\n#![doc = \"x ] y\"]\n#![no_std]\n\npub fn f() {}\n";
    let mut p = pkg("a", "core", &[], vec![]);
    p.lib_source = Some(src.to_string());
    assert_eq!(messages(&[p]), Vec::<String>::new());
}

#[test]
fn a_multi_line_string_cannot_fake_a_lints_table() {
    let mut p = pkg("a", "edge", &[], vec![]);
    p.manifest =
        "[package]\nname = \"a\"\ndescription = \"\"\"\n[lints]\nworkspace = true\n\"\"\"\n"
            .to_string();
    one(&[p], "lints.workspace = true");
    let mut q = pkg("a", "edge", &[], vec![]);
    q.manifest =
        "[package]\ndescription = '''\n[x]\n'''\n\n[lints]\nworkspace = true\n".to_string();
    assert_eq!(messages(&[q]), Vec::<String>::new());
}

#[test]
fn a_hash_inside_a_string_is_not_a_comment() {
    let mut p = pkg("a", "edge", &[], vec![]);
    p.manifest = "[package]\nname = \"a\"\n\n[lints]\nworkspace = true # opted in\n".to_string();
    assert_eq!(messages(&[p]), Vec::<String>::new());
    let root = "[workspace.lints.rust]\nunsafe_code = \"forbid\" # a \"#\" here\n";
    assert_eq!(
        layers::check(&[pkg("a", "edge", &[], vec![])], root),
        Vec::new()
    );
}

#[test]
fn a_nested_inline_unsafe_code_is_not_the_lint() {
    let root = "[workspace.lints]\nrust = { other = { unsafe_code = \"forbid\" } }\n";
    let got = layers::check(&[pkg("a", "edge", &[], vec![])], root);
    assert_eq!(got.len(), 1, "{got:#?}");
    assert!(got[0].message.contains("forbid"), "{got:#?}");
}

const HANDLED: Comb = Comb {
    variant: Variant::Handled,
    bridge: None,
};

fn bridged(bridge: &str) -> Comb {
    Comb {
        variant: Variant::Handled,
        bridge: Some(bridge.to_string()),
    }
}

fn plain() -> Comb {
    Comb {
        variant: Variant::Plain,
        bridge: None,
    }
}

fn in_tooth(mut p: Package, tooth: &str) -> Package {
    p.tooth = Some(tooth.to_string());
    p
}

fn comb_messages(packages: &[Package], comb: &Comb) -> Vec<String> {
    layers::check_comb(packages, comb)
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn comb_one(packages: &[Package], comb: &Comb, needle: &str) {
    let got = comb_messages(packages, comb);
    assert_eq!(got.len(), 1, "{got:#?}");
    assert!(got[0].contains(needle), "{got:#?}");
}

#[test]
fn no_teeth_means_no_comb_violations() {
    let ps = [
        pkg("core", "core", &[], vec![]),
        pkg("rt", "runtime", &["core"], vec![member("core")]),
        pkg("ffi", "unsafe", &[], vec![]),
    ];
    assert_eq!(comb_messages(&ps, &HANDLED), Vec::<String>::new());
    assert_eq!(comb_messages(&ps, &plain()), Vec::<String>::new());
}

#[test]
fn a_dependency_between_teeth_names_both() {
    let ps = [
        pkg("proto", "core", &[], vec![]),
        in_tooth(pkg("a", "core", &[], vec![]), "alpha"),
        in_tooth(pkg("b", "core", &["a"], vec![member("a")]), "beta"),
    ];
    comb_one(
        &ps,
        &bridged("proto"),
        "b: tooth `beta` may not depend on tooth `alpha` crate `a`",
    );
}

#[test]
fn dev_and_build_edges_between_teeth_are_free() {
    let mut dev = member("a");
    dev.kind = DepKind::Dev;
    let ps = [
        pkg("proto", "core", &[], vec![]),
        in_tooth(pkg("a", "core", &[], vec![]), "alpha"),
        in_tooth(
            pkg("b", "core", &["a"], vec![dev, build_member("a")]),
            "beta",
        ),
    ];
    assert_eq!(comb_messages(&ps, &bridged("proto")), Vec::<String>::new());
}

#[test]
fn the_spine_may_not_depend_on_a_tooth_but_the_handle_may() {
    let ps = [
        pkg("proto", "core", &[], vec![]),
        in_tooth(pkg("a", "core", &[], vec![]), "alpha"),
        pkg("spine", "core", &["a"], vec![member("a")]),
        pkg("handle", "runtime", &["a"], vec![member("a")]),
    ];
    comb_one(
        &ps,
        &bridged("proto"),
        "spine: the spine may not depend on tooth `alpha` crate `a`",
    );
}

#[test]
fn tooling_and_primitive_may_not_declare_a_tooth() {
    let ps = [
        pkg("proto", "core", &[], vec![]),
        in_tooth(pkg("t", "tooling", &[], vec![]), "alpha"),
    ];
    comb_one(
        &ps,
        &bridged("proto"),
        "t: a `tooling` crate may not declare a tooth",
    );
}

#[test]
fn a_malformed_tooth_name_is_refused() {
    let ps = [
        pkg("proto", "core", &[], vec![]),
        in_tooth(pkg("a", "core", &[], vec![]), "Alpha"),
    ];
    comb_one(&ps, &bridged("proto"), "a: tooth `Alpha`: use lowercase");
    assert!(layers::valid_tooth("a1-b_c"));
    assert!(!layers::valid_tooth("1a"));
    assert!(!layers::valid_tooth(""));
}

#[test]
fn handled_teeth_are_kernel_or_core() {
    for layer in ["runtime", "edge", "unsafe"] {
        let ps = [
            pkg("proto", "core", &[], vec![]),
            in_tooth(pkg("a", layer, &[], vec![]), "alpha"),
        ];
        comb_one(
            &ps,
            &bridged("proto"),
            &format!(
                "a: handled haircomb: tooth `alpha` crate is `{layer}`; teeth are kernel or core"
            ),
        );
    }
}

#[test]
fn handled_needs_a_core_bridge_with_no_tooth_once_teeth_exist() {
    let tooth = in_tooth(pkg("a", "core", &[], vec![]), "alpha");
    comb_one(
        std::slice::from_ref(&tooth),
        &HANDLED,
        "workspace: handled haircomb needs `bridge`",
    );
    comb_one(
        std::slice::from_ref(&tooth),
        &bridged("nope"),
        "workspace: bridge `nope` is not a workspace member",
    );
    let rt = pkg("proto", "runtime", &[], vec![]);
    comb_one(
        &[tooth.clone(), rt],
        &bridged("proto"),
        "workspace: bridge `proto` must be a core crate with no tooth",
    );
    comb_one(
        std::slice::from_ref(&tooth),
        &bridged("a"),
        "workspace: bridge `a` must be a core crate with no tooth",
    );
}

#[test]
fn plain_allows_effectful_teeth_and_refuses_a_bridge() {
    let ps = [
        in_tooth(pkg("a", "core", &[], vec![]), "alpha"),
        in_tooth(
            pkg(
                "a-rt",
                "runtime",
                &["a", "a-ffi"],
                vec![member("a"), member("a-ffi")],
            ),
            "alpha",
        ),
        in_tooth(pkg("a-ffi", "unsafe", &[], vec![]), "alpha"),
    ];
    assert_eq!(comb_messages(&ps, &plain()), Vec::<String>::new());
    let with_bridge = Comb {
        variant: Variant::Plain,
        bridge: Some("a".to_string()),
    };
    comb_one(
        &ps,
        &with_bridge,
        "workspace: `bridge` applies only to handled haircomb",
    );
}

#[test]
fn plain_a_teeths_unsafe_crate_is_not_reachable_from_another_tooth() {
    let ps = [
        in_tooth(pkg("a-ffi", "unsafe", &[], vec![]), "alpha"),
        in_tooth(
            pkg("b-rt", "runtime", &["a-ffi"], vec![member("a-ffi")]),
            "beta",
        ),
    ];
    comb_one(
        &ps,
        &plain(),
        "tooth `beta` may not depend on tooth `alpha` crate `a-ffi`",
    );
}

#[test]
fn comb_reads_workspace_metadata() {
    let json =
        |d: &str| format!(r#"{{"packages": [], "metadata": {{"disciplines": {{ {d} }} }} }}"#);
    assert_eq!(layers::comb(&json("")), Ok(HANDLED));
    assert_eq!(layers::comb(&json(r#""haircomb": "plain""#)), Ok(plain()));
    assert_eq!(
        layers::comb(&json(r#""haircomb": "handled", "bridge": "proto""#)),
        Ok(bridged("proto"))
    );
    assert!(
        layers::comb(&json(r#""haircomb": "comb""#))
            .unwrap_err()
            .contains("haircomb")
    );
    assert!(
        layers::comb(&json(r#""bridge": 3"#))
            .unwrap_err()
            .contains("bridge")
    );
    assert_eq!(layers::comb(r#"{"packages": []}"#), Ok(HANDLED));
}

#[test]
fn parse_reads_a_tooth() {
    let json = one_package_json(
        r#"{"disciplines": {"layer": "core", "tooth": "alpha"}}"#,
        "",
    );
    let ps = layers::parse_metadata(&json, &fixture_read).unwrap();
    assert_eq!(ps[0].tooth.as_deref(), Some("alpha"));
    let bad = one_package_json(r#"{"disciplines": {"layer": "core", "tooth": 1}}"#, "");
    assert!(
        layers::parse_metadata(&bad, &fixture_read)
            .unwrap_err()
            .contains("`tooth` must be a string")
    );
}

const PRIMITIVE_MANIFEST: &str = "[package]\nname = \"p\"\n\n[lints.rust]\nunsafe_op_in_unsafe_fn = \"deny\"\n\n[lints.clippy]\nundocumented_unsafe_blocks = \"deny\"\n";

#[test]
fn a_primitive_needs_both_lint_lines() {
    let mut p = pkg("p", "primitive", &[], vec![]);
    assert_eq!(messages(std::slice::from_ref(&p)), Vec::<String>::new());
    p.manifest =
        "[package]\nname = \"p\"\n\n[lints.rust]\nunsafe_op_in_unsafe_fn = \"deny\"\n".to_string();
    one(
        &[p.clone()],
        "p: a primitive crate must set `undocumented_unsafe_blocks = \"deny\"` under [lints.clippy]",
    );
    p.manifest = "[package]\nname = \"p\"\n\n[lints]\nrust.unsafe_op_in_unsafe_fn = \"forbid\"\nclippy.undocumented_unsafe_blocks = { level = \"deny\", priority = 1 }\n".to_string();
    assert_eq!(messages(std::slice::from_ref(&p)), Vec::<String>::new());
    p.manifest = "[package]\nname = \"p\"\n\n[lints.rust]\nunsafe_op_in_unsafe_fn = \"warn\"\n\n[lints.clippy]\nundocumented_unsafe_blocks = \"deny\"\n".to_string();
    one(
        &[p],
        "must set `unsafe_op_in_unsafe_fn = \"deny\"` under [lints.rust]",
    );
}

#[test]
fn a_primitive_needs_no_std_and_no_workspace_lints() {
    let mut p = pkg("p", "primitive", &[], vec![]);
    p.lib_source = Some("pub fn f() {}\n".to_string());
    one(&[p], "p: the lib root lacks `#![no_std]`");
}

#[test]
fn no_std_crates_include_primitives() {
    let ps = [
        pkg("p", "primitive", &[], vec![]),
        pkg("c", "core", &[], vec![]),
    ];
    assert_eq!(layers::no_std_crates(&ps), Ok(vec!["p", "c"]));
}

fn cover(packages: &[Package], comb: &Comb, proofs: &[(&str, &Kind)]) -> Vec<String> {
    layers::coverage(packages, comb, proofs)
        .iter()
        .map(ToString::to_string)
        .collect()
}

#[test]
fn handled_teeth_need_a_kani_proof_once_any_proof_exists() {
    let ps = [
        pkg("proto", "core", &[], vec![]),
        in_tooth(pkg("a", "core", &[], vec![]), "alpha"),
        in_tooth(pkg("b", "kernel", &[], vec![]), "beta"),
    ];
    assert_eq!(cover(&ps, &bridged("proto"), &[]), Vec::<String>::new());
    assert_eq!(
        cover(
            &ps,
            &bridged("proto"),
            &[("a", &Kind::Kani), ("b", &Kind::Command(vec![]))]
        ),
        [
            "b: tooth `beta` crate has no core-prover entry, kani or verus, and depends on no crate of its tooth with a verus entry (handled haircomb: every tooth is proved once proofs exist; a crate holding the text around a Verus-proved core depends on it; a tooth that is only data a proved spine runs declares `data_only = \"<reason>\"`)"
        ]
    );
    assert_eq!(
        cover(&ps, &plain(), &[("a", &Kind::Kani)]),
        Vec::<String>::new()
    );
}

/// A tooth's text crate is covered by a Verus-proved crate of the same tooth
/// it depends on directly (a normal dependency on a member); not by one of
/// another tooth or of none, a Kani-proved one, a build or dev dependency, a
/// non-member, a dependency that is itself only covered, or an unproved one.
#[test]
fn a_tooth_crate_is_covered_by_a_proved_crate_of_its_tooth_it_depends_on() {
    let core = || in_tooth(pkg("a-core", "core", &[], vec![]), "alpha");
    let text = |dep: Dep| in_tooth(pkg("a", "core", &[], vec![dep]), "alpha");
    let gap = |name: &str| {
        format!(
            "{name}: tooth `alpha` crate has no core-prover entry, kani or verus, and depends on no crate of its tooth with a verus entry (handled haircomb: every tooth is proved once proofs exist; a crate holding the text around a Verus-proved core depends on it; a tooth that is only data a proved spine runs declares `data_only = \"<reason>\"`)"
        )
    };
    let ps = [core(), text(member("a-core"))];
    assert_eq!(
        cover(&ps, &bridged("proto"), &[("a-core", &Kind::Verus)]),
        Vec::<String>::new()
    );
    assert_eq!(
        cover(
            &ps,
            &bridged("proto"),
            &[("a-core", &Kind::Command(vec![]))]
        ),
        [gap("a-core"), gap("a")],
        "a command entry proves nothing"
    );
    let ps = [core(), text(build_member("a-core"))];
    assert_eq!(
        cover(&ps, &bridged("proto"), &[("a-core", &Kind::Verus)]),
        [gap("a")]
    );
    let ps = [
        in_tooth(pkg("b-core", "core", &[], vec![]), "beta"),
        text(member("b-core")),
    ];
    assert_eq!(
        cover(&ps, &bridged("proto"), &[("b-core", &Kind::Verus)]),
        [gap("a")]
    );
    let ps = [
        core(),
        text(member("a-core")),
        in_tooth(pkg("a-more", "core", &[], vec![member("a")]), "alpha"),
    ];
    assert_eq!(
        cover(&ps, &bridged("proto"), &[("a-core", &Kind::Verus)]),
        [gap("a-more")],
        "coverage is not transitive"
    );
    let ps = [core(), text(member("a-core"))];
    assert_eq!(
        cover(&ps, &bridged("proto"), &[("a-core", &Kind::Kani)]),
        [gap("a")],
        "a Kani tooth keeps its text beside its harnesses"
    );
    let dev = Dep {
        kind: DepKind::Dev,
        ..member("a-core")
    };
    let ps = [core(), text(dev)];
    assert_eq!(
        cover(&ps, &bridged("proto"), &[("a-core", &Kind::Verus)]),
        [gap("a")],
        "a dev-dependency"
    );
    let outside = Dep {
        member: false,
        ..member("a-core")
    };
    let ps = [core(), text(outside)];
    assert_eq!(
        cover(&ps, &bridged("proto"), &[("a-core", &Kind::Verus)]),
        [gap("a")],
        "a registry package named like the core"
    );
    let ps = [pkg("spine", "core", &[], vec![]), text(member("spine"))];
    assert_eq!(
        cover(&ps, &bridged("proto"), &[("spine", &Kind::Verus)]),
        [gap("a")],
        "a proved spine crate is no tooth's core"
    );
}

/// Coverage asks a prover only of a tooth's kernel and core crates: a tooth
/// on another layer is the comb check's violation, reported once there.
#[test]
fn coverage_skips_teeth_outside_kernel_and_core() {
    let ps = [
        pkg("proto", "core", &[], vec![]),
        in_tooth(pkg("r", "runtime", &[], vec![]), "alpha"),
        in_tooth(pkg("e", "edge", &[], vec![]), "beta"),
    ];
    assert_eq!(
        cover(&ps, &bridged("proto"), &[("proto", &Kind::Verus)]),
        Vec::<String>::new()
    );
    assert_eq!(
        comb_messages(&ps, &bridged("proto")).len(),
        2,
        "each misplaced tooth is the comb check's violation"
    );
}

fn data_only(p: Package, why: &str) -> Package {
    Package {
        data_only: Some(why.to_string()),
        ..p
    }
}

#[test]
fn a_data_only_tooth_needs_a_reason_and_no_kani_entry() {
    let script = || in_tooth(pkg("s", "core", &[], vec![]), "script");
    let ps = [
        pkg("proto", "core", &[], vec![]),
        data_only(script(), "a script the spine's proved interpreter runs"),
    ];
    assert_eq!(
        cover(&ps, &bridged("proto"), &[("proto", &Kind::Verus)]),
        Vec::<String>::new()
    );
    assert_eq!(
        cover(
            &ps,
            &bridged("proto"),
            &[("proto", &Kind::Verus), ("s", &Kind::Kani)]
        ),
        ["s: `data_only` with a core-prover entry (kani or verus): drop one of them"]
    );
    let ps = [data_only(script(), " ")];
    assert_eq!(
        cover(&ps, &bridged("proto"), &[("proto", &Kind::Verus)]),
        ["s: `data_only` needs a reason: what proves the code this data drives"]
    );
    let ps = [data_only(pkg("h", "core", &[], vec![]), "why")];
    assert_eq!(
        cover(&ps, &bridged("proto"), &[]),
        ["h: `data_only` is only for tooth crates"]
    );
}

#[test]
fn a_primitive_needs_a_proof_entry() {
    let ps = [pkg("p", "primitive", &[], vec![])];
    assert_eq!(
        cover(&ps, &HANDLED, &[]),
        [
            "p: primitive crate has no proof entry (Kani for its contracts, Miri for undefined behaviour)"
        ]
    );
    assert_eq!(
        cover(&ps, &HANDLED, &[("p", &Kind::Command(vec![]))]),
        Vec::<String>::new()
    );
}

#[test]
fn without_teeth_the_comb_keys_do_not_apply() {
    let ps = [
        pkg("core", "core", &[], vec![]),
        pkg("rt", "runtime", &[], vec![]),
    ];
    let plain_bridge = Comb {
        variant: Variant::Plain,
        bridge: Some("core".to_string()),
    };
    assert_eq!(comb_messages(&ps, &plain_bridge), Vec::<String>::new());
    assert_eq!(comb_messages(&ps, &bridged("nope")), Vec::<String>::new());
}

#[test]
fn a_tooth_on_a_crate_without_a_layer_names_only_the_layer_problem() {
    let mut p = in_tooth(pkg("a", "core", &[], vec![]), "alpha");
    p.layer = None;
    let ps = [pkg("proto", "core", &[], vec![]), p];
    assert_eq!(comb_messages(&ps, &bridged("proto")), Vec::<String>::new());
}

#[test]
fn primitive_lints_accept_inline_tables_and_quoted_keys() {
    for manifest in [
        "[package]\nname = \"p\"\n\n[lints]\nrust = { unsafe_op_in_unsafe_fn = \"deny\", unused = \"warn\" }\nclippy = { undocumented_unsafe_blocks = { level = \"deny\", priority = 1 } }\n",
        "[package]\nname = \"p\"\n\n[lints.rust]\n\"unsafe_op_in_unsafe_fn\" = \"forbid\"\n\n[lints.clippy]\n'undocumented_unsafe_blocks' = \"deny\"\n",
    ] {
        let mut p = pkg("p", "primitive", &[], vec![]);
        p.manifest = manifest.to_string();
        assert_eq!(messages(&[p]), Vec::<String>::new(), "{manifest}");
    }
    let mut p = pkg("p", "primitive", &[], vec![]);
    p.manifest = "[package]\nname = \"p\"\n\n[lints]\nrust = { other = { unsafe_op_in_unsafe_fn = \"deny\" } }\n\n[lints.clippy]\nundocumented_unsafe_blocks = \"deny\"\n".to_string();
    let got = messages(&[p]);
    assert_eq!(got.len(), 1, "{got:#?}");
    assert!(got[0].contains("(as `[lints.rust]` with `unsafe_op_in_unsafe_fn = \"deny\"`, or `[lints]` with `rust.unsafe_op_in_unsafe_fn = \"deny\"` or `rust = { unsafe_op_in_unsafe_fn = \"deny\" }`)"), "{got:#?}");
}

#[test]
fn quoted_lint_keys_inside_inline_tables_count_and_literal_dotted_keys_do_not() {
    let mut p = pkg("p", "primitive", &[], vec![]);
    p.manifest = "[package]\nname = \"p\"\n\n[lints]\nrust = { \"unsafe_op_in_unsafe_fn\" = \"deny\" }\nclippy = { 'undocumented_unsafe_blocks' = \"deny\" }\n".to_string();
    assert_eq!(messages(std::slice::from_ref(&p)), Vec::<String>::new());
    p.manifest = "[package]\nname = \"p\"\n\n[lints]\n\"rust.unsafe_op_in_unsafe_fn\" = \"deny\"\n\n[lints.clippy]\nundocumented_unsafe_blocks = \"deny\"\n".to_string();
    assert_eq!(messages(&[p]).len(), 1);
}
