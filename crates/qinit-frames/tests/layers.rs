// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Layer loading and amend merge.
mod common;

use common::TempDir;
use qinit_frames::error::Code;
use qinit_frames::layers::{LayerInput, load, load_enable};
use std::path::Path;

fn layer(root: &Path, name: &str, files: &[(&str, &str)]) -> LayerInput {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).expect("mkdir");
    for (f, body) in files {
        std::fs::write(dir.join(f), body).expect("write");
    }
    LayerInput {
        name: name.to_string(),
        dir,
    }
}

fn tmp(tag: &str) -> TempDir {
    TempDir::new(tag)
}

/// Merge a vendor layer and an etc layer; return the worker.x table or the errors.
fn two(tag: &str, a: &str, b: &str) -> Result<toml::Table, Vec<qinit_frames::error::Error>> {
    let root = tmp(tag);
    let ls = [
        layer(&root, "vendor", &[("a.toml", a)]),
        layer(&root, "etc", &[("b.toml", b)]),
    ];
    load(&ls).map(|m| m.table)
}

fn exec_of(t: &toml::Table) -> Vec<String> {
    t["worker"]["x"]["exec"]
        .as_array()
        .expect("array")
        .iter()
        .map(|v| v.as_str().expect("str").to_string())
        .collect()
}

#[test]
fn one_layer_loads_every_toml_file_in_name_order() {
    let root = tmp("order");
    let ls = [layer(
        &root,
        "vendor",
        &[
            ("b.toml", "[worker.b]\nexec=[\"/b\"]"),
            ("a.toml", "[worker.a]\nexec=[\"/a\"]"),
            ("n.txt", "junk"),
        ],
    )];
    let m = load(&ls).expect("loads");
    let names: Vec<_> = m.table["worker"]
        .as_table()
        .expect("t")
        .keys()
        .cloned()
        .collect();
    assert_eq!(names, ["a", "b"]);
}

#[test]
fn a_frame_defined_twice_in_one_layer_is_a_duplicate() {
    let root = tmp("dup");
    let ls = [layer(
        &root,
        "vendor",
        &[
            ("a.toml", "[worker.a]\nexec=[\"/a\"]"),
            ("b.toml", "[worker.a]\nexec=[\"/b\"]"),
        ],
    )];
    let e = load(&ls).unwrap_err();
    assert_eq!(e[0].code, Code::DuplicateFrame);
    assert_eq!(e[0].key, "worker.a");
    assert_eq!(e[0].layer.as_deref(), Some("vendor"));
}

#[test]
fn a_later_layer_replaces_a_scalar_and_keeps_the_rest() {
    let t = two(
        "scalar",
        "[worker.x]\nexec=[\"/x\"]\ntemplate=\"a\"\nready=\"pipe\"",
        "[worker.x]\nready=\"exit\"",
    )
    .unwrap();
    assert_eq!(t["worker"]["x"]["ready"].as_str(), Some("exit"));
    assert_eq!(t["worker"]["x"]["template"].as_str(), Some("a"));
}

#[test]
fn tables_merge_key_by_key() {
    let t = two(
        "tables",
        "[worker.x]\nrestart={policy=\"always\", max=5}",
        "[worker.x]\nrestart={max=9}",
    )
    .unwrap();
    assert_eq!(
        t["worker"]["x"]["restart"]["policy"].as_str(),
        Some("always")
    );
    assert_eq!(t["worker"]["x"]["restart"]["max"].as_integer(), Some(9));
}

#[test]
fn append_adds_to_a_list() {
    let t = two(
        "append",
        "[worker.x]\nexec=[\"/x\"]",
        "[worker.x]\nexec={append=[\"--x\"]}",
    )
    .unwrap();
    assert_eq!(exec_of(&t), ["/x", "--x"]);
}

#[test]
fn remove_deletes_matching_items() {
    let t = two(
        "remove",
        "[worker.x]\nexec=[\"/x\",\"-a\",\"-b\",\"-a\"]",
        "[worker.x]\nexec={remove=[\"-a\"]}",
    )
    .unwrap();
    assert_eq!(exec_of(&t), ["/x", "-b"]);
}

#[test]
fn remove_of_an_absent_item_is_a_list_op_error() {
    let e = two(
        "rmabs",
        "[worker.x]\nexec=[\"/x\"]",
        "[worker.x]\nexec={remove=[\"-z\"]}",
    )
    .unwrap_err();
    assert_eq!(e[0].code, Code::ListOp);
    assert_eq!(e[0].key, "worker.x.exec");
    assert_eq!(e[0].layer.as_deref(), Some("etc"));
    assert!(e[0].file.as_ref().is_some_and(|f| f.ends_with("b.toml")));
    assert!(e[0].detail.contains("-z"));
}

#[test]
fn replace_swaps_a_list() {
    let t = two(
        "replace",
        "[worker.x]\nexec=[\"/x\",\"-a\"]",
        "[worker.x]\nexec={replace=[\"/y\"]}",
    )
    .unwrap();
    assert_eq!(exec_of(&t), ["/y"]);
}

#[test]
fn a_plain_array_over_an_existing_list_is_a_list_op_error() {
    let e = two(
        "plain",
        "[worker.x]\nexec=[\"/x\"]",
        "[worker.x]\nexec=[\"/y\"]",
    )
    .unwrap_err();
    assert_eq!(e[0].code, Code::ListOp);
}

#[test]
fn a_list_op_table_with_an_unknown_verb_is_a_list_op_error() {
    let e = two(
        "verb",
        "[worker.x]\nexec=[\"/x\"]",
        "[worker.x]\nexec={prepend=[\"/y\"]}",
    )
    .unwrap_err();
    assert_eq!(e[0].code, Code::ListOp);
    let e = two(
        "mix",
        "[worker.x]\nexec=[\"/x\"]",
        "[worker.x]\nexec={append=[\"/y\"], remove=[\"/x\"]}",
    )
    .unwrap_err();
    assert_eq!(e[0].code, Code::ListOp);
}

#[test]
fn a_list_op_over_a_non_list_is_a_list_op_error() {
    let e = two(
        "nonlist",
        "[worker.x]\nready=\"pipe\"",
        "[worker.x]\nready={append=[\"x\"]}",
    )
    .unwrap_err();
    assert_eq!(e[0].code, Code::ListOp);
    let e = two(
        "fresh",
        "[worker.x]\nready=\"pipe\"",
        "[worker.x]\nexec={append=[\"x\"]}",
    )
    .unwrap_err();
    assert_eq!(e[0].code, Code::ListOp);
}

#[test]
fn disable_true_removes_the_frame() {
    let t = two(
        "disable",
        "[worker.x]\nexec=[\"/x\"]\n[worker.y]\nexec=[\"/y\"]",
        "[worker.x]\ndisable=true",
    )
    .unwrap();
    assert!(t["worker"].as_table().expect("t").get("x").is_none());
    assert!(t["worker"].as_table().expect("t").get("y").is_some());
}

#[test]
fn disable_false_is_ignored() {
    let t = two(
        "disfalse",
        "[worker.x]\nexec=[\"/x\"]",
        "[worker.x]\ndisable=false",
    )
    .unwrap();
    assert!(
        t["worker"]["x"]
            .as_table()
            .expect("t")
            .get("disable")
            .is_none()
    );
    assert_eq!(exec_of(&t), ["/x"]);
}

#[test]
fn provenance_names_the_layer_that_set_each_key() {
    let root = tmp("prov");
    let ls = [
        layer(
            &root,
            "vendor",
            &[(
                "a.toml",
                "[worker.x]\nexec=[\"/x\"]\nrestart={policy=\"always\", max=5}",
            )],
        ),
        layer(
            &root,
            "etc",
            &[(
                "b.toml",
                "[worker.x]\nrestart={max=9}\nexec={append=[\"-v\"]}",
            )],
        ),
    ];
    let m = load(&ls).expect("loads");
    assert_eq!(m.provenance["worker.x.restart.policy"], "vendor");
    assert_eq!(m.provenance["worker.x.restart.max"], "etc");
    assert_eq!(m.provenance["worker.x.exec"], "etc");
}

#[test]
fn the_enable_list_merges_with_the_same_list_ops() {
    let root = tmp("enable");
    let ls = [
        layer(&root, "vendor", &[("enable.toml", "enable=[\"a\",\"b\"]")]),
        layer(&root, "etc", &[("enable.toml", "enable={append=[\"c\"]}")]),
        layer(
            &root,
            "local",
            &[("enable.toml", "enable={remove=[\"a\"]}")],
        ),
    ];
    let e = load_enable(&ls).expect("loads");
    assert_eq!(e.roots, ["b", "c"]);
    assert!(e.syslog.is_empty());
}

#[test]
fn the_syslog_list_merges_with_the_same_list_ops() {
    let root = tmp("syslog");
    let ls = [
        layer(
            &root,
            "vendor",
            &[("enable.toml", "enable=[\"a\"]\nsyslog=[\"logd\",\"old\"]")],
        ),
        layer(
            &root,
            "etc",
            &[("enable.toml", "syslog={remove=[\"old\"]}")],
        ),
        layer(
            &root,
            "local",
            &[("enable.toml", "syslog={append=[\"extra\"]}")],
        ),
    ];
    let e = load_enable(&ls).expect("loads");
    assert_eq!(e.roots, ["a"]);
    assert_eq!(e.syslog, ["logd", "extra"]);
}

#[test]
fn enable_plain_array_over_existing_and_unknown_key_are_errors() {
    let root = tmp("enable-err");
    let ls = [
        layer(&root, "vendor", &[("enable.toml", "syslog=[\"a\"]")]),
        layer(&root, "etc", &[("enable.toml", "syslog=[\"b\"]\ncolour=1")]),
    ];
    let e = load_enable(&ls).unwrap_err();
    assert!(e.iter().any(|x| x.code == Code::UnknownKey));
    assert!(
        e.iter()
            .any(|x| x.code == Code::ListOp && x.key == "syslog")
    );
}

#[test]
fn a_missing_enable_file_is_an_empty_enable() {
    let root = tmp("noenable");
    let ls = [layer(&root, "vendor", &[])];
    let e = load_enable(&ls).expect("loads");
    assert!(e.roots.is_empty() && e.syslog.is_empty());
}

#[test]
fn an_io_error_names_the_file() {
    let root = tmp("io");
    let ls = [LayerInput {
        name: "vendor".into(),
        dir: root.join("absent"),
    }];
    let e = load(&ls).unwrap_err();
    assert_eq!(e[0].code, Code::Io);
    assert!(e[0].file.is_some());
}

#[test]
fn a_toml_syntax_error_names_the_file() {
    let root = tmp("syntax");
    let ls = [layer(&root, "vendor", &[("a.toml", "[worker.a\n")])];
    let e = load(&ls).unwrap_err();
    assert_eq!(e[0].code, Code::Parse);
    assert!(e[0].file.as_ref().is_some_and(|f| f.ends_with("a.toml")));
}

#[test]
fn parse_errors_from_different_files_accumulate() {
    let root = tmp("accum");
    let ls = [layer(
        &root,
        "vendor",
        &[("a.toml", "[worker.a\n"), ("b.toml", "x = = 1\n")],
    )];
    let e = load(&ls).unwrap_err();
    assert_eq!(e.len(), 2);
}

#[test]
fn an_unknown_top_level_table_is_an_unknown_key() {
    let root = tmp("unk");
    let ls = [layer(
        &root,
        "vendor",
        &[("a.toml", "[daemon.a]\nexec=[\"/a\"]")],
    )];
    let e = load(&ls).unwrap_err();
    assert_eq!(e[0].code, Code::UnknownKey);
    assert_eq!(e[0].key, "daemon");
}
