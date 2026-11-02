// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Layer rules: disable semantics, error accumulation, enable validation, missing directories.
mod common;

use common::{TempDir, set_in};
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

fn layers(tag: &str, specs: &[(&str, &str, &str)]) -> (TempDir, Vec<LayerInput>) {
    let root = tmp(tag);
    let ls = specs
        .iter()
        .map(|(n, f, b)| layer(&root, n, &[(f, b)]))
        .collect();
    (root, ls)
}

#[test]
fn disable_true_removes_the_frame_and_its_provenance() {
    let (_root, ls) = layers(
        "dis-prov",
        &[
            (
                "vendor",
                "a.toml",
                "[worker.x]\nexec=[\"/x\"]\n[worker.y]\nexec=[\"/y\"]",
            ),
            ("etc", "b.toml", "[worker.x]\ndisable=true"),
        ],
    );
    let m = load(&ls).expect("loads");
    assert!(m.table["worker"].as_table().expect("t").get("x").is_none());
    assert!(m.table["worker"].as_table().expect("t").get("y").is_some());
    assert_eq!(set_in(&m.provenance, "worker", "x", &["exec"]), None);
    assert_eq!(set_in(&m.provenance, "worker", "x", &[]), Some("etc"));
    assert_eq!(
        set_in(&m.provenance, "worker", "y", &["exec"]),
        Some("vendor")
    );
}

#[test]
fn a_later_layer_can_redefine_a_disabled_frame() {
    let (_root, ls) = layers(
        "redefine",
        &[
            ("vendor", "a.toml", "[worker.x]\nexec=[\"/x\"]"),
            ("etc", "b.toml", "[worker.x]\ndisable=true"),
            ("local", "c.toml", "[worker.x]\nexec=[\"/new\"]"),
        ],
    );
    let m = load(&ls).expect("loads");
    assert_eq!(m.table["worker"]["x"]["exec"][0].as_str(), Some("/new"));
    assert_eq!(
        set_in(&m.provenance, "worker", "x", &["exec"]),
        Some("local")
    );
}

#[test]
fn disable_true_discards_other_keys_in_the_same_table() {
    let (_root, ls) = layers(
        "dis-keys",
        &[
            ("vendor", "a.toml", "[worker.x]\nexec=[\"/x\"]"),
            (
                "etc",
                "b.toml",
                "[worker.x]\ndisable=true\nready=\"exit\"\nexec={append=[\"-v\"]}",
            ),
        ],
    );
    let m = load(&ls).expect("loads");
    assert!(m.table["worker"].as_table().expect("t").get("x").is_none());
    assert_eq!(set_in(&m.provenance, "worker", "x", &["ready"]), None);
}

#[test]
fn disable_of_an_absent_frame_is_accepted() {
    let (_root, ls) = layers(
        "dis-absent",
        &[("vendor", "a.toml", "[worker.ghost]\ndisable=true")],
    );
    let m = load(&ls).expect("loads");
    assert!(
        m.table
            .get("worker")
            .is_none_or(|w| w.as_table().expect("t").is_empty())
    );
}

#[test]
fn list_op_errors_from_different_layers_are_all_reported() {
    let (_root, ls) = layers(
        "listops",
        &[
            (
                "vendor",
                "a.toml",
                "[worker.x]\nexec=[\"/x\"]\n[worker.y]\nexec=[\"/y\"]",
            ),
            ("etc", "b.toml", "[worker.x]\nexec=[\"/z\"]"),
            ("local", "c.toml", "[worker.y]\nexec={remove=[\"-q\"]}"),
        ],
    );
    let e = load(&ls).unwrap_err();
    assert_eq!(e.len(), 2);
    assert!(e.iter().all(|x| x.code == Code::ListOp));
    assert_eq!(e[0].layer.as_deref(), Some("etc"));
    assert_eq!(e[1].layer.as_deref(), Some("local"));
}

#[test]
fn a_parse_error_stops_the_merge_but_not_the_reading() {
    // vendor is fine and merges. etc has a broken file plus an amend (a plain array over the
    // vendor list) that would be a ListOp error if etc were merged. local is still read.
    let root = tmp("stops");
    let ls = [
        layer(&root, "vendor", &[("a.toml", "[worker.x]\nexec=[\"/x\"]")]),
        layer(
            &root,
            "etc",
            &[
                ("a.toml", "[worker.x\n"),
                ("b.toml", "[worker.x]\nexec=[\"/y\"]"),
            ],
        ),
        layer(&root, "local", &[("c.toml", "[daemon.z]\n")]),
    ];
    let e = load(&ls).unwrap_err();
    let codes: Vec<_> = e.iter().map(|x| x.code).collect();
    assert_eq!(codes, [Code::Parse, Code::UnknownKey], "{e:?}");
    assert!(!codes.contains(&Code::ListOp));
}

#[test]
fn a_missing_layer_directory_is_an_io_error() {
    let root = tmp("missing");
    let ls = [LayerInput {
        name: "etc".into(),
        dir: root.join("nope"),
    }];
    let e = load(&ls).unwrap_err();
    assert_eq!(e[0].code, Code::Io);
    assert_eq!(e[0].layer.as_deref(), Some("etc"));
    assert_eq!(e[0].file.as_deref(), Some(root.join("nope").as_path()));
}

#[test]
fn a_scalar_enable_is_a_bad_value_naming_its_file_and_layer() {
    let (root, ls) = layers(
        "enable-scalar",
        &[
            ("vendor", "enable.toml", "enable=[\"a\"]"),
            ("etc", "enable.toml", "enable=\"sshd\""),
        ],
    );
    let e = load_enable(&ls).unwrap_err();
    assert_eq!(e.len(), 1);
    assert_eq!((e[0].code, e[0].key.as_str()), (Code::BadValue, "enable"));
    assert_eq!(e[0].layer.as_deref(), Some("etc"));
    assert_eq!(
        e[0].file.as_deref(),
        Some(root.join("etc/enable.toml").as_path())
    );
}

#[test]
fn a_scalar_syslog_is_a_bad_value() {
    let (_root, ls) = layers("syslog-scalar", &[("vendor", "enable.toml", "syslog=3")]);
    let e = load_enable(&ls).unwrap_err();
    assert_eq!((e[0].code, e[0].key.as_str()), (Code::BadValue, "syslog"));
    assert_eq!(e[0].layer.as_deref(), Some("vendor"));
}

#[test]
fn a_non_string_element_is_a_bad_value_from_the_layer_that_set_it() {
    let (root, ls) = layers(
        "enable-elem",
        &[
            ("vendor", "enable.toml", "enable=[\"a\"]"),
            ("etc", "enable.toml", "enable={append=[1]}"),
            ("local", "enable.toml", "syslog=[\"l\"]"),
        ],
    );
    let e = load_enable(&ls).unwrap_err();
    assert_eq!((e[0].code, e[0].key.as_str()), (Code::BadValue, "enable"));
    assert_eq!(e[0].layer.as_deref(), Some("etc"));
    assert_eq!(
        e[0].file.as_deref(),
        Some(root.join("etc/enable.toml").as_path())
    );
}

#[test]
fn a_bad_enable_element_is_blamed_on_the_last_layer_that_set_the_list() {
    // vendor wrote the bad element, but etc appended after it and is the last setter.
    let (_root, ls) = layers(
        "enable-last",
        &[
            ("vendor", "enable.toml", "enable=[\"a\", 1]"),
            ("etc", "enable.toml", "enable={append=[\"c\"]}"),
        ],
    );
    let e = load_enable(&ls).unwrap_err();
    assert_eq!((e[0].code, e[0].key.as_str()), (Code::BadValue, "enable"));
    assert_eq!(e[0].layer.as_deref(), Some("etc"));
}
