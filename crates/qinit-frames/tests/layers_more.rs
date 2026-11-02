// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Layer rules: disable semantics, error accumulation, enable validation, missing directories.
use qinit_frames::error::Code;
use qinit_frames::layers::{LayerInput, load, load_enable};
use std::path::{Path, PathBuf};

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

fn tmp(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("qinit-frames-more-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("mkdir");
    p
}

fn layers(tag: &str, specs: &[(&str, &str, &str)]) -> (PathBuf, Vec<LayerInput>) {
    let root = tmp(tag);
    let ls = specs
        .iter()
        .map(|(n, f, b)| layer(&root, n, &[(f, b)]))
        .collect();
    (root, ls)
}

#[test]
fn disable_true_removes_the_frame_and_its_provenance() {
    let (root, ls) = layers(
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
    assert!(!m.provenance.contains_key("worker.x.exec"));
    assert_eq!(m.provenance["worker.x"], "etc");
    assert_eq!(m.provenance["worker.y.exec"], "vendor");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_later_layer_can_redefine_a_disabled_frame() {
    let (root, ls) = layers(
        "redefine",
        &[
            ("vendor", "a.toml", "[worker.x]\nexec=[\"/x\"]"),
            ("etc", "b.toml", "[worker.x]\ndisable=true"),
            ("local", "c.toml", "[worker.x]\nexec=[\"/new\"]"),
        ],
    );
    let m = load(&ls).expect("loads");
    assert_eq!(m.table["worker"]["x"]["exec"][0].as_str(), Some("/new"));
    assert_eq!(m.provenance["worker.x.exec"], "local");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn disable_true_discards_other_keys_in_the_same_table() {
    let (root, ls) = layers(
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
    assert!(!m.provenance.contains_key("worker.x.ready"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn disable_of_an_absent_frame_is_accepted() {
    let (root, ls) = layers(
        "dis-absent",
        &[("vendor", "a.toml", "[worker.ghost]\ndisable=true")],
    );
    let m = load(&ls).expect("loads");
    assert!(
        m.table
            .get("worker")
            .is_none_or(|w| w.as_table().expect("t").is_empty())
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn list_op_errors_from_different_layers_are_all_reported() {
    let (root, ls) = layers(
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
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_parse_error_stops_the_merge_but_not_the_reading() {
    let (root, ls) = layers(
        "stops",
        &[
            ("vendor", "a.toml", "[worker.x\n"),
            ("etc", "b.toml", "[worker.y]\nexec=[\"/y\"]"),
            ("local", "c.toml", "[daemon.z]\n"),
        ],
    );
    let e = load(&ls).unwrap_err();
    assert_eq!(
        e.iter().map(|x| x.code).collect::<Vec<_>>(),
        [Code::Parse, Code::UnknownKey]
    );
    let _ = std::fs::remove_dir_all(&root);
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
    let _ = std::fs::remove_dir_all(&root);
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
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_scalar_syslog_is_a_bad_value() {
    let (root, ls) = layers("syslog-scalar", &[("vendor", "enable.toml", "syslog=3")]);
    let e = load_enable(&ls).unwrap_err();
    assert_eq!((e[0].code, e[0].key.as_str()), (Code::BadValue, "syslog"));
    assert_eq!(e[0].layer.as_deref(), Some("vendor"));
    let _ = std::fs::remove_dir_all(&root);
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
    let _ = std::fs::remove_dir_all(&root);
}
