// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Errors found after the merge carry the file and layer of the frame key they name.
mod common;

use common::Tree;
use qinit_frames::compile::compile;
use qinit_frames::error::{Code, Error};

fn one(es: &[Error]) -> &Error {
    assert_eq!(es.len(), 1, "{es:?}");
    &es[0]
}

#[test]
fn a_resolve_error_carries_the_file_that_set_the_key() {
    let t = Tree::new("loc-resolve");
    t.file("vendor", "a.toml", "[worker.a]\nexec = [\"/a\"]\n");
    t.file(
        "etc",
        "a.toml",
        "[worker.a]\noutput = { pipe = \"nope\" }\n",
    );
    let es = compile(&t.input(&["vendor", "etc"])).expect_err("refused");
    let e = one(&es);
    assert_eq!(
        (e.code, e.key.as_str()),
        (Code::MissingTarget, "worker.a.output")
    );
    assert_eq!(e.layer.as_deref(), Some("etc"));
    assert_eq!(e.file, Some(t.root.join("etc/a.toml")));
}

#[test]
fn a_policy_error_carries_the_file_of_the_credentials() {
    let t = Tree::new("loc-policy");
    t.file("vendor", "a.toml", "[worker.a]\nexec = [\"/a\"]\n");
    t.file(
        "etc",
        "a.toml",
        "[worker.a]\ncredentials = { uid = \"root\", caps = [\"sys_admin\"] }\n",
    );
    t.file(
        "vendor",
        "f.toml",
        "[forager.f]\nexec = [\"/f\"]\ncredentials = { uid = \"root\" }\n",
    );
    let policy = t.root.join("policy.toml");
    std::fs::write(&policy, "default = \"deny\"\n[[rule]]\nmatch = \"a\"\n").expect("policy");
    let mut input = t.input(&["vendor", "etc"]);
    input.policy = Some(policy);
    let es = compile(&input).expect_err("refused");
    assert_eq!(es.len(), 2, "{es:?}");
    assert!(es.iter().all(|e| e.code == Code::Policy), "{es:?}");
    let a = es
        .iter()
        .find(|e| e.key == "worker.a.credentials")
        .expect("a");
    assert_eq!(a.layer.as_deref(), Some("etc"));
    assert_eq!(a.file, Some(t.root.join("etc/a.toml")));
    // A forager's policy error is keyed by its own kind, so it is located too.
    let f = es
        .iter()
        .find(|e| e.key == "forager.f.credentials")
        .expect("f");
    assert_eq!(f.layer.as_deref(), Some("vendor"));
    assert_eq!(f.file, Some(t.root.join("vendor/f.toml")));
}

#[test]
fn a_cycle_error_carries_the_file_of_its_first_frame() {
    let t = Tree::new("loc-cycle");
    let dep = |to: &str| {
        format!("deps = [{{ group = \"require_all\", edges = [{{ to = \"{to}\" }}] }}]\n")
    };
    t.file(
        "vendor",
        "a.toml",
        &format!("[worker.a]\nexec = [\"/a\"]\n{}", dep("b")),
    );
    t.file(
        "vendor",
        "b.toml",
        &format!("[worker.b]\nexec = [\"/b\"]\n{}", dep("a")),
    );
    let es = compile(&t.input(&["vendor"])).expect_err("refused");
    let e = one(&es);
    assert_eq!((e.code, e.key.as_str()), (Code::Cycle, "worker.a"));
    assert_eq!(e.layer.as_deref(), Some("vendor"));
    assert_eq!(e.file, Some(t.root.join("vendor/a.toml")));
}

#[test]
fn an_error_on_an_inherited_key_carries_the_template_file() {
    let t = Tree::new("loc-template");
    t.file("vendor", "t.toml", "[template.t]\nexec = [\"/x\"]\n");
    t.file("etc", "b.toml", "[brood.b]\ntemplate = \"t\"\n");
    let es = compile(&t.input(&["vendor", "etc"])).expect_err("refused");
    let e = one(&es);
    assert_eq!((e.code, e.key.as_str()), (Code::BadValue, "brood.b.exec"));
    assert_eq!(e.layer.as_deref(), Some("vendor"));
    assert_eq!(e.file, Some(t.root.join("vendor/t.toml")));
}

#[test]
fn an_instance_error_carries_the_file_of_its_frame() {
    let t = Tree::new("loc-instance");
    t.file(
        "vendor",
        "g.toml",
        "[worker.g]\nexec = [\"/g\", \"%i\"]\ninstances = [\"x\"]\n",
    );
    t.file("etc", "g.toml", "[worker.g]\nready = { path = \"\" }\n");
    let es = compile(&t.input(&["vendor", "etc"])).expect_err("refused");
    let e = one(&es);
    assert_eq!(
        (e.code, e.key.as_str()),
        (Code::BadValue, "worker.g@x.ready")
    );
    assert_eq!(e.layer.as_deref(), Some("etc"));
    assert_eq!(e.file, Some(t.root.join("etc/g.toml")));
}
