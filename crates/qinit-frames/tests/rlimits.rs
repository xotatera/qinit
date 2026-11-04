// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The `rlimits` frame table: every kernel resource but `core`, with units and `"infinity"`.
mod common;

use common::{Tree, errs, node, ok};
use qinit_frames::compile::compile;
use qinit_frames::error::Code;

fn worker(limits: &str) -> String {
    format!(
        "[worker.a]\nexec = [\"/a\"]\ncredentials = {{ uid = \"svc\" }}\nrlimits = {{ {limits} }}\n"
    )
}

#[test]
fn every_key_compiles_into_the_node() {
    let r = ok(&worker(
        "cpu = 10, fsize = 20, data = 30, stack = \"infinity\", rss = \"1K\", nproc = 60, \
         nofile = 70, memlock = \"64M\", as = \"2G\", locks = 100, sigpending = 110, \
         msgqueue = \"1M\", nice = 40, rtprio = 0, rttime = 150",
    ));
    let l = node(&r.model, "a").rlimits;
    assert_eq!(l[0], Some(10));
    assert_eq!(l[1], Some(20));
    assert_eq!(l[2], Some(30));
    assert_eq!(l[3], Some(u64::MAX));
    assert_eq!(l[4], None);
    assert_eq!(l[5], Some(1024));
    assert_eq!(l[6], Some(60));
    assert_eq!(l[7], Some(70));
    assert_eq!(l[8], Some(67_108_864));
    assert_eq!(l[9], Some(2 << 30));
    assert_eq!(l[10], Some(100));
    assert_eq!(l[11], Some(110));
    assert_eq!(l[12], Some(1 << 20));
    assert_eq!(l[13], Some(40));
    assert_eq!(l[14], Some(0));
    assert_eq!(l[15], Some(150));
}

#[test]
fn no_rlimits_table_sets_nothing() {
    let r = ok("[worker.a]\nexec = [\"/a\"]\ncredentials = { uid = \"svc\" }\n");
    assert_eq!(node(&r.model, "a").rlimits, [None; 16]);
}

fn only(src: &str, code: Code, key: &str) {
    let es = errs(src);
    assert_eq!(es.len(), 1, "{es:?}");
    assert_eq!((es[0].code, es[0].key.as_str()), (code, key), "{es:?}");
}

#[test]
fn core_is_an_unknown_key() {
    only(
        &worker("core = 0"),
        Code::UnknownKey,
        "worker.a.rlimits.core",
    );
}

#[test]
fn nofile_infinity_is_an_error() {
    only(
        &worker("nofile = \"infinity\""),
        Code::BadValue,
        "worker.a.rlimits.nofile",
    );
}

#[test]
fn nofile_zero_is_an_error() {
    only(
        &worker("nofile = 0"),
        Code::BadValue,
        "worker.a.rlimits.nofile",
    );
}

#[test]
fn nice_41_is_an_error() {
    only(
        &worker("nice = 41"),
        Code::BadValue,
        "worker.a.rlimits.nice",
    );
}

#[test]
fn rtprio_100_is_an_error() {
    only(
        &worker("rtprio = 100"),
        Code::BadValue,
        "worker.a.rlimits.rtprio",
    );
}

#[test]
fn a_size_on_a_count_key_is_an_error() {
    only(
        &worker("nproc = \"64M\""),
        Code::BadValue,
        "worker.a.rlimits.nproc",
    );
}

#[test]
fn a_bad_size_on_a_byte_key_is_an_error() {
    only(
        &worker("memlock = \"lots\""),
        Code::BadValue,
        "worker.a.rlimits.memlock",
    );
}

#[test]
fn rlimits_on_a_brood_is_an_error() {
    only(
        "[brood.a]\nrlimits = { nproc = 1 }\n",
        Code::BadValue,
        "brood.a.rlimits",
    );
}

#[test]
fn frame_rlimits_replace_the_template_table() {
    let r = ok(r#"
        [template.t]
        rlimits = { nofile = 100, stack = "8M" }
        [worker.a]
        template = "t"
        exec = ["/a"]
        credentials = { uid = "svc" }
        rlimits = { nproc = 5 }
        [worker.b]
        template = "t"
        exec = ["/b"]
        credentials = { uid = "svc" }
    "#);
    let a = node(&r.model, "a").rlimits;
    assert_eq!((a[6], a[7], a[3]), (Some(5), None, None));
    let b = node(&r.model, "b").rlimits;
    assert_eq!((b[6], b[7], b[3]), (None, Some(100), Some(8 << 20)));
}

#[test]
fn dump_prints_every_set_limit() {
    let t = Tree::new("rlimits-dump");
    t.file(
        "vendor",
        "a.toml",
        &worker("memlock = \"64M\", stack = \"infinity\", nice = 3"),
    );
    let c = compile(&t.input(&["vendor"])).expect("compiles");
    for line in [
        "rlimits.memlock = 67108864",
        "rlimits.stack = infinity",
        "rlimits.nice = 3",
    ] {
        assert!(
            c.dump.lines().any(|l| l.trim_start().starts_with(line)),
            "{line}: {}",
            c.dump
        );
    }
    assert!(!c.dump.contains("rlimits.nofile"), "{}", c.dump);
}

#[test]
fn a_size_beyond_four_tib_is_accepted_for_a_byte_limit() {
    let r = ok(&worker("memlock = \"5000G\""));
    assert_eq!(node(&r.model, "a").rlimits[8], Some(5000 << 30));
}

#[test]
fn a_limit_of_the_wrong_shape_does_not_name_an_internal_type() {
    for v in ["-1", "1.5"] {
        let es = errs(&worker(&format!("nice = {v}")));
        assert!(!es.is_empty(), "{v}");
        assert!(
            es.iter().all(|e| !e.detail.contains("untagged enum")),
            "{es:?}"
        );
    }
}
