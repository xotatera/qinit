// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The compile pipeline end to end: bytes, determinism, provenance in the dump, warnings and
//! error accumulation.
mod common;

use common::{Tree, golden_dir, golden_input};
use qinit_frames::compile::compile;
use qinit_frames::error::Code;

const SSHD: &str = r#"
[worker.sshd]
exec = ["/usr/sbin/sshd", "-D"]
restart = { policy = "on-failure", max = 3, window = "60s" }
cell = { pids_max = 64 }
"#;

#[test]
fn a_minimal_tree_compiles_and_the_bytes_validate() {
    let t = Tree::new("pipe-min");
    t.file("vendor", "a.toml", "[worker.a]\nexec = [\"/a\"]\n");
    let c = compile(&t.input(&["vendor"])).expect("compiles");
    let r = qinit_db::open(&c.bytes).expect("validates");
    let m = r.decode();
    assert_eq!(m.nodes.len(), 1);
    assert_eq!(m.nodes[0].name, "a");
    assert!(c.warnings.is_empty());
    assert!(c.dump.starts_with("worker a\n"), "{}", c.dump);
}

#[test]
fn compile_is_deterministic_across_runs_and_file_creation_order() {
    let files = [
        ("a.toml", "[worker.a]\nexec = [\"/a\"]\n"),
        (
            "b.toml",
            "[worker.b]\nexec = [\"/b\"]\n\
             deps = [{ group = \"require_all\", edges = [{ to = \"a\" }] }]\n",
        ),
        ("c.toml", "[brood.c]\n"),
        ("enable.toml", "enable = [\"b\", \"c\"]\n"),
    ];
    let one = Tree::new("pipe-det-1");
    for (f, body) in files {
        one.file("vendor", f, body);
    }
    let two = Tree::new("pipe-det-2");
    for (f, body) in files.iter().rev() {
        two.file("vendor", f, body);
    }
    let a = compile(&one.input(&["vendor"])).expect("compiles");
    let b = compile(&one.input(&["vendor"])).expect("compiles");
    let c = compile(&two.input(&["vendor"])).expect("compiles");
    assert_eq!(a.bytes, b.bytes);
    assert_eq!(a.bytes, c.bytes);
    assert_eq!(a.dump, c.dump);
}

#[test]
fn an_etc_amend_changes_only_the_amended_key() {
    let t = Tree::new("pipe-amend");
    t.file("vendor", "sshd.toml", SSHD);
    t.file("etc", "sshd.toml", "[worker.sshd]\nrestart = { max = 9 }\n");
    let c = compile(&t.input(&["vendor", "etc"])).expect("compiles");
    let m = qinit_db::open(&c.bytes).expect("validates").decode();
    assert_eq!(m.nodes[0].restart.max, 9);
    assert_eq!(m.nodes[0].restart.window_ms, 60_000);
    // The node's indented `key = value  # layer` lines; the trailer lines are not keyed.
    let lines: Vec<&str> = c
        .dump
        .lines()
        .filter(|l| l.starts_with("  ") && l.contains(" = "))
        .collect();
    assert!(lines.len() > 3, "{}", c.dump);
    let max = lines
        .iter()
        .find(|l| l.trim_start().starts_with("restart.max ="))
        .expect("restart.max line");
    assert!(max.ends_with("  # etc"), "{max}");
    for l in lines
        .iter()
        .filter(|l| !l.trim_start().starts_with("restart.max"))
    {
        assert!(l.ends_with("  # vendor"), "{l}");
    }
}

#[test]
fn the_dump_is_stable() {
    let c = compile(&golden_input()).expect("golden compiles");
    let want = std::fs::read_to_string(golden_dir().join("expected.dump")).expect("expected.dump");
    assert_eq!(c.dump, want);
}

#[test]
fn warnings_report_dropped_optional_edges() {
    let t = Tree::new("pipe-warn");
    t.file(
        "vendor",
        "a.toml",
        "[worker.a]\nexec = [\"/a\"]\n\
         deps = [{ group = \"optional_all\", edges = [{ to = \"nope\" }] }]\n",
    );
    let c = compile(&t.input(&["vendor"])).expect("compiles");
    assert_eq!(c.warnings.len(), 1, "{:?}", c.warnings);
    assert_eq!(c.warnings[0].key, "worker.a.deps[0].edges[0].to");
}

#[test]
fn every_error_from_a_failing_stage_is_returned_together() {
    let t = Tree::new("pipe-errs");
    t.file(
        "vendor",
        "a.toml",
        "[worker.a]\nexec = [\"/a\"]\nrestart = { policy = \"sometimes\" }\n",
    );
    t.file(
        "vendor",
        "b.toml",
        "[worker.b]\nexec = [\"/b\"]\ncell = { memory_max = \"lots\" }\n",
    );
    let es = compile(&t.input(&["vendor"])).expect_err("refused");
    assert_eq!(es.len(), 2, "{es:?}");
    assert!(es.iter().all(|e| e.code == Code::BadValue), "{es:?}");
    let keys: Vec<&str> = es.iter().map(|e| e.key.as_str()).collect();
    assert!(keys.contains(&"worker.a.restart.policy"), "{keys:?}");
    assert!(keys.contains(&"worker.b.cell.memory_max"), "{keys:?}");
}
