// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The restart delay, stop table, start timeout and edge cascade keys (sub-project 4): schema
//! rules, resolved defaults, the derived restart window and its warning, layer interplay.
mod common;

use common::{Tree, node, ok};
use qinit_db::StopMode;
use qinit_frames::compile::compile;
use qinit_frames::error::Code;
use qinit_frames::schema::{Frame, parse_frame};

fn parse(kind: &str, src: &str) -> Result<Frame, qinit_frames::error::Error> {
    let v = toml::Value::Table(src.parse::<toml::Table>().expect("test toml"));
    parse_frame(kind, "t", &v)
}

fn refused(kind: &str, src: &str, key: &str) {
    let e = parse(kind, src).expect_err(src);
    assert_eq!(
        (e.code, e.key.as_str()),
        (Code::BadValue, key),
        "{src}: {e:?}"
    );
}

#[test]
fn stop_and_start_timeout_are_banned_on_a_brood() {
    refused("brood", "stop = { mode = \"cell\" }", "brood.t.stop");
    refused("brood", "start_timeout = \"5s\"", "brood.t.start_timeout");
}

#[test]
fn a_delay_or_grace_under_100ms_is_refused() {
    let w = "exec = [\"/x\"]\n";
    refused(
        "worker",
        &format!("{w}restart = {{ policy = \"always\", delay = \"99ms\" }}"),
        "worker.t.restart.delay",
    );
    refused(
        "worker",
        &format!("{w}stop = {{ grace = \"99ms\" }}"),
        "worker.t.stop.grace",
    );
    parse(
        "worker",
        &format!("{w}restart = {{ policy = \"always\", delay = \"100ms\" }}\nstop = {{ grace = \"100ms\" }}"),
    )
    .expect("100 ms is the floor");
}

#[test]
fn a_bad_stop_mode_or_start_timeout_is_refused() {
    let w = "exec = [\"/x\"]\n";
    refused(
        "worker",
        &format!("{w}stop = {{ mode = \"both\" }}"),
        "worker.t.stop.mode",
    );
    refused(
        "worker",
        &format!("{w}start_timeout = \"soon\""),
        "worker.t.start_timeout",
    );
}

#[test]
fn cascade_is_for_a_require_all_edge_to_a_frame() {
    let edge = |group: &str, target: &str| {
        format!(
            "exec = [\"/x\"]\ndeps = [{{ group = \"{group}\", edges = [{{ {target}, cascade = true }}] }}]"
        )
    };
    let key = "worker.t.deps[0].edges[0].cascade";
    refused("worker", &edge("require_any", "to = \"b\""), key);
    refused("worker", &edge("optional_all", "to = \"b\""), key);
    refused("worker", &edge("require_all", "path = \"/run/x\""), key);
    parse("worker", &edge("require_all", "to = \"b\"")).expect("allowed");
}

#[test]
fn restart_and_stop_defaults_resolve() {
    let r = ok(r#"
        [worker.a]
credentials = { uid = "svc" }
        exec = ["/a"]
        [worker.oneshot]
credentials = { uid = "svc" }
        exec = ["/o"]
        ready = "exit"
        [forager.f]
credentials = { uid = "svc" }
        exec = ["/f"]
        [brood.b]
    "#);
    let m = &r.model;
    for name in ["a", "oneshot", "f"] {
        let n = node(m, name);
        assert_eq!(n.restart.delay_ms, 1000, "{name}");
        assert_eq!(n.restart.window_ms, 0, "{name}");
        assert_eq!(
            (n.stop.mode, n.stop.grace_ms),
            (StopMode::Main, 10_000),
            "{name}"
        );
    }
    assert_eq!(node(m, "a").start_timeout_ms, 90_000);
    assert_eq!(node(m, "oneshot").start_timeout_ms, 0);
    assert_eq!(node(m, "f").start_timeout_ms, 0);
}

#[test]
fn explicit_stop_start_timeout_and_delay_resolve_and_inherit_from_a_template() {
    let r = ok(r#"
        [template.t]
        stop = { mode = "cell", grace = "3s" }
        start_timeout = "5s"
        restart = { policy = "always", delay = "250ms" }
        [worker.a]
credentials = { uid = "svc" }
        exec = ["/a"]
        template = "t"
        [worker.b]
credentials = { uid = "svc" }
        exec = ["/b"]
        template = "t"
        start_timeout = "0s"
    "#);
    let m = &r.model;
    let a = node(m, "a");
    assert_eq!(
        (a.stop.mode, a.stop.grace_ms, a.start_timeout_ms),
        (StopMode::Cell, 3000, 5000)
    );
    assert_eq!(a.restart.delay_ms, 250);
    assert_eq!(node(m, "b").start_timeout_ms, 0);
}

#[test]
fn an_omitted_window_is_derived_from_max_and_delay() {
    let r = ok(r#"
        [worker.a]
credentials = { uid = "svc" }
        exec = ["/a"]
        restart = { policy = "on-failure", max = 5 }
        [worker.b]
credentials = { uid = "svc" }
        exec = ["/b"]
        restart = { policy = "on-failure", max = 3, delay = "200ms" }
        [worker.c]
credentials = { uid = "svc" }
        exec = ["/c"]
        restart = { policy = "always" }
    "#);
    let m = &r.model;
    assert_eq!(node(m, "a").restart.window_ms, 50_000);
    assert_eq!(node(m, "b").restart.window_ms, 6_000);
    assert_eq!(node(m, "c").restart.window_ms, 0);
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
}

#[test]
fn a_window_shorter_than_the_backoff_up_to_max_warns() {
    // 1 + 2 + 4 + 8 + 10 = 25 s of delays before the fifth restart.
    let src = |window: &str| {
        format!(
            "[worker.a]\ncredentials = {{ uid = \"svc\" }}\nexec = [\"/a\"]\nrestart = {{ policy = \"on-failure\", max = 5, window = \"{window}\" }}\n"
        )
    };
    let r = ok(&src("10s"));
    assert_eq!(r.warnings.len(), 1, "{:?}", r.warnings);
    assert_eq!(r.warnings[0].key, "worker.a.restart.window");
    assert_eq!(node(&r.model, "a").restart.window_ms, 10_000);
    assert!(ok(&src("25s")).warnings.is_empty());
}

#[test]
fn cascade_reaches_the_edge() {
    let r = ok(r#"
        [worker.b]
credentials = { uid = "svc" }
        exec = ["/b"]
        [worker.a]
credentials = { uid = "svc" }
        exec = ["/a"]
        deps = [{ group = "require_all", edges = [{ to = "b", cascade = true }, { to = "b" }] }]
    "#);
    let edges = &node(&r.model, "a").groups[0].edges;
    assert!(edges[0].cascade);
    assert!(!edges[1].cascade);
}

#[test]
fn a_window_set_across_layers_is_derived_after_the_merge() {
    let t = Tree::new("sp4-window-layers");
    t.file(
        "vendor",
        "f.toml",
        "[worker.a]\ncredentials = { uid = \"svc\" }\nexec = [\"/a\"]\nrestart = { policy = \"on-failure\" }\n",
    );
    t.file(
        "etc",
        "f.toml",
        "[worker.a]\ncredentials = { uid = \"svc\" }\nrestart = { max = 4 }\n",
    );
    t.file("etc", "enable.toml", "enable = [\"a\"]\n");
    let c = compile(&t.input(&["vendor", "etc"])).expect("compiles");
    let m = qinit_db::open(&c.bytes).expect("validates").decode();
    assert_eq!(node(&m, "a").restart.max, 4);
    assert_eq!(node(&m, "a").restart.window_ms, 40_000);

    t.file(
        "etc",
        "f.toml",
        "[worker.a]\ncredentials = { uid = \"svc\" }\nrestart = { max = 4, window = \"5s\" }\n",
    );
    let c = compile(&t.input(&["vendor", "etc"])).expect("compiles");
    let m = qinit_db::open(&c.bytes).expect("validates").decode();
    assert_eq!(node(&m, "a").restart.window_ms, 5_000);
    assert_eq!(c.warnings.len(), 1, "{:?}", c.warnings);
}
