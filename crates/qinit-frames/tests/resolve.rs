// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Reference resolution, logger pipes, pre-syslog list, enable closure and limits.
mod common;

use common::{TempDir, enable, errs, idx, node, ok, run};
use qinit_db::{Edge, Group, GroupKind, Mode, RestartOn, Route, Target};
use qinit_frames::error::Code;
use qinit_frames::expand::expand;
use qinit_frames::layers::{Enable, LayerInput, load};
use qinit_frames::resolve::resolve;

fn logger_edge(to: u32) -> Group {
    Group {
        kind: GroupKind::RequireAll,
        edges: vec![Edge {
            target: Target::Node(to),
            mode: Mode::Sync,
            deadline_ms: 0,
            restart_on: RestartOn::None,
            stop_parallel: false,
        }],
    }
}

#[test]
fn a_require_all_edge_resolves_to_a_node_index() {
    let r = ok(r#"
        [worker.b]
        exec = ["/b"]
        deps = [{ group = "require_all", edges = [{ to = "a", restart_on = "error" }] }]
        [brood.a]
    "#);
    let m = &r.model;
    let g = &node(m, "b").groups[0];
    assert_eq!(g.kind, GroupKind::RequireAll);
    assert_eq!(g.edges[0].target, Target::Node(idx(m, "a")));
    assert_eq!(g.edges[0].mode, Mode::Sync);
    assert_eq!(g.edges[0].restart_on, RestartOn::Error);
}

#[test]
fn a_missing_require_target_is_missing_target() {
    let es = errs(
        r#"
        [worker.b]
        exec = ["/b"]
        deps = [{ group = "require_any", edges = [{ to = "nope" }] }]
        [worker.c]
        exec = ["/c"]
        deps = [{ group = "require_all", edges = [{ to = "gone" }] }]
    "#,
    );
    assert_eq!(es.len(), 2, "both frames are reported: {es:?}");
    assert!(es.iter().all(|e| e.code == Code::MissingTarget), "{es:?}");
    assert_eq!(es[0].key, "worker.b.deps[0].edges[0].to");
}

#[test]
fn a_target_masked_by_disable_is_missing_target_for_require() {
    let root = TempDir::new("mask");
    let mk = |name: &str, body: &str| {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("f.toml"), body).expect("write");
        LayerInput {
            name: name.into(),
            dir,
        }
    };
    let ls = [
        mk(
            "vendor",
            "[brood.a]\n[worker.b]\nexec = [\"/b\"]\n\
             deps = [{ group = \"require_all\", edges = [{ to = \"a\" }] }]\n",
        ),
        mk("etc", "[brood.a]\ndisable = true\n"),
    ];
    let m = load(&ls).expect("loads");
    let es = resolve(&expand(&m).expect("expands"), &Enable::default()).expect_err("refused");
    assert_eq!(es[0].code, Code::MissingTarget);
    assert_eq!(es[0].key, "worker.b.deps[0].edges[0].to");
}

#[test]
fn a_missing_optional_or_exclude_target_is_dropped_with_a_warning() {
    let r = ok(r#"
        [worker.b]
        exec = ["/b"]
        deps = [
          { group = "optional_all", edges = [{ to = "nope" }, { to = "a" }] },
          { group = "exclude_all", edges = [{ to = "gone" }] },
        ]
        [brood.a]
    "#);
    let b = node(&r.model, "b");
    assert_eq!(b.groups[0].edges.len(), 1);
    assert_eq!(b.groups[1].edges.len(), 0);
    assert_eq!(r.warnings.len(), 2, "{:?}", r.warnings);
    assert_eq!(r.warnings[0].key, "worker.b.deps[0].edges[0].to");
}

#[test]
fn a_logger_pipe_adds_an_implicit_sync_require_all_edge() {
    let r = ok(r#"
        [worker.app]
        exec = ["/app"]
        output = { pipe = "log" }
        [worker.log]
        exec = ["/log"]
    "#);
    let m = &r.model;
    let app = node(m, "app");
    assert_eq!(app.groups, [logger_edge(idx(m, "log"))]);
    assert_eq!(
        m.routes[app.output.expect("route") as usize],
        Route::Pipe(idx(m, "log"))
    );
}

#[test]
fn a_worker_that_is_its_own_logger_is_a_cycle() {
    let es = errs("[worker.a]\nexec = [\"/a\"]\nerrors = { pipe = \"a\" }\n");
    assert_eq!(es[0].code, Code::Cycle);
    assert_eq!(es[0].key, "worker.a.errors");
}

#[test]
fn a_pipe_to_a_non_worker_is_bad_value() {
    let es = errs(
        r#"
        [worker.a]
        exec = ["/a"]
        output = { pipe = "b" }
        [brood.b]
        [worker.c]
        exec = ["/c"]
        output = { pipe = "nobody" }
    "#,
    );
    assert_eq!(es.len(), 2, "{es:?}");
    assert_eq!(es[0].code, Code::BadValue);
    assert_eq!(es[0].key, "worker.a.output");
    assert_eq!(es[1].code, Code::MissingTarget);
}

#[test]
fn a_pipe_route_is_shared_per_producer_and_path_routes_are_interned() {
    let r = ok(r#"
        [worker.a]
        exec = ["/a"]
        output = { pipe = "log" }
        errors = { pipe = "log" }
        [worker.b]
        exec = ["/b"]
        output = { pipe = "log" }
        [worker.c]
        exec = ["/c"]
        output = "/dev/console"
        [worker.d]
        exec = ["/d"]
        output = "/dev/console"
        errors = "/var/log/d"
        [worker.log]
        exec = ["/log"]
    "#);
    let m = &r.model;
    let (na, nb, nc, nd) = (node(m, "a"), node(m, "b"), node(m, "c"), node(m, "d"));
    assert_eq!(
        na.output, na.errors,
        "one route for a producer's two streams"
    );
    assert_ne!(na.output, nb.output, "each producer has its own pipe route");
    assert_eq!(na.groups.len(), 1, "one implicit group for one logger");
    assert_eq!(nc.output, nd.output, "equal paths share a route");
    assert_ne!(nd.output, nd.errors);
    assert_eq!(m.routes.len(), 4);
}

#[test]
fn errors_defaults_to_output() {
    let r =
        ok("[worker.a]\nexec = [\"/a\"]\noutput = \"/dev/console\"\n[worker.b]\nexec = [\"/b\"]\n");
    let (a, b) = (node(&r.model, "a"), node(&r.model, "b"));
    assert!(a.output.is_some());
    assert_eq!(a.errors, a.output);
    assert_eq!((b.output, b.errors), (None, None));
}

#[test]
fn workers_before_any_syslog_worker_are_listed() {
    let src = r#"
        [worker.early]
        exec = ["/e"]
        [worker.syslog-ng]
        exec = ["/s"]
        [worker.late]
        exec = ["/l"]
        deps = [{ group = "require_all", edges = [{ to = "mid" }] }]
        [brood.mid]
        deps = [{ group = "require_any", edges = [{ to = "syslog-ng" }] }]
        [brood.boot]
        deps = [{ group = "require_all", edges = [{ to = "early" }, { to = "late" }] }]
    "#;
    let r = run(src, &enable(&["boot"], &["syslog-ng"])).expect("resolves");
    let m = &r.model;
    assert_eq!(m.presyslog, [idx(m, "early")]);
    let r = run(src, &enable(&["boot"], &[])).expect("resolves");
    assert!(r.model.presyslog.is_empty());
    let es = run(src, &enable(&["boot"], &["mid"])).expect_err("not a worker");
    assert_eq!(es[0].code, Code::BadValue);
    let es = run(src, &enable(&["boot"], &["nope"])).expect_err("missing");
    assert_eq!(es[0].code, Code::MissingTarget);
}

#[test]
fn the_enable_closure_follows_require_edges_only() {
    let src = r#"
        [brood.root]
        deps = [
          { group = "require_all", edges = [{ to = "a" }] },
          { group = "require_any", edges = [{ to = "b" }] },
          { group = "optional_all", edges = [{ to = "opt" }] },
          { group = "exclude_all", edges = [{ to = "ex" }] },
        ]
        [worker.a]
        exec = ["/a"]
        output = { pipe = "log" }
        [worker.b]
        exec = ["/b"]
        deps = [{ group = "require_all", edges = [{ to = "c", mode = "async" }, { path = "/run/x" }] }]
        [worker.c]
        exec = ["/c"]
        [worker.log]
        exec = ["/log"]
        [worker.opt]
        exec = ["/o"]
        [worker.ex]
        exec = ["/x"]
        [worker.other]
        exec = ["/y"]
    "#;
    let r = run(src, &enable(&["root"], &[])).expect("resolves");
    let m = &r.model;
    let mut want: Vec<u32> = ["root", "a", "b", "c", "log"]
        .iter()
        .map(|n| idx(m, n))
        .collect();
    want.sort_unstable();
    assert_eq!(m.enabled, want);
}

#[test]
fn an_enable_entry_naming_no_frame_is_missing_target() {
    let es = run("[brood.a]\n", &enable(&["a", "nope", "gone"], &[])).expect_err("refused");
    assert_eq!(es.len(), 2, "{es:?}");
    assert!(
        es.iter()
            .all(|e| e.code == Code::MissingTarget && e.key == "enable")
    );
}

#[test]
fn a_sync_edge_with_a_deadline_is_bad_value() {
    let es = errs(
        r#"
        [worker.b]
        exec = ["/b"]
        deps = [{ group = "require_all", edges = [{ to = "a", deadline = "1s" }] }]
        [brood.a]
    "#,
    );
    assert_eq!(es[0].code, Code::BadValue);
}

#[test]
fn a_zero_deadline_async_edge_is_optional() {
    let r = ok(r#"
        [worker.b]
        exec = ["/b"]
        deps = [{ group = "require_all", edges = [
          { to = "a", mode = "async", deadline = "0s" },
          { to = "a", mode = "async" },
          { to = "a", mode = "async", deadline = "2s" },
        ] }]
        [brood.a]
    "#);
    let e = &node(&r.model, "b").groups[0].edges;
    assert_eq!((e[0].mode, e[0].deadline_ms), (Mode::Async, 0));
    assert_eq!(e[1].deadline_ms, 0);
    assert_eq!(e[2].deadline_ms, 2000);
}

#[test]
fn unknown_caps_and_namespaces_are_bad_values() {
    let es = errs(
        r#"
        [worker.a]
        exec = ["/a"]
        credentials = { uid = "a", caps = ["net_bind_service", "fly"] }
        [worker.b]
        exec = ["/b"]
        sandbox = { namespaces = ["mount", "time"] }
    "#,
    );
    assert_eq!(es.len(), 2, "{es:?}");
    assert!(es.iter().all(|e| e.code == Code::BadValue), "{es:?}");
    assert_eq!(es[0].key, "worker.a.credentials.caps");
    assert_eq!(es[1].key, "worker.b.sandbox.namespaces");
}

#[test]
fn more_nodes_than_the_limit_is_a_limit_error() {
    use std::fmt::Write as _;
    let mut src = String::new();
    for i in 0..4097 {
        let _ = write!(src, "[worker.w{i}]\nexec = [\"/w\"]\n");
    }
    let es = errs(&src);
    assert_eq!(es.len(), 1, "{es:?}");
    assert_eq!(es[0].code, Code::Limit);
    assert!(es[0].detail.contains("nodes"), "{}", es[0].detail);
}

#[test]
fn stop_parallel_on_a_hard_edge_is_refused_at_resolve() {
    let es = errs(
        r#"
        [worker.b]
        exec = ["/b"]
        deps = [{ group = "require_all", edges = [{ to = "a", stop = "parallel" }] }]
        [brood.a]
    "#,
    );
    assert_eq!(es[0].code, Code::HardParallel);
    assert_eq!(es[0].key, "worker.b.deps[0].edges[0].stop");
    let r = ok(r#"
        [worker.b]
        exec = ["/b"]
        deps = [
          { group = "require_all", edges = [{ to = "a", mode = "async", stop = "parallel" }] },
          { group = "optional_all", edges = [{ to = "a", stop = "parallel" }] },
        ]
        [brood.a]
    "#);
    assert!(
        node(&r.model, "b")
            .groups
            .iter()
            .all(|g| g.edges[0].stop_parallel)
    );
}
