// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `resolve` is public, so it refuses a hand-built `Expanded` that `schema::parse_frame` would
//! have rejected, instead of mapping a bad word to a default.
use qinit_db::Kind;
use qinit_frames::error::{Code, Error};
use qinit_frames::expand::Expanded;
use qinit_frames::layers::Enable;
use qinit_frames::resolve::resolve;
use qinit_frames::schema::Frame;

/// Resolves a worker `a` built from `body` (frame TOML, unchecked; its user is added) next to a
/// valid worker `b`.
fn refused(body: &str) -> Vec<Error> {
    let frame = |s: &str| {
        toml::from_str::<Frame>(&format!("{s}\ncredentials = {{ uid = \"svc\" }}\n"))
            .expect("frame shape")
    };
    let expanded = Expanded {
        frames: vec![
            ("a".to_owned(), Kind::Worker, frame(body)),
            ("b".to_owned(), Kind::Worker, frame("exec = [\"/b\"]")),
        ],
        ..Expanded::default()
    };
    resolve(&expanded, &Enable::default()).expect_err("refused")
}

/// Worker `a` with one edge `edge` in a group of kind `group`.
fn edge_frame(group: &str, edge: &str) -> String {
    format!("exec = [\"/a\"]\ndeps = [{{ group = \"{group}\", edges = [{{ {edge} }}] }}]")
}

/// `body` is refused with exactly one error, a `BadValue` at `key`.
fn only_bad(body: &str, key: &str) {
    let e = refused(body);
    assert_eq!(e.len(), 1, "{e:?}");
    assert_eq!((e[0].code, e[0].key.as_str()), (Code::BadValue, key));
}

#[test]
fn an_unknown_group_kind_is_refused() {
    let f = edge_frame("exclude_most", "to = \"b\"");
    only_bad(&f, "worker.a.deps[0].group");
}

#[test]
fn an_unknown_stop_word_is_refused() {
    let f = edge_frame("optional_all", "to = \"b\", stop = \"serial\"");
    only_bad(&f, "worker.a.deps[0].edges[0].stop");
}

#[test]
fn an_edge_with_both_to_and_path_is_refused() {
    let f = edge_frame("optional_all", "to = \"b\", path = \"/x\"");
    only_bad(&f, "worker.a.deps[0].edges[0]");
}

#[test]
fn an_edge_with_neither_to_nor_path_is_refused() {
    let f = edge_frame("optional_all", "mode = \"async\"");
    only_bad(&f, "worker.a.deps[0].edges[0]");
}

#[test]
fn an_unknown_mode_is_refused() {
    let f = edge_frame("optional_all", "to = \"b\", mode = \"lazy\"");
    only_bad(&f, "worker.a.deps[0].edges[0].mode");
}

#[test]
fn a_bad_deadline_is_refused() {
    let edge = "to = \"b\", mode = \"async\", deadline = \"soon\"";
    only_bad(
        &edge_frame("optional_all", edge),
        "worker.a.deps[0].edges[0].deadline",
    );
}

#[test]
fn a_deadline_on_a_sync_edge_is_refused() {
    let f = edge_frame("optional_all", "to = \"b\", deadline = \"1s\"");
    only_bad(&f, "worker.a.deps[0].edges[0].deadline");
}

#[test]
fn an_unknown_restart_on_word_is_refused() {
    let f = edge_frame("optional_all", "to = \"b\", restart_on = \"crash\"");
    only_bad(&f, "worker.a.deps[0].edges[0].restart_on");
}

#[test]
fn an_unknown_ready_word_is_refused() {
    only_bad("exec = [\"/a\"]\nready = \"later\"", "worker.a.ready");
}

#[test]
fn an_unknown_restart_policy_is_refused() {
    let f = "exec = [\"/a\"]\nrestart = { policy = \"sometimes\" }";
    only_bad(f, "worker.a.restart.policy");
}

#[test]
fn a_bad_restart_window_is_refused() {
    let f = "exec = [\"/a\"]\nrestart = { policy = \"always\", window = \"a while\" }";
    only_bad(f, "worker.a.restart.window");
}

#[test]
fn a_bad_memory_size_is_refused() {
    let f = "exec = [\"/a\"]\ncell = { memory_max = \"lots\" }";
    only_bad(f, "worker.a.cell.memory_max");
}
