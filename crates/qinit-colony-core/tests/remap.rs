// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Carrying the node table over to a new database: unchanged machines keep their state, every
//! other entry starts off.
mod common;

use common::*;
use qinit_colony_core::*;
use qinit_db::{Model, RestartPolicy, write};

fn two(a_policy: RestartPolicy) -> Model {
    let mut a = worker("a");
    a.restart.policy = a_policy;
    a.restart.max = 3;
    a.restart.window_ms = 60_000;
    model(vec![a, worker("b"), worker("c")], &[0, 1, 2])
}

#[test]
fn remap_copies_unchanged_and_resets_the_rest() {
    let (h, _) = Harness::load(two(RestartPolicy::OnFailure));
    // Everything has started; the cells report ready.
    let mut h = h;
    for name in ["a", "b", "c"] {
        h.cell(name, CellReport::Ready, 5);
    }
    assert!(h.nodes.iter().all(|n| n.state == State::Ready));
    // The new database: `a` changed its restart policy (the machine reads it), `b` is as
    // before, `c` is gone and `d` is new. Names stay sorted, so `d` is last.
    let mut a2 = worker("a");
    a2.restart.policy = RestartPolicy::Always;
    a2.restart.max = 3;
    a2.restart.window_ms = 60_000;
    let new = model(vec![a2, worker("b"), worker("d")], &[0, 1]);
    let new_db = write(&new).unwrap();
    let map = [0u32, 1, NONE_NODE];
    let mut out = vec![off(); 3];
    remap(&h.db, &new_db, &h.nodes, &map, &mut out);
    assert_eq!(
        out[0],
        off(),
        "a's machine reads other words: it starts off"
    );
    assert_eq!(
        out[1], h.nodes[1],
        "b is unchanged: its state is carried over"
    );
    assert_eq!(out[2], off(), "d is new");
}

const NONE_NODE: u32 = u32::MAX;

#[test]
fn a_node_taken_from_the_old_table_keeps_everything_including_its_timers() {
    let (mut h, _) = Harness::load(two(RestartPolicy::OnFailure));
    h.cell("a", CellReport::Ready, 5);
    h.cell("a", CellReport::MainExited(Some(1)), 10);
    h.cell("a", CellReport::Empty, 10);
    let waiting = h.node("a");
    assert!(
        matches!(waiting.state, State::Waiting(_)),
        "{:?}",
        waiting.state
    );
    let new_db = write(&two(RestartPolicy::OnFailure)).unwrap();
    let mut out = vec![off(); 3];
    remap(&h.db, &new_db, &h.nodes, &[0, 1, 2], &mut out);
    assert_eq!(out[0], waiting);
}

#[test]
fn a_map_entry_outside_the_old_table_is_a_new_node() {
    let (h, _) = Harness::load(two(RestartPolicy::OnFailure));
    let new_db = write(&two(RestartPolicy::OnFailure)).unwrap();
    let mut out = vec![h.nodes[0]; 3];
    remap(&h.db, &new_db, &h.nodes, &[7, NONE_NODE, 2], &mut out);
    assert_eq!(out[0], off());
    assert_eq!(out[1], off());
    assert_eq!(out[2], h.nodes[2]);
}

#[test]
fn rebuild_late_flags_the_unmet_edges_of_running_nodes_only() {
    // `a` requires `b` (async, 1 s) and is running; `c` is off with the same edge.
    let mut a = worker("a");
    a.groups.push(group(
        qinit_db::GroupKind::RequireAll,
        vec![async_edge(1, 1000)],
    ));
    let mut c = worker("c");
    c.groups.push(group(
        qinit_db::GroupKind::RequireAll,
        vec![async_edge(1, 1000)],
    ));
    let m = model(vec![a, worker("b"), c], &[]);
    let db = write(&m).unwrap();
    let mut nodes = vec![off(); 3];
    nodes[0].state = State::Ready;
    nodes[0].wanted = true;
    let paths = vec![false; 2];
    let mut late = vec![false; 2];
    rebuild_late(&db, &nodes, &paths, &mut late);
    assert_eq!(late, [true, false]);
}
