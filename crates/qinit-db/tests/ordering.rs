// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
mod common;

use common::{edge, node, sample};
use qinit_db::{Group, GroupKind, Kind, Mode, Model, Target, ordering_edges};
use qinit_graph_core::GEdge;

#[test]
fn only_node_targets_of_ordering_groups_become_graph_edges() {
    let edges = ordering_edges(&sample());
    // sshd (3): require_all sync to logd (1) and firewall (0), optional_all async to net (2);
    // the exclude_all path edge produces nothing.
    assert_eq!(
        edges,
        vec![
            GEdge {
                from: 3,
                to: 1,
                hard: true,
                parallel: false
            },
            GEdge {
                from: 3,
                to: 0,
                hard: true,
                parallel: false
            },
            GEdge {
                from: 3,
                to: 2,
                hard: false,
                parallel: true
            },
        ]
    );
}

#[test]
fn hardness_needs_a_require_group_and_sync_mode() {
    let mut a = node("a", Kind::Worker);
    a.groups = vec![
        Group {
            kind: GroupKind::RequireAny,
            edges: vec![edge(Target::Node(1), Mode::Sync, 0)],
        },
        Group {
            kind: GroupKind::RequireAll,
            edges: vec![edge(Target::Node(1), Mode::Async, 5)],
        },
        Group {
            kind: GroupKind::OptionalAll,
            edges: vec![edge(Target::Node(1), Mode::Sync, 0)],
        },
        Group {
            kind: GroupKind::ExcludeAll,
            edges: vec![edge(Target::Node(1), Mode::Sync, 0)],
        },
        Group {
            kind: GroupKind::RequireAll,
            edges: vec![edge(Target::Path("/x".into()), Mode::Sync, 0)],
        },
    ];
    let model = Model {
        nodes: vec![a, node("b", Kind::Worker)],
        ..Model::default()
    };
    let hard: Vec<bool> = ordering_edges(&model).iter().map(|e| e.hard).collect();
    assert_eq!(hard, vec![true, false, false]);
}
