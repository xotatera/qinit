// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! What status and list ask: a node's state with why it is not running, and the node list.

use crate::effects::Effects;
use crate::engine::Colony;
use crate::handle::{EntryView, NodeStatusView, state_word};
use qinit_colony_core::{State, Why, edge_met, group_met, remaining_ms};
use qinit_db::{Kind, Target, group_word};
use qinit_proto_core::MAX_LIST_ENTRIES;

/// The wire number of a node kind.
fn kind_word(k: Kind) -> u32 {
    match k {
        Kind::Worker => 0,
        Kind::Forager => 1,
        Kind::Brood => 2,
    }
}

impl<E: Effects> Colony<E> {
    /// The first group of node `i` that is not satisfied now, with its first edge that is not
    /// met: the group's index within the node, and the node or path the edge names.
    fn blocking(&self, i: usize, now: u64) -> Option<(u32, String)> {
        let (mut group, mut edge) = (0usize, 0usize);
        for (j, node) in self.model.nodes.iter().enumerate() {
            if j == i {
                for (k, g) in node.groups.iter().enumerate() {
                    if !group_met(&self.db, &self.nodes, &self.paths, group + k, now) {
                        let first = edge
                            + node.groups[..k]
                                .iter()
                                .map(|g| g.edges.len())
                                .sum::<usize>();
                        let target = g.edges.iter().enumerate().find(|(m, _)| {
                            !edge_met(
                                &self.db,
                                &self.nodes,
                                &self.paths,
                                group_word(g.kind),
                                first + m,
                                now,
                            )
                        });
                        let (_, e) = target.or_else(|| g.edges.iter().enumerate().next())?;
                        let text = match &e.target {
                            Target::Node(t) => self.model.nodes[*t as usize].name.clone(),
                            Target::Path(p) => clip_name(p),
                        };
                        return Some((u32::try_from(k).unwrap_or(u32::MAX), text));
                    }
                }
                return None;
            }
            group += node.groups.len();
            edge += node.groups.iter().map(|g| g.edges.len()).sum::<usize>();
        }
        None
    }

    /// The status of node `node`.
    ///
    /// # Panics
    /// If `node` is outside the database.
    #[must_use]
    pub fn node_status(&self, node: u32, now: u64) -> NodeStatusView {
        let i = node as usize;
        let ns = &self.nodes[i];
        let model = &self.model.nodes[i];
        let since = match ns.state {
            State::Waiting(_) => ns.wait_since_ms,
            State::Starting | State::Ready | State::Stopping => ns.last_start_ms,
            _ => now,
        };
        let blocking = if ns.state == State::Waiting(Why::Deps) {
            self.blocking(i, now)
        } else {
            None
        };
        let backoff_ms = if ns.state == State::Waiting(Why::Backoff) {
            remaining_ms(*ns, model.restart.delay_ms, now)
        } else {
            0
        };
        NodeStatusView {
            name: model.name.clone(),
            kind: kind_word(model.kind),
            state: state_word(ns.state),
            blocking,
            backoff_ms,
            since_ms: now.saturating_sub(since),
            restarts: self.starts[i].saturating_sub(1),
            pid: self.pid(node),
        }
    }

    /// A page of the node list: the nodes from index `cursor` on that match `kind` (0 all,
    /// 1 worker, 2 forager, 3 brood), at most [`MAX_LIST_ENTRIES`], and the cursor of the next
    /// page when more match.
    #[must_use]
    pub fn list(&self, cursor: u32, kind: u32) -> (Vec<EntryView>, Option<u32>) {
        let wanted = |k: Kind| kind == 0 || kind_word(k) + 1 == kind;
        let mut matching = self
            .model
            .nodes
            .iter()
            .enumerate()
            .skip(cursor as usize)
            .filter(|(_, n)| wanted(n.kind));
        let mut entries = Vec::new();
        for (i, n) in matching.by_ref().take(MAX_LIST_ENTRIES) {
            entries.push(EntryView {
                name: n.name.clone(),
                kind: kind_word(n.kind),
                state: state_word(self.nodes[i].state),
            });
        }
        let next = matching
            .next()
            .map(|(i, _)| u32::try_from(i).unwrap_or(u32::MAX));
        (entries, next)
    }
}

/// The longest prefix of `text` that is a legal wire name (at most 96 bytes, whole characters):
/// a long path target is shown clipped, since the field only tells a person what is awaited.
fn clip_name(text: &str) -> String {
    let mut end = text.len().min(qinit_proto_core::MAX_NAME_LEN);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}
