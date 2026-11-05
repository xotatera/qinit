// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Resuming from a state the daemon saved: the node table as it was (what is wanted, what is
//! quarantined, what already ran to completion, the restart counters) rather than the
//! database's own enabled list. The proved core checks nothing about where a table came from,
//! so [`Colony::restore`] checks the invariant first and refuses a table that breaks it.

use crate::effects::Effects;
use crate::engine::{Colony, Error, Outcome, adopted};
use qinit_colony_core::{
    Action, NodeState, Reason, State, inv_ok, off, params, restore as core_restore,
};
use qinit_db::open;
use std::collections::VecDeque;

/// The numbers a node's restart pacing keeps between runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub burst_begin_ms: u64,
    pub burst_count: u32,
    pub backoff_exp: u32,
    pub last_start_ms: u64,
    pub ended_ms: u64,
}

/// Where a restored node stands. `Ready` and `Starting` are only for a node whose cell the
/// caller adopted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Restored {
    Off,
    Done,
    Quarantined(Reason),
    Ready,
    Starting,
}

/// One node of a saved table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoredNode {
    pub node: u32,
    pub wanted: bool,
    pub phase: Restored,
    pub counters: Counters,
}

/// The end states worth keeping across a restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SavedTerminal {
    Done,
    Quarantined(Reason),
}

impl Counters {
    fn of(ns: &NodeState) -> Counters {
        Counters {
            burst_begin_ms: ns.burst_begin_ms,
            burst_count: ns.burst_count,
            backoff_exp: ns.backoff_exp,
            last_start_ms: ns.last_start_ms,
            ended_ms: ns.ended_ms,
        }
    }

    fn put(self, ns: NodeState) -> NodeState {
        NodeState {
            burst_begin_ms: self.burst_begin_ms,
            burst_count: self.burst_count,
            backoff_exp: self.backoff_exp,
            last_start_ms: self.last_start_ms,
            ended_ms: self.ended_ms,
            ..ns
        }
    }
}

/// The node table and the cell flags a saved state describes, checked against the invariant.
fn table_of(
    bytes: &[u8],
    n: usize,
    nodes: &[RestoredNode],
    now_ms: u64,
) -> Result<(Vec<NodeState>, Vec<bool>), Error> {
    let mut table = vec![off(); n];
    let mut live = vec![false; n];
    for r in nodes {
        let i = r.node as usize;
        if i >= n {
            return Err(Error::UnknownNode(r.node));
        }
        let base = match r.phase {
            Restored::Off => off(),
            Restored::Done => NodeState {
                state: State::Done,
                done: true,
                ..off()
            },
            Restored::Quarantined(why) => NodeState {
                state: State::Quarantined(why),
                ..off()
            },
            Restored::Ready | Restored::Starting => {
                live[i] = true;
                adopted(params(bytes, i), r.phase == Restored::Ready, now_ms)
            }
        };
        table[i] = r.counters.put(NodeState {
            wanted: r.wanted,
            ..base
        });
    }
    if !inv_ok(bytes, &table) {
        return Err(Error::Restore);
    }
    Ok((table, live))
}

impl<E: Effects> Colony<E> {
    /// Resumes from the saved table `nodes` (a node not listed is off and unwanted) against the
    /// database `bytes`. A `Ready` or `Starting` entry is a node whose cell the caller adopted:
    /// it has a cell, and if it waits on a path that path is watched, as in [`Colony::load`].
    /// Nothing is wanted that the table does not say is wanted.
    ///
    /// # Errors
    /// `Error::Db` if `bytes` do not pass the validator, `Error::UnknownNode` for an entry
    /// outside the database, `Error::Restore` if the table breaks the scheduler's invariant.
    pub fn restore(
        bytes: Vec<u8>,
        nodes: &[RestoredNode],
        effects: E,
        now_ms: u64,
    ) -> Result<(Self, Outcome), Error> {
        let model = open(&bytes).map_err(Error::Db)?.decode();
        let (table, live) = table_of(&bytes, model.nodes.len(), nodes, now_ms)?;
        let mut c = Self::assemble(bytes, model, table, live, effects);
        let mut out = Outcome::default();
        let converged = core_restore(
            &c.db,
            &mut c.nodes,
            &c.paths,
            &mut c.late,
            &mut c.meta,
            now_ms,
        );
        if !converged {
            out.errors.push(Error::Unconverged);
        }
        let mut queue = VecDeque::new();
        for r in nodes {
            if matches!(r.phase, Restored::Ready | Restored::Starting)
                && !c.path_edges[r.node as usize].is_empty()
            {
                c.perform(Action::WatchPath(r.node), &mut queue, &mut out);
            }
        }
        c.drain(&mut queue, &mut out);
        c.run_queue(&mut queue, now_ms, &mut out);
        Ok((c, out))
    }

    /// Whether [`Colony::restore`] would accept `nodes` against `bytes`, without consuming
    /// anything: a caller that wants to fall back to [`Colony::load`] checks first.
    ///
    /// # Errors
    /// The errors of [`Colony::restore`].
    pub fn validate_restore(
        bytes: &[u8],
        nodes: &[RestoredNode],
        now_ms: u64,
    ) -> Result<(), Error> {
        let model = open(bytes).map_err(Error::Db)?.decode();
        table_of(bytes, model.nodes.len(), nodes, now_ms).map(|_| ())
    }

    /// The compiled database in force, as bytes (what a restart reloads).
    #[must_use]
    pub fn db(&self) -> &[u8] {
        &self.db
    }

    /// What a restart needs of each node that is not plain off and unwanted: `(name, wanted,
    /// end state, counters)`.
    #[must_use]
    pub fn saved(&self) -> Vec<(String, bool, Option<SavedTerminal>, Counters)> {
        self.model
            .nodes
            .iter()
            .zip(&self.nodes)
            .filter_map(|(m, ns)| {
                let counters = Counters::of(ns);
                let end = match ns.state {
                    State::Done => Some(SavedTerminal::Done),
                    State::Quarantined(why) => Some(SavedTerminal::Quarantined(why)),
                    _ => None,
                };
                let plain = ns.state == State::Off && !ns.wanted && counters == Counters::default();
                (!plain).then(|| (m.name.clone(), ns.wanted, end, counters))
            })
            .collect()
    }

    /// Makes the next instance id at least `next` (ids restart at 1 with the daemon; a caller
    /// that knows better, from state it saved, keeps them from repeating).
    pub fn seed_instance_ids(&mut self, next: u32) {
        self.next_id = self.next_id.max(next);
    }

    /// The main process of an adopted node is gone and its status is unknown (it was not this
    /// process's child): counts as a failure, as `MainExited(None)` does everywhere.
    pub fn adopted_exit(&mut self, node: u32, now_ms: u64) -> Outcome {
        self.on_cell(node, qinit_cell_core::Report::MainExited(None), now_ms)
    }
}
