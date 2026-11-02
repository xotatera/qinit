// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The text colony shows: one status line per node.

use qinit_colony_core::{NodeState, Reason, State, Why};
use qinit_db::Model;
use std::fmt::Write as _;

/// A state in words.
#[must_use]
pub fn state_text(s: State) -> &'static str {
    match s {
        State::Off => "off",
        State::Waiting(Why::Deps) => "waiting (dependencies)",
        State::Waiting(Why::Backoff) => "waiting (back-off)",
        State::Starting => "starting",
        State::Ready => "ready",
        State::Done => "done",
        State::Stopping => "stopping",
        State::Quarantined(Reason::Breaker) => "quarantined (too many failures)",
        State::Quarantined(Reason::Cascade) => "quarantined (dependency)",
        State::Quarantined(Reason::StartTimeout) => "quarantined (start timeout)",
        State::Quarantined(Reason::StopFailed) => "quarantined (stop failed)",
    }
}

/// The millisecond clock reading at which the node entered its state, where it records one.
fn since(n: &NodeState) -> Option<u64> {
    match n.state {
        State::Waiting(_) => Some(n.wait_since_ms),
        State::Starting | State::Ready | State::Stopping => Some(n.last_start_ms),
        _ => None,
    }
}

/// One line per node: `name state since <ms>`, the numbers right-aligned. A state that records
/// no time (off, done, quarantined) shows `-`.
#[must_use]
pub fn status(model: &Model, nodes: &[NodeState], now: u64) -> String {
    let mut out = String::new();
    for (node, ns) in model.nodes.iter().zip(nodes) {
        let since = since(ns).map_or_else(|| "-".to_owned(), |ms| format!("{ms} ms"));
        let _ = writeln!(
            out,
            "{:<24} {:<32} since {since:>12} (now {now:>9} ms)",
            node.name,
            state_text(ns.state),
        );
    }
    out
}
