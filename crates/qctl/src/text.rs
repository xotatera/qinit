// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The names of the protocol's state and detail words (`docs/control-protocol.md`, enum values).
use qinit_client::{Report, StateWord};

/// The name of a node state word, with `/detail` where the state has one: `waiting/backoff`,
/// `quarantined/breaker`. A word the table does not know prints as its number.
#[must_use]
pub fn state(w: StateWord) -> String {
    let name = match w.state {
        0 => "off",
        1 => "waiting",
        2 => "starting",
        3 => "ready",
        4 => "done",
        5 => "stopping",
        6 => "quarantined",
        n => return format!("state{n}/{}", w.detail),
    };
    let detail = match (w.state, w.detail) {
        (1, 0) => "dependency",
        (1, 1) => "backoff",
        (6, 0) => "breaker",
        (6, 1) => "cascade",
        (6, 2) => "start-timeout",
        (6, 3) => "stop-failed",
        (_, 0) => return name.to_owned(),
        (_, d) => return format!("{name}/{d}"),
    };
    format!("{name}/{detail}")
}

/// The name of a node kind word.
#[must_use]
pub fn kind(k: u32) -> String {
    match k {
        0 => "worker".to_owned(),
        1 => "forager".to_owned(),
        2 => "brood".to_owned(),
        n => format!("kind{n}"),
    }
}

/// The name of an instance state word.
#[must_use]
pub fn instance_state(s: u32) -> String {
    match s {
        2 => "starting".to_owned(),
        3 => "running".to_owned(),
        4 => "exited".to_owned(),
        5 => "stopping".to_owned(),
        n => format!("state{n}"),
    }
}

/// The name of what a notice reports.
#[must_use]
pub fn report(r: Report) -> &'static str {
    match r {
        Report::Current => "current",
        Report::Started => "started",
        Report::Ready => "ready",
        Report::Done => "done",
        Report::Stopped => "stopped",
        Report::Failed => "failed",
        Report::Quarantined => "quarantined",
        Report::Refused => "refused",
        Report::Lost => "lost",
        Report::Starting => "starting",
        Report::Running => "running",
        Report::Stopping => "stopping",
        Report::Exited => "exited",
    }
}
