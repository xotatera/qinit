// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `--json`: one JSON object per line of output (`docs/qctl.md`).
//!
//! Every shape is built from the same value the text line is printed from, and a state is
//! named by [`crate::text`], so the two forms cannot name different things. An absent optional
//! field is left out, never `null`.
use crate::text;
use qinit_client::{Entry, Event, InstanceInfo, NodeInfo, Outcome, StateWord};
use serde_json::{Map, Value, json};
use std::io::Write;

/// How a command prints its result.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Output {
    /// Lines for people.
    #[default]
    Text,
    /// One JSON object per line.
    Json,
}

impl Output {
    /// `Json` when `--json` was given.
    #[must_use]
    pub fn of(json: bool) -> Output {
        if json { Output::Json } else { Output::Text }
    }

    /// Write one line: `text` as it is, or `json` compactly.
    ///
    /// # Errors
    /// The write failed.
    pub fn line(self, out: &mut dyn Write, text: &str, json: &Value) -> std::io::Result<()> {
        match self {
            Output::Text => writeln!(out, "{text}"),
            Output::Json => writeln!(out, "{json}"),
        }
    }
}

/// An object from `fields`.
fn object(fields: Value) -> Map<String, Value> {
    match fields {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

/// Add `state` (and `detail` where the word has one) to `m`.
fn put_state(m: &mut Map<String, Value>, w: StateWord) {
    let (state, detail) = text::state_parts(w);
    m.insert("state".into(), state.into());
    if let Some(d) = detail {
        m.insert("detail".into(), d.into());
    }
}

/// The state words of `w` as `state` and `detail`.
fn state_fields(w: StateWord) -> Map<String, Value> {
    let mut m = Map::new();
    put_state(&mut m, w);
    m
}

/// A node's status.
#[must_use]
pub fn status(n: &NodeInfo) -> Value {
    let mut m = object(json!({"name": n.name, "kind": text::kind(n.kind)}));
    put_state(&mut m, n.state);
    if let Some((group, target)) = &n.blocking {
        m.insert("blocking".into(), json!({"group": group, "target": target}));
    }
    m.insert("backoff_ms".into(), n.backoff_ms.into());
    m.insert("since_ms".into(), n.since_ms.into());
    m.insert("restarts".into(), n.restarts.into());
    if let Some(pid) = n.pid {
        m.insert("pid".into(), pid.into());
    }
    Value::Object(m)
}

/// An instance's status.
#[must_use]
pub fn instance_status(i: &InstanceInfo) -> Value {
    let mut m = object(json!({
        "frame": i.frame,
        "id": i.id,
        "state": text::instance_state(i.state),
    }));
    if let Some(status) = i.status {
        m.insert("status".into(), status.into());
    }
    if let Some(pid) = i.pid {
        m.insert("pid".into(), pid.into());
    }
    Value::Object(m)
}

/// One entry of a list.
#[must_use]
pub fn entry(e: &Entry) -> Value {
    let mut m = object(json!({"kind": text::kind(e.kind), "name": e.name}));
    m.extend(state_fields(e.state));
    Value::Object(m)
}

/// The result of a change.
#[must_use]
pub fn change(outcome: Outcome) -> Value {
    let (result, state) = match outcome {
        Outcome::Accepted => ("accepted", None),
        Outcome::Settled(s) => ("settled", Some(s)),
        Outcome::Pending(s) => ("pending", Some(s)),
        Outcome::Superseded(s) => ("superseded", Some(s)),
    };
    let mut m = object(json!({"result": result}));
    if let Some(s) = state {
        m.extend(state_fields(s));
    }
    Value::Object(m)
}

/// A launch or run event: `event` is the word, `name` the instance, `extra` the `code` or
/// `signal`.
#[must_use]
pub fn event(event: &str, name: &str, extra: Option<(&str, i32)>) -> Value {
    let mut m = object(json!({"event": event, "name": name}));
    if let Some((key, n)) = extra {
        m.insert(key.into(), n.into());
    }
    Value::Object(m)
}

/// A watch notice.
#[must_use]
pub fn notice(e: &Event) -> Value {
    match e {
        Event::Node {
            name,
            report,
            state,
            status,
        } => {
            let mut m = object(json!({
                "kind": "node",
                "name": name,
                "report": text::report(*report),
            }));
            m.extend(state_fields(*state));
            if let Some(s) = status {
                m.insert("status".into(), (*s).into());
            }
            Value::Object(m)
        }
        Event::Instance {
            frame,
            id,
            report,
            state,
            status,
        } => {
            let mut m = object(json!({
                "kind": "instance",
                "name": frame,
                "id": id,
                "report": text::report(*report),
                "state": text::instance_state(*state),
            }));
            if let Some(s) = status {
                m.insert("status".into(), (*s).into());
            }
            Value::Object(m)
        }
        Event::Swapped => json!({"kind": "swapped"}),
        Event::ShutdownComplete { still_populated } => {
            json!({"kind": "shutdown_complete", "still_populated": still_populated})
        }
    }
}

/// The last object of a watch: the final node `state`.
#[must_use]
pub fn ended(state: StateWord) -> Value {
    let mut m = object(json!({"kind": "ended"}));
    m.extend(state_fields(state));
    Value::Object(m)
}

/// The last object of an instance's watch.
#[must_use]
pub fn ended_instance(state: u32) -> Value {
    json!({"kind": "ended", "state": text::instance_state(state)})
}
