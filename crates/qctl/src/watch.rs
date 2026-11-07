// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qctl watch` (spec 2026-11-05 §4.6): one line per notice, with no limit on the wait, until
//! the stream ends (`ended <state>`, exit 0). A closed connection or an error is exit 1.
use crate::control::Failure;
use crate::json::{self, Output};
use crate::text;
use qinit_client::{Client, ClientError, Event, Next, Scope, Watcher};
use std::io::Write;
use std::path::Path;

/// Watch everything (`all`) or `target`, a node or an instance (`<frame>#<id>`), at `socket`.
pub fn run(
    all: bool,
    target: &str,
    socket: &Path,
    output: Output,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let scope = if all {
        Scope::All
    } else {
        Scope::Target(target)
    };
    // An instance's stream speaks the instance's state words.
    let instance = !all && target.contains('#');
    match Client::connect(socket).and_then(|c| c.watch(scope).map_err(ClientError::from)) {
        Ok(w) => follow(w, instance, output, out, err),
        Err(e) => exit(Err(e.into()), err),
    }
}

/// Print the stream of `w` (an instance's when `instance`) until it ends; returns the exit
/// code: 0 at the end of the stream, 1 when the connection closed or failed.
pub fn follow(
    mut w: Watcher,
    instance: bool,
    output: Output,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    exit(stream(&mut w, instance, output, out), err)
}

fn exit(result: Result<(), Failure>, err: &mut dyn Write) -> i32 {
    match result {
        Ok(()) => 0,
        Err(Failure::Client(ClientError::Unexpected)) => {
            // The client's Unexpected: the connection closed, or a reply that is no notice (a
            // report word it does not know, say).
            let _ = writeln!(
                err,
                "qctl: the stream ended: colony closed it or sent a reply that is not a notice"
            );
            1
        }
        Err(f) => f.report(err),
    }
}

fn stream(
    w: &mut Watcher,
    instance: bool,
    output: Output,
    out: &mut dyn Write,
) -> Result<(), Failure> {
    loop {
        match w.next(None)? {
            Next::Event(e) => {
                output.line(out, &line(&e), &json::notice(&e))?;
                out.flush()?;
                // The exit of a watched instance is the last notice of its stream.
                if let Event::Instance { state, .. } = e
                    && w.is_spent()
                {
                    let text = format!("ended {}", text::instance_state(state));
                    output.line(out, &text, &json::ended_instance(state))?;
                    return Ok(());
                }
            }
            Next::Ended(s) => {
                if instance {
                    let text = format!("ended {}", text::instance_state(s.state));
                    output.line(out, &text, &json::ended_instance(s.state))?;
                } else {
                    let text = format!("ended {}", text::state(s));
                    output.line(out, &text, &json::ended(s))?;
                }
                return Ok(());
            }
            // No timeout was given; nothing to print.
            Next::Timeout => {}
        }
    }
}

/// The line of one event.
#[must_use]
pub fn line(e: &Event) -> String {
    let status = |s: &Option<i32>| s.map_or_else(String::new, |n| format!(" status={n}"));
    match e {
        Event::Node {
            name,
            report,
            state,
            status: s,
        } => format!(
            "node {name} {} {}{}",
            text::report(*report),
            text::state(*state),
            status(s)
        ),
        Event::Instance {
            frame,
            id,
            report,
            state,
            status: s,
        } => format!(
            "instance {frame}#{id} {} {}{}",
            text::report(*report),
            text::instance_state(*state),
            status(s)
        ),
        Event::Swapped => "swapped".to_owned(),
        Event::ShutdownComplete { still_populated } => {
            format!("shutdown-complete still={still_populated}")
        }
    }
}
