// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qctl watch` (spec 2026-11-05 §4.6): one line per notice, with no limit on the wait, until
//! the stream ends (`ended <state>`, exit 0). A closed connection or an error is exit 1.
use crate::control::Failure;
use crate::text;
use qinit_client::{Client, ClientError, Event, Next, Scope};
use std::io::Write;
use std::path::Path;

/// Watch everything (`all`) or `target`, a node or an instance (`<frame>#<id>`), at `socket`.
pub fn run(
    all: bool,
    target: &str,
    socket: &Path,
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
    match watch(scope, instance, socket, out) {
        Ok(()) => 0,
        Err(Failure::Client(ClientError::Unexpected)) => {
            let _ = writeln!(err, "qctl: colony closed the stream");
            1
        }
        Err(f) => f.report(err),
    }
}

fn watch(
    scope: Scope<'_>,
    instance: bool,
    socket: &Path,
    out: &mut dyn Write,
) -> Result<(), Failure> {
    let mut w = Client::connect(socket)?.watch(scope)?;
    loop {
        match w.next(None)? {
            Next::Event(e) => {
                writeln!(out, "{}", line(&e))?;
                out.flush()?;
                // An instance's exit is the last notice of its stream.
                if let Event::Instance {
                    report: qinit_client::Report::Exited,
                    state,
                    ..
                } = e
                    && instance
                {
                    writeln!(out, "ended {}", text::instance_state(state))?;
                    return Ok(());
                }
            }
            Next::Ended(s) => {
                let state = if instance {
                    text::instance_state(s.state)
                } else {
                    text::state(s)
                };
                writeln!(out, "ended {state}")?;
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
