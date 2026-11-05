// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The control commands over the client library (spec 2026-11-05 §4.6).
use crate::args::{self, Command};
use crate::text;
use qinit_client::{Client, ClientError, Outcome, Status, Wait};
use std::io::Write;
use std::os::fd::AsFd;
use std::path::Path;
use std::time::Duration;

/// The longest `--wait` the protocol allows, in milliseconds.
const MAX_WAIT_MS: u32 = 600_000;

/// Run one control command against the colony at `socket`; `command` is one of status, list,
/// change, refresh or shutdown. Returns the exit code: 0 done, 1 refused or failed, 2 usage.
pub fn run(command: &Command, socket: &Path, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let wait = match wait_of(command) {
        Ok(w) => w,
        Err(msg) => {
            let _ = writeln!(err, "qctl: {msg}\nTry 'qctl --help'.");
            return 2;
        }
    };
    match go(command, socket, wait, out) {
        Ok(()) => 0,
        Err(f) => f.report(err),
    }
}

/// Why a command over the protocol failed.
pub(crate) enum Failure {
    Client(ClientError),
    Io(std::io::Error),
}

impl Failure {
    /// Print the failure on `err` (a server refusal says so) and return exit code 1.
    pub(crate) fn report(&self, err: &mut dyn Write) -> i32 {
        let _ = writeln!(err, "qctl: {self}");
        1
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Client(ClientError::Server(code, detail)) => {
                write!(f, "colony refused: {code:?} ({detail})")
            }
            Failure::Client(e) => write!(f, "{e}"),
            Failure::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<ClientError> for Failure {
    fn from(e: ClientError) -> Self {
        Failure::Client(e)
    }
}

impl From<std::io::Error> for Failure {
    fn from(e: std::io::Error) -> Self {
        Failure::Io(e)
    }
}

fn wait_of(command: &Command) -> Result<Wait, String> {
    let ms = match command {
        Command::Change { wait, .. }
        | Command::Refresh { wait, .. }
        | Command::Shutdown { wait, .. } => *wait,
        _ => None,
    };
    ms.map_or(Ok(Wait::Now), |ms| wait_ms(ms).map(Wait::Settled))
}

/// A `--wait` value: 1 ms to the protocol's maximum.
pub(crate) fn wait_ms(ms: u32) -> Result<Duration, String> {
    if (1..=MAX_WAIT_MS).contains(&ms) {
        Ok(Duration::from_millis(u64::from(ms)))
    } else {
        Err(format!("--wait: {ms} is not from 1 to {MAX_WAIT_MS}"))
    }
}

fn go(command: &Command, socket: &Path, wait: Wait, out: &mut dyn Write) -> Result<(), Failure> {
    match command {
        Command::Status { target } => {
            let status = Client::connect(socket)?.status(target)?;
            print_status(&status, out)?;
        }
        Command::List { kind } => {
            for e in Client::connect(socket)?.list(*kind)? {
                writeln!(
                    out,
                    "{} {} {}",
                    text::kind(e.kind),
                    e.name,
                    text::state(e.state)
                )?;
            }
        }
        Command::Change { target, action, .. } => {
            let action = match action {
                args::Action::Start => qinit_client::Action::Start,
                args::Action::Stop => qinit_client::Action::Stop,
                args::Action::Restart => qinit_client::Action::Restart,
                args::Action::Clear => qinit_client::Action::Clear,
            };
            let outcome = Client::connect(socket)?.change(target, action, wait)?;
            print_outcome(outcome, out)?;
        }
        Command::Refresh { db, .. } => {
            let file = std::fs::File::open(db)
                .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", db.display())))?;
            let outcome = Client::connect(socket)?.refresh(file.as_fd(), wait)?;
            print_outcome(outcome, out)?;
        }
        Command::Shutdown { mode, .. } => {
            let mode = match mode {
                args::Mode::Poweroff => qinit_client::Mode::Poweroff,
                args::Mode::Reboot => qinit_client::Mode::Reboot,
                args::Mode::Halt => qinit_client::Mode::Halt,
            };
            let outcome = Client::connect(socket)?.shutdown(mode, wait)?;
            print_outcome(outcome, out)?;
        }
        other => {
            return Err(Failure::Io(std::io::Error::other(format!(
                "{} is not a control command",
                other.name()
            ))));
        }
    }
    Ok(())
}

fn print_status(status: &Status, out: &mut dyn Write) -> std::io::Result<()> {
    match status {
        Status::Node(n) => {
            writeln!(out, "name: {}", n.name)?;
            writeln!(out, "kind: {}", text::kind(n.kind))?;
            writeln!(out, "state: {}", text::state(n.state))?;
            if let Some((group, target)) = &n.blocking {
                writeln!(out, "blocking: group {group} on {target}")?;
            }
            writeln!(out, "backoff_ms: {}", n.backoff_ms)?;
            writeln!(out, "since_ms: {}", n.since_ms)?;
            writeln!(out, "restarts: {}", n.restarts)?;
            if let Some(pid) = n.pid {
                writeln!(out, "pid: {pid}")?;
            }
        }
        Status::Instance(i) => {
            writeln!(out, "frame: {}", i.frame)?;
            writeln!(out, "id: {}", i.id)?;
            writeln!(out, "state: {}", text::instance_state(i.state))?;
            if let Some(status) = i.status {
                writeln!(out, "status: {status}")?;
            }
            if let Some(pid) = i.pid {
                writeln!(out, "pid: {pid}")?;
            }
        }
    }
    Ok(())
}

fn print_outcome(outcome: Outcome, out: &mut dyn Write) -> std::io::Result<()> {
    match outcome {
        Outcome::Accepted => writeln!(out, "accepted"),
        Outcome::Settled(s) => writeln!(out, "settled {}", text::state(s)),
        Outcome::Pending(s) => writeln!(out, "pending {}", text::state(s)),
        Outcome::Superseded(s) => writeln!(out, "superseded {}", text::state(s)),
    }
}
