// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! What colony says about a notice: one line, with a severity, in the words of `qinit_colony`.
use crate::syslog::Sev;
use qinit_colony::{InstanceView, Notice, Report, SlotState, State};
use qinit_db::Model;

/// A wait status in words: `exit 3`, `signal 9`, or `status unknown` for none (`None`, or a
/// negative number as an instance records it).
#[must_use]
pub fn status_words(status: Option<i32>) -> String {
    match status {
        None => "status unknown".to_owned(),
        Some(s) if s < 0 => "status unknown".to_owned(),
        Some(s) if libc::WIFEXITED(s) => format!("exit {}", libc::WEXITSTATUS(s)),
        Some(s) if libc::WIFSIGNALED(s) => format!("signal {}", libc::WTERMSIG(s)),
        Some(s) => format!("status {s:#x}"),
    }
}

/// The line for `notice`, if it is worth one. `view` is the instance a notice names, if it names
/// one that colony still knows.
#[must_use]
pub fn describe(
    model: &Model,
    view: Option<&InstanceView>,
    notice: &Notice,
) -> Option<(Sev, String)> {
    match *notice {
        Notice::Node(ix, report) => {
            let name = model
                .nodes
                .get(ix as usize)
                .map_or("?", |n| n.name.as_str());
            let (sev, what) = match report {
                Report::Started => (Sev::Info, "starting".to_owned()),
                Report::Ready => (Sev::Info, "ready".to_owned()),
                Report::Done => (Sev::Info, "done".to_owned()),
                Report::Stopped => (Sev::Info, "stopped".to_owned()),
                Report::Failed(status) => (Sev::Info, format!("failed ({})", status_words(status))),
                Report::Quarantined(r) => (
                    Sev::Info,
                    qinit_colony::text::state_text(State::Quarantined(r)).to_owned(),
                ),
                Report::Refused => (Sev::Info, "request refused".to_owned()),
                Report::Lost => (Sev::Err, "a report was lost".to_owned()),
                Report::Reload => return None,
                Report::ShutdownComplete { still_populated } => {
                    return Some((
                        Sev::Info,
                        format!("shutdown complete ({still_populated} cells still populated)"),
                    ));
                }
            };
            Some((sev, format!("{name}: {what}")))
        }
        Notice::Instance(id, state) => {
            let name = format!("{}#{id}", view.map_or("?", |v| v.frame_name.as_str()));
            let what = match state {
                SlotState::Free => return None,
                SlotState::Starting => "starting".to_owned(),
                SlotState::Running => "running".to_owned(),
                SlotState::Stopping => "stopping".to_owned(),
                SlotState::Exited(s) => format!("exited ({})", status_words(Some(s))),
            };
            Some((Sev::Info, format!("{name}: {what}")))
        }
        Notice::InstanceReady(id) => {
            let name = format!("{}#{id}", view.map_or("?", |v| v.frame_name.as_str()));
            Some((Sev::Info, format!("{name}: ready")))
        }
        Notice::Swapped => Some((Sev::Info, "database refreshed".to_owned())),
    }
}
