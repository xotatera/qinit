// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The words colony uses for what happens to a node or an instance.
mod common;

use common::*;
use qinit_colony::{InstanceView, Notice, Reason, Report, SlotState};
use qinit_colonyd::notes::{describe, status_words};
use qinit_colonyd::syslog::Sev;

fn say(n: &Notice) -> Option<(Sev, String)> {
    let m = model(vec![worker("db")]);
    let view = InstanceView {
        frame: 0,
        frame_name: "backup".into(),
        id: 7,
        state: SlotState::Running,
        pid: Some(1),
    };
    describe(&m, Some(&view), n)
}

#[test]
fn node_notices_read_as_one_line_each() {
    let node = |r| say(&Notice::Node(0, r));
    assert_eq!(node(Report::Ready), Some((Sev::Info, "db: ready".into())));
    assert_eq!(
        node(Report::Started),
        Some((Sev::Info, "db: starting".into()))
    );
    assert_eq!(node(Report::Done), Some((Sev::Info, "db: done".into())));
    assert_eq!(
        node(Report::Stopped),
        Some((Sev::Info, "db: stopped".into()))
    );
    assert_eq!(
        node(Report::Failed(Some(1 << 8))),
        Some((Sev::Info, "db: failed (exit 1)".into()))
    );
    assert_eq!(
        node(Report::Failed(Some(9))),
        Some((Sev::Info, "db: failed (signal 9)".into()))
    );
    assert_eq!(
        node(Report::Failed(None)),
        Some((Sev::Info, "db: failed (status unknown)".into()))
    );
    assert_eq!(
        node(Report::Quarantined(Reason::Breaker)),
        Some((Sev::Info, "db: quarantined (too many failures)".into()))
    );
    assert_eq!(node(Report::Lost).map(|(s, _)| s), Some(Sev::Err));
    assert_eq!(node(Report::Reload), None, "a signal, not news");
}

#[test]
fn an_unknown_node_index_still_gets_a_line() {
    let line = say(&Notice::Node(99, Report::Ready)).unwrap().1;
    assert_eq!(line, "?: ready");
}

#[test]
fn shutdown_and_refresh_have_their_own_words() {
    assert_eq!(
        say(&Notice::Node(
            0,
            Report::ShutdownComplete { still_populated: 2 }
        )),
        Some((
            Sev::Info,
            "shutdown complete (2 cells still populated)".into()
        ))
    );
    assert_eq!(
        say(&Notice::Swapped),
        Some((Sev::Info, "database refreshed".into()))
    );
}

#[test]
fn instance_notices_name_the_frame_and_the_id() {
    assert_eq!(
        say(&Notice::Instance(7, SlotState::Starting)),
        Some((Sev::Info, "backup#7: starting".into()))
    );
    assert_eq!(
        say(&Notice::Instance(7, SlotState::Exited(2 << 8))),
        Some((Sev::Info, "backup#7: exited (exit 2)".into()))
    );
    assert_eq!(
        say(&Notice::Instance(7, SlotState::Exited(-1))),
        Some((Sev::Info, "backup#7: exited (status unknown)".into()))
    );
    assert_eq!(
        say(&Notice::InstanceReady(7)),
        Some((Sev::Info, "backup#7: ready".into()))
    );
    assert_eq!(say(&Notice::Instance(7, SlotState::Free)), None);
}

#[test]
fn status_words_cover_exit_signal_and_unknown() {
    assert_eq!(status_words(Some(0)), "exit 0");
    assert_eq!(status_words(Some(137 << 8)), "exit 137");
    assert_eq!(status_words(Some(15)), "signal 15");
    assert_eq!(status_words(None), "status unknown");
    assert_eq!(status_words(Some(-1)), "status unknown");
}
