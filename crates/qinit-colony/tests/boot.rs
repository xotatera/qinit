// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Booting a compiled graph against simulated cells.
mod common;

use common::*;
use qinit_colony::sim::{Call, Script, Sim};
use qinit_colony::{Colony, Error, Notice, Report, State, TimerKind};

#[test]
fn two_boots_in_order() {
    let (mut c, out) = boot("two.toml", &["a"], Sim::new());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    assert_eq!(start_order(&c), ["b"], "a waits for b");
    pass(&mut c, 1);
    assert_eq!(start_order(&c), ["b", "a"]);
    pass(&mut c, 1);
    let (a, b) = (idx(&c, "a"), idx(&c, "b"));
    assert_eq!(
        (c.state(a), c.state(b)),
        (Some(State::Ready), Some(State::Ready))
    );
}

#[test]
fn branches_boot_in_parallel_and_the_brood_last() {
    let (mut c, _) = boot("branches.toml", &["multi-user"], Sim::new());
    assert_eq!(
        start_order(&c),
        ["a1", "b1"],
        "the two chains start together"
    );
    let notices = pass(&mut c, 1);
    assert_eq!(start_order(&c), ["a1", "b1", "a2", "b2"]);
    let m = idx(&c, "multi-user");
    assert_eq!(c.state(m), Some(State::Ready));
    assert!(
        notices.contains(&Notice::Node(m, Report::Ready)),
        "the brood reports ready: {notices:?}"
    );
    assert!(
        !start_order(&c).contains(&"multi-user".to_owned()),
        "a brood has no process"
    );
}

#[test]
fn producers_wait_for_their_logger() {
    let mut sim = Sim::new();
    let (probe, _) = boot("logger.toml", &["p1", "p2"], Sim::new());
    let logd = idx(&probe, "logd");
    sim.scripts.insert(
        logd,
        Script {
            ready_after_ms: Some(50),
            ..Script::default()
        },
    );
    let (mut c, _) = boot("logger.toml", &["p1", "p2"], sim);
    assert_eq!(start_order(&c), ["logd"]);
    pass(&mut c, 49);
    assert_eq!(start_order(&c), ["logd"], "not before the logger is ready");
    pass(&mut c, 1);
    assert_eq!(start_order(&c), ["logd", "p1", "p2"]);
}

#[test]
fn load_with_initial_marks_nodes_ready_and_starts_only_the_rest() {
    let bytes = database("two.toml", &["a"]);
    let (probe, _) = Colony::load(bytes.clone(), &[], Sim::new(), 0).expect("loads");
    let b = idx(&probe, "b");
    let (c, out) = Colony::load(bytes, &[(b, true)], Sim::new(), 100).expect("loads");
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    assert_eq!(start_order(&c), ["a"], "b was already running");
    assert_eq!(c.state(b), Some(State::Ready));
}

#[test]
fn an_initial_entry_outside_the_database_is_refused() {
    let bytes = database("two.toml", &["a"]);
    let err = Colony::load(bytes, &[(99, true)], Sim::new(), 0).err();
    assert_eq!(err, Some(Error::UnknownNode(99)));
}

#[test]
fn status_text_has_one_line_per_node() {
    let (mut c, _) = boot("two.toml", &["a"], Sim::new());
    pass(&mut c, 2);
    let text = c.status(2);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert!(
        lines[0].starts_with("a ") && lines[0].contains("ready"),
        "{text}"
    );
    assert!(
        lines[1].starts_with("b ") && lines[1].contains("ready"),
        "{text}"
    );
}

#[test]
fn an_effect_error_on_start_is_a_spawn_failure() {
    let (probe, _) = boot("two.toml", &["a"], Sim::new());
    let b = idx(&probe, "b");
    let mut sim = Sim::new();
    sim.fail_start.insert(b);
    let (mut c, out) = boot("two.toml", &["a"], sim);
    assert!(
        out.errors.is_empty(),
        "a failed start is an event, not an error: {:?}",
        out.errors
    );
    assert!(c.effects.calls.contains(&Call::Start(b)));
    let notices = pass(&mut c, 1);
    assert_eq!(c.state(b), Some(State::Off), "never restarted");
    assert!(
        notices
            .iter()
            .chain(&out.notices)
            .any(|n| matches!(n, Notice::Node(x, Report::Failed(_)) if *x == b)),
        "{notices:?} {:?}",
        out.notices
    );
    let a = idx(&c, "a");
    assert_ne!(c.state(a), Some(State::Ready), "a never starts without b");
}

#[test]
fn the_start_timeout_timer_is_armed_and_cancelled() {
    let (mut c, _) = boot("two.toml", &["a"], Sim::new());
    let b = idx(&c, "b");
    assert!(
        c.effects
            .calls
            .contains(&Call::Arm(b, TimerKind::StartTimeout, 90_000))
    );
    pass(&mut c, 1);
    assert!(
        c.effects
            .calls
            .contains(&Call::Cancel(b, TimerKind::StartTimeout))
    );
}
