// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Refresh requests, reload signals and `restart_on = "refresh"` edges through the whole
//! pipeline: TOML, compiler, database, scheduler, simulated cells.
mod common;

use common::*;
use qinit_colony::sim::{Call, Sim};
use qinit_colony::{Colony, Notice, Report, Request, State};

/// `a` requires `b` with the given `restart_on`; `b` declares a reload signal when `reload`.
fn pair(restart_on: &str, reload: bool) -> String {
    let reload = if reload { "reload = \"SIGHUP\"\n" } else { "" };
    format!(
        "[worker.a]\ncredentials = {{ uid = \"svc\" }}\nexec = [\"/bin/a\"]\n\
         deps = [{{ group = \"require_all\", edges = [{{ to = \"b\", restart_on = \"{restart_on}\" }}] }}]\n\
         [worker.b]\ncredentials = {{ uid = \"svc\" }}\nexec = [\"/bin/b\"]\n{reload}"
    )
}

fn count(c: &Colony<Sim>, f: impl Fn(&Call) -> bool) -> usize {
    c.effects.calls.iter().filter(|call| f(call)).count()
}

fn stops_of(c: &Colony<Sim>, node: u32) -> usize {
    count(c, |call| matches!(call, Call::Stop(n, _, _) if *n == node))
}

fn starts_of(c: &Colony<Sim>, node: u32) -> usize {
    count(c, |call| matches!(call, Call::Start(n) if *n == node))
}

fn signals_of(c: &Colony<Sim>, node: u32) -> Vec<i32> {
    c.effects
        .calls
        .iter()
        .filter_map(|call| match call {
            Call::Signal(n, sig) if *n == node => Some(*sig),
            _ => None,
        })
        .collect()
}

/// Boots `frames` with `a` enabled, lets it settle and refreshes `b`.
fn refreshed(frames: &str) -> (Colony<Sim>, u32, u32) {
    let (mut c, _) = boot(frames, &["a"], Sim::new());
    pass(&mut c, 5);
    let (a, b) = (idx(&c, "a"), idx(&c, "b"));
    let now = c.effects.now();
    c.request(b, Request::Refresh, now);
    pass(&mut c, 5);
    (c, a, b)
}

#[test]
fn refresh_on_a_reloadable_ready_node_signals_and_stays_ready() {
    let (c, _, b) = refreshed(&pair("none", true));
    assert_eq!(signals_of(&c, b), [1]);
    assert_eq!(stops_of(&c, b), 0);
    assert_eq!(starts_of(&c, b), 1);
    assert_eq!(c.state(b), Some(State::Ready));
}

#[test]
fn each_reload_signal_is_its_linux_number() {
    for (name, number) in [("SIGHUP", 1), ("SIGUSR1", 10), ("SIGUSR2", 12)] {
        let frames = format!(
            "[worker.b]\ncredentials = {{ uid = \"svc\" }}\nexec = [\"/bin/b\"]\nreload = \"{name}\"\n"
        );
        let (mut c, _) = boot(&frames, &["b"], Sim::new());
        pass(&mut c, 5);
        let b = idx(&c, "b");
        let now = c.effects.now();
        c.request(b, Request::Refresh, now);
        assert_eq!(signals_of(&c, b), [number], "{name}");
    }
}

#[test]
fn refresh_without_reload_restarts_the_node() {
    let (c, _, b) = refreshed(&pair("none", false));
    assert_eq!(stops_of(&c, b), 1);
    assert_eq!(starts_of(&c, b), 2);
    assert_eq!(signals_of(&c, b), Vec::<i32>::new());
    assert_eq!(c.state(b), Some(State::Ready));
}

#[test]
fn a_refresh_edge_dependent_restarts_on_a_refresh() {
    for reload in [true, false] {
        let (c, a, _) = refreshed(&pair("refresh", reload));
        assert_eq!(stops_of(&c, a), 1, "reload {reload}");
        assert_eq!(starts_of(&c, a), 2, "reload {reload}");
        assert_eq!(c.state(a), Some(State::Ready));
    }
}

#[test]
fn a_restart_edge_dependent_does_not_restart_on_a_reload() {
    let (c, a, b) = refreshed(&pair("restart", true));
    assert_eq!(signals_of(&c, b), [1]);
    assert_eq!(stops_of(&c, a), 0);
    assert_eq!(starts_of(&c, a), 1);
}

#[test]
fn a_restart_edge_dependent_restarts_when_the_refresh_restarted_the_target() {
    let (c, a, _) = refreshed(&pair("restart", false));
    assert_eq!(stops_of(&c, a), 1);
    assert_eq!(starts_of(&c, a), 2);
}

#[test]
fn an_error_edge_ignores_a_refresh() {
    for reload in [true, false] {
        let (c, a, _) = refreshed(&pair("error", reload));
        assert_eq!(stops_of(&c, a), 0, "reload {reload}");
        assert_eq!(starts_of(&c, a), 1, "reload {reload}");
    }
}

#[test]
fn a_none_edge_ignores_a_refresh() {
    let (c, a, _) = refreshed(&pair("none", true));
    assert_eq!(stops_of(&c, a), 0);
}

#[test]
fn refresh_on_a_node_that_is_not_running_is_refused() {
    let (mut c, _) = boot(&pair("none", true), &["a"], Sim::new());
    // `b` is pulled in by `a`; a second database leaves it off.
    let lone =
        "[worker.c]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/c\"]\nreload = \"SIGHUP\"\n";
    let (mut off, _) = boot(lone, &[], Sim::new());
    let n = idx(&off, "c");
    let out = off.request(n, Request::Refresh, 0);
    assert!(
        out.notices.contains(&Notice::Node(n, Report::Refused)),
        "{:?}",
        out.notices
    );
    assert_eq!(off.effects.calls.len(), 0);
    pass(&mut c, 1);
}

#[test]
fn a_refresh_during_shutdown_is_refused() {
    let (mut c, _) = boot(&pair("none", true), &["a"], Sim::new());
    pass(&mut c, 5);
    let b = idx(&c, "b");
    let now = c.effects.now();
    c.shutdown(now);
    let out = c.request(b, Request::Refresh, now);
    assert!(out.notices.contains(&Notice::Node(b, Report::Refused)));
    assert_eq!(signals_of(&c, b), Vec::<i32>::new());
}

#[test]
fn a_node_with_a_stop_pending_is_not_resurrected_by_a_refresh() {
    let (mut c, _) = boot(&pair("restart", false), &["a"], Sim::new());
    pass(&mut c, 5);
    let (a, b) = (idx(&c, "a"), idx(&c, "b"));
    let now = c.effects.now();
    // Stopping `b` stops its hard dependent `a` first; `b` waits with its stop pending, and a
    // refresh in that moment must neither cancel the stop nor restart it.
    c.request(b, Request::Stop, now);
    let out = c.request(b, Request::Refresh, now);
    pass(&mut c, 5);
    assert_eq!(c.state(b), Some(State::Off), "{:?}", out.notices);
    assert_eq!(starts_of(&c, b), 1, "b was not started again");
    assert_ne!(c.state(a), Some(State::Ready), "a waits for the stopped b");
}
