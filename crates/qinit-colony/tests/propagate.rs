// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Failure and restart propagation, cascade, async deadlines and exclusion through the whole
//! pipeline: TOML, compiler, database, scheduler, simulated cells.
mod common;

use common::*;
use qinit_colony::sim::{Call, Script, Sim};
use qinit_colony::{Colony, Reason, Request, State};

/// `a` requires `b` with the given `restart_on`; both enabled.
fn pair(restart_on: &str) -> String {
    format!(
        "[worker.a]\nexec = [\"/bin/a\"]\n\
         deps = [{{ group = \"require_all\", edges = [{{ to = \"b\", restart_on = \"{restart_on}\" }}] }}]\n\
         [worker.b]\nexec = [\"/bin/b\"]\n"
    )
}

fn stopped(c: &Colony<Sim>, name: &str) -> bool {
    let n = idx(c, name);
    c.effects
        .calls
        .iter()
        .any(|call| matches!(call, Call::Stop(x, _, _) if *x == n))
}

#[test]
fn restart_on_values_behave() {
    // (restart_on, a is stopped by an administrator's stop of b, by a failure of b)
    for (on, by_stop, by_failure) in [
        ("none", false, false),
        ("error", false, true),
        ("restart", true, true),
    ] {
        let frames = pair(on);
        // An administrator's stop of b.
        let (mut c, _) = boot(&frames, &["a"], Sim::new());
        pass(&mut c, 5);
        let b = idx(&c, "b");
        c.request(b, Request::Stop, 10);
        pass(&mut c, 5);
        assert_eq!(
            stopped(&c, "a"),
            by_stop,
            "restart_on {on}, administrator's stop"
        );
        // A failure of b: its main process exits with status 1.
        let (probe, _) = boot(&frames, &["a"], Sim::new());
        let mut sim = Sim::new();
        sim.scripts.insert(
            idx(&probe, "b"),
            Script {
                exit_after: Some((100, Some(1))),
                ..Script::default()
            },
        );
        let (mut c, _) = boot(&frames, &["a"], sim);
        pass(&mut c, 200);
        assert_eq!(stopped(&c, "a"), by_failure, "restart_on {on}, failure");
    }
}

#[test]
fn cascade_and_per_node_clear() {
    let frames = "[worker.a]\nexec = [\"/bin/a\"]\n\
        deps = [{ group = \"require_all\", edges = [{ to = \"b\", restart_on = \"none\", cascade = true }] }]\n\
        [worker.b]\nexec = [\"/bin/b\"]\nrestart = { policy = \"on-failure\", max = 1 }\n";
    let (probe, _) = boot(frames, &["a"], Sim::new());
    let mut sim = Sim::new();
    sim.scripts.insert(
        idx(&probe, "b"),
        Script {
            exit_after: Some((10, Some(1))),
            ..Script::default()
        },
    );
    let (mut c, _) = boot(frames, &["a"], sim);
    let (a, b) = (idx(&c, "a"), idx(&c, "b"));
    pass(&mut c, 10_000);
    assert_eq!(c.state(b), Some(State::Quarantined(Reason::Breaker)));
    assert_eq!(c.state(a), Some(State::Quarantined(Reason::Cascade)));
    // Clearing a alone changes nothing while b is quarantined.
    let now = c.effects.now();
    c.request(a, Request::Clear, now);
    assert_eq!(c.state(a), Some(State::Quarantined(Reason::Cascade)));
    // Fix b, clear b, then clear a.
    c.effects.scripts.insert(b, Script::default());
    c.request(b, Request::Clear, now);
    pass(&mut c, 1);
    assert_eq!(c.state(b), Some(State::Ready));
    c.request(a, Request::Clear, c.effects.now());
    pass(&mut c, 1);
    assert_eq!(c.state(a), Some(State::Ready));
}

#[test]
fn async_deadline_then_late_arrival_restart() {
    let frames = "[worker.a]\nexec = [\"/bin/a\"]\n\
        deps = [{ group = \"require_all\", edges = [{ to = \"b\", mode = \"async\", deadline = \"1s\", restart_on = \"restart\" }] }]\n\
        [worker.b]\nexec = [\"/bin/b\"]\n";
    let (probe, _) = boot(frames, &["a"], Sim::new());
    let mut sim = Sim::new();
    sim.scripts.insert(
        idx(&probe, "b"),
        Script {
            ready_after_ms: Some(3000),
            ..Script::default()
        },
    );
    let (mut c, _) = boot(frames, &["a"], sim);
    let a = idx(&c, "a");
    pass(&mut c, 999);
    assert!(
        c.effects.starts.iter().all(|(n, _)| *n != a),
        "a waits for its deadline"
    );
    pass(&mut c, 1);
    assert_eq!(c.effects.starts.iter().filter(|(n, _)| *n == a).count(), 1);
    pass(&mut c, 5000);
    // b arrived at 3 s: a is restarted, once.
    let times: Vec<u64> = c
        .effects
        .starts
        .iter()
        .filter(|(n, _)| *n == a)
        .map(|&(_, t)| t)
        .collect();
    assert_eq!(times, [1000, 3000]);
    assert_eq!(c.state(a), Some(State::Ready));
}

#[test]
fn exclude_conflict() {
    let frames = "[worker.a]\nexec = [\"/bin/a\"]\n\
        deps = [{ group = \"exclude_all\", edges = [{ to = \"b\" }] }]\n\
        [worker.b]\nexec = [\"/bin/b\"]\n";
    let (mut c, _) = boot(frames, &["a", "b"], Sim::new());
    pass(&mut c, 10);
    let (a, b) = (idx(&c, "a"), idx(&c, "b"));
    assert_eq!(c.state(b), Some(State::Ready));
    assert_ne!(c.state(a), Some(State::Ready), "a and b exclude each other");
    c.request(b, Request::Stop, c.effects.now());
    pass(&mut c, 10);
    assert_eq!(c.state(a), Some(State::Ready), "a runs once b is gone");
}
