// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Restart pacing, the breaker, quarantine and foragers, against virtual time.
mod common;

use common::*;
use qinit_colony::sim::{Call, Script, Sim};
use qinit_colony::{Notice, Reason, Report, Request, State};

/// A simulation in which node `name` of `frames` follows `script`.
fn scripted(frames: &str, enable: &[&str], name: &str, script: Script) -> Sim {
    let (probe, _) = boot(frames, enable, Sim::new());
    let mut sim = Sim::new();
    sim.scripts.insert(idx(&probe, name), script);
    sim
}

fn start_times(c: &qinit_colony::Colony<Sim>, node: u32) -> Vec<u64> {
    c.effects
        .starts
        .iter()
        .filter(|(n, _)| *n == node)
        .map(|&(_, t)| t)
        .collect()
}

#[test]
fn a_crash_loop_backs_off_and_quarantines() {
    let script = Script {
        exit_after: Some((10, Some(1))),
        ..Script::default()
    };
    let sim = scripted("crashy.toml", &["crashy"], "crashy", script);
    let (mut c, _) = boot("crashy.toml", &["crashy"], sim);
    let n = idx(&c, "crashy");
    pass(&mut c, 20_000);
    // The delay doubles from one second, measured from the previous start: 0, 1 s, 3 s, 7 s.
    assert_eq!(start_times(&c, n), [0, 1000, 3000, 7000]);
    assert_eq!(c.state(n), Some(State::Quarantined(Reason::Breaker)));
}

#[test]
fn clear_restarts_a_quarantined_worker() {
    let script = Script {
        exit_after: Some((10, Some(1))),
        ..Script::default()
    };
    let sim = scripted("crashy.toml", &["crashy"], "crashy", script);
    let (mut c, _) = boot("crashy.toml", &["crashy"], sim);
    let n = idx(&c, "crashy");
    pass(&mut c, 20_000);
    assert_eq!(c.state(n), Some(State::Quarantined(Reason::Breaker)));
    let now = c.effects.now();
    let out = c.request(n, Request::Clear, now);
    assert!(out.errors.is_empty());
    assert_eq!(start_times(&c, n).len(), 5, "cleared and started again");
    // A refused clear is reported, not silent.
    let out = c.request(n, Request::Clear, now);
    assert!(
        out.notices.contains(&Notice::Node(n, Report::Refused)),
        "{:?}",
        out.notices
    );
}

#[test]
fn a_long_run_resets_the_backoff() {
    let script = Script {
        exit_after: Some((20_000, Some(1))),
        ..Script::default()
    };
    let sim = scripted("crashy.toml", &["crashy"], "crashy", script);
    let (mut c, _) = boot("crashy.toml", &["crashy"], sim);
    let n = idx(&c, "crashy");
    pass(&mut c, 45_000);
    // It ran longer than the back-off cap each time, so it restarts at once, not after 2 s.
    assert_eq!(&start_times(&c, n)[..3], [0, 20_000, 40_000]);
}

#[test]
fn a_start_timeout_stops_and_counts() {
    let script = Script {
        ready_after_ms: None,
        ..Script::default()
    };
    let sim = scripted("slow.toml", &["slow"], "slow", script);
    let (mut c, _) = boot("slow.toml", &["slow"], sim);
    let n = idx(&c, "slow");
    pass(&mut c, 4999);
    assert!(
        !c.effects
            .calls
            .iter()
            .any(|call| matches!(call, Call::Stop(..))),
        "not before the timeout"
    );
    pass(&mut c, 1);
    assert!(
        c.effects
            .calls
            .contains(&Call::Stop(n, qinit_colony::StopMode::Main, 10_000))
    );
    pass(&mut c, 30_000);
    assert_eq!(
        c.state(n),
        Some(State::Quarantined(Reason::Breaker)),
        "timeouts are failures"
    );
    assert_eq!(start_times(&c, n), [0, 5000, 10_000, 15_000]);
}

#[test]
fn a_forager_runs_once_and_reports_done() {
    let (probe, _) = boot("forager.toml", &["w"], Sim::new());
    let (w, job) = (idx(&probe, "w"), idx(&probe, "job"));
    let mut sim = Sim::new();
    sim.scripts.insert(
        job,
        Script {
            exit_after: Some((50, Some(0))),
            ..Script::default()
        },
    );
    let (mut c, _) = boot("forager.toml", &["w"], sim);
    pass(&mut c, 1);
    assert_eq!(c.state(w), Some(State::Ready));
    assert_eq!(c.state(job), Some(State::Off), "a forager waits to be run");
    let out = c.request(job, Request::Run, c.effects.now());
    assert!(out.errors.is_empty());
    let notices = pass(&mut c, 100);
    assert_eq!(c.state(job), Some(State::Done));
    assert!(
        notices.contains(&Notice::Node(job, Report::Done)),
        "{notices:?}"
    );
    assert_eq!(start_times(&c, job).len(), 1);
}

#[test]
fn a_failed_forager_is_not_restarted() {
    let (probe, _) = boot("forager.toml", &["w"], Sim::new());
    let job = idx(&probe, "job");
    let mut sim = Sim::new();
    sim.scripts.insert(
        job,
        Script {
            exit_after: Some((50, Some(1))),
            ..Script::default()
        },
    );
    let (mut c, _) = boot("forager.toml", &["w"], sim);
    pass(&mut c, 1);
    c.request(job, Request::Run, c.effects.now());
    let notices = pass(&mut c, 60_000);
    assert_eq!(c.state(job), Some(State::Off));
    assert!(
        notices.contains(&Notice::Node(job, Report::Failed(Some(1)))),
        "{notices:?}"
    );
    assert_eq!(
        start_times(&c, job).len(),
        1,
        "never run again without a request"
    );
}

// ---- final review fixes ----

#[test]
fn an_adopted_node_waiting_for_a_path_is_watched_and_comes_back() {
    let frames = "[worker.a]\nexec = [\"/bin/a\"]\nrestart = { policy = \"on-failure\" }\n\
                  deps = [{ group = \"require_all\", edges = [{ path = \"/run/x\" }] }]\n";
    let mut sim = Sim::new();
    sim.paths.insert("/run/x".to_owned());
    sim.cells.insert(0);
    let (mut c, out) =
        qinit_colony::Colony::load(database(frames, &["a"]), &[(0, true)], sim, 0).expect("loads");
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    assert!(
        c.effects.calls.contains(&Call::Watch("/run/x".to_owned())),
        "{:?}",
        c.effects.calls
    );
    c.on_cell(0, qinit_cell_core::Report::MainExited(Some(1)), 10);
    c.on_cell(0, qinit_cell_core::Report::Empty, 10);
    pass(&mut c, 5000);
    assert_eq!(c.state(0), Some(State::Ready), "{}", c.status(5000));
}

#[test]
fn a_failed_start_is_not_stopped_through_the_effects() {
    // There is no cell to stop: a layer that refuses `stop` for it must not strand the node.
    let mut sim = Sim::new();
    sim.fail_start.insert(0);
    let (c, _) = boot("[worker.a]\nexec = [\"/bin/a\"]\n", &["a"], sim);
    assert_eq!(c.state(0), Some(State::Off), "{}", c.status(0));
    assert!(
        !c.effects
            .calls
            .iter()
            .any(|x| matches!(x, Call::Stop(..) | Call::Release(_))),
        "{:?}",
        c.effects.calls
    );
}

#[test]
fn a_stale_empty_does_not_release_a_cell_twice() {
    let (mut c, _) = boot("crashy.toml", &["crashy"], Sim::new());
    c.on_cell(0, qinit_cell_core::Report::Empty, 5);
    c.on_cell(0, qinit_cell_core::Report::Empty, 6);
    let releases = c
        .effects
        .calls
        .iter()
        .filter(|x| matches!(x, Call::Release(0)))
        .count();
    assert_eq!(releases, 1);
}
