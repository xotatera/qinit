// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The two-phase database swap through the whole pipeline: TOML, compiler, database, scheduler,
//! simulated cells.
mod common;

use common::*;
use qinit_colony::sim::{Call, Script, Sim, advance};
use qinit_colony::{Colony, LaunchArgs, Notice, Request, SlotState, State, SwapError};

fn worker(name: &str, extra: &str) -> String {
    format!(
        "[worker.{name}]\ncredentials = {{ uid = \"svc\" }}\nexec = [\"/bin/{name}\"]\n{extra}\n"
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

fn signals_of(c: &Colony<Sim>, node: u32) -> usize {
    count(c, |call| matches!(call, Call::Signal(n, _) if *n == node))
}

fn swapped(out: &qinit_colony::Outcome) -> bool {
    out.notices.contains(&Notice::Swapped)
}

fn position(c: &Colony<Sim>, f: impl Fn(&Call) -> bool) -> Option<usize> {
    c.effects.calls.iter().position(f)
}

#[test]
fn an_identical_database_changes_nothing() {
    let frames = format!("{}{}", worker("a", ""), worker("b", ""));
    let (mut c, _) = boot(&frames, &["a", "b"], Sim::new());
    pass(&mut c, 5);
    let calls = c.effects.calls.len();
    let out = c
        .refresh(database(&frames, &["a", "b"]), c.effects.now())
        .unwrap();
    assert!(swapped(&out), "{:?}", out.notices);
    assert_eq!(c.effects.calls.len(), calls);
    assert!(!c.swapping());
    assert_eq!(c.state(idx(&c, "a")), Some(State::Ready));
}

#[test]
fn a_removed_node_stops_and_disappears() {
    let both = format!("{}{}", worker("a", ""), worker("b", ""));
    let (mut c, _) = boot(&both, &["a", "b"], Sim::new());
    pass(&mut c, 5);
    let (a, b) = (idx(&c, "a"), idx(&c, "b"));
    let now = c.effects.now();
    let only_a = worker("a", "");
    let out = c.refresh(database(&only_a, &["a"]), now).unwrap();
    pass(&mut c, 5);
    assert!(c.node_index("b").is_none());
    assert_eq!(stops_of(&c, b), 1);
    assert_eq!(stops_of(&c, a), 0);
    assert_eq!(c.state(idx(&c, "a")), Some(State::Ready));
    assert!(!c.swapping());
    let _ = out;
}

#[test]
fn an_added_enabled_node_starts_after_phase_1() {
    let one = worker("a", "");
    let (mut c, _) = boot(&one, &["a"], Sim::new());
    pass(&mut c, 5);
    let two = format!("{}{}", worker("a", ""), worker("c", ""));
    let out = c
        .refresh(database(&two, &["a", "c"]), c.effects.now())
        .unwrap();
    assert!(swapped(&out));
    pass(&mut c, 5);
    let cc = idx(&c, "c");
    assert_eq!(starts_of(&c, cc), 1);
    assert_eq!(c.state(cc), Some(State::Ready));
    assert_eq!(starts_of(&c, idx(&c, "a")), 1, "a keeps running");
}

#[test]
fn an_added_node_that_is_not_enabled_stays_off() {
    let one = worker("a", "");
    let (mut c, _) = boot(&one, &["a"], Sim::new());
    pass(&mut c, 5);
    let two = format!("{}{}", worker("a", ""), worker("c", ""));
    c.refresh(database(&two, &["a"]), c.effects.now()).unwrap();
    pass(&mut c, 5);
    assert_eq!(c.state(idx(&c, "c")), Some(State::Off));
}

#[test]
fn a_rename_never_runs_twice() {
    let old = worker("a", "");
    let (mut c, _) = boot(&old, &["a"], Sim::new());
    // The old one needs a while to stop.
    c.effects.scripts.insert(
        0,
        Script {
            ignore_term: true,
            ..Script::default()
        },
    );
    pass(&mut c, 5);
    let a = idx(&c, "a");
    let renamed = worker("b", "");
    let now = c.effects.now();
    let out = c.refresh(database(&renamed, &["b"]), now).unwrap();
    assert!(c.swapping(), "phase 1 waits for a to stop");
    assert!(!swapped(&out));
    pass(&mut c, 20_000);
    assert!(!c.swapping());
    let b = idx(&c, "b");
    let released = position(&c, |call| matches!(call, Call::Release(n) if *n == a)).unwrap();
    let last_start = c
        .effects
        .calls
        .iter()
        .rposition(|call| matches!(call, Call::Start(n) if *n == b))
        .unwrap();
    assert!(released < last_start, "b starts only once a is released");
    assert_eq!(starts_of(&c, b), 2, "a once, then b");
    assert_eq!(c.state(b), Some(State::Ready));
}

#[test]
fn a_changed_launch_field_restarts_the_node() {
    let old = worker("a", "");
    let (mut c, _) = boot(&old, &["a"], Sim::new());
    pass(&mut c, 5);
    let new = "[worker.a]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/a\", \"--new\"]\n";
    c.refresh(database(new, &["a"]), c.effects.now()).unwrap();
    pass(&mut c, 5);
    let a = idx(&c, "a");
    assert_eq!(stops_of(&c, a), 1);
    assert_eq!(starts_of(&c, a), 2);
    assert_eq!(c.state(a), Some(State::Ready));
    assert_eq!(c.model().nodes[a as usize].exec, ["/bin/a", "--new"]);
}

fn with_dep(extra_dep: bool, reload: bool) -> String {
    let reload = if reload { "reload = \"SIGHUP\"\n" } else { "" };
    let deps = if extra_dep {
        "deps = [{ group = \"optional_all\", edges = [{ to = \"d\" }] }]\n"
    } else {
        ""
    };
    format!(
        "{}{}{}",
        worker("a", &format!("{reload}{deps}")),
        worker("d", ""),
        ""
    )
}

#[test]
fn a_changed_dependency_only_with_reload_signals() {
    let (mut c, _) = boot(&with_dep(false, true), &["a"], Sim::new());
    pass(&mut c, 5);
    let a = idx(&c, "a");
    c.refresh(database(&with_dep(true, true), &["a"]), c.effects.now())
        .unwrap();
    pass(&mut c, 5);
    assert_eq!(signals_of(&c, a), 1);
    assert_eq!(stops_of(&c, a), 0);
    assert_eq!(starts_of(&c, a), 1);
    assert_eq!(c.state(a), Some(State::Ready));
}

#[test]
fn a_changed_dependency_without_reload_restarts() {
    let (mut c, _) = boot(&with_dep(false, false), &["a"], Sim::new());
    pass(&mut c, 5);
    let a = idx(&c, "a");
    c.refresh(database(&with_dep(true, false), &["a"]), c.effects.now())
        .unwrap();
    pass(&mut c, 5);
    assert_eq!(signals_of(&c, a), 0);
    assert_eq!(stops_of(&c, a), 1);
    assert_eq!(starts_of(&c, a), 2);
}

#[test]
fn a_changed_node_that_is_off_only_takes_the_new_definition() {
    let old = format!("{}{}", worker("a", ""), worker("z", ""));
    let (mut c, _) = boot(&old, &["a"], Sim::new());
    pass(&mut c, 5);
    let calls = c.effects.calls.len();
    let new = format!(
        "{}[worker.z]\ncredentials = {{ uid = \"svc\" }}\nexec = [\"/bin/z2\"]\n",
        worker("a", "")
    );
    c.refresh(database(&new, &["a"]), c.effects.now()).unwrap();
    pass(&mut c, 5);
    let z = idx(&c, "z");
    assert_eq!(c.effects.calls.len(), calls);
    assert_eq!(c.state(z), Some(State::Off));
    assert_eq!(c.model().nodes[z as usize].exec, ["/bin/z2"]);
}

#[test]
fn refresh_edges_fire_for_refreshed_nodes_in_phase_2() {
    let old = format!(
        "{}{}",
        worker(
            "a",
            "deps = [{ group = \"require_all\", edges = [{ to = \"b\", restart_on = \"refresh\" }] }]\n"
        ),
        worker("b", "reload = \"SIGHUP\"\n")
    );
    let (mut c, _) = boot(&old, &["a"], Sim::new());
    pass(&mut c, 5);
    let (a, b) = (idx(&c, "a"), idx(&c, "b"));
    // b gains a new dependency (not launch-affecting): it is signalled, and a restarts.
    let new = format!(
        "{}{}{}",
        worker(
            "a",
            "deps = [{ group = \"require_all\", edges = [{ to = \"b\", restart_on = \"refresh\" }] }]\n"
        ),
        worker(
            "b",
            "reload = \"SIGHUP\"\ndeps = [{ group = \"optional_all\", edges = [{ to = \"d\" }] }]\n"
        ),
        worker("d", "")
    );
    c.refresh(database(&new, &["a"]), c.effects.now()).unwrap();
    pass(&mut c, 5);
    assert_eq!(signals_of(&c, b), 1);
    assert_eq!(stops_of(&c, a), 1);
    assert_eq!(starts_of(&c, a), 2);
    assert_eq!(stops_of(&c, b), 0);
}

#[test]
fn an_invalid_database_changes_nothing() {
    let frames = worker("a", "");
    let (mut c, _) = boot(&frames, &["a"], Sim::new());
    pass(&mut c, 5);
    let calls = c.effects.calls.len();
    let mut bad = database(&frames, &["a"]);
    bad.truncate(bad.len() - 3);
    assert!(matches!(
        c.refresh(bad, c.effects.now()),
        Err(SwapError::Invalid(_))
    ));
    let junk = vec![7u8; 100];
    assert!(matches!(
        c.refresh(junk, c.effects.now()),
        Err(SwapError::Invalid(_))
    ));
    assert_eq!(c.effects.calls.len(), calls);
    assert_eq!(c.state(idx(&c, "a")), Some(State::Ready));
    assert!(!c.swapping());
}

fn slow_removed() -> (Colony<Sim>, String) {
    let both = format!("{}{}", worker("a", ""), worker("b", ""));
    let (mut c, _) = boot(&both, &["a", "b"], Sim::new());
    let b = idx(&c, "b");
    c.effects.scripts.insert(
        b,
        Script {
            ignore_term: true,
            ..Script::default()
        },
    );
    pass(&mut c, 5);
    (c, worker("a", ""))
}

#[test]
fn a_refresh_during_phase_1_is_busy() {
    let (mut c, only_a) = slow_removed();
    let now = c.effects.now();
    c.refresh(database(&only_a, &["a"]), now).unwrap();
    assert!(c.swapping());
    assert!(matches!(
        c.refresh(database(&only_a, &["a"]), now),
        Err(SwapError::Busy)
    ));
    pass(&mut c, 20_000);
    assert!(!c.swapping());
}

#[test]
fn a_refresh_during_shutdown_is_refused() {
    let frames = worker("a", "");
    let (mut c, _) = boot(&frames, &["a"], Sim::new());
    pass(&mut c, 5);
    c.shutdown(c.effects.now());
    assert!(matches!(
        c.refresh(database(&frames, &["a"]), c.effects.now()),
        Err(SwapError::ShuttingDown)
    ));
}

#[test]
fn a_shutdown_during_phase_1_stops_the_old_graph() {
    let (mut c, only_a) = slow_removed();
    let now = c.effects.now();
    c.refresh(database(&only_a, &["a"]), now).unwrap();
    assert!(c.swapping());
    let out = c.shutdown(now);
    assert!(!c.swapping());
    let _ = out;
    pass(&mut c, 30_000);
    assert!(c.node_index("b").is_some(), "the swap never happened");
    assert_eq!(c.state(idx(&c, "a")), Some(State::Off));
    assert_eq!(c.state(idx(&c, "b")), Some(State::Off));
}

fn frames_with_forager(extra: &str) -> String {
    format!(
        "[forager.job]\ncredentials = {{ uid = \"svc\" }}\nexec = [\"/bin/job\"]\n{extra}\
         [forager.job.launch]\nconcurrency = 2\n{}",
        worker("a", "")
    )
}

fn launch(c: &mut Colony<Sim>) -> u32 {
    c.effects.instance_script = Script {
        ready_after_ms: None,
        exit_after: None,
        ..Script::default()
    };
    let now = c.effects.now();
    c.launch(
        LaunchArgs {
            frame: "job".into(),
            argv_tail: Vec::new(),
            env_add: Vec::new(),
            fds: [None, None, None],
        },
        now,
    )
    .unwrap()
    .0
}

#[test]
fn instances_of_a_removed_frame_are_stopped_in_phase_1() {
    let (mut c, _) = boot(&frames_with_forager(""), &["a"], Sim::new());
    pass(&mut c, 5);
    let id = launch(&mut c);
    pass(&mut c, 5);
    let only_a = worker("a", "");
    let now = c.effects.now();
    c.refresh(database(&only_a, &["a"]), now).unwrap();
    pass(&mut c, 50);
    assert!(!c.swapping());
    assert!(c.node_index("job").is_none());
    assert_eq!(c.instance(id).unwrap().state, SlotState::Exited(-1));
}

#[test]
fn instances_of_a_changed_frame_keep_running() {
    let (mut c, _) = boot(&frames_with_forager(""), &["a"], Sim::new());
    pass(&mut c, 5);
    let id = launch(&mut c);
    pass(&mut c, 5);
    let changed = frames_with_forager("env = { NEW = \"1\" }\n");
    let now = c.effects.now();
    c.refresh(database(&changed, &["a"]), now).unwrap();
    pass(&mut c, 50);
    assert!(!c.swapping());
    let view = c.instance(id).unwrap();
    assert!(matches!(
        view.state,
        SlotState::Starting | SlotState::Running
    ));
    assert_eq!(view.frame, idx(&c, "job"));
    assert_eq!(c.live_instances(idx(&c, "job")), 1);
}

#[test]
fn a_node_keeps_its_timers_across_a_renumbering() {
    // `a` starts slowly (ready after 3 s); a node sorted before it appears in the new database,
    // so a's index changes while its readiness is still to come.
    let old = worker("m", "");
    let (probe, _) = boot(&old, &["m"], Sim::new());
    let m = idx(&probe, "m");
    let mut sim = Sim::new();
    sim.scripts.insert(
        m,
        Script {
            ready_after_ms: Some(3000),
            ..Script::default()
        },
    );
    let (mut c, _) = boot(&old, &["m"], sim);
    pass(&mut c, 1000);
    assert_eq!(c.state(idx(&c, "m")), Some(State::Starting));
    let new = format!("{}{}", worker("a", ""), worker("m", ""));
    c.refresh(database(&new, &["m"]), c.effects.now()).unwrap();
    advance(&mut c, 3000);
    assert_eq!(c.state(idx(&c, "m")), Some(State::Ready));
}

#[test]
fn requests_still_reach_a_node_after_a_swap() {
    let one = worker("a", "");
    let (mut c, _) = boot(&one, &["a"], Sim::new());
    pass(&mut c, 5);
    let two = format!("{}{}", worker("a", ""), worker("c", ""));
    c.refresh(database(&two, &["a"]), c.effects.now()).unwrap();
    let cc = idx(&c, "c");
    let now = c.effects.now();
    c.request(cc, Request::Start, now);
    pass(&mut c, 5);
    assert_eq!(c.state(cc), Some(State::Ready));
}
