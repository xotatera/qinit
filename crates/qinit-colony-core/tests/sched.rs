// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The scheduler over real databases: group evaluation, starts, exclusion, the bounded drain.
mod common;

use common::*;
use qinit_colony_core::{
    Action, CellReport, Input, K, NodeState, Reason, Report, Request, State, TimerKind, Why,
    inv_ok, load_from, off, restore,
};
use qinit_db::{GroupKind, RestartOn, RestartPolicy};

/// `a` requires `b` (sync), both enabled.
fn a_requires_b() -> qinit_db::Model {
    model(
        vec![requires(worker("a"), vec![edge(1)]), worker("b")],
        &[0, 1],
    )
}

#[test]
fn an_enabled_node_without_deps_starts_at_load() {
    let (h, actions) = Harness::load(model(vec![worker("a")], &[0]));
    assert_eq!(h.state("a"), State::Starting);
    assert_eq!(
        actions,
        [
            Action::Arm(0, TimerKind::StartTimeout, 90_000),
            Action::Start(0),
            Action::Report(0, Report::Started),
        ]
    );
}

#[test]
fn a_sync_dependent_waits_for_ready() {
    let (mut h, actions) = Harness::load(a_requires_b());
    assert_eq!(starts(&h, &actions), ["b"]);
    assert_eq!(h.state("a"), State::Waiting(Why::Deps));
    let actions = h.cell("b", CellReport::Ready, 5);
    assert_eq!(starts(&h, &actions), ["a"]);
    assert_eq!(h.state("a"), State::Starting);
    assert!(actions.contains(&Action::Report(1, Report::Ready)));
}

#[test]
fn independent_branches_start_in_one_drain() {
    let (h, actions) = Harness::load(model(
        vec![worker("a"), worker("b"), worker("c")],
        &[0, 1, 2],
    ));
    assert_eq!(starts(&h, &actions), ["a", "b", "c"]);
}

#[test]
fn an_async_edge_with_a_zero_deadline_does_not_wait() {
    let a = requires(worker("a"), vec![async_edge(1, 0)]);
    let (h, actions) = Harness::load(model(vec![a, worker("b")], &[0, 1]));
    assert_eq!(starts(&h, &actions), ["a", "b"]);
}

#[test]
fn an_async_deadline_arms_an_edge_timer_and_then_starts() {
    let a = requires(worker("a"), vec![async_edge(1, 1000)]);
    let (mut h, actions) = Harness::load(model(vec![a, worker("b")], &[0, 1]));
    assert_eq!(starts(&h, &actions), ["b"]);
    assert!(
        actions.contains(&Action::Arm(0, TimerKind::Edge, 1000)),
        "{actions:?}"
    );
    assert_eq!(h.state("a"), State::Waiting(Why::Deps));
    let actions = h.deadline("a", TimerKind::Edge, 1000);
    assert_eq!(starts(&h, &actions), ["a"]);
}

#[test]
fn a_path_edge_watches_and_starts_on_appearance() {
    let a = requires(worker("a"), vec![path_edge("/run/x")]);
    let (mut h, actions) = Harness::load(model(vec![a], &[0]));
    assert!(actions.contains(&Action::WatchPath(0)), "{actions:?}");
    assert!(starts(&h, &actions).is_empty());
    let actions = h.input(Input::PathAppeared { edge: 0 }, 7);
    assert_eq!(starts(&h, &actions), ["a"]);
}

#[test]
fn optional_all_waits_for_a_starting_target_but_not_for_one_that_will_never_run() {
    let mut a = worker("a");
    a.groups.push(group(GroupKind::OptionalAll, vec![edge(1)]));
    let b = restarting(worker("b"), RestartPolicy::Never, 0, 0);
    let (mut h, actions) = Harness::load(model(vec![a, b], &[0, 1]));
    assert_eq!(starts(&h, &actions), ["b"]);
    assert_eq!(
        h.state("a"),
        State::Waiting(Why::Deps),
        "b is still starting"
    );
    // b fails and, never restarted, goes off unwanted: a no longer waits for it.
    h.cell("b", CellReport::MainExited(Some(1)), 3);
    let actions = h.cell("b", CellReport::Empty, 3);
    assert_eq!(starts(&h, &actions), ["a"]);
}

#[test]
fn exclude_all_blocks_a_start_while_the_target_is_wanted() {
    let mut a = worker("a");
    a.groups.push(group(GroupKind::ExcludeAll, vec![edge(1)]));
    // b is wanted: a must not start, however far b gets.
    let (mut h, actions) = Harness::load(model(vec![a.clone(), worker("b")], &[0, 1]));
    assert_eq!(starts(&h, &actions), ["b"]);
    h.cell("b", CellReport::Ready, 1);
    assert_eq!(h.state("a"), State::Waiting(Why::Deps));
    // b is not wanted: a starts.
    let (h, actions) = Harness::load(model(vec![a, worker("b")], &[0]));
    assert_eq!(starts(&h, &actions), ["a"]);
}

#[test]
fn exclude_all_counts_a_wanted_target_that_is_not_running() {
    // b is wanted but waits for a path that never appears: not active, only wanted.
    let mut a = worker("a");
    a.groups.push(group(GroupKind::ExcludeAll, vec![edge(1)]));
    let b = requires(worker("b"), vec![path_edge("/run/never")]);
    let (h, actions) = Harness::load(model(vec![a, b], &[0, 1]));
    assert!(starts(&h, &actions).is_empty(), "{actions:?}");
    assert_eq!(h.state("a"), State::Waiting(Why::Deps));
    assert_eq!(h.state("b"), State::Waiting(Why::Deps));
}

#[test]
fn a_brood_is_ready_when_its_groups_are() {
    let m = brood("m");
    let m = requires(m, vec![edge(0), edge(1)]);
    let (mut h, _) = Harness::load(model(vec![worker("a"), worker("b"), m], &[0, 1, 2]));
    assert_eq!(h.state("m"), State::Waiting(Why::Deps));
    h.cell("a", CellReport::Ready, 1);
    assert_eq!(h.state("m"), State::Waiting(Why::Deps));
    let actions = h.cell("b", CellReport::Ready, 2);
    assert_eq!(h.state("m"), State::Ready);
    assert!(
        actions.contains(&Action::Report(2, Report::Ready)),
        "{actions:?}"
    );
    assert!(starts(&h, &actions).is_empty(), "a brood has no process");
}

#[test]
fn start_pulls_in_the_require_closure() {
    let nodes = vec![
        requires(worker("a"), vec![edge(1)]),
        requires(worker("b"), vec![edge(2)]),
        worker("c"),
        worker("d"),
    ];
    let (mut h, actions) = Harness::load(model(nodes, &[]));
    assert!(actions.is_empty(), "nothing is enabled");
    let actions = h.request("a", Request::Start, 5);
    assert_eq!(starts(&h, &actions), ["c"], "a needs b needs c");
    assert_eq!(h.state("d"), State::Off);
    assert!(h.node("b").wanted && h.node("c").wanted);
}

#[test]
fn the_drain_is_bounded() {
    let nodes: Vec<_> = (0..50).map(|i| worker(&format!("n{i:02}"))).collect();
    let enabled: Vec<u32> = (0..50).collect();
    let (h, actions) = Harness::load(model(nodes, &enabled));
    assert_eq!(actions.len(), 3 * 50, "arm, start, report per node");
    assert!(actions.len() <= K * h.nodes.len());
}

#[test]
fn a_start_waits_out_the_backoff() {
    let a = restarting(worker("a"), RestartPolicy::OnFailure, 0, 0);
    let (mut h, _) = Harness::load(model(vec![a], &[0]));
    h.cell("a", CellReport::Ready, 0);
    h.cell("a", CellReport::MainExited(Some(1)), 0);
    let actions = h.cell("a", CellReport::Empty, 0);
    assert_eq!(h.state("a"), State::Waiting(Why::Backoff));
    assert!(
        actions.contains(&Action::Arm(0, TimerKind::Backoff, 1000)),
        "{actions:?}"
    );
    assert!(starts(&h, &actions).is_empty());
    let actions = h.deadline("a", TimerKind::Backoff, 1000);
    assert_eq!(starts(&h, &actions), ["a"]);
}

#[test]
fn a_node_that_depends_on_a_quarantined_one_keeps_waiting() {
    let a = requires(worker("a"), vec![with_restart_on(edge(1), RestartOn::None)]);
    let b = restarting(worker("b"), RestartPolicy::OnFailure, 1, 60_000);
    let (mut h, _) = Harness::load(model(vec![a, b], &[0, 1]));
    for round in 0..2u64 {
        let t = round * 1000;
        h.cell("b", CellReport::MainExited(Some(1)), t);
        let actions = h.cell("b", CellReport::Empty, t);
        if round == 0 {
            h.deadline("b", TimerKind::Backoff, 1000);
            assert!(
                actions
                    .iter()
                    .any(|a| matches!(a, Action::Arm(1, TimerKind::Backoff, _)))
            );
        }
    }
    assert!(
        matches!(h.state("b"), State::Quarantined(_)),
        "{:?}",
        h.state("b")
    );
    assert_eq!(h.state("a"), State::Waiting(Why::Deps));
}

// ---- stops, propagation, cascade, shutdown (Task 7) ----

/// `a` requires `b` over a sync edge whose `restart_on` is `on`; both running and ready.
fn running_pair(on: RestartOn) -> Harness {
    let a = requires(worker("a"), vec![with_restart_on(edge(1), on)]);
    let (mut h, _) = Harness::load(model(vec![a, worker("b")], &[0, 1]));
    h.cell("b", CellReport::Ready, 1);
    h.cell("a", CellReport::Ready, 2);
    assert_eq!((h.state("a"), h.state("b")), (State::Ready, State::Ready));
    h
}

#[test]
fn a_dependency_stops_only_after_its_hard_dependents_are_empty() {
    let mut h = running_pair(RestartOn::Restart);
    let actions = h.request("b", Request::Stop, 10);
    assert_eq!(
        stops(&h, &actions),
        ["a"],
        "the dependent first: {actions:?}"
    );
    assert_eq!(h.state("a"), State::Stopping);
    assert_eq!(h.state("b"), State::Ready, "b waits for a to be empty");
    let actions = h.cell("a", CellReport::Empty, 11);
    assert_eq!(stops(&h, &actions), ["b"]);
    assert_eq!(h.state("b"), State::Stopping);
}

#[test]
fn a_none_dependent_outlives_its_dependency() {
    let mut h = running_pair(RestartOn::None);
    let actions = h.request("b", Request::Stop, 10);
    assert_eq!(stops(&h, &actions), ["b"], "{actions:?}");
    h.cell("b", CellReport::Empty, 11);
    assert_eq!(h.state("b"), State::Off);
    assert_eq!(
        h.state("a"),
        State::Ready,
        "restart_on none leaves it running"
    );
    // And it is not restarted when b comes back.
    let actions = h.request("b", Request::Start, 20);
    assert_eq!(starts(&h, &actions), ["b"]);
    let actions = h.cell("b", CellReport::Ready, 21);
    assert!(
        starts(&h, &actions).is_empty() && stops(&h, &actions).is_empty(),
        "{actions:?}"
    );
}

#[test]
fn an_error_dependent_stops_on_error_only() {
    let mut h = running_pair(RestartOn::Error);
    // An administrator's stop is not an error.
    let actions = h.request("b", Request::Stop, 10);
    assert_eq!(stops(&h, &actions), ["b"]);
    h.cell("b", CellReport::Empty, 11);
    assert_eq!(h.state("a"), State::Ready);
    let actions = h.request("b", Request::Start, 20);
    assert_eq!(starts(&h, &actions), ["b"]);
    h.cell("b", CellReport::Ready, 21);
    // A failure is.
    let actions = h.cell("b", CellReport::MainExited(Some(1)), 30);
    assert_eq!(stops(&h, &actions), ["a"], "{actions:?}");
    let actions = h.cell("a", CellReport::Empty, 31);
    assert_eq!(stops(&h, &actions), ["b"], "b's cell is cleaned up after a");
}

#[test]
fn a_restart_dependent_stops_on_any_leave_and_comes_back() {
    let mut h = running_pair(RestartOn::Restart);
    h.request("b", Request::Stop, 10);
    h.cell("a", CellReport::Empty, 11);
    assert_eq!(h.state("a"), State::Waiting(Why::Deps), "a is still wanted");
    h.cell("b", CellReport::Empty, 12);
    assert_eq!(h.state("b"), State::Off);
    h.request("b", Request::Start, 20);
    let actions = h.cell("b", CellReport::Ready, 21);
    assert_eq!(
        starts(&h, &actions),
        ["a"],
        "a comes back with b: {actions:?}"
    );
}

#[test]
fn a_late_async_arrival_restarts_a_restart_dependent() {
    let a = requires(
        worker("a"),
        vec![with_restart_on(async_edge(1, 1000), RestartOn::Restart)],
    );
    let (mut h, _) = Harness::load(model(vec![a, worker("b")], &[0, 1]));
    h.deadline("a", TimerKind::Edge, 1000);
    h.cell("a", CellReport::Ready, 1001);
    assert_eq!(h.state("a"), State::Ready);
    assert_eq!(h.state("b"), State::Starting, "b is still starting");
    // b was not ready when a started: its arrival restarts a.
    let actions = h.cell("b", CellReport::Ready, 2000);
    assert_eq!(stops(&h, &actions), ["a"], "{actions:?}");
    let actions = h.cell("a", CellReport::Empty, 2001);
    assert_eq!(starts(&h, &actions), ["a"], "{actions:?}");
}

#[test]
fn an_async_dependent_is_not_stopped_while_its_target_is_still_starting() {
    // The dependent started past the deadline; its target has never been ready, so nothing
    // has "left" and nothing is propagated, whatever restart_on says.
    let a = requires(
        worker("a"),
        vec![with_restart_on(async_edge(1, 1000), RestartOn::Restart)],
    );
    let (mut h, _) = Harness::load(model(vec![a, worker("b")], &[0, 1]));
    let actions = h.deadline("a", TimerKind::Edge, 1000);
    assert_eq!(starts(&h, &actions), ["a"]);
    assert!(stops(&h, &actions).is_empty(), "{actions:?}");
    assert_eq!(h.state("a"), State::Starting);
}

#[test]
fn an_exclude_target_becoming_wanted_stops_the_dependent() {
    let mut a = worker("a");
    a.groups.push(group(GroupKind::ExcludeAll, vec![edge(1)]));
    let (mut h, _) = Harness::load(model(vec![a, worker("b")], &[0]));
    h.cell("a", CellReport::Ready, 1);
    let actions = h.request("b", Request::Start, 10);
    assert_eq!(stops(&h, &actions), ["a"], "{actions:?}");
    assert!(starts(&h, &actions).contains(&"b".to_owned()));
    h.cell("a", CellReport::Empty, 11);
    assert_eq!(
        h.state("a"),
        State::Waiting(Why::Deps),
        "a waits while b is wanted"
    );
    h.cell("b", CellReport::Ready, 12);
    h.request("b", Request::Stop, 20);
    h.cell("b", CellReport::Empty, 21);
    assert_eq!(h.state("a"), State::Starting, "a comes back when b is gone");
}

#[test]
fn cascade_quarantines_a_wanted_dependent_and_clear_is_per_node() {
    let a = requires(worker("a"), vec![cascade_edge(1)]);
    let b = restarting(worker("b"), RestartPolicy::OnFailure, 1, 60_000);
    let (mut h, _) = Harness::load(model(vec![a, b], &[0, 1]));
    h.cell("b", CellReport::Ready, 1);
    h.cell("a", CellReport::Ready, 2);
    // b fails twice within the window and is quarantined.
    h.cell("b", CellReport::MainExited(Some(1)), 10);
    h.cell("b", CellReport::Empty, 10);
    h.deadline("b", TimerKind::Backoff, 1010);
    h.cell("b", CellReport::Ready, 1010);
    h.cell("b", CellReport::MainExited(Some(1)), 1020);
    h.cell("b", CellReport::Empty, 1020);
    assert_eq!(h.state("b"), State::Quarantined(Reason::Breaker));
    // a, wanted and cascading, follows: stopped first, then quarantined.
    h.cell("a", CellReport::Empty, 1021);
    assert_eq!(h.state("a"), State::Quarantined(Reason::Cascade));
    // Clearing a alone does not help while b is quarantined.
    h.request("a", Request::Clear, 2000);
    assert_eq!(h.state("a"), State::Quarantined(Reason::Cascade));
    // Clearing b starts it; then a can be cleared and starts too.
    let actions = h.request("b", Request::Clear, 2001);
    assert_eq!(starts(&h, &actions), ["b"]);
    h.cell("b", CellReport::Ready, 2002);
    let actions = h.request("a", Request::Clear, 2003);
    assert_eq!(starts(&h, &actions), ["a"]);
}

#[test]
fn shutdown_stops_in_reverse_hard_order_and_refuses_starts() {
    let mut h = running_pair(RestartOn::None);
    let actions = h.input(Input::Shutdown, 10);
    assert_eq!(
        stops(&h, &actions),
        ["a"],
        "the dependent first: {actions:?}"
    );
    assert_eq!(h.state("b"), State::Ready, "b waits for a to be empty");
    let actions = h.request("a", Request::Start, 11);
    assert!(starts(&h, &actions).is_empty());
    assert!(
        actions.contains(&Action::Report(0, Report::Refused)),
        "{actions:?}"
    );
    let actions = h.cell("a", CellReport::Empty, 12);
    assert_eq!(stops(&h, &actions), ["b"]);
    assert_eq!(h.state("a"), State::Off, "a is not restarted in shutdown");
    let actions = h.cell("b", CellReport::Empty, 13);
    assert!(
        actions.contains(&Action::Report(
            0,
            Report::ShutdownComplete { still_populated: 0 }
        )),
        "{actions:?}"
    );
}

#[test]
fn shutdown_cancels_backoff_timers() {
    let a = restarting(worker("a"), RestartPolicy::OnFailure, 0, 0);
    let (mut h, _) = Harness::load(model(vec![a], &[0]));
    h.cell("a", CellReport::Ready, 0);
    h.cell("a", CellReport::MainExited(Some(1)), 0);
    h.cell("a", CellReport::Empty, 0);
    assert_eq!(h.state("a"), State::Waiting(Why::Backoff));
    let actions = h.input(Input::Shutdown, 5);
    assert!(
        actions.contains(&Action::Cancel(0, TimerKind::Backoff)),
        "{actions:?}"
    );
    assert_eq!(h.state("a"), State::Off);
    assert!(starts(&h, &actions).is_empty());
    // The back-off timer firing late changes nothing.
    let actions = h.deadline("a", TimerKind::Backoff, 1000);
    assert!(actions.is_empty(), "{actions:?}");
}

#[test]
fn shutdown_reports_once_with_the_stuck_count() {
    let (mut h, _) = Harness::load(model(vec![worker("a"), worker("b")], &[0, 1]));
    h.cell("a", CellReport::Ready, 1);
    h.cell("b", CellReport::Ready, 1);
    let actions = h.input(Input::Shutdown, 10);
    assert_eq!(stops(&h, &actions), ["a", "b"]);
    h.cell("a", CellReport::CellFailed, 11);
    assert_eq!(h.state("a"), State::Quarantined(Reason::StopFailed));
    let actions = h.cell("b", CellReport::Empty, 12);
    let done = Report::ShutdownComplete { still_populated: 1 };
    assert!(actions.contains(&Action::Report(0, done)), "{actions:?}");
    let again = h.request("b", Request::Stop, 13);
    assert!(
        !again
            .iter()
            .any(|a| matches!(a, Action::Report(_, Report::ShutdownComplete { .. }))),
        "reported once: {again:?}"
    );
}

#[test]
fn an_always_worker_that_exits_zero_comes_back_after_the_delay() {
    let a = restarting(worker("a"), RestartPolicy::Always, 0, 0);
    let (mut h, _) = Harness::load(model(vec![a], &[0]));
    h.cell("a", CellReport::Ready, 0);
    let actions = h.cell("a", CellReport::MainExited(Some(0)), 10);
    assert_eq!(
        stops(&h, &actions),
        ["a"],
        "the stop is issued: {actions:?}"
    );
    let actions = h.cell("a", CellReport::Empty, 10);
    assert!(
        actions.contains(&Action::Arm(0, TimerKind::Backoff, 990)),
        "{actions:?}"
    );
    let actions = h.deadline("a", TimerKind::Backoff, 1000);
    assert_eq!(starts(&h, &actions), ["a"]);
}

#[test]
fn a_stop_that_fails_in_the_cell_quarantines() {
    let (mut h, _) = Harness::load(model(vec![worker("a")], &[0]));
    h.cell("a", CellReport::Ready, 0);
    let actions = h.request("a", Request::Stop, 5);
    assert_eq!(stops(&h, &actions), ["a"]);
    h.cell("a", CellReport::CellFailed, 6);
    assert_eq!(h.state("a"), State::Quarantined(Reason::StopFailed));
}

// ---- found by the review after Task 7 ----

/// `b` requires `a` (the dependency has the LOWER index), both ready.
fn swapped_pair(on: RestartOn) -> Harness {
    let b = requires(worker("b"), vec![with_restart_on(edge(0), on)]);
    let (mut h, _) = Harness::load(model(vec![worker("a"), b], &[0, 1]));
    h.cell("a", CellReport::Ready, 1);
    h.cell("b", CellReport::Ready, 2);
    assert_eq!((h.state("a"), h.state("b")), (State::Ready, State::Ready));
    h
}

#[test]
fn stop_order_holds_when_the_dependency_has_the_lower_index() {
    let mut h = swapped_pair(RestartOn::Restart);
    let actions = h.request("a", Request::Stop, 10);
    assert_eq!(
        stops(&h, &actions),
        ["b"],
        "the dependent first: {actions:?}"
    );
    assert_eq!(h.state("a"), State::Ready, "a waits for b to be empty");
    let actions = h.cell("b", CellReport::Empty, 11);
    assert_eq!(stops(&h, &actions), ["a"]);
}

#[test]
fn stop_order_holds_on_a_failure_when_the_dependency_has_the_lower_index() {
    let mut h = swapped_pair(RestartOn::Error);
    let actions = h.cell("a", CellReport::MainExited(Some(1)), 10);
    assert_eq!(stops(&h, &actions), ["b"], "{actions:?}");
    let actions = h.cell("b", CellReport::Empty, 11);
    assert_eq!(stops(&h, &actions), ["a"], "a's cell is cleaned up after b");
}

#[test]
fn stop_order_holds_along_a_chain_in_the_worst_index_order() {
    // c requires b requires a: the dependents have the higher indices.
    let b = requires(
        worker("b"),
        vec![with_restart_on(edge(0), RestartOn::Restart)],
    );
    let c = requires(
        worker("c"),
        vec![with_restart_on(edge(1), RestartOn::Restart)],
    );
    let (mut h, _) = Harness::load(model(vec![worker("a"), b, c], &[0, 1, 2]));
    h.cell("a", CellReport::Ready, 1);
    h.cell("b", CellReport::Ready, 2);
    h.cell("c", CellReport::Ready, 3);
    let actions = h.request("a", Request::Stop, 10);
    assert_eq!(stops(&h, &actions), ["c"], "{actions:?}");
    let actions = h.cell("c", CellReport::Empty, 11);
    assert_eq!(stops(&h, &actions), ["b"], "{actions:?}");
    let actions = h.cell("b", CellReport::Empty, 12);
    assert_eq!(stops(&h, &actions), ["a"], "{actions:?}");
}

#[test]
fn start_does_not_undo_an_unrelated_stop() {
    // a requires b (restart): stopping b leaves a waiting and wanted. Starting c must not
    // pull b back in through a.
    let a = requires(
        worker("a"),
        vec![with_restart_on(edge(1), RestartOn::Restart)],
    );
    let (mut h, _) = Harness::load(model(vec![a, worker("b"), worker("c")], &[0, 1]));
    h.cell("b", CellReport::Ready, 1);
    h.cell("a", CellReport::Ready, 2);
    h.request("b", Request::Stop, 10);
    h.cell("a", CellReport::Empty, 11);
    h.cell("b", CellReport::Empty, 12);
    assert_eq!(
        (h.state("a"), h.state("b")),
        (State::Waiting(Why::Deps), State::Off)
    );
    let actions = h.request("c", Request::Start, 20);
    assert_eq!(starts(&h, &actions), ["c"], "{actions:?}");
    assert_eq!(h.state("b"), State::Off);
    assert!(!h.node("b").wanted);
}

#[test]
fn a_forager_stopped_by_its_dependency_is_not_run_again() {
    let f = requires(
        forager("f"),
        vec![with_restart_on(edge(1), RestartOn::Restart)],
    );
    let (mut h, _) = Harness::load(model(vec![f, worker("w")], &[1]));
    h.cell("w", CellReport::Ready, 1);
    let actions = h.request("f", Request::Run, 2);
    assert_eq!(starts(&h, &actions), ["f"]);
    let actions = h.request("w", Request::Restart, 3);
    assert_eq!(stops(&h, &actions), ["f"], "{actions:?}");
    h.cell("f", CellReport::Empty, 4);
    assert_eq!(
        h.state("f"),
        State::Off,
        "a forager does not wait to run again"
    );
    assert!(!h.node("f").wanted);
    h.cell("w", CellReport::Empty, 5);
    let actions = h.cell("w", CellReport::Ready, 6);
    assert!(starts(&h, &actions).is_empty(), "{actions:?}");
    assert_eq!(h.state("f"), State::Off);
}

#[test]
fn a_late_sync_arrival_does_not_restart_a_require_any_dependent() {
    let a = group_with(
        worker("a"),
        GroupKind::RequireAny,
        vec![
            with_restart_on(edge(1), RestartOn::Restart),
            with_restart_on(edge(2), RestartOn::Restart),
        ],
    );
    let (mut h, _) = Harness::load(model(vec![a, worker("b"), worker("c")], &[0, 1, 2]));
    h.cell("b", CellReport::Ready, 1);
    assert_eq!(h.state("a"), State::Starting, "b satisfies the group");
    h.cell("a", CellReport::Ready, 2);
    let actions = h.cell("c", CellReport::Ready, 3);
    assert!(
        stops(&h, &actions).is_empty(),
        "c is only the alternative: {actions:?}"
    );
    assert_eq!(h.state("a"), State::Ready);
}

#[test]
fn a_restart_request_stops_and_starts_again() {
    let (mut h, _) = Harness::load(model(vec![worker("a")], &[0]));
    h.cell("a", CellReport::Ready, 0);
    let actions = h.request("a", Request::Restart, 5);
    assert_eq!(stops(&h, &actions), ["a"]);
    let actions = h.cell("a", CellReport::Empty, 6);
    assert_eq!(starts(&h, &actions), ["a"], "{actions:?}");
    assert_eq!(
        h.node("a").burst_count,
        0,
        "an administrator's restart is not a failure"
    );
}

#[test]
fn stopping_a_starting_node_cancels_its_start_timeout() {
    let (mut h, _) = Harness::load(model(vec![worker("a")], &[0]));
    let actions = h.request("a", Request::Stop, 5);
    assert!(
        actions.contains(&Action::Cancel(0, TimerKind::StartTimeout)),
        "{actions:?}"
    );
    assert_eq!(stops(&h, &actions), ["a"]);
}

#[test]
fn a_ready_report_after_the_start_timeout_is_ignored() {
    let (mut h, _) = Harness::load(model(vec![worker("a")], &[0]));
    h.deadline("a", TimerKind::StartTimeout, 90_000);
    assert_eq!(h.state("a"), State::Stopping);
    h.cell("a", CellReport::Ready, 90_001);
    assert_eq!(
        h.state("a"),
        State::Stopping,
        "a timed-out node does not become ready"
    );
}

#[test]
fn clear_restarts_a_node_quarantined_by_its_start_timeout() {
    let a = restarting(worker("a"), RestartPolicy::Never, 0, 0);
    let (mut h, _) = Harness::load(model(vec![a], &[0]));
    h.deadline("a", TimerKind::StartTimeout, 90_000);
    h.cell("a", CellReport::Empty, 90_001);
    assert_eq!(h.state("a"), State::Quarantined(Reason::StartTimeout));
    let actions = h.request("a", Request::Clear, 100_000);
    assert_eq!(
        starts(&h, &actions),
        ["a"],
        "cleared means wanted again: {actions:?}"
    );
}

#[test]
fn the_earliest_of_two_async_deadlines_is_armed_then_the_next() {
    let a = requires(worker("a"), vec![async_edge(1, 1000), async_edge(2, 5000)]);
    let (mut h, actions) = Harness::load(model(vec![a, worker("b"), worker("c")], &[0, 1, 2]));
    assert!(
        actions.contains(&Action::Arm(0, TimerKind::Edge, 1000)),
        "{actions:?}"
    );
    let actions = h.deadline("a", TimerKind::Edge, 1000);
    assert!(
        actions.contains(&Action::Arm(0, TimerKind::Edge, 4000)),
        "{actions:?}"
    );
    let actions = h.deadline("a", TimerKind::Edge, 5000);
    assert_eq!(starts(&h, &actions), ["a"]);
}

#[test]
fn shutdown_while_starting_cancels_and_stops() {
    let (mut h, _) = Harness::load(model(vec![worker("a")], &[0]));
    let actions = h.input(Input::Shutdown, 5);
    assert!(
        actions.contains(&Action::Cancel(0, TimerKind::StartTimeout)),
        "{actions:?}"
    );
    assert_eq!(stops(&h, &actions), ["a"]);
}

#[test]
fn shutdown_of_a_quiet_graph_reports_at_once() {
    let (mut h, _) = Harness::load(model(vec![worker("a")], &[]));
    let actions = h.input(Input::Shutdown, 5);
    let done = Report::ShutdownComplete { still_populated: 0 };
    assert!(actions.contains(&Action::Report(0, done)), "{actions:?}");
}

// ---- final review fixes ----

#[test]
fn a_refused_start_leaves_the_table_unchanged() {
    // a requires b and is breaker-quarantined (still wanted). b was stopped by the administrator.
    // Start(a) is refused and must not pull b back in.
    let a = requires(
        restarting(worker("a"), RestartPolicy::OnFailure, 1, 60_000),
        vec![edge(1)],
    );
    let (mut h, _) = Harness::load(model(vec![a, worker("b")], &[0, 1]));
    h.cell("b", CellReport::Ready, 1);
    h.cell("a", CellReport::Ready, 2);
    h.cell("a", CellReport::MainExited(Some(1)), 3);
    h.cell("a", CellReport::Empty, 3);
    h.deadline("a", TimerKind::Backoff, 1003);
    h.cell("a", CellReport::Ready, 1004);
    h.cell("a", CellReport::MainExited(Some(1)), 1005);
    h.cell("a", CellReport::Empty, 1005);
    assert!(
        matches!(h.state("a"), State::Quarantined(_)),
        "{:?}",
        h.state("a")
    );
    h.request("b", Request::Stop, 2000);
    h.cell("b", CellReport::Empty, 2001);
    assert_eq!(h.state("b"), State::Off);
    let actions = h.request("a", Request::Start, 3000);
    assert!(
        actions.contains(&Action::Report(0, Report::Refused)),
        "{actions:?}"
    );
    assert!(starts(&h, &actions).is_empty(), "{actions:?}");
    assert_eq!(h.state("b"), State::Off);
    assert!(!h.node("b").wanted);
}

#[test]
fn a_finished_one_shot_does_not_exclude() {
    // b runs to completion (ready = exit); a excludes it. Once b is Done it holds nothing.
    let mut a = worker("a");
    a.groups.push(group(GroupKind::ExcludeAll, vec![edge(1)]));
    let mut b = worker("b");
    b.ready = qinit_db::Ready::Exit;
    let (mut h, actions) = Harness::load(model(vec![a, b], &[0, 1]));
    assert_eq!(starts(&h, &actions), ["b"]);
    h.cell("b", CellReport::MainExited(Some(0)), 5);
    let actions = h.cell("b", CellReport::Empty, 5);
    assert_eq!(h.state("b"), State::Done);
    assert_eq!(starts(&h, &actions), ["a"], "{actions:?}");
}

#[test]
fn a_cascade_reaches_a_dependent_in_backoff() {
    // a requires b with cascade, and fails into back-off; b is then quarantined: a follows
    // at once, not when its timer fires.
    let mut e = edge(1);
    e.cascade = true;
    let a = requires(
        restarting(worker("a"), RestartPolicy::OnFailure, 0, 0),
        vec![e],
    );
    let b = restarting(worker("b"), RestartPolicy::OnFailure, 1, 60_000);
    let (mut h, _) = Harness::load(model(vec![a, b], &[0, 1]));
    h.cell("b", CellReport::Ready, 1);
    h.cell("a", CellReport::Ready, 2);
    h.cell("a", CellReport::MainExited(Some(1)), 3);
    h.cell("a", CellReport::Empty, 3);
    assert_eq!(h.state("a"), State::Waiting(Why::Backoff));
    // b fails twice: quarantined (max 1), once a is waiting for it.
    for t in [10u64, 2000] {
        h.cell("b", CellReport::MainExited(Some(1)), t);
        h.cell("b", CellReport::Empty, t);
        if matches!(h.state("b"), State::Waiting(_)) {
            h.deadline("b", TimerKind::Backoff, t + 1000);
            h.cell("b", CellReport::Ready, t + 1001);
        }
    }
    assert!(
        matches!(h.state("b"), State::Quarantined(_)),
        "{:?}",
        h.state("b")
    );
    assert_eq!(h.state("a"), State::Quarantined(Reason::Cascade));
}

#[test]
fn a_forager_whose_clock_went_backwards_waits_on_a_timer() {
    let f = forager("f");
    let (mut h, _) = Harness::load(model(vec![f], &[]));
    h.request("f", Request::Run, 200);
    h.cell("f", CellReport::MainExited(Some(0)), 210);
    h.cell("f", CellReport::Empty, 210);
    // The clock went back to 50: the forager may not run before it catches up.
    let actions = h.request("f", Request::Run, 50);
    assert!(starts(&h, &actions).is_empty(), "{actions:?}");
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::Arm(0, TimerKind::Edge, _))),
        "{actions:?}"
    );
}

#[test]
fn a_worker_whose_clock_went_backwards_waits_for_the_gap() {
    let a = restarting(worker("a"), RestartPolicy::OnFailure, 0, 0);
    let (mut h, _) = Harness::load(model(vec![a], &[0]));
    h.cell("a", CellReport::Ready, 1);
    h.cell("a", CellReport::MainExited(Some(1)), 300);
    h.cell("a", CellReport::Empty, 300);
    // The first run began at 0: the one-second back-off is measured from there.
    let actions = h.deadline("a", TimerKind::Backoff, 1000);
    assert_eq!(starts(&h, &actions), ["a"]);
    // That start was at 1000. It fails with the clock reading 400.
    h.cell("a", CellReport::Ready, 1001);
    h.cell("a", CellReport::MainExited(Some(1)), 400);
    let actions = h.cell("a", CellReport::Empty, 400);
    assert!(starts(&h, &actions).is_empty(), "{actions:?}");
    assert!(
        actions
            .iter()
            .any(|x| matches!(x, Action::Arm(0, TimerKind::Backoff, ms) if *ms >= 600)),
        "{actions:?}"
    );
}

#[test]
fn a_late_optional_sync_target_does_not_restart_its_dependent() {
    let mut a = worker("a");
    a.groups.push(group(
        GroupKind::OptionalAll,
        vec![with_restart_on(edge(1), RestartOn::Restart)],
    ));
    let b = restarting(worker("b"), RestartPolicy::Never, 0, 0);
    let (mut h, _) = Harness::load(model(vec![a, b], &[0, 1]));
    // b fails and is never restarted: a starts without it (b `wont_run`).
    h.cell("b", CellReport::MainExited(Some(1)), 1);
    h.cell("b", CellReport::Empty, 1);
    assert_eq!(h.state("a"), State::Starting);
    // b is started by hand and becomes ready late: a is not restarted (the edge is sync).
    h.request("b", Request::Start, 10);
    let actions = h.cell("b", CellReport::Ready, 11);
    assert!(stops(&h, &actions).is_empty(), "{actions:?}");
    assert_eq!(h.state("a"), State::Starting);
}

// ---- restore (SP7, R15) ----
/// A harness over `m` whose table is `tbl` as saved, without loading it.
fn saved(m: qinit_db::Model, tbl: Vec<NodeState>) -> Harness {
    let (mut h, _) = Harness::load(m);
    h.nodes = tbl;
    h.late = vec![false; h.late.len()];
    h.meta = qinit_colony_core::meta();
    h
}

#[test]
fn restore_keeps_an_enabled_node_unwanted() {
    let m = model(vec![worker("a")], &[0]);
    let mut h = saved(m.clone(), vec![off()]);
    assert!(inv_ok(&h.db, &h.nodes));
    assert!(restore(
        &h.db,
        &mut h.nodes,
        &h.paths,
        &mut h.late,
        &mut h.meta,
        7
    ));
    assert_eq!(h.state("a"), State::Off);
    assert!(!h.node("a").wanted);
    // `load_from` wants every enabled node: that is what `restore` must not do.
    let mut g = saved(m, vec![off()]);
    assert!(load_from(
        &g.db,
        &mut g.nodes,
        &g.paths,
        &mut g.late,
        &mut g.meta,
        7
    ));
    assert_eq!(g.state("a"), State::Starting);
}

#[test]
fn restore_keeps_a_quarantine() {
    let m = model(
        vec![restarting(worker("a"), RestartPolicy::OnFailure, 3, 60_000)],
        &[0],
    );
    let quarantined = NodeState {
        state: State::Quarantined(Reason::Breaker),
        wanted: true,
        burst_count: 4,
        ..off()
    };
    let mut h = saved(m, vec![quarantined]);
    assert!(inv_ok(&h.db, &h.nodes));
    assert!(restore(
        &h.db,
        &mut h.nodes,
        &h.paths,
        &mut h.late,
        &mut h.meta,
        7
    ));
    assert_eq!(h.state("a"), State::Quarantined(Reason::Breaker));
    assert_eq!(h.node("a").burst_count, 4);
}

#[test]
fn inv_ok_refuses_a_breaker_quarantine_below_max() {
    let m = model(
        vec![restarting(worker("a"), RestartPolicy::OnFailure, 3, 60_000)],
        &[0],
    );
    let q = |burst_count| NodeState {
        state: State::Quarantined(Reason::Breaker),
        burst_count,
        ..off()
    };
    let h = saved(m, vec![q(0)]);
    assert!(!inv_ok(&h.db, &h.nodes));
    assert!(!inv_ok(&h.db, &[q(3)]), "at max is not over it");
    assert!(inv_ok(&h.db, &[q(4)]));
}

#[test]
fn inv_ok_refuses_a_forager_in_backoff() {
    let m = model(vec![forager("f")], &[]);
    let backoff = NodeState {
        state: State::Waiting(Why::Backoff),
        timer: Some(TimerKind::Backoff),
        ..off()
    };
    let h = saved(m, vec![off()]);
    assert!(inv_ok(&h.db, &h.nodes));
    assert!(!inv_ok(&h.db, &[backoff]));
}

#[test]
fn inv_ok_refuses_a_timer_the_state_does_not_own() {
    let m = model(vec![worker("a")], &[]);
    let h = saved(m, vec![off()]);
    let armed_off = NodeState {
        timer: Some(TimerKind::StartTimeout),
        ..off()
    };
    assert!(!inv_ok(&h.db, &[armed_off]));
    let stop_without_process = NodeState {
        to_stop: true,
        ..off()
    };
    assert!(!inv_ok(&h.db, &[stop_without_process]));
}
