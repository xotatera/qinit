// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Protocol requests against colony: authorization, status, settled waits, launches, refresh and
//! shutdown, through the whole pipeline.
mod common;

use common::*;
use qinit_colony::sim::{Call, Script, Sim};
use qinit_colony::{
    Attached, Colony, Handled, Notice, Outcome, OwnedRep, Peer, ShutdownMode, SlotState, WaitId,
};
use qinit_wire::{Action, ErrorCode, Mode, Req, StateWord, StrList};

const ROOT: Peer = Peer {
    uid: 0,
    gid: 0,
    pid: 1,
};
const USER: Peer = Peer {
    uid: 1000,
    gid: 1000,
    pid: 2,
};

fn frames() -> String {
    "[worker.db]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/db\"]\n\
     [worker.app]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/app\"]\n\
     deps = [{ group = \"require_all\", edges = [{ to = \"db\" }] }]\n\
     [worker.flaky]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/flaky\"]\n\
     restart = { policy = \"on-failure\", max = 1, window = \"1m\" }\n\
     [forager.backup]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/backup\"]\n\
     [forager.backup.launch]\nconcurrency = 2\nargv_tail = 2\nenv = [\"TARGET\"]\nfds = [\"stdout\"]\n\
     [forager.plain]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/plain\"]\n\
     [brood.group]\ndeps = [{ group = \"require_all\", edges = [{ to = \"db\" }] }]\n"
        .to_owned()
}

fn state(state: u32, detail: u32) -> StateWord {
    StateWord { state, detail }
}

fn handle(c: &mut Colony<Sim>, peer: Peer, req: &Req<'_>, wait: u64) -> Handled {
    let now = c.effects.now();
    c.handle(peer, req, Attached::default(), WaitId(wait), now)
}

fn change(target: &'static str, action: Action, settled: bool, wait_ms: u32) -> Req<'static> {
    Req::Change {
        target,
        action,
        settled,
        wait_ms,
    }
}

/// Everything colony replied to while `ms` of virtual time passed.
fn run(c: &mut Colony<Sim>, ms: u64) -> Outcome {
    qinit_colony::sim::advance_outcome(c, ms)
}

fn replies(out: &Outcome) -> Vec<(u64, OwnedRep)> {
    out.replies.iter().map(|(w, r)| (w.0, r.clone())).collect()
}

fn script(ready_after_ms: Option<u64>, exit: Option<(u64, i32)>) -> Script {
    Script {
        ready_after_ms,
        exit_after: exit.map(|(ms, s)| (ms, Some(s))),
        ..Script::default()
    }
}

fn booted(enable: &[&str]) -> Colony<Sim> {
    boot(&frames(), enable, Sim::new()).0
}

fn error(code: ErrorCode, detail: u32) -> OwnedRep {
    OwnedRep::Error { code, detail }
}

#[test]
fn non_root_change_is_denied() {
    let mut c = booted(&[]);
    let h = handle(&mut c, USER, &change("db", Action::Start, false, 0), 1);
    assert_eq!(h.reply, error(ErrorCode::Denied, 0));
    assert!(!h.waiting);
    assert_eq!(c.state(idx(&c, "db")), Some(qinit_colony::State::Off));
    for req in [
        Req::Refresh {
            settled: false,
            wait_ms: 0,
        },
        Req::Shutdown {
            mode: Mode::Halt,
            settled: false,
            wait_ms: 0,
        },
        Req::Launch {
            frame: "backup",
            argv_tail: StrList::new(b""),
            env_add: StrList::new(b""),
            fd_roles: 0,
            wait_ms: 1000,
        },
    ] {
        assert_eq!(
            handle(&mut c, USER, &req, 2).reply,
            error(ErrorCode::Denied, 0)
        );
    }
    assert!(c.shutdown_mode().is_none());
}

#[test]
fn status_is_open_to_every_user() {
    let mut c = booted(&["db"]);
    run(&mut c, 5);
    let h = handle(&mut c, USER, &Req::Status { target: "db" }, 1);
    let OwnedRep::NodeStatus(s) = h.reply else {
        panic!("{:?}", h.reply)
    };
    assert_eq!((s.name.as_str(), s.kind, s.state), ("db", 0, state(3, 0)));
}

#[test]
fn status_names_the_blocking_target() {
    let mut sim = Sim::new();
    let (probe, _) = boot(&frames(), &["app"], Sim::new());
    sim.scripts
        .insert(idx(&probe, "db"), script(Some(5000), None));
    let (mut c, _) = boot(&frames(), &["app"], sim);
    run(&mut c, 100);
    let OwnedRep::NodeStatus(s) = handle(&mut c, USER, &Req::Status { target: "app" }, 1).reply
    else {
        panic!()
    };
    assert_eq!(s.state, state(1, 0));
    assert_eq!(s.blocking, Some((0, "db".to_owned())));
    assert!(s.since_ms >= 100 || s.since_ms == 0);
}

#[test]
fn status_reports_backoff_remaining_and_restarts_since_load() {
    let (probe, _) = boot(&frames(), &["flaky"], Sim::new());
    let mut sim = Sim::new();
    sim.scripts
        .insert(idx(&probe, "flaky"), script(Some(0), Some((100, 1))));
    let (mut c, _) = boot(&frames(), &["flaky"], sim);
    run(&mut c, 150);
    let OwnedRep::NodeStatus(s) = handle(&mut c, USER, &Req::Status { target: "flaky" }, 1).reply
    else {
        panic!()
    };
    assert_eq!(s.state.state, 1, "waiting out the back-off: {s:?}");
    assert_eq!(s.state.detail, 1);
    assert!(s.backoff_ms > 0 && s.backoff_ms <= 1000, "{s:?}");
    assert_eq!(s.restarts, 0, "the first start is not a restart");
    run(&mut c, 1200);
    let OwnedRep::NodeStatus(s) = handle(&mut c, USER, &Req::Status { target: "flaky" }, 2).reply
    else {
        panic!()
    };
    assert_eq!(s.restarts, 1, "{s:?}");
}

#[test]
fn status_carries_the_pid_from_effects() {
    let mut c = booted(&["db"]);
    run(&mut c, 5);
    let db = idx(&c, "db");
    let OwnedRep::NodeStatus(s) = handle(&mut c, USER, &Req::Status { target: "db" }, 1).reply
    else {
        panic!()
    };
    assert_eq!(s.pid, Some(1000 + i32::try_from(db).unwrap()));
    let OwnedRep::NodeStatus(off) = handle(&mut c, USER, &Req::Status { target: "plain" }, 2).reply
    else {
        panic!()
    };
    assert_eq!(off.pid, None);
}

#[test]
fn status_of_an_unknown_target_is_unknown_node() {
    let mut c = booted(&[]);
    assert_eq!(
        handle(&mut c, USER, &Req::Status { target: "nope" }, 1).reply,
        error(ErrorCode::UnknownNode, 0)
    );
    assert_eq!(
        handle(&mut c, USER, &Req::Status { target: "backup#9" }, 2).reply,
        error(ErrorCode::UnknownNode, 0)
    );
}

#[test]
fn start_now_replies_accepted() {
    let mut c = booted(&[]);
    let h = handle(&mut c, ROOT, &change("db", Action::Start, false, 0), 1);
    assert_eq!(h.reply, OwnedRep::Accepted);
    assert!(!h.waiting);
    run(&mut c, 5);
    assert_eq!(c.state(idx(&c, "db")), Some(qinit_colony::State::Ready));
}

#[test]
fn start_settled_replies_when_ready() {
    let (probe, _) = boot(&frames(), &[], Sim::new());
    let mut sim = Sim::new();
    sim.scripts
        .insert(idx(&probe, "db"), script(Some(100), None));
    let (mut c, _) = boot(&frames(), &[], sim);
    let h = handle(&mut c, ROOT, &change("db", Action::Start, true, 5000), 7);
    assert_eq!(h.reply, OwnedRep::Accepted);
    assert!(h.waiting);
    assert!(h.outcome.replies.is_empty());
    let out = run(&mut c, 200);
    assert_eq!(replies(&out), [(7, OwnedRep::Settled(state(3, 0)))]);
    // The wait is over: nothing more arrives.
    assert!(run(&mut c, 10_000).replies.is_empty());
}

#[test]
fn start_settled_on_a_node_that_is_already_ready_replies_at_once() {
    let mut c = booted(&["db"]);
    run(&mut c, 5);
    let h = handle(&mut c, ROOT, &change("db", Action::Start, true, 5000), 3);
    assert_eq!(h.reply, OwnedRep::Accepted);
    assert_eq!(replies(&h.outcome), [(3, OwnedRep::Settled(state(3, 0)))]);
}

#[test]
fn start_settled_on_a_failing_node_replies_settled_quarantined() {
    let (probe, _) = boot(&frames(), &[], Sim::new());
    let mut sim = Sim::new();
    sim.scripts
        .insert(idx(&probe, "flaky"), script(None, Some((10, 1))));
    let (mut c, _) = boot(&frames(), &[], sim);
    handle(
        &mut c,
        ROOT,
        &change("flaky", Action::Start, true, 60_000),
        4,
    );
    let out = run(&mut c, 30_000);
    let got = replies(&out);
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].0, 4);
    assert_eq!(got[0].1, OwnedRep::Settled(state(6, 0)));
}

#[test]
fn settled_wait_answers_pending_at_wait_ms() {
    let (probe, _) = boot(&frames(), &[], Sim::new());
    let mut sim = Sim::new();
    sim.scripts.insert(idx(&probe, "db"), script(None, None));
    let (mut c, _) = boot(&frames(), &[], sim);
    handle(&mut c, ROOT, &change("db", Action::Start, true, 1000), 5);
    assert!(
        c.effects
            .calls
            .iter()
            .any(|call| matches!(call, Call::ArmWait(5, 1000)))
    );
    let out = run(&mut c, 1000);
    assert_eq!(replies(&out), [(5, OwnedRep::Pending(state(2, 0)))]);
    // The request stays in effect: the node is still starting.
    assert_eq!(c.state(idx(&c, "db")), Some(qinit_colony::State::Starting));
}

#[test]
fn another_stop_supersedes_a_parked_start() {
    let (probe, _) = boot(&frames(), &[], Sim::new());
    let mut sim = Sim::new();
    sim.scripts.insert(idx(&probe, "db"), script(None, None));
    let (mut c, _) = boot(&frames(), &[], sim);
    handle(&mut c, ROOT, &change("db", Action::Start, true, 60_000), 1);
    let h = handle(&mut c, ROOT, &change("db", Action::Stop, false, 0), 2);
    assert_eq!(h.reply, OwnedRep::Accepted);
    let got = replies(&h.outcome);
    assert!(
        got.iter()
            .any(|(w, r)| *w == 1 && matches!(r, OwnedRep::Superseded(_))),
        "{got:?}"
    );
    // Its deadline is gone: nothing else comes for wait 1.
    let out = run(&mut c, 120_000);
    assert!(replies(&out).iter().all(|(w, _)| *w != 1));
}

#[test]
fn a_refresh_that_removes_the_node_supersedes_its_wait() {
    let (probe, _) = boot(&frames(), &[], Sim::new());
    let mut sim = Sim::new();
    sim.scripts.insert(idx(&probe, "plain"), script(None, None));
    let (mut c, _) = boot(&frames(), &[], sim);
    handle(&mut c, ROOT, &change("plain", Action::Run, true, 60_000), 9);
    let smaller = frames().replace(
        "[forager.plain]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/plain\"]\n",
        "",
    );
    let now = c.effects.now();
    let attached = Attached {
        fds: Vec::new(),
        database: Some(Ok(database(&smaller, &[]))),
    };
    let h = c.handle(
        ROOT,
        &Req::Refresh {
            settled: false,
            wait_ms: 0,
        },
        attached,
        WaitId(10),
        now,
    );
    assert_eq!(h.reply, OwnedRep::Accepted);
    let mut all = replies(&h.outcome);
    all.extend(replies(&run(&mut c, 20_000)));
    assert!(
        all.iter()
            .any(|(w, r)| *w == 9 && matches!(r, OwnedRep::Superseded(_))),
        "{all:?}"
    );
}

#[test]
fn start_on_a_quarantined_node_is_not_now() {
    let (probe, _) = boot(&frames(), &[], Sim::new());
    let mut sim = Sim::new();
    sim.scripts
        .insert(idx(&probe, "flaky"), script(Some(0), Some((10, 1))));
    let (mut c, _) = boot(&frames(), &["flaky"], sim);
    run(&mut c, 30_000);
    assert_eq!(
        c.state(idx(&c, "flaky")),
        Some(qinit_colony::State::Quarantined(
            qinit_colony::Reason::Breaker
        ))
    );
    let h = handle(&mut c, ROOT, &change("flaky", Action::Start, false, 0), 1);
    assert_eq!(h.reply, error(ErrorCode::NotNow, 6));
}

#[test]
fn clear_on_a_node_not_quarantined_is_not_now() {
    let mut c = booted(&["db"]);
    run(&mut c, 5);
    let h = handle(&mut c, ROOT, &change("db", Action::Clear, false, 0), 1);
    assert_eq!(h.reply, error(ErrorCode::NotNow, 3));
}

#[test]
fn run_on_a_forager_node_runs_it() {
    let (probe, _) = boot(&frames(), &[], Sim::new());
    let mut sim = Sim::new();
    sim.scripts
        .insert(idx(&probe, "plain"), script(None, Some((20, 0))));
    let (mut c, _) = boot(&frames(), &[], sim);
    handle(&mut c, ROOT, &change("plain", Action::Run, true, 5000), 3);
    let out = run(&mut c, 100);
    assert_eq!(replies(&out), [(3, OwnedRep::Settled(state(4, 0)))]);
}

fn launch_req(wait_ms: u32) -> Req<'static> {
    Req::Launch {
        frame: "backup",
        argv_tail: StrList::new(b"--full"),
        env_add: StrList::new(b"TARGET=/data"),
        fd_roles: 0,
        wait_ms,
    }
}

#[test]
fn launch_replies_launched_then_exited() {
    let mut c = booted(&[]);
    c.effects.instance_script = script(None, Some((50, 3)));
    let h = handle(&mut c, ROOT, &launch_req(5000), 11);
    assert_eq!(h.reply, OwnedRep::Launched { id: 1 });
    assert!(h.waiting);
    let out = run(&mut c, 200);
    assert_eq!(replies(&out), [(11, OwnedRep::Exited { status: 3 })]);
}

#[test]
fn launch_pending_after_wait_ms_then_status_by_id() {
    let mut c = booted(&[]);
    c.effects.instance_script = script(None, None);
    let h = handle(&mut c, ROOT, &launch_req(1000), 12);
    let OwnedRep::Launched { id } = h.reply else {
        panic!()
    };
    let out = run(&mut c, 1000);
    let got = replies(&out);
    assert_eq!(got.len(), 1);
    assert!(
        matches!(got[0].1, OwnedRep::Pending(StateWord { state: 3, .. })),
        "{got:?}"
    );
    let target = format!("backup#{id}");
    let leaked: &'static str = Box::leak(target.into_boxed_str());
    let OwnedRep::InstanceStatus(s) =
        handle(&mut c, USER, &Req::Status { target: leaked }, 13).reply
    else {
        panic!()
    };
    assert_eq!(
        (s.frame.as_str(), s.id, s.state, s.status),
        ("backup", id, 3, None)
    );
}

#[test]
fn launch_failure_is_launch_failed_not_an_error() {
    let mut c = booted(&[]);
    c.effects.instance_script = Script {
        spawn_fails: true,
        ..Script::default()
    };
    let h = handle(&mut c, ROOT, &launch_req(1000), 1);
    assert_eq!(h.reply, OwnedRep::LaunchFailed { step: 0, errno: 2 });
    assert!(!h.waiting);
}

#[test]
fn launch_refusals_have_their_error_codes() {
    let mut c = booted(&[]);
    c.effects.instance_script = script(None, None);
    let unknown = Req::Launch {
        frame: "nothing",
        argv_tail: StrList::new(b""),
        env_add: StrList::new(b""),
        fd_roles: 0,
        wait_ms: 1000,
    };
    assert_eq!(
        handle(&mut c, ROOT, &unknown, 1).reply,
        error(ErrorCode::UnknownNode, 0)
    );
    let plain = Req::Launch {
        frame: "plain",
        argv_tail: StrList::new(b""),
        env_add: StrList::new(b""),
        fd_roles: 0,
        wait_ms: 1000,
    };
    assert_eq!(
        handle(&mut c, ROOT, &plain, 2).reply,
        error(ErrorCode::NotLaunchable, 0)
    );
    let bad_key = Req::Launch {
        frame: "backup",
        argv_tail: StrList::new(b""),
        env_add: StrList::new(b"PATH=/x"),
        fd_roles: 0,
        wait_ms: 1000,
    };
    assert_eq!(
        handle(&mut c, ROOT, &bad_key, 3).reply,
        error(ErrorCode::Denied, 0)
    );
    handle(&mut c, ROOT, &launch_req(1000), 4);
    handle(&mut c, ROOT, &launch_req(1000), 5);
    assert_eq!(
        handle(&mut c, ROOT, &launch_req(1000), 6).reply,
        error(ErrorCode::NoSlot, 0)
    );
}

#[test]
fn stop_on_an_instance_target_stops_it() {
    let mut c = booted(&[]);
    c.effects.instance_script = script(None, None);
    let OwnedRep::Launched { id } = handle(&mut c, ROOT, &launch_req(60_000), 1).reply else {
        panic!()
    };
    run(&mut c, 5);
    let h = handle(&mut c, ROOT, &change("backup#1", Action::Stop, false, 0), 2);
    assert_eq!(h.reply, OwnedRep::Accepted);
    let out = run(&mut c, 50);
    assert!(
        replies(&out)
            .iter()
            .any(|(w, r)| *w == 1 && matches!(r, OwnedRep::Exited { .. }))
    );
    assert_eq!(c.instance(id).unwrap().state, SlotState::Exited(-1));
}

#[test]
fn restart_on_an_instance_target_is_denied_as_bad_request() {
    let mut c = booted(&[]);
    c.effects.instance_script = script(None, None);
    handle(&mut c, ROOT, &launch_req(60_000), 1);
    for action in [
        Action::Start,
        Action::Restart,
        Action::Clear,
        Action::Run,
        Action::Refresh,
    ] {
        let h = handle(&mut c, ROOT, &change("backup#1", action, false, 0), 2);
        assert_eq!(h.reply, error(ErrorCode::BadRequest, 6), "{action:?}");
    }
}

#[test]
fn refresh_settled_replies_after_phase_2() {
    let mut c = booted(&["db"]);
    run(&mut c, 5);
    let changed = frames().replace("/bin/db", "/bin/db2");
    let now = c.effects.now();
    let h = c.handle(
        ROOT,
        &Req::Refresh {
            settled: true,
            wait_ms: 10_000,
        },
        Attached {
            fds: Vec::new(),
            database: Some(Ok(database(&changed, &["db"]))),
        },
        WaitId(21),
        now,
    );
    assert_eq!(h.reply, OwnedRep::Accepted);
    let mut all = replies(&h.outcome);
    all.extend(replies(&run(&mut c, 100)));
    assert_eq!(all, [(21, OwnedRep::Settled(state(3, 0)))]);
    assert_eq!(c.model().nodes[idx(&c, "db") as usize].exec, ["/bin/db2"]);
}

#[test]
fn a_refused_database_is_invalid_with_its_reason() {
    let mut c = booted(&["db"]);
    let now = c.effects.now();
    let mut bad = database(&frames(), &["db"]);
    bad.truncate(bad.len() - 5);
    let h = c.handle(
        ROOT,
        &Req::Refresh {
            settled: false,
            wait_ms: 0,
        },
        Attached {
            fds: Vec::new(),
            database: Some(Ok(bad)),
        },
        WaitId(1),
        now,
    );
    assert!(matches!(
        h.reply,
        OwnedRep::Error {
            code: ErrorCode::Invalid,
            ..
        }
    ));
    let h = c.handle(
        ROOT,
        &Req::Refresh {
            settled: false,
            wait_ms: 0,
        },
        Attached {
            fds: Vec::new(),
            database: Some(Err(19)),
        },
        WaitId(2),
        now,
    );
    assert_eq!(h.reply, error(ErrorCode::Invalid, 19));
}

#[test]
fn shutdown_settled_replies_when_the_graph_and_instances_are_stopped() {
    let mut c = booted(&["db", "app"]);
    c.effects.instance_script = script(None, None);
    handle(&mut c, ROOT, &launch_req(60_000), 1);
    run(&mut c, 5);
    let h = handle(
        &mut c,
        ROOT,
        &Req::Shutdown {
            mode: Mode::Reboot,
            settled: true,
            wait_ms: 60_000,
        },
        2,
    );
    assert_eq!(h.reply, OwnedRep::Accepted);
    assert_eq!(c.shutdown_mode(), Some(ShutdownMode::Reboot));
    let mut all = replies(&h.outcome);
    all.extend(replies(&run(&mut c, 1000)));
    assert!(
        all.iter()
            .any(|(w, r)| *w == 2 && matches!(r, OwnedRep::Settled(_))),
        "{all:?}"
    );
    assert!(
        all.iter()
            .any(|(w, r)| *w == 1 && matches!(r, OwnedRep::Exited { .. })),
        "{all:?}"
    );
}

#[test]
fn a_second_shutdown_replaces_the_mode() {
    let mut c = booted(&["db"]);
    let off = |mode| Req::Shutdown {
        mode,
        settled: false,
        wait_ms: 0,
    };
    handle(&mut c, ROOT, &off(Mode::Poweroff), 1);
    assert_eq!(c.shutdown_mode(), Some(ShutdownMode::Poweroff));
    let h = handle(&mut c, ROOT, &off(Mode::Reboot), 2);
    assert_eq!(h.reply, OwnedRep::Accepted);
    assert_eq!(c.shutdown_mode(), Some(ShutdownMode::Reboot));
}

#[test]
fn shutdown_stops_instances_before_the_graph() {
    let mut c = booted(&["db"]);
    c.effects.instance_script = script(None, None);
    handle(&mut c, ROOT, &launch_req(60_000), 1);
    run(&mut c, 5);
    handle(
        &mut c,
        ROOT,
        &Req::Shutdown {
            mode: Mode::Poweroff,
            settled: false,
            wait_ms: 0,
        },
        2,
    );
    let calls = &c.effects.calls;
    let last_instance = calls
        .iter()
        .rposition(|call| matches!(call, Call::StopInstance(..)))
        .unwrap();
    let first_graph = calls
        .iter()
        .position(|call| matches!(call, Call::Stop(..)))
        .unwrap();
    assert!(last_instance < first_graph, "{calls:?}");
}

#[test]
fn requests_during_shutdown_are_shutting_down_except_status() {
    let mut c = booted(&["db"]);
    handle(
        &mut c,
        ROOT,
        &Req::Shutdown {
            mode: Mode::Poweroff,
            settled: false,
            wait_ms: 0,
        },
        1,
    );
    assert_eq!(
        handle(&mut c, ROOT, &change("db", Action::Start, false, 0), 2).reply,
        error(ErrorCode::ShuttingDown, 0)
    );
    assert_eq!(
        handle(&mut c, ROOT, &launch_req(1000), 3).reply,
        error(ErrorCode::ShuttingDown, 0)
    );
    assert!(matches!(
        handle(&mut c, USER, &Req::Status { target: "db" }, 4).reply,
        OwnedRep::NodeStatus(_)
    ));
    assert!(matches!(
        handle(&mut c, USER, &Req::List { cursor: 0, kind: 0 }, 5).reply,
        OwnedRep::ListPage { .. }
    ));
}

#[test]
fn list_pages_and_filters_by_kind() {
    let mut c = booted(&["db"]);
    run(&mut c, 5);
    let OwnedRep::ListPage { entries, next } =
        handle(&mut c, USER, &Req::List { cursor: 0, kind: 0 }, 1).reply
    else {
        panic!()
    };
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["app", "backup", "db", "flaky", "group", "plain"]);
    assert_eq!(next, None);
    let OwnedRep::ListPage { entries, .. } =
        handle(&mut c, USER, &Req::List { cursor: 0, kind: 2 }, 2).reply
    else {
        panic!()
    };
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["backup", "plain"]);
    let OwnedRep::ListPage { entries, .. } =
        handle(&mut c, USER, &Req::List { cursor: 2, kind: 1 }, 3).reply
    else {
        panic!()
    };
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["db", "flaky"]);
    assert_eq!(entries[0].state, state(3, 0));
}

#[test]
fn a_cursor_past_the_end_is_an_empty_page() {
    let mut c = booted(&[]);
    let OwnedRep::ListPage { entries, next } = handle(
        &mut c,
        USER,
        &Req::List {
            cursor: 1000,
            kind: 0,
        },
        1,
    )
    .reply
    else {
        panic!()
    };
    assert!(entries.is_empty());
    assert_eq!(next, None);
}

#[test]
fn non_root_status_shows_no_credentials() {
    // The record has no field for argv, environment or credentials at all.
    let mut c = booted(&["db"]);
    let h = handle(&mut c, USER, &Req::Status { target: "db" }, 1);
    let text = format!("{:?}", h.reply);
    for secret in ["/bin/db", "svc"] {
        assert!(!text.contains(secret), "{text}");
    }
}

#[test]
fn drop_wait_cancels_its_timer() {
    let (probe, _) = boot(&frames(), &[], Sim::new());
    let mut sim = Sim::new();
    sim.scripts.insert(idx(&probe, "db"), script(None, None));
    let (mut c, _) = boot(&frames(), &[], sim);
    handle(&mut c, ROOT, &change("db", Action::Start, true, 1000), 5);
    c.drop_wait(WaitId(5));
    assert!(
        c.effects
            .calls
            .iter()
            .any(|call| matches!(call, Call::CancelWait(5)))
    );
    assert!(replies(&run(&mut c, 5000)).is_empty());
}

#[test]
fn notices_still_flow_alongside_replies() {
    let mut c = booted(&[]);
    let h = handle(&mut c, ROOT, &change("db", Action::Start, false, 0), 1);
    let out = run(&mut c, 5);
    assert!(
        h.outcome
            .notices
            .iter()
            .chain(&out.notices)
            .any(|n| matches!(n, Notice::Node(_, qinit_colony::Report::Ready)))
    );
}

#[test]
fn a_refused_change_leaves_other_waits_alone() {
    let (probe, _) = boot(&frames(), &[], Sim::new());
    let mut sim = Sim::new();
    sim.scripts.insert(idx(&probe, "db"), script(None, None));
    let (mut c, _) = boot(&frames(), &[], sim);
    handle(&mut c, ROOT, &change("db", Action::Start, true, 60_000), 1);
    // `clear` on a node that is not quarantined does nothing: the parked start stays parked.
    let h = handle(&mut c, ROOT, &change("db", Action::Clear, false, 0), 2);
    assert_eq!(h.reply, error(ErrorCode::NotNow, 2));
    assert!(replies(&h.outcome).is_empty(), "{:?}", replies(&h.outcome));
    let out = run(&mut c, 61_000);
    assert_eq!(replies(&out), [(1, OwnedRep::Pending(state(2, 0)))]);
}

#[test]
fn an_identical_refresh_settles_at_once_after_a_restarting_one() {
    let (probe, _) = boot(&frames(), &[], Sim::new());
    let mut sim = Sim::new();
    sim.scripts.insert(idx(&probe, "db"), script(None, None));
    let (mut c, _) = boot(&frames(), &["db"], sim);
    run(&mut c, 5);
    let changed = frames().replace("/bin/db", "/bin/db2");
    let refresh = |c: &mut Colony<Sim>, id: u64| {
        let now = c.effects.now();
        c.handle(
            ROOT,
            &Req::Refresh {
                settled: true,
                wait_ms: 60_000,
            },
            Attached {
                fds: Vec::new(),
                database: Some(Ok(database(&changed, &["db"]))),
            },
            WaitId(id),
            now,
        )
    };
    // The first refresh restarts db, which never becomes ready: its wait stays parked.
    let first = refresh(&mut c, 31);
    assert!(first.waiting);
    run(&mut c, 100);
    // The same bytes again change nothing, so nothing is awaited and the answer is immediate.
    let second = refresh(&mut c, 32);
    let got = replies(&second.outcome);
    assert!(
        got.iter()
            .any(|(w, r)| *w == 32 && matches!(r, OwnedRep::Settled(_))),
        "{got:?}"
    );
}

#[test]
fn a_wait_that_cannot_be_armed_ends_at_once() {
    let mut sim = Sim::new();
    sim.fail_arm_wait = true;
    let (probe, _) = boot(&frames(), &[], Sim::new());
    sim.scripts.insert(idx(&probe, "db"), script(None, None));
    let (mut c, _) = boot(&frames(), &[], sim);
    let h = handle(&mut c, ROOT, &change("db", Action::Start, true, 60_000), 1);
    assert!(!h.waiting);
    let got = replies(&h.outcome);
    assert!(
        got.iter()
            .any(|(w, r)| *w == 1 && matches!(r, OwnedRep::Pending(_))),
        "{got:?}"
    );
}

#[test]
fn a_long_path_target_is_shown_clipped_to_the_name_limit() {
    let path = format!("/{}", "p/".repeat(60));
    let frames = format!(
        "[worker.app]\ncredentials = {{ uid = \"svc\" }}\nexec = [\"/bin/app\"]\n\
         deps = [{{ group = \"require_all\", edges = [{{ path = \"{path}\" }}] }}]\n"
    );
    let (mut c, _) = boot(&frames, &["app"], Sim::new());
    run(&mut c, 100);
    let OwnedRep::NodeStatus(s) = handle(&mut c, USER, &Req::Status { target: "app" }, 1).reply
    else {
        panic!()
    };
    let (group, text) = s.blocking.expect("blocked on the path");
    assert_eq!(group, 0);
    assert_eq!(text.len(), 96);
    assert!(path.starts_with(&text));
}

#[test]
fn a_refresh_that_adds_an_enabled_forager_runs_it() {
    let without = frames().replace(
        "[forager.plain]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/plain\"]\n",
        "",
    );
    assert_ne!(without, frames());
    let (mut c, _) = boot(&without, &["db"], Sim::new());
    run(&mut c, 5);
    let now = c.effects.now();
    let h = c.handle(
        ROOT,
        &Req::Refresh {
            settled: false,
            wait_ms: 0,
        },
        Attached {
            fds: Vec::new(),
            database: Some(Ok(database(&frames(), &["db", "plain"]))),
        },
        WaitId(41),
        now,
    );
    assert_eq!(h.reply, OwnedRep::Accepted);
    run(&mut c, 100);
    let OwnedRep::NodeStatus(s) = handle(&mut c, USER, &Req::Status { target: "plain" }, 2).reply
    else {
        panic!()
    };
    assert_ne!(s.state, state(0, 0), "the forager never started");
}
