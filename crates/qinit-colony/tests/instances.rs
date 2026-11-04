// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Forager instance slots and launches through the whole pipeline: TOML, compiler, database,
//! scheduler, simulated cells.
mod common;

use common::*;
use qinit_colony::sim::{Call, Script, Sim, advance};
use qinit_colony::{Colony, LaunchArgs, LaunchError, Request, SlotState, State};

/// A launchable forager `backup`, and a worker `db` it can require.
fn frames(concurrency: u32, requires_db: bool) -> String {
    let deps = if requires_db {
        "deps = [{ group = \"require_all\", edges = [{ to = \"db\" }] }]\n"
    } else {
        ""
    };
    format!(
        "[forager.backup]\ncredentials = {{ uid = \"svc\" }}\nexec = [\"/bin/backup\"]\n{deps}\
         [forager.backup.launch]\nconcurrency = {concurrency}\nargv_tail = 2\n\
         env = [\"TARGET\", \"VERBOSE\"]\nfds = [\"stdout\", \"stderr\"]\n\
         [forager.plain]\ncredentials = {{ uid = \"svc\" }}\nexec = [\"/bin/plain\"]\n\
         [worker.db]\ncredentials = {{ uid = \"svc\" }}\nexec = [\"/bin/db\"]\n"
    )
}

fn args(frame: &str) -> LaunchArgs {
    LaunchArgs {
        frame: frame.to_owned(),
        argv_tail: Vec::new(),
        env_add: Vec::new(),
        fds: [None, None, None],
    }
}

fn long_running() -> Script {
    Script {
        ready_after_ms: None,
        exit_after: None,
        ..Script::default()
    }
}

fn exits_after(ms: u64, status: i32) -> Script {
    Script {
        ready_after_ms: None,
        exit_after: Some((ms, Some(status))),
        ..Script::default()
    }
}

fn started(c: &Colony<Sim>) -> Vec<(u32, String)> {
    c.effects
        .calls
        .iter()
        .filter_map(|call| match call {
            Call::StartInstance(slot, name) => Some((*slot, name.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn a_launch_gets_its_own_cell_named_frame_hash_id() {
    let (mut c, _) = boot(&frames(2, false), &[], Sim::new());
    c.effects.instance_script = long_running();
    let (id, _) = c.launch(args("backup"), 0).unwrap();
    assert_eq!(id, 1);
    assert_eq!(started(&c), [(0, "backup#1".to_owned())]);
    assert_eq!(c.instance(id).unwrap().state, SlotState::Starting);
}

#[test]
fn ids_increase_and_are_not_reused() {
    let (mut c, _) = boot(&frames(1, false), &[], Sim::new());
    c.effects.instance_script = exits_after(5, 0);
    let mut seen = Vec::new();
    for _ in 0..4 {
        let (id, _) = c.launch(args("backup"), c.effects.now()).unwrap();
        seen.push(id);
        advance(&mut c, 50);
    }
    assert_eq!(seen, [1, 2, 3, 4]);
    let names: Vec<String> = started(&c).into_iter().map(|(_, n)| n).collect();
    assert_eq!(names, ["backup#1", "backup#2", "backup#3", "backup#4"]);
}

#[test]
fn the_cap_refuses_with_no_slot() {
    let (mut c, _) = boot(&frames(2, false), &[], Sim::new());
    c.effects.instance_script = exits_after(1000, 0);
    c.launch(args("backup"), 0).unwrap();
    c.launch(args("backup"), 0).unwrap();
    assert_eq!(
        c.launch(args("backup"), 0).unwrap_err(),
        LaunchError::NoSlot
    );
    advance(&mut c, 2000);
    assert!(c.launch(args("backup"), c.effects.now()).is_ok());
}

#[test]
fn a_frame_without_launch_is_not_launchable() {
    let (mut c, _) = boot(&frames(2, false), &[], Sim::new());
    assert_eq!(
        c.launch(args("plain"), 0).unwrap_err(),
        LaunchError::NotLaunchable
    );
    assert_eq!(
        c.launch(args("db"), 0).unwrap_err(),
        LaunchError::NotLaunchable
    );
    assert_eq!(
        c.launch(args("nothing"), 0).unwrap_err(),
        LaunchError::UnknownNode
    );
}

#[test]
fn unsatisfied_deps_refuse_the_launch() {
    let (mut c, _) = boot(&frames(2, true), &[], Sim::new());
    assert_eq!(
        c.launch(args("backup"), 0).unwrap_err(),
        LaunchError::Unsatisfied
    );
    let db = idx(&c, "db");
    c.request(db, Request::Start, 0);
    pass(&mut c, 10);
    assert_eq!(c.state(db), Some(State::Ready));
    assert!(c.launch(args("backup"), c.effects.now()).is_ok());
}

#[test]
fn an_env_key_not_listed_is_denied() {
    let (mut c, _) = boot(&frames(2, false), &[], Sim::new());
    let mut a = args("backup");
    a.env_add = vec![("TARGET".into(), "/data".into())];
    assert!(c.launch(a, 0).is_ok());
    let mut a = args("backup");
    a.env_add = vec![("PATH".into(), "/evil".into())];
    assert_eq!(c.launch(a, 0).unwrap_err(), LaunchError::Denied);
    assert_eq!(started(&c).len(), 1);
}

#[test]
fn an_fd_role_not_listed_is_denied() {
    let (mut c, _) = boot(&frames(2, false), &[], Sim::new());
    let (r, w) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut a = args("backup");
    a.fds = [Some(r.into()), None, None];
    assert_eq!(c.launch(a, 0).unwrap_err(), LaunchError::Denied);
    let mut a = args("backup");
    a.fds = [None, Some(w.into()), None];
    assert!(c.launch(a, 0).is_ok());
}

#[test]
fn an_argv_tail_over_the_frames_limit_is_denied() {
    let (mut c, _) = boot(&frames(2, false), &[], Sim::new());
    let mut a = args("backup");
    a.argv_tail = vec!["a".into(), "b".into()];
    assert!(c.launch(a, 0).is_ok());
    let mut a = args("backup");
    a.argv_tail = vec!["a".into(), "b".into(), "c".into()];
    assert_eq!(c.launch(a, 0).unwrap_err(), LaunchError::Denied);
}

#[test]
fn a_spawn_failure_frees_the_slot() {
    let (mut c, _) = boot(&frames(1, false), &[], Sim::new());
    c.effects.instance_script = Script {
        spawn_fails: true,
        ..Script::default()
    };
    assert!(matches!(
        c.launch(args("backup"), 0).unwrap_err(),
        LaunchError::Spawn(_)
    ));
    c.effects.instance_script = long_running();
    assert!(c.launch(args("backup"), 0).is_ok());
}

#[test]
fn the_frames_own_run_and_instances_are_independent() {
    let (mut c, _) = boot(&frames(2, false), &[], Sim::new());
    c.effects.instance_script = long_running();
    let (a, _) = c.launch(args("backup"), 0).unwrap();
    let (b, _) = c.launch(args("backup"), 0).unwrap();
    let node = idx(&c, "backup");
    c.effects.scripts.insert(node, exits_after(5, 0));
    c.request(node, Request::Run, 0);
    pass(&mut c, 10);
    assert_eq!(c.state(node), Some(State::Done));
    assert!(c.instance(a).is_some() && c.instance(b).is_some());
    assert_eq!(
        c.launch(args("backup"), 20).unwrap_err(),
        LaunchError::NoSlot
    );
}

#[test]
fn an_instance_exit_is_kept_in_the_ring() {
    let (mut c, _) = boot(&frames(1, false), &[], Sim::new());
    c.effects.instance_script = exits_after(5, 3);
    let (id, _) = c.launch(args("backup"), 0).unwrap();
    advance(&mut c, 100);
    let view = c.instance(id).unwrap();
    assert_eq!(view.state, SlotState::Exited(3));
    assert_eq!(view.frame, idx(&c, "backup"));
    // 256 later exits keep it; the 257th evicts it.
    for k in 0..255 {
        c.launch(args("backup"), c.effects.now()).unwrap();
        advance(&mut c, 50);
        assert!(c.instance(id).is_some(), "after {k} later exits");
    }
    c.launch(args("backup"), c.effects.now()).unwrap();
    advance(&mut c, 50);
    assert!(c.instance(id).is_none());
}

#[test]
fn stop_instance_stops_only_that_instance() {
    let (mut c, _) = boot(&frames(2, false), &[], Sim::new());
    c.effects.instance_script = long_running();
    let (a, _) = c.launch(args("backup"), 0).unwrap();
    let (b, _) = c.launch(args("backup"), 0).unwrap();
    pass(&mut c, 10);
    c.stop_instance(a, 20).unwrap();
    pass(&mut c, 10);
    assert_eq!(c.instance(a).unwrap().state, SlotState::Exited(-1));
    assert_ne!(c.instance(b).unwrap().state, SlotState::Exited(-1));
    assert_eq!(
        c.stop_instance(999, 30).unwrap_err(),
        LaunchError::UnknownNode
    );
    let stops: Vec<u32> = c
        .effects
        .calls
        .iter()
        .filter_map(|call| match call {
            Call::StopInstance(slot, _, _) => Some(*slot),
            _ => None,
        })
        .collect();
    assert_eq!(stops, [0]);
}

#[test]
fn shutdown_refuses_launches() {
    let (mut c, _) = boot(&frames(2, false), &[], Sim::new());
    c.shutdown(0);
    assert_eq!(
        c.launch(args("backup"), 1).unwrap_err(),
        LaunchError::ShuttingDown
    );
}
