// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Watchers (D37): a watch is registered by name, its notices are fanned out as colony pushes
//! them, a targeted watch starts with the current state, and an instance exit or a refresh that
//! removes the node ends it.
mod common;

use common::*;
use qinit_colony::sim::{Script, Sim};
use qinit_colony::{Attached, Colony, Handled, Outcome, OwnedRep, Peer, Stream, WaitId};
use qinit_wire::{Action, ErrorCode, Mode, Req, StrList};

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

fn run(c: &mut Colony<Sim>, ms: u64) -> Outcome {
    qinit_colony::sim::advance_outcome(c, ms)
}

/// An instance that exits with status 0 as soon as it runs.
fn instant() -> Script {
    Script {
        ready_after_ms: None,
        exit_after: Some((0, Some(0))),
        ..Script::default()
    }
}

fn watch(c: &mut Colony<Sim>, peer: Peer, all: bool, target: &str, wait: u64) -> Handled {
    handle(c, peer, &Req::Watch { all, target }, wait)
}

/// `(kind, name, id, state, report, status)` of a notice on the stream.
fn notice(s: &Stream) -> (u32, &str, u32, u32, u32, i32) {
    match &s.rep {
        OwnedRep::Notice {
            kind,
            name,
            id,
            state,
            report,
            status,
        } => (*kind, name.as_str(), *id, state.state, *report, *status),
        other => panic!("not a notice: {other:?}"),
    }
}

/// The stream entries for `wait` across the handled call and the outcome after it.
fn for_wait<'a>(h: &'a Handled, out: &'a Outcome, wait: u64) -> Vec<&'a Stream> {
    h.outcome
        .stream
        .iter()
        .chain(out.stream.iter())
        .filter(|s| s.wait == WaitId(wait))
        .collect()
}

fn refresh_with(c: &mut Colony<Sim>, bytes: Vec<u8>, wait: u64) -> Handled {
    let now = c.effects.now();
    let attached = Attached {
        database: Some(Ok(bytes)),
        ..Attached::default()
    };
    c.handle(
        ROOT,
        &Req::Refresh {
            settled: false,
            wait_ms: 0,
        },
        attached,
        WaitId(wait),
        now,
    )
}

#[test]
fn a_targeted_watch_gets_the_current_state_first_then_the_change() {
    let (mut c, _) = boot(&frames(), &["db"], Sim::new());
    run(&mut c, 5);
    let h = watch(&mut c, USER, false, "db", 1);
    assert_eq!(h.reply, OwnedRep::Accepted);
    assert!(!h.waiting);
    assert_eq!(h.outcome.stream.len(), 1);
    let (kind, name, _, state, report, _) = notice(&h.outcome.stream[0]);
    assert_eq!((kind, name, report), (0, "db", 0));
    assert_eq!(state, 3); // ready after the boot
    let h = handle(&mut c, ROOT, &change("db", Action::Stop, false, 0), 2);
    let out = run(&mut c, 20_000);
    let stopped = for_wait(&h, &out, 1);
    assert!(stopped.iter().any(|s| notice(s).4 == 4), "{stopped:?}");
    assert!(stopped.iter().all(|s| !s.ends));
    assert!(stopped.iter().all(|s| notice(s).1 == "db"));
}

#[test]
fn an_all_watch_starts_with_accepted_only_and_sees_every_node() {
    let (mut c, _) = boot(&frames(), &["db", "app"], Sim::new());
    run(&mut c, 5);
    let h = watch(&mut c, USER, true, "", 1);
    assert_eq!(h.reply, OwnedRep::Accepted);
    assert!(!h.waiting);
    assert!(h.outcome.stream.is_empty(), "{:?}", h.outcome.stream);
    let a = handle(&mut c, ROOT, &change("app", Action::Stop, false, 0), 2);
    let mut out = run(&mut c, 20_000);
    out.stream.splice(0..0, a.outcome.stream);
    let h = handle(&mut c, ROOT, &change("db", Action::Stop, false, 0), 3);
    out.stream.extend(run(&mut c, 20_000).stream);
    let seen = for_wait(&h, &out, 1);
    for name in ["db", "app"] {
        assert!(
            seen.iter().any(|s| notice(s).1 == name && notice(s).4 == 4),
            "{name}: {seen:?}"
        );
    }
    assert!(seen.iter().all(|s| notice(s).4 != 0 && !s.ends));
}

#[test]
fn an_unknown_target_is_unknown_node_and_an_empty_colony_watch_is_fine() {
    let (mut c, _) = boot(&frames(), &["db"], Sim::new());
    assert_eq!(
        watch(&mut c, USER, false, "nope", 1).reply,
        OwnedRep::Error {
            code: ErrorCode::UnknownNode,
            detail: 0
        }
    );
    assert_eq!(
        watch(&mut c, USER, false, "backup#9", 2).reply,
        OwnedRep::Error {
            code: ErrorCode::UnknownNode,
            detail: 0
        }
    );
    assert_eq!(watch(&mut c, USER, true, "", 3).reply, OwnedRep::Accepted);
    // The refused watches left nothing behind: a change reaches only the accepted one.
    let h = handle(&mut c, ROOT, &change("db", Action::Stop, false, 0), 4);
    let out = run(&mut c, 20_000);
    assert!(for_wait(&h, &out, 1).is_empty());
    assert!(for_wait(&h, &out, 2).is_empty());
    assert!(!for_wait(&h, &out, 3).is_empty());
}

fn launch_backup(c: &mut Colony<Sim>, wait: u64) -> u32 {
    let h = handle(
        c,
        ROOT,
        &Req::Launch {
            frame: "backup",
            argv_tail: StrList::new(b"--full"),
            env_add: StrList::new(b"TARGET=/data"),
            fd_roles: 0,
            wait_ms: 60_000,
            flags: 0,
        },
        wait,
    );
    let OwnedRep::Launched { id } = h.reply else {
        panic!("{:?}", h.reply)
    };
    id
}

#[test]
fn an_instance_watch_ends_with_the_exit() {
    let (mut c, _) = boot(&frames(), &[], Sim::new());
    c.effects.instance_script = instant();
    let id = launch_backup(&mut c, 10);
    let target = format!("backup#{id}");
    let h = watch(&mut c, USER, false, &target, 1);
    assert_eq!(h.reply, OwnedRep::Accepted);
    assert_eq!(h.outcome.stream.len(), 1);
    let first = &h.outcome.stream[0];
    assert_eq!(notice(first), (1, "backup", id, 2, 0, 0));
    assert!(!first.ends);
    let out = run(&mut c, 1000);
    let seen: Vec<_> = out.stream.iter().filter(|s| s.wait == WaitId(1)).collect();
    let last = seen.last().expect("notices");
    assert_eq!(notice(last), (1, "backup", id, 4, 5, 0), "{seen:?}");
    assert!(last.ends);
    assert!(seen[..seen.len() - 1].iter().all(|s| !s.ends), "{seen:?}");
    // Ended: nothing more reaches it, and a watch of the exited instance ends at once.
    let id2 = launch_backup(&mut c, 11);
    let out = run(&mut c, 1000);
    assert!(out.stream.iter().all(|s| s.wait != WaitId(1)));
    let h = watch(&mut c, USER, false, &format!("backup#{id2}"), 2);
    assert_eq!(h.reply, OwnedRep::Accepted);
    assert_eq!(h.outcome.stream.len(), 1);
    assert_eq!(notice(&h.outcome.stream[0]), (1, "backup", id2, 4, 5, 0));
    assert!(h.outcome.stream[0].ends);
}

#[test]
fn a_refresh_that_removes_the_node_ends_the_watch_with_superseded() {
    let (mut c, _) = boot(&frames(), &["db", "app"], Sim::new());
    run(&mut c, 5);
    watch(&mut c, USER, false, "app", 1);
    watch(&mut c, USER, true, "", 2);
    let smaller = frames().replace(
        "[worker.app]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/app\"]\n\
         deps = [{ group = \"require_all\", edges = [{ to = \"db\" }] }]\n",
        "",
    );
    let h = refresh_with(&mut c, database(&smaller, &["db"]), 3);
    assert_eq!(h.reply, OwnedRep::Accepted);
    let out = run(&mut c, 20_000);
    let seen = for_wait(&h, &out, 1);
    let last = seen.last().expect("entries");
    assert!(matches!(last.rep, OwnedRep::Superseded(_)), "{seen:?}");
    assert!(last.ends);
    assert_eq!(
        seen.iter().filter(|s| s.ends).count(),
        1,
        "only the last ends: {seen:?}"
    );
    // A watcher of everything sees the swap and keeps watching.
    let all = for_wait(&h, &out, 2);
    assert!(all.iter().any(|s| notice(s).0 == 2), "{all:?}");
    assert!(all.iter().all(|s| !s.ends));
    let h = handle(&mut c, ROOT, &change("db", Action::Stop, false, 0), 4);
    let out = run(&mut c, 20_000);
    assert!(!for_wait(&h, &out, 2).is_empty());
    assert!(for_wait(&h, &out, 1).is_empty());
}

#[test]
fn a_dropped_watcher_gets_nothing_more() {
    let (mut c, _) = boot(&frames(), &["db"], Sim::new());
    watch(&mut c, USER, true, "", 1);
    watch(&mut c, USER, false, "db", 3);
    c.drop_wait(WaitId(1));
    c.drop_wait(WaitId(3));
    let h = handle(&mut c, ROOT, &change("db", Action::Stop, false, 0), 2);
    let out = run(&mut c, 20_000);
    assert!(
        h.outcome
            .stream
            .iter()
            .chain(out.stream.iter())
            .all(|s| s.wait != WaitId(1) && s.wait != WaitId(3))
    );
}

#[test]
fn a_watch_during_shutdown_is_served_and_sees_the_end() {
    let (mut c, _) = boot(&frames(), &["db", "app"], Sim::new());
    run(&mut c, 5);
    let s = handle(
        &mut c,
        ROOT,
        &Req::Shutdown {
            mode: Mode::Halt,
            settled: false,
            wait_ms: 0,
        },
        1,
    );
    assert_eq!(s.reply, OwnedRep::Accepted);
    let h = watch(&mut c, USER, true, "", 2);
    assert_eq!(h.reply, OwnedRep::Accepted);
    let t = watch(&mut c, USER, false, "db", 3);
    assert_eq!(t.reply, OwnedRep::Accepted);
    let out = run(&mut c, 60_000);
    let seen = for_wait(&h, &out, 2);
    let end: Vec<_> = seen.iter().filter(|s| notice(s).0 == 3).collect();
    assert_eq!(end.len(), 1, "{seen:?}");
    let (_, name, id, state, report, status) = notice(end[0]);
    assert_eq!((name, id, state, report, status), ("", 0, 0, 0, 0));
    // The kind 3 notice is the colony's, not node 0's: a node watcher does not get it.
    assert!(
        t.outcome
            .stream
            .iter()
            .chain(out.stream.iter())
            .filter(|s| s.wait == WaitId(3))
            .all(|s| notice(s).0 == 0)
    );
}

#[test]
fn a_swap_keeps_a_watcher_by_name() {
    let (mut c, _) = boot(&frames(), &["db"], Sim::new());
    run(&mut c, 5);
    watch(&mut c, USER, false, "db", 1);
    // A database where db has a new index: a node sorted before it.
    let more = format!(
        "[worker.aaa]\ncredentials = {{ uid = \"svc\" }}\nexec = [\"/bin/aaa\"]\n{}",
        frames()
    );
    let before = idx(&c, "db");
    let h = refresh_with(&mut c, database(&more, &["db"]), 2);
    assert_eq!(h.reply, OwnedRep::Accepted);
    let out = run(&mut c, 20_000);
    assert_ne!(idx(&c, "db"), before, "the swap renumbers db");
    assert!(for_wait(&h, &out, 1).iter().all(|s| !s.ends));
    let h = handle(&mut c, ROOT, &change("db", Action::Stop, false, 0), 3);
    let out = run(&mut c, 20_000);
    let seen = for_wait(&h, &out, 1);
    assert!(
        seen.iter().any(|s| notice(s).1 == "db" && notice(s).4 == 4),
        "{seen:?}"
    );
    assert!(seen.iter().all(|s| notice(s).1 == "db"));
}

#[test]
fn a_notice_encodes_as_a_wire_notice() {
    let rep = OwnedRep::Notice {
        kind: 1,
        name: "backup".to_owned(),
        id: 7,
        state: qinit_wire::StateWord {
            state: 4,
            detail: 0,
        },
        report: 5,
        status: -1,
    };
    let mut buf: Box<[u8; qinit_proto_core::MAX_MESSAGE]> =
        vec![0u8; qinit_proto_core::MAX_MESSAGE]
            .into_boxed_slice()
            .try_into()
            .expect("sized");
    let n = rep.encode(&mut buf).expect("encodes");
    let msg = qinit_wire::decode(&buf[..n], 0).expect("decodes");
    assert_eq!(
        msg,
        qinit_wire::Msg::Rep(qinit_wire::Rep::Notice(qinit_wire::Notice {
            kind: 1,
            name: "backup",
            id: 7,
            state: qinit_wire::StateWord {
                state: 4,
                detail: 0
            },
            report: 5,
            status: -1,
        }))
    );
}
