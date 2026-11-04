// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `Run`: a whole launch request as a frameless instance, judged by the compiled policy.
mod common;

use common::*;
use qinit_colony::sim::{Call, Script, Sim, advance_outcome};
use qinit_colony::{Attached, Colony, Handled, OwnedRep, Peer, SlotState, WaitId};
use qinit_launch::{RequestSpec, Stream};
use qinit_wire::{Action, ErrorCode, Req};
use std::os::fd::OwnedFd;

const ROOT: Peer = Peer {
    uid: 0,
    gid: 0,
    pid: 1,
};

const FRAMES: &str = "[worker.db]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/db\"]\n\
     [forager.backup]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/backup\"]\n\
     [forager.backup.launch]\nconcurrency = 1\n";

/// Run rules only: `~job*` may be unprivileged root-less; everything privileged needs a rule.
const POLICY: &str = "default = \"deny\"\n\
     [[rule]]\nmatch = \"~priv*\"\nusers = [\"svc\"]\ncaps_max = [\"chown\"]\n\
     [[rule]]\nmatch = \"~*\"\nusers = [\"root\"]\n";

fn booted() -> Colony<Sim> {
    boot_with_policy(FRAMES, &[], POLICY, Sim::new())
}

fn spec() -> RequestSpec {
    RequestSpec {
        argv: vec!["/bin/job".into()],
        user: "svc".into(),
        ..RequestSpec::default()
    }
}

fn memfd(bytes: &[u8]) -> OwnedFd {
    qinit_sys::memfd::sealed(c"req", bytes).unwrap()
}

fn pipe() -> OwnedFd {
    std::io::pipe().unwrap().0.into()
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_pass_by_value)] // the caller hands over the descriptors
fn run(
    c: &mut Colony<Sim>,
    name: &'static str,
    bytes: Vec<u8>,
    roles: u32,
    fds: Vec<OwnedFd>,
    stop: (u32, u32),
    wait: u64,
) -> Handled {
    let req = Req::Run {
        name,
        fd_roles: roles,
        flags: 0,
        memory_max_kib: 0,
        pids_max: 0,
        stop_mode: stop.0,
        stop_grace_ms: stop.1,
        wait_ms: 60_000,
    };
    let attached = Attached {
        fds,
        request: Some(Ok((bytes.clone(), memfd(&bytes)))),
        ..Attached::default()
    };
    let now = c.effects.now();
    c.handle(ROOT, &req, attached, WaitId(wait), now)
}

fn simple(c: &mut Colony<Sim>, name: &'static str, spec: &RequestSpec) -> Handled {
    run(c, name, spec.bytes().unwrap(), 0, vec![], (0, 1000), 1)
}

fn error(code: ErrorCode, detail: u32) -> OwnedRep {
    OwnedRep::Error { code, detail }
}

#[test]
fn run_starts_a_frameless_instance_named_with_the_sigil() {
    let mut c = booted();
    c.effects.instance_script = Script {
        ready_after_ms: None,
        ..Script::default()
    };
    let h = simple(&mut c, "job", &spec());
    assert_eq!(h.reply, OwnedRep::Launched { id: 1 }, "{:?}", h.reply);
    assert!(h.waiting);
    assert!(
        c.effects
            .calls
            .contains(&Call::StartInstance(0, "~job#1".into()))
    );
    assert!(c.effects.instance_requests.contains_key(&0));
    let now = c.effects.now();
    let s = c.handle(
        ROOT,
        &Req::Status { target: "~job#1" },
        Attached::default(),
        WaitId(9),
        now,
    );
    let OwnedRep::InstanceStatus(i) = s.reply else {
        panic!("{:?}", s.reply)
    };
    assert_eq!((i.frame.as_str(), i.id), ("~job", 1));
}

#[test]
fn a_bad_request_is_invalid_with_the_decoder_error() {
    let mut c = booted();
    let h = run(&mut c, "job", vec![0u8; 8], 0, vec![], (0, 1000), 1);
    assert_eq!(h.reply, error(ErrorCode::Invalid, 1), "{:?}", h.reply);
    let mut s = spec();
    s.argv = vec![];
    let h = simple(&mut c, "job", &s);
    assert!(matches!(
        h.reply,
        OwnedRep::Error {
            code: ErrorCode::Invalid,
            ..
        }
    ));
}

#[test]
fn a_route_without_its_role_is_denied() {
    let mut c = booted();
    let mut s = spec();
    s.stdout = Stream::Fd(6);
    // The request routes stdout to descriptor 6 but no stdout descriptor was sent.
    let h = simple(&mut c, "job", &s);
    assert_eq!(h.reply, error(ErrorCode::Denied, 0));
    // A sent role that no stream uses is refused too.
    let h = run(
        &mut c,
        "job",
        spec().bytes().unwrap(),
        2,
        vec![pipe()],
        (0, 1000),
        2,
    );
    assert_eq!(h.reply, error(ErrorCode::Denied, 0));
    // Agreement: stdout 6 with the stdout role sent.
    let h = run(
        &mut c,
        "job",
        s.bytes().unwrap(),
        2,
        vec![pipe()],
        (0, 1000),
        3,
    );
    assert!(
        matches!(h.reply, OwnedRep::Launched { .. }),
        "{:?}",
        h.reply
    );
}

#[test]
fn a_readiness_pipe_is_denied() {
    let mut c = booted();
    let mut s = spec();
    s.ready_fd = Some(8);
    assert_eq!(simple(&mut c, "job", &s).reply, error(ErrorCode::Denied, 0));
}

#[test]
fn a_policy_refusal_is_denied_with_its_clause() {
    let mut c = booted();
    // `~other` privileged (root): the `~*` rule names user root only, and root passes.
    let mut s = spec();
    s.user = "root".into();
    let h = simple(&mut c, "other", &s);
    assert!(
        matches!(h.reply, OwnedRep::Launched { .. }),
        "{:?}",
        h.reply
    );
    // `~priv-x` with capabilities above the rule's ceiling: clause 3.
    let mut s = spec();
    s.caps = 1 << 21;
    assert_eq!(
        simple(&mut c, "priv-x", &s).reply,
        error(ErrorCode::Denied, 3)
    );
    // `~priv-y` for another user: clause 2.
    let mut s = spec();
    s.user = "root".into();
    assert_eq!(
        simple(&mut c, "priv-y", &s).reply,
        error(ErrorCode::Denied, 2)
    );
}

#[test]
fn no_policy_compiled_denies_every_run() {
    let (mut c, _) = boot(FRAMES, &[], Sim::new());
    assert_eq!(
        simple(&mut c, "job", &spec()).reply,
        error(ErrorCode::Denied, 1)
    );
}

#[test]
fn run_stops_with_its_own_mode_and_grace() {
    let mut c = booted();
    c.effects.instance_script = Script {
        ready_after_ms: None,
        ..Script::default()
    };
    let h = run(
        &mut c,
        "job",
        spec().bytes().unwrap(),
        0,
        vec![],
        (1, 250),
        1,
    );
    assert!(matches!(h.reply, OwnedRep::Launched { id: 1 }));
    let now = c.effects.now();
    let stop = Req::Change {
        target: "~job#1",
        action: Action::Stop,
        settled: false,
        wait_ms: 0,
    };
    let h = c.handle(ROOT, &stop, Attached::default(), WaitId(2), now);
    assert_eq!(h.reply, OwnedRep::Accepted);
    assert!(c.effects.calls.contains(&Call::StopInstance(
        0,
        qinit_colony_core::StopMode::Cell,
        250
    )));
}

const REFRESHED: &str = "[worker.db]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/db2\"]\n";

#[test]
fn a_refresh_leaves_run_instances_alone() {
    let mut c = booted();
    c.effects.instance_script = Script {
        ready_after_ms: None,
        ..Script::default()
    };
    assert!(matches!(
        simple(&mut c, "job", &spec()).reply,
        OwnedRep::Launched { id: 1 }
    ));
    // A database without the forager frame at all.
    let new = database_with_policy(REFRESHED, &[], POLICY);
    let now = c.effects.now();
    let req = Req::Refresh {
        settled: false,
        wait_ms: 0,
    };
    let attached = Attached {
        database: Some(Ok(new)),
        ..Attached::default()
    };
    let h = c.handle(ROOT, &req, attached, WaitId(5), now);
    assert_eq!(h.reply, OwnedRep::Accepted);
    let view = c.instance(1).expect("the instance is still there");
    assert_eq!(
        (view.frame_name.as_str(), view.state),
        ("~job", SlotState::Starting)
    );
    // Nor was it remapped onto the new database's frames.
    assert_eq!(view.frame, qinit_colony::FRAMELESS);
    assert!(
        !c.effects
            .calls
            .iter()
            .any(|x| matches!(x, Call::StopInstance(..))),
        "{:?}",
        c.effects.calls
    );
    // Still stoppable by its address.
    let stop = Req::Change {
        target: "~job#1",
        action: Action::Stop,
        settled: false,
        wait_ms: 0,
    };
    let h = c.handle(ROOT, &stop, Attached::default(), WaitId(6), now);
    assert_eq!(h.reply, OwnedRep::Accepted);
}

#[test]
fn shutdown_stops_run_instances() {
    let mut c = booted();
    c.effects.instance_script = Script {
        ready_after_ms: None,
        ..Script::default()
    };
    simple(&mut c, "job", &spec());
    let now = c.effects.now();
    let req = Req::Shutdown {
        mode: qinit_wire::Mode::Halt,
        settled: false,
        wait_ms: 0,
    };
    c.handle(ROOT, &req, Attached::default(), WaitId(3), now);
    assert!(
        c.effects
            .calls
            .iter()
            .any(|x| matches!(x, Call::StopInstance(0, ..)))
    );
}

#[test]
fn a_name_outside_the_node_name_bytes_is_invalid() {
    // `#` would split the instance name `~a#b#1` at the wrong place; `~`, `*`, `/` and a NUL are
    // not node-name bytes either.
    for name in ["a#b", "~a", "a*", "a/b", "a\0b", "a b", "é"] {
        let mut c = booted();
        let h = simple(&mut c, name, &spec());
        assert_eq!(h.reply, error(ErrorCode::Invalid, 0), "{name:?}");
        assert!(
            !c.effects
                .calls
                .iter()
                .any(|c| matches!(c, Call::StartInstance(..))),
            "{name:?}"
        );
    }
    // The node-name bytes are accepted.
    let mut c = booted();
    let h = simple(&mut c, "A.b_c@d:e+f-9", &spec());
    assert!(
        matches!(h.reply, OwnedRep::Launched { .. }),
        "{:?}",
        h.reply
    );
}

/// `Req::Run` flag bit 1: the second reply waits for readiness.
const WAIT_READY: u32 = 2;

/// A request that wants a readiness pipe on descriptor 8.
fn ready_spec() -> RequestSpec {
    RequestSpec {
        ready_fd: Some(8),
        ..spec()
    }
}

/// Runs `s` with `flags` and a `wait_ms` wait parked as `wait`.
fn run_flags(
    c: &mut Colony<Sim>,
    name: &'static str,
    s: &RequestSpec,
    flags: u32,
    wait_ms: u32,
    wait: u64,
) -> Handled {
    let bytes = s.bytes().unwrap();
    let req = Req::Run {
        name,
        fd_roles: 0,
        flags,
        memory_max_kib: 0,
        pids_max: 0,
        stop_mode: 0,
        stop_grace_ms: 1000,
        wait_ms,
    };
    let attached = Attached {
        request: Some(Ok((bytes.clone(), memfd(&bytes)))),
        ..Attached::default()
    };
    let now = c.effects.now();
    c.handle(ROOT, &req, attached, WaitId(wait), now)
}

#[test]
fn wait_ready_replies_settled_when_the_service_is_ready() {
    let mut c = booted();
    c.effects.instance_script = Script {
        ready_after_ms: Some(300),
        ..Script::default()
    };
    let h = run_flags(&mut c, "job", &ready_spec(), WAIT_READY, 5000, 1);
    // The id goes out at once; the wait stays parked.
    assert_eq!(h.reply, OwnedRep::Launched { id: 1 }, "{:?}", h.reply);
    assert!(h.waiting);
    assert!(advance_outcome(&mut c, 299).replies.is_empty());
    let out = advance_outcome(&mut c, 2);
    assert_eq!(
        out.replies,
        [(
            WaitId(1),
            OwnedRep::Settled(qinit_wire::StateWord {
                state: 3,
                detail: 0
            })
        )]
    );
    // The instance runs on: the call is over, not the service.
    let v = c.instance(1).unwrap();
    assert_eq!(v.state, SlotState::Running);
}

#[test]
fn wait_ready_exit_before_ready_replies_exited_only() {
    let mut c = booted();
    c.effects.instance_script = Script {
        ready_after_ms: Some(500),
        exit_after: Some((100, Some(7 << 8))),
        ..Script::default()
    };
    let h = run_flags(&mut c, "job", &ready_spec(), WAIT_READY, 5000, 1);
    assert!(matches!(h.reply, OwnedRep::Launched { id: 1 }));
    let out = advance_outcome(&mut c, 2000);
    assert_eq!(
        out.replies,
        [(WaitId(1), OwnedRep::Exited { status: 7 << 8 })],
        "{:?}",
        out.replies
    );
}

#[test]
fn wait_ready_times_out_with_pending_and_leaves_the_instance_running() {
    let mut c = booted();
    c.effects.instance_script = Script {
        ready_after_ms: None,
        ..Script::default()
    };
    let h = run_flags(&mut c, "job", &ready_spec(), WAIT_READY, 400, 1);
    assert!(matches!(h.reply, OwnedRep::Launched { id: 1 }));
    let out = advance_outcome(&mut c, 401);
    // Not ready yet: the state is "starting", although the process is running.
    assert_eq!(
        out.replies,
        [(
            WaitId(1),
            OwnedRep::Pending(qinit_wire::StateWord {
                state: 2,
                detail: 0
            })
        )]
    );
    assert!(c.instance(1).is_some_and(|v| v.state == SlotState::Running));
}

#[test]
fn a_disconnect_while_waiting_for_ready_leaves_the_instance_running() {
    let mut c = booted();
    c.effects.instance_script = Script {
        ready_after_ms: Some(300),
        ..Script::default()
    };
    let h = run_flags(&mut c, "job", &ready_spec(), WAIT_READY, 5000, 1);
    assert!(matches!(h.reply, OwnedRep::Launched { id: 1 }));
    c.drop_wait(WaitId(1));
    assert!(c.effects.calls.contains(&Call::CancelWait(1)));
    let out = advance_outcome(&mut c, 1000);
    assert!(out.replies.is_empty(), "{:?}", out.replies);
    assert!(c.instance(1).is_some_and(|v| v.state == SlotState::Running));
    assert!(
        !c.effects
            .calls
            .iter()
            .any(|x| matches!(x, Call::StopInstance(..)))
    );
}

#[test]
fn wait_ready_without_a_pipe_is_denied() {
    let mut c = booted();
    let h = run_flags(&mut c, "job", &spec(), WAIT_READY, 5000, 1);
    assert_eq!(h.reply, error(ErrorCode::Denied, 0));
}

#[test]
fn a_pipe_on_a_role_descriptor_does_not_decode() {
    let mut c = booted();
    // The request routes stdout to 6 and its readiness pipe to 6 as well.
    let mut s = ready_spec();
    s.stdout = Stream::Fd(6);
    s.ready_fd = Some(6);
    let bytes = s.bytes().unwrap();
    let req = Req::Run {
        name: "job",
        fd_roles: 2,
        flags: WAIT_READY,
        memory_max_kib: 0,
        pids_max: 0,
        stop_mode: 0,
        stop_grace_ms: 1000,
        wait_ms: 5000,
    };
    let attached = Attached {
        fds: vec![pipe()],
        request: Some(Ok((bytes.clone(), memfd(&bytes)))),
        ..Attached::default()
    };
    let now = c.effects.now();
    let h = c.handle(ROOT, &req, attached, WaitId(1), now);
    // The decoder keeps a stream's descriptor and the readiness pipe's apart (consistency, 4).
    assert_eq!(h.reply, error(ErrorCode::Invalid, 4), "{:?}", h.reply);
}

#[test]
fn a_pipe_without_wait_ready_is_still_denied() {
    let mut c = booted();
    let h = run_flags(&mut c, "job", &ready_spec(), 0, 5000, 1);
    assert_eq!(h.reply, error(ErrorCode::Denied, 0));
}

#[test]
fn without_wait_ready_the_replies_are_unchanged() {
    let mut c = booted();
    c.effects.instance_script = Script {
        ready_after_ms: None,
        exit_after: Some((100, Some(0))),
        ..Script::default()
    };
    let h = run_flags(&mut c, "job", &spec(), 0, 5000, 1);
    assert_eq!(h.reply, OwnedRep::Launched { id: 1 });
    let out = advance_outcome(&mut c, 200);
    assert_eq!(out.replies, [(WaitId(1), OwnedRep::Exited { status: 0 })]);
}

#[test]
fn a_wait_ready_instance_starts_with_a_pipe_at_the_requests_descriptor() {
    let mut c = booted();
    c.effects.instance_script = Script {
        ready_after_ms: None,
        ..Script::default()
    };
    run_flags(&mut c, "job", &ready_spec(), WAIT_READY, 5000, 1);
    assert_eq!(c.effects.instance_ready, [(0, Some(8))]);
    run_flags(&mut c, "job2", &spec(), 0, 5000, 2);
    assert_eq!(c.effects.instance_ready, [(0, Some(8)), (1, None)]);
}
