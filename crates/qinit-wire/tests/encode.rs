// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! The encoder: every message round-trips, and the bytes are the canonical layout.
#[path = "../../qinit-proto-core/tests/common/mod.rs"]
mod common;

use common::*;
use qinit_proto_core::*;
use qinit_wire::*;

fn encoded(m: &Msg<'_>, fds: u32) -> Result<Vec<u8>, EncodeError> {
    let mut out: Box<[u8; MAX_MESSAGE]> = vec![0u8; MAX_MESSAGE].try_into().unwrap();
    encode(m, fds, &mut out).map(|n| out[..n].to_vec())
}

fn round_trip(m: &Msg<'_>) {
    let fds = required_fds(m);
    let bytes = encoded(m, fds).expect("encodes");
    assert_eq!(check(&bytes, fds as usize), Ok(()), "{m:?}");
    assert_eq!(&decode(&bytes, fds as usize).expect("decodes"), m);
}

fn st(state: u32, detail: u32) -> StateWord {
    StateWord { state, detail }
}

#[test]
fn every_request_round_trips() {
    let msgs = [
        Msg::Req(Req::Status { target: "sshd" }),
        Msg::Req(Req::Status {
            target: "backup#4294967295",
        }),
        Msg::Req(Req::List {
            cursor: 12,
            kind: 2,
        }),
        Msg::Req(Req::Change {
            target: "sshd",
            action: Action::Restart,
            settled: true,
            wait_ms: 600_000,
        }),
        Msg::Req(Req::Change {
            target: "backup#3",
            action: Action::Stop,
            settled: false,
            wait_ms: 0,
        }),
        Msg::Req(Req::Launch {
            frame: "backup",
            argv_tail: StrList::new(b"--full\0/data"),
            env_add: StrList::new(b"TARGET=/data\0V="),
            fd_roles: 7,
            wait_ms: 1,
            flags: 0,
        }),
        Msg::Req(Req::Launch {
            frame: "backup",
            argv_tail: StrList::new(b""),
            env_add: StrList::new(b""),
            fd_roles: 0,
            wait_ms: 30_000,
            flags: 0,
        }),
        Msg::Req(Req::Refresh {
            settled: true,
            wait_ms: 5000,
        }),
        Msg::Req(Req::Shutdown {
            mode: Mode::Halt,
            settled: false,
            wait_ms: 0,
        }),
        Msg::Req(Req::Run {
            name: "job",
            fd_roles: 6,
            flags: 1,
            memory_max_kib: 1024,
            pids_max: 8,
            stop_mode: 1,
            stop_grace_ms: 100,
            wait_ms: 60_000,
        }),
    ];
    for m in &msgs {
        round_trip(m);
    }
}

#[test]
fn every_reply_round_trips() {
    let entries = [
        ListEntry {
            name: "sshd",
            kind: 0,
            state: st(3, 0),
        },
        ListEntry {
            name: "mount-var",
            kind: 1,
            state: st(4, 0),
        },
    ];
    let msgs = [
        Msg::Rep(Rep::Error {
            code: ErrorCode::NotNow,
            detail: 6,
            version: 1,
        }),
        Msg::Rep(Rep::NodeStatus(NodeStatus {
            name: "sshd",
            kind: 0,
            state: st(1, 2),
            blocking: Some((0, "mount-var")),
            backoff_ms: 1000,
            since_ms: 0x1_0000_0002,
            restarts: 3,
            pid: Some(4242),
        })),
        Msg::Rep(Rep::NodeStatus(NodeStatus {
            name: "multi-user",
            kind: 2,
            state: st(3, 0),
            blocking: None,
            backoff_ms: 0,
            since_ms: 5,
            restarts: 0,
            pid: None,
        })),
        Msg::Rep(Rep::InstanceStatus(InstanceStatus {
            frame: "backup",
            id: 7,
            state: 4,
            status: Some(256),
            pid: None,
        })),
        Msg::Rep(Rep::InstanceStatus(InstanceStatus {
            frame: "backup",
            id: 8,
            state: 3,
            status: None,
            pid: Some(99),
        })),
        Msg::Rep(Rep::ListPage {
            entries: Entries::given(&entries),
            next: Some(40),
        }),
        Msg::Rep(Rep::ListPage {
            entries: Entries::given(&[]),
            next: None,
        }),
        Msg::Rep(Rep::Accepted),
        Msg::Rep(Rep::Settled(st(3, 0))),
        Msg::Rep(Rep::Pending(st(1, 2))),
        Msg::Rep(Rep::Superseded(st(0, 0))),
        Msg::Rep(Rep::Launched { id: 7 }),
        Msg::Rep(Rep::LaunchFailed {
            step: 11,
            errno: 13,
        }),
        Msg::Rep(Rep::Exited { status: -1 }),
        Msg::Rep(Rep::Exited { status: 256 }),
    ];
    for m in &msgs {
        round_trip(m);
    }
}

#[test]
fn lists_of_0_1_and_64_elements_round_trip() {
    for n in [0usize, 1, 64] {
        let argv = vec!["x"; n].join("\0");
        let env = vec!["K=v"; n].join("\0");
        round_trip(&Msg::Req(Req::Launch {
            frame: "f",
            argv_tail: StrList::new(argv.as_bytes()),
            env_add: StrList::new(env.as_bytes()),
            fd_roles: 0,
            wait_ms: 1000,
            flags: 0,
        }));
    }
}

#[test]
fn a_list_page_of_256_entries_round_trips() {
    let names: Vec<String> = (0..256).map(|i| format!("node-{i:0>91}")).collect();
    let entries: Vec<ListEntry<'_>> = names
        .iter()
        .map(|n| ListEntry {
            name: n,
            kind: 0,
            state: StateWord {
                state: 3,
                detail: 0,
            },
        })
        .collect();
    assert_eq!(names[0].len(), 96);
    round_trip(&Msg::Rep(Rep::ListPage {
        entries: Entries::given(&entries),
        next: None,
    }));
}

#[test]
fn an_overlong_name_is_invalid() {
    let name = "n".repeat(97);
    let m = Msg::Req(Req::Launch {
        frame: &name,
        argv_tail: StrList::new(b""),
        env_add: StrList::new(b""),
        fd_roles: 0,
        wait_ms: 1000,
        flags: 0,
    });
    assert_eq!(encoded(&m, 0), Err(EncodeError::Invalid));
    let empty = Msg::Req(Req::Status { target: "" });
    assert_eq!(encoded(&empty, 0), Err(EncodeError::Invalid));
}

#[test]
fn an_invalid_value_is_refused_not_encoded() {
    let zero_wait = Msg::Req(Req::Change {
        target: "sshd",
        action: Action::Start,
        settled: true,
        wait_ms: 0,
    });
    assert_eq!(encoded(&zero_wait, 0), Err(EncodeError::Invalid));
    let too_long_wait = Msg::Req(Req::Refresh {
        settled: true,
        wait_ms: MAX_WAIT_MS + 1,
    });
    assert_eq!(encoded(&too_long_wait, 1), Err(EncodeError::Invalid));
    let bad_roles = Msg::Req(Req::Launch {
        frame: "f",
        argv_tail: StrList::new(b""),
        env_add: StrList::new(b""),
        fd_roles: 8,
        wait_ms: 1000,
        flags: 0,
    });
    assert_eq!(encoded(&bad_roles, 0), Err(EncodeError::Invalid));
    let bad_state = Msg::Rep(Rep::Settled(StateWord {
        state: 7,
        detail: 0,
    }));
    assert_eq!(encoded(&bad_state, 0), Err(EncodeError::Invalid));
}

#[test]
fn the_declared_fd_count_must_be_the_required_one() {
    let launch = Msg::Req(Req::Launch {
        frame: "f",
        argv_tail: StrList::new(b""),
        env_add: StrList::new(b""),
        fd_roles: 3,
        wait_ms: 1000,
        flags: 0,
    });
    assert!(encoded(&launch, 2).is_ok());
    assert_eq!(encoded(&launch, 1), Err(EncodeError::Invalid));
    assert_eq!(encoded(&launch, 0), Err(EncodeError::Invalid));
}

#[test]
fn a_message_over_65536_bytes_is_too_large() {
    let tail = "t".repeat(1000);
    let list = vec![tail.as_str(); 64].join("\0");
    let m = Msg::Req(Req::Launch {
        frame: "f",
        argv_tail: StrList::new(list.as_bytes()),
        env_add: StrList::new(b""),
        fd_roles: 0,
        wait_ms: 1000,
        flags: 0,
    });
    assert!(encoded(&m, 0).is_ok(), "64000 bytes of arguments fit");
    let tail = "t".repeat(1100);
    let list = vec![tail.as_str(); 64].join("\0");
    let m = Msg::Req(Req::Launch {
        frame: "f",
        argv_tail: StrList::new(list.as_bytes()),
        env_add: StrList::new(b""),
        fd_roles: 0,
        wait_ms: 1000,
        flags: 0,
    });
    assert_eq!(encoded(&m, 0), Err(EncodeError::TooLarge));
}

#[test]
fn the_bytes_are_the_canonical_layout() {
    for t in TYPES {
        let (hand, fds) = valid(t);
        let m = decode(&hand, fds).expect("decodes");
        assert_eq!(
            encoded(&m, u32::try_from(fds).unwrap()).unwrap(),
            hand,
            "type {t}"
        );
    }
}

#[test]
fn the_same_value_gives_the_same_bytes() {
    let m = Msg::Req(Req::Status { target: "sshd" });
    assert_eq!(encoded(&m, 0).unwrap(), encoded(&m, 0).unwrap());
}

#[test]
fn op_of_names_the_operation() {
    assert_eq!(op_of(&Req::Status { target: "x" }), Op::Status);
    assert_eq!(op_of(&Req::List { cursor: 0, kind: 0 }), Op::List);
    assert_eq!(
        op_of(&Req::Refresh {
            settled: false,
            wait_ms: 0
        }),
        Op::Refresh
    );
}

#[test]
fn a_run_requires_its_request_fd_and_its_roles() {
    let named = |name, fd_roles| Req::Run {
        name,
        fd_roles,
        flags: 0,
        memory_max_kib: 0,
        pids_max: 0,
        stop_mode: 0,
        stop_grace_ms: 100,
        wait_ms: 1,
    };
    let run = |fd_roles| named("job", fd_roles);
    assert_eq!(required_fds(&Msg::Req(run(0))), 1);
    assert_eq!(required_fds(&Msg::Req(run(7))), 4);
    assert_eq!(
        encoded(&Msg::Req(run(7)), 3).unwrap_err(),
        EncodeError::Invalid
    );
    let long = "a".repeat(96);
    assert!(encoded(&Msg::Req(named(&long, 0)), 1).is_err());
}
