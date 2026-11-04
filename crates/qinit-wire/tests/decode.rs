// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! Messages as values: what the accessors read from a laid-out message.
#[path = "../../qinit-proto-core/tests/common/mod.rs"]
mod common;

use common::*;
use qinit_proto_core::{T_CHANGE, T_LAUNCH, T_LIST_PAGE};
use qinit_wire::*;

#[test]
fn every_valid_default_decodes_to_a_value() {
    for t in TYPES {
        let (b, fds) = valid(t);
        assert!(decode(&b, fds).is_ok(), "type {t}: {:?}", decode(&b, fds));
    }
}

#[test]
fn accessors_read_what_was_laid_out() {
    let (b, fds) = valid(T_CHANGE);
    assert_eq!(
        decode(&b, fds).unwrap(),
        Msg::Req(Req::Change {
            target: "sshd",
            action: Action::Start,
            settled: true,
            wait_ms: 5000
        })
    );
    let (b, fds) = valid(T_LAUNCH);
    let Msg::Req(Req::Launch {
        frame,
        argv_tail,
        env_add,
        fd_roles,
        wait_ms,
    }) = decode(&b, fds).unwrap()
    else {
        panic!("not a launch");
    };
    assert_eq!((frame, fd_roles, wait_ms), ("backup", 5, 5000));
    assert_eq!(argv_tail.iter().collect::<Vec<_>>(), ["--full", "/data"]);
    assert_eq!(env_add.iter().collect::<Vec<_>>(), ["TARGET=/data"]);
    let (b, fds) = valid(T_LIST_PAGE);
    let Msg::Rep(Rep::ListPage { entries, next }) = decode(&b, fds).unwrap() else {
        panic!("not a page");
    };
    assert_eq!(next, None);
    let seen: Vec<_> = entries
        .iter()
        .map(|e| (e.name, e.kind, e.state.state))
        .collect();
    assert_eq!(seen, [("sshd", 0, 3), ("mount-var", 1, 4)]);
}

#[test]
fn a_reply_type_decodes_as_a_reply_and_a_request_as_a_request() {
    for t in TYPES {
        let (b, fds) = valid(t);
        let m = decode(&b, fds).unwrap();
        assert_eq!(matches!(m, Msg::Req(_)), t < 64, "type {t}");
    }
}
