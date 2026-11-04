// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! Who may do what.
use qinit_proto_core::*;

const OPS: [Op; 7] = [
    Op::Status,
    Op::List,
    Op::Change,
    Op::Launch,
    Op::Refresh,
    Op::Shutdown,
    Op::Run,
];

#[test]
fn root_may_do_everything() {
    for op in OPS {
        assert!(authorized(op, PeerId { uid: 0 }), "{op:?}");
    }
}

#[test]
fn non_root_may_only_read() {
    for uid in [1, 1000, 65534, u32::MAX] {
        for op in OPS {
            let want = matches!(op, Op::Status | Op::List);
            assert_eq!(authorized(op, PeerId { uid }), want, "uid {uid} {op:?}");
        }
    }
}

#[test]
fn request_types_map_to_operations_and_replies_to_none() {
    let want = [
        (T_STATUS, Some(Op::Status)),
        (T_LIST, Some(Op::List)),
        (T_CHANGE, Some(Op::Change)),
        (T_LAUNCH, Some(Op::Launch)),
        (T_REFRESH, Some(Op::Refresh)),
        (T_SHUTDOWN, Some(Op::Shutdown)),
        (T_RUN, Some(Op::Run)),
        (0, None),
        (T_ERROR, None),
        (T_EXITED, None),
        (1000, None),
    ];
    for (t, op) in want {
        assert_eq!(op_of_type(t), op, "type {t}");
    }
}
