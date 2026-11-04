// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! The QCP1 message layout: limits, message types, enum values and record word indices. Every
//! word is little-endian. The byte-level description is `docs/control-protocol.md`.
use vstd::prelude::*;

verus! {

/// Message magic: "QCP1" read as a little-endian word.
pub const QCP_MAGIC: u32 = 0x3150_4351;

/// Protocol version.
pub const QCP_VERSION: u32 = 1;

/// Words in the header: magic, version, total length, type, descriptor count.
pub const HEADER_WORDS: usize = 5;

/// Bytes of a message at most.
pub const MAX_MESSAGE: usize = 65536;

/// Descriptors one message carries at most.
pub const MAX_FDS: usize = 3;

/// Extra argv elements a launch may append at most.
pub const MAX_ARGV_TAIL: usize = 64;

/// Environment entries a launch may add at most.
pub const MAX_ENV_ADD: usize = 64;

/// The longest settled wait, milliseconds.
pub const MAX_WAIT_MS: u32 = 600_000;

/// Entries in one list page at most.
pub const MAX_LIST_ENTRIES: usize = 256;

/// Bytes in a node name at most.
pub const MAX_NAME_LEN: usize = 96;

/// Bytes in a target at most: a node name, or `<frame>#<n>` with `n` below 2^32.
pub const MAX_TARGET_LEN: usize = 107;

/// No group blocks the node (`NodeStatus` group word); no next page (`ListPage` next word).
pub const NONE: u32 = 0xFFFF_FFFF;

/// Header word 0: magic.
pub const H_MAGIC: usize = 0;

/// Header word 1: version.
pub const H_VERSION: usize = 1;

/// Header word 2: total length in bytes.
pub const H_TOTAL_LEN: usize = 2;

/// Header word 3: message type.
pub const H_TYPE: usize = 3;

/// Header word 4: descriptors that travel with the message.
pub const H_FD_COUNT: usize = 4;

/// Request: status of a node or an instance.
pub const T_STATUS: u32 = 1;

/// Request: a page of the node list.
pub const T_LIST: u32 = 2;

/// Request: an action on a node or an instance.
pub const T_CHANGE: u32 = 3;

/// Request: launch an instance of a forager.
pub const T_LAUNCH: u32 = 4;

/// Request: swap in a new database.
pub const T_REFRESH: u32 = 5;

/// Request: shut down.
pub const T_SHUTDOWN: u32 = 6;

/// Reply: an error.
pub const T_ERROR: u32 = 64;

/// Reply: the status of a node.
pub const T_NODE_STATUS: u32 = 65;

/// Reply: the status of an instance.
pub const T_INSTANCE_STATUS: u32 = 66;

/// Reply: a page of the node list.
pub const T_LIST_PAGE: u32 = 67;

/// Reply: the request was accepted.
pub const T_ACCEPTED: u32 = 68;

/// Reply: the awaited state was reached.
pub const T_SETTLED: u32 = 69;

/// Reply: the wait ended with the state not reached.
pub const T_PENDING: u32 = 70;

/// Reply: another request changed what the wait waited for.
pub const T_SUPERSEDED: u32 = 71;

/// Reply: an instance was launched.
pub const T_LAUNCHED: u32 = 72;

/// Reply: the launch failed.
pub const T_LAUNCH_FAILED: u32 = 73;

/// Reply: the instance exited.
pub const T_EXITED: u32 = 74;

/// Status request word 0: `target_off`.
pub const ST_TARGET_OFF: usize = 0;

/// Status request word 1: `target_len`.
pub const ST_TARGET_LEN: usize = 1;

/// List request word 0: `cursor`, the index of the first entry.
pub const LI_CURSOR: usize = 0;

/// List request word 1: `kind`, 0 all, 1 worker, 2 forager, 3 brood.
pub const LI_KIND: usize = 1;

/// Change request word 0: `target_off`.
pub const CH_TARGET_OFF: usize = 0;

/// Change request word 1: `target_len`.
pub const CH_TARGET_LEN: usize = 1;

/// Change request word 2: `action`, 0 start, 1 stop, 2 restart, 3 clear, 4 refresh, 5 run.
pub const CH_ACTION: usize = 2;

/// Change request word 3: `settled`, 0 or 1.
pub const CH_SETTLED: usize = 3;

/// Change request word 4: `wait_ms`, 1 to `MAX_WAIT_MS` when settled, else 0.
pub const CH_WAIT_MS: usize = 4;

/// Launch request word 0: `frame_off`.
pub const LA_FRAME_OFF: usize = 0;

/// Launch request word 1: `frame_len`.
pub const LA_FRAME_LEN: usize = 1;

/// Launch request word 2: `argv_off`, NUL-separated extra argv elements.
pub const LA_ARGV_OFF: usize = 2;

/// Launch request word 3: `argv_len`.
pub const LA_ARGV_LEN: usize = 3;

/// Launch request word 4: `env_off`, NUL-separated `KEY=VALUE` entries.
pub const LA_ENV_OFF: usize = 4;

/// Launch request word 5: `env_len`.
pub const LA_ENV_LEN: usize = 5;

/// Launch request word 6: `fd_roles`, a mask of 1 stdin, 2 stdout, 4 stderr.
pub const LA_FD_ROLES: usize = 6;

/// Launch request word 7: `wait_ms`, 1 to `MAX_WAIT_MS`.
pub const LA_WAIT_MS: usize = 7;

/// Refresh request word 0: `settled`, 0 or 1.
pub const RF_SETTLED: usize = 0;

/// Refresh request word 1: `wait_ms`, 1 to `MAX_WAIT_MS` when settled, else 0.
pub const RF_WAIT_MS: usize = 1;

/// Shutdown request word 0: `mode`, 0 poweroff, 1 reboot, 2 halt.
pub const SH_MODE: usize = 0;

/// Shutdown request word 1: `settled`, 0 or 1.
pub const SH_SETTLED: usize = 1;

/// Shutdown request word 2: `wait_ms`, 1 to `MAX_WAIT_MS` when settled, else 0.
pub const SH_WAIT_MS: usize = 2;

/// Error reply word 0: `code`, 1 to 12.
pub const ER_CODE: usize = 0;

/// Error reply word 1: `detail`, the code's detail word.
pub const ER_DETAIL: usize = 1;

/// Error reply word 2: `version`, the protocol version the server speaks.
pub const ER_VERSION: usize = 2;

/// Error code: the version is not spoken.
pub const CODE_VERSION: u32 = 1;

/// Error code: the request was malformed; the detail is the decode error.
pub const CODE_BAD_REQUEST: u32 = 2;

/// Error code: the caller may not do this.
pub const CODE_DENIED: u32 = 3;

/// Error code: a connection limit is reached.
pub const CODE_FULL: u32 = 4;

/// Error code: another operation is in progress.
pub const CODE_BUSY: u32 = 5;

/// Error code: the system is shutting down.
pub const CODE_SHUTTING_DOWN: u32 = 6;

/// Error code: no such node or instance.
pub const CODE_UNKNOWN_NODE: u32 = 7;

/// Error code: the frame cannot be launched.
pub const CODE_NOT_LAUNCHABLE: u32 = 8;

/// Error code: the frame's dependencies are not satisfied.
pub const CODE_UNSATISFIED: u32 = 9;

/// Error code: every instance slot is taken.
pub const CODE_NO_SLOT: u32 = 10;

/// Error code: the node's state does not allow this; the detail is the state.
pub const CODE_NOT_NOW: u32 = 11;

/// Error code: the database was refused; the detail is the reason.
pub const CODE_INVALID: u32 = 12;

/// Node status word 0: `name_off`.
pub const NS_NAME_OFF: usize = 0;

/// Node status word 1: `name_len`.
pub const NS_NAME_LEN: usize = 1;

/// Node status word 2: `kind`, 0 worker, 1 forager, 2 brood.
pub const NS_KIND: usize = 2;

/// Node status word 3: `state`, 0 to 6.
pub const NS_STATE: usize = 3;

/// Node status word 4: `detail`, why a waiting node waits or why a node is quarantined.
pub const NS_DETAIL: usize = 4;

/// Node status word 5: `group`, the first unsatisfied group, or `NONE`.
pub const NS_GROUP: usize = 5;

/// Node status word 6: `target_off`, the first unsatisfied target of that group.
pub const NS_TARGET_OFF: usize = 6;

/// Node status word 7: `target_len`, 0 exactly when `group` is `NONE`.
pub const NS_TARGET_LEN: usize = 7;

/// Node status word 8: `backoff_ms`, the restart back-off remaining.
pub const NS_BACKOFF_MS: usize = 8;

/// Node status word 9: `since_lo`, milliseconds in the current state, low half.
pub const NS_SINCE_LO: usize = 9;

/// Node status word 10: `since_hi`, high half.
pub const NS_SINCE_HI: usize = 10;

/// Node status word 11: `restarts`, restarts since the node was loaded.
pub const NS_RESTARTS: usize = 11;

/// Node status word 12: `pid`, the main process, 0 for none.
pub const NS_PID: usize = 12;

/// Instance status word 0: `frame_off`.
pub const IS_FRAME_OFF: usize = 0;

/// Instance status word 1: `frame_len`.
pub const IS_FRAME_LEN: usize = 1;

/// Instance status word 2: `id`.
pub const IS_ID: usize = 2;

/// Instance status word 3: `state`, 2 starting, 3 running, 4 exited, 5 stopping.
pub const IS_STATE: usize = 3;

/// Instance status word 4: `has_status`, 1 exactly when the instance exited.
pub const IS_HAS_STATUS: usize = 4;

/// Instance status word 5: `status`, the wait status; 0 unless `has_status`.
pub const IS_STATUS: usize = 5;

/// Instance status word 6: `pid`, the main process, 0 for none.
pub const IS_PID: usize = 6;

/// List page word 0: `count`, entries in the page, at most `MAX_LIST_ENTRIES`.
pub const LP_COUNT: usize = 0;

/// List page word 1: `next`, the cursor of the next page, or `NONE`.
pub const LP_NEXT: usize = 1;

/// Words in a list page's fixed record; the entries follow it.
pub const LP_FIXED_WORDS: usize = 2;

/// Words in one list entry.
pub const ENTRY_WORDS: usize = 5;

/// List entry word 0: `name_off`.
pub const EN_NAME_OFF: usize = 0;

/// List entry word 1: `name_len`.
pub const EN_NAME_LEN: usize = 1;

/// List entry word 2: `kind`, 0 to 2.
pub const EN_KIND: usize = 2;

/// List entry word 3: `state`, 0 to 6.
pub const EN_STATE: usize = 3;

/// List entry word 4: `detail`.
pub const EN_DETAIL: usize = 4;

/// State word of `Settled`, `Pending` and `Superseded`: word 0, the state, 0 to 6.
pub const SW_STATE: usize = 0;

/// State word of `Settled`, `Pending` and `Superseded`: word 1, the detail.
pub const SW_DETAIL: usize = 1;

/// Launched reply word 0: `id`.
pub const LD_ID: usize = 0;

/// Launch-failed reply word 0: `step`, the overseer step that failed.
pub const LF_STEP: usize = 0;

/// Launch-failed reply word 1: `errno`.
pub const LF_ERRNO: usize = 1;

/// Exited reply word 0: `status`, the wait status as a signed word.
pub const EX_STATUS: usize = 0;

/// Every message type with the words in its fixed record.
pub const RECORD_WORDS: [(u32, usize); 17] = [
    (T_STATUS, 2),
    (T_LIST, 2),
    (T_CHANGE, 5),
    (T_LAUNCH, 8),
    (T_REFRESH, 2),
    (T_SHUTDOWN, 3),
    (T_ERROR, 3),
    (T_NODE_STATUS, 13),
    (T_INSTANCE_STATUS, 7),
    (T_LIST_PAGE, 2),
    (T_ACCEPTED, 0),
    (T_SETTLED, 2),
    (T_PENDING, 2),
    (T_SUPERSEDED, 2),
    (T_LAUNCHED, 1),
    (T_LAUNCH_FAILED, 2),
    (T_EXITED, 1),
];

/// Words in the fixed record of message type `t`, or 0 for a type the format does not know.
/// A list page's entries come after its fixed record.
pub open spec fn spec_record_words(t: int) -> int {
    if t == 1 {
        2
    } else if t == 2 {
        2
    } else if t == 3 {
        5
    } else if t == 4 {
        8
    } else if t == 5 {
        2
    } else if t == 6 {
        3
    } else if t == 64 {
        3
    } else if t == 65 {
        13
    } else if t == 66 {
        7
    } else if t == 67 {
        2
    } else if t == 68 {
        0
    } else if t == 69 || t == 70 || t == 71 {
        2
    } else if t == 72 {
        1
    } else if t == 73 {
        2
    } else if t == 74 {
        1
    } else {
        0
    }
}

/// `t` is a message type of the format.
pub open spec fn spec_known_type(t: int) -> bool {
    (1 <= t <= 6) || (64 <= t <= 74)
}

/// Words in the fixed record of message type `t`; `record_words` for an unknown type is 0.
#[must_use]
#[allow(clippy::match_same_arms, clippy::if_same_then_else)]  // one branch per type, as in `spec_record_words`
pub fn record_words(t: u32) -> (n: usize)
    ensures
        n as int == spec_record_words(t as int),
{
    if t == T_STATUS || t == T_LIST || t == T_REFRESH || t == T_LIST_PAGE {
        2
    } else if t == T_CHANGE {
        5
    } else if t == T_LAUNCH {
        8
    } else if t == T_SHUTDOWN {
        3
    } else if t == T_ERROR {
        3
    } else if t == T_NODE_STATUS {
        13
    } else if t == T_INSTANCE_STATUS {
        7
    } else if t == T_SETTLED || t == T_PENDING || t == T_SUPERSEDED {
        2
    } else if t == T_LAUNCHED || t == T_EXITED {
        1
    } else if t == T_LAUNCH_FAILED {
        2
    } else {
        0
    }
}

/// `t` is a message type of the format.
#[must_use]
#[allow(clippy::manual_range_contains)]  // `contains` has no Verus spec
pub fn known_type(t: u32) -> (r: bool)
    ensures
        r == spec_known_type(t as int),
{
    (1 <= t && t <= 6) || (64 <= t && t <= 74)
}

} // verus!
