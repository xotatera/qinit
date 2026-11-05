// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! The structures a caller passes in and gets back, and the protocol's enum words
//! (`docs/control-protocol.md`, "Enum values" and the reply tables).
#![allow(non_camel_case_types)] // the C names

use std::ffi::{c_char, c_int};

/// The version of this interface; `qinit_abi_version()` returns it at run time.
pub const QINIT_ABI_VERSION: u32 = 1;
/// The longest name (a node, a frame) in bytes; names out are copied into `QINIT_NAME_MAX + 1`
/// bytes, NUL-terminated.
pub const QINIT_NAME_MAX: u32 = 96;
/// The longest target in bytes: a node name or `<frame>#<id>`.
pub const QINIT_TARGET_MAX: u32 = 107;
/// The longest launch name of `qinit_run_begin` in bytes.
pub const QINIT_RUN_NAME_MAX: u32 = 95;
/// The longest launch request (QLR1) in bytes.
pub const QINIT_REQUEST_MAX: u32 = 65536;

/// State words (`state`): the detail words that go with them are in the protocol document.
pub const QINIT_STATE_OFF: u32 = 0;
pub const QINIT_STATE_WAITING: u32 = 1;
pub const QINIT_STATE_STARTING: u32 = 2;
/// Ready; for an instance, running.
pub const QINIT_STATE_READY: u32 = 3;
/// Done; for an instance, exited.
pub const QINIT_STATE_DONE: u32 = 4;
pub const QINIT_STATE_STOPPING: u32 = 5;
pub const QINIT_STATE_QUARANTINED: u32 = 6;

/// Node kinds (`kind` of a status or a list entry).
pub const QINIT_KIND_WORKER: u32 = 0;
pub const QINIT_KIND_FORAGER: u32 = 1;
pub const QINIT_KIND_BROOD: u32 = 2;

/// The `kind` filter of `qinit_list`.
pub const QINIT_LIST_ALL: u32 = 0;
pub const QINIT_LIST_WORKERS: u32 = 1;
pub const QINIT_LIST_FORAGERS: u32 = 2;
pub const QINIT_LIST_BROODS: u32 = 3;

/// Actions of `qinit_change`.
pub const QINIT_ACTION_START: u32 = 0;
pub const QINIT_ACTION_STOP: u32 = 1;
pub const QINIT_ACTION_RESTART: u32 = 2;
pub const QINIT_ACTION_CLEAR: u32 = 3;
pub const QINIT_ACTION_REFRESH: u32 = 4;
pub const QINIT_ACTION_RUN: u32 = 5;

/// Modes of `qinit_shutdown`.
pub const QINIT_MODE_POWEROFF: u32 = 0;
pub const QINIT_MODE_REBOOT: u32 = 1;
pub const QINIT_MODE_HALT: u32 = 2;

/// Stop modes of `qinit_run_begin`: the main process, or every process of the cell.
pub const QINIT_STOP_MAIN: u32 = 0;
pub const QINIT_STOP_CELL: u32 = 1;

/// Protocol error codes (`code` of a `QINIT_E_SERVER` error).
pub const QINIT_CODE_VERSION: i32 = 1;
pub const QINIT_CODE_BAD_REQUEST: i32 = 2;
pub const QINIT_CODE_DENIED: i32 = 3;
pub const QINIT_CODE_FULL: i32 = 4;
pub const QINIT_CODE_BUSY: i32 = 5;
pub const QINIT_CODE_SHUTTING_DOWN: i32 = 6;
pub const QINIT_CODE_UNKNOWN_NODE: i32 = 7;
pub const QINIT_CODE_NOT_LAUNCHABLE: i32 = 8;
pub const QINIT_CODE_UNSATISFIED: i32 = 9;
pub const QINIT_CODE_NO_SLOT: i32 = 10;
pub const QINIT_CODE_NOT_NOW: i32 = 11;
pub const QINIT_CODE_INVALID: i32 = 12;

/// `outcome` of a `qinit_wait_result`.
pub const QINIT_OUTCOME_ACCEPTED: u32 = 0;
pub const QINIT_OUTCOME_SETTLED: u32 = 1;
pub const QINIT_OUTCOME_PENDING: u32 = 2;
pub const QINIT_OUTCOME_SUPERSEDED: u32 = 3;

/// `kind` of a `qinit_begun`.
pub const QINIT_BEGUN_STARTED: u32 = 0;
pub const QINIT_BEGUN_FAILED: u32 = 1;

/// `kind` of a `qinit_finish`.
pub const QINIT_FINISH_EXITED: u32 = 0;
pub const QINIT_FINISH_PENDING: u32 = 1;
pub const QINIT_FINISH_READY: u32 = 2;

/// `kind` of a `qinit_event`, as the `Notice` record.
pub const QINIT_EVENT_NODE: u32 = 0;
pub const QINIT_EVENT_INSTANCE: u32 = 1;
pub const QINIT_EVENT_SWAPPED: u32 = 2;
pub const QINIT_EVENT_SHUTDOWN_COMPLETE: u32 = 3;

/// `report` of a node event.
pub const QINIT_REPORT_CURRENT: u32 = 0;
pub const QINIT_REPORT_STARTED: u32 = 1;
pub const QINIT_REPORT_READY: u32 = 2;
pub const QINIT_REPORT_DONE: u32 = 3;
pub const QINIT_REPORT_STOPPED: u32 = 4;
pub const QINIT_REPORT_FAILED: u32 = 5;
pub const QINIT_REPORT_QUARANTINED: u32 = 6;
pub const QINIT_REPORT_REFUSED: u32 = 7;
pub const QINIT_REPORT_LOST: u32 = 8;
/// `report` of an instance event (0 is `QINIT_REPORT_CURRENT`).
pub const QINIT_REPORT_INSTANCE_STARTING: u32 = 1;
pub const QINIT_REPORT_INSTANCE_RUNNING: u32 = 2;
pub const QINIT_REPORT_INSTANCE_READY: u32 = 3;
pub const QINIT_REPORT_INSTANCE_STOPPING: u32 = 4;
pub const QINIT_REPORT_INSTANCE_EXITED: u32 = 5;

/// What `qinit_watch_next` returns when it does not fail (it fails with `-QINIT_E_*`).
pub const QINIT_WATCH_EVENT: c_int = 0;
pub const QINIT_WATCH_ENDED: c_int = 1;
pub const QINIT_WATCH_TIMEOUT: c_int = 2;

/// What `qinit_pidfd_exit` returns when it does not fail (it fails with `-QINIT_E_*`).
pub const QINIT_PIDFD_EXITED: c_int = 0;
pub const QINIT_PIDFD_RUNNING: c_int = 1;
pub const QINIT_PIDFD_UNSUPPORTED: c_int = 2;

/// The bytes of a name out, with its NUL.
pub(crate) const NAME_BUF: usize = 97;

/// `s` in a NUL-terminated name array, cut at a character boundary to `QINIT_NAME_MAX` bytes.
pub(crate) fn name(s: &str) -> [c_char; NAME_BUF] {
    let mut end = s.len().min(NAME_BUF - 1);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = [0; NAME_BUF];
    for (d, b) in out.iter_mut().zip(&s.as_bytes()[..end]) {
        *d = c_char::from_ne_bytes([*b]);
    }
    out
}

/// A node's status.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct qinit_node_info {
    pub name: [c_char; 97],
    /// `QINIT_KIND_*`.
    pub kind: u32,
    /// `QINIT_STATE_*`.
    pub state: u32,
    pub detail: u32,
    /// The first unsatisfied dependency group, or `0xFFFFFFFF` for none.
    pub group: u32,
    /// The first unsatisfied target of that group; empty when `group` is none.
    pub blocking: [c_char; 97],
    pub backoff_ms: u32,
    pub since_ms: u64,
    pub restarts: u32,
    /// The main process, 0 for none.
    pub pid: i32,
}

/// An instance's status.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct qinit_instance_info {
    pub frame: [c_char; 97],
    pub id: u32,
    /// 2 starting, 3 running, 4 exited, 5 stopping.
    pub state: u32,
    /// 1 exactly when the instance exited.
    pub has_status: i32,
    /// The wait status; 0 unless `has_status`.
    pub status: i32,
    /// The main process, 0 for none.
    pub pid: i32,
}

/// What `qinit_status` fills: `node` when `is_instance` is 0, else `instance`; the other is
/// zeroed.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct qinit_status {
    pub is_instance: i32,
    pub node: qinit_node_info,
    pub instance: qinit_instance_info,
}

impl qinit_node_info {
    pub(crate) const ZERO: qinit_node_info = qinit_node_info {
        name: [0; 97],
        kind: 0,
        state: 0,
        detail: 0,
        group: 0,
        blocking: [0; 97],
        backoff_ms: 0,
        since_ms: 0,
        restarts: 0,
        pid: 0,
    };
}

impl qinit_instance_info {
    pub(crate) const ZERO: qinit_instance_info = qinit_instance_info {
        frame: [0; 97],
        id: 0,
        state: 0,
        has_status: 0,
        status: 0,
        pid: 0,
    };
}

/// One line of the node list.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct qinit_entry {
    pub name: [c_char; 97],
    pub kind: u32,
    pub state: u32,
    pub detail: u32,
}

/// The final reply to a request that can wait: `outcome` is a `QINIT_OUTCOME_*`; `state` and
/// `detail` are those of what was awaited (0 for accepted).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct qinit_wait_result {
    pub outcome: u32,
    pub state: u32,
    pub detail: u32,
}

/// What a launch adds to the frame: `argv_tail_len` arguments, `env_len` `"K=V"` strings, the
/// three streams (-1 for none, borrowed for the call) and whether a pidfd is wanted (0 or 1).
/// An array may be NULL when its length is 0.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct qinit_launch_args {
    pub argv_tail: *const *const c_char,
    pub argv_tail_len: usize,
    pub env: *const *const c_char,
    pub env_len: usize,
    pub stdin_fd: c_int,
    pub stdout_fd: c_int,
    pub stderr_fd: c_int,
    pub want_pidfd: c_int,
}

/// What a run sends: the QLR1 request bytes (the library puts them in a sealed memfd), the three
/// streams (-1 for none), `want_pidfd` and `wait_ready` (0 or 1), the cell limits (0 for none),
/// the stop mode (`QINIT_STOP_*`) and the grace before the kill (at least 100 ms).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct qinit_run_args {
    pub request: *const u8,
    pub request_len: usize,
    pub stdin_fd: c_int,
    pub stdout_fd: c_int,
    pub stderr_fd: c_int,
    pub want_pidfd: c_int,
    pub wait_ready: c_int,
    pub memory_max_kib: u32,
    pub pids_max: u32,
    pub stop_mode: u32,
    pub stop_grace_ms: u32,
}

/// The first reply of a launch or a run: `kind` `QINIT_BEGUN_STARTED` with `id` and `pidfd` (-1
/// for none; the caller's to close), or `QINIT_BEGUN_FAILED` with `step` and `error_number`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct qinit_begun {
    pub kind: u32,
    pub id: u32,
    pub pidfd: c_int,
    pub step: u32,
    pub error_number: u32,
}

/// How a begun launch or run ended: `kind` `QINIT_FINISH_EXITED` with `status`,
/// `QINIT_FINISH_PENDING` with `state` and `detail` (the wait ended first), or
/// `QINIT_FINISH_READY` (the service wrote its readiness byte).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct qinit_finish {
    pub kind: u32,
    pub status: i32,
    pub state: u32,
    pub detail: u32,
}

/// One event of a watch, as the `Notice` record: `kind` `QINIT_EVENT_*`, the node's name or the
/// instance's frame, the instance `id`, the state after the event, the `report`
/// (`QINIT_REPORT_*`) and the `status` (a wait status for a failed node or an exited instance,
/// -1 when it was not seen; the cells still populated for `QINIT_EVENT_SHUTDOWN_COMPLETE`; else
/// 0). When the stream ends, only `state` and `detail` are set: the final state.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct qinit_event {
    pub kind: u32,
    pub name: [c_char; 97],
    pub id: u32,
    pub state: u32,
    pub detail: u32,
    pub report: u32,
    pub status: i32,
}

impl qinit_event {
    pub(crate) const ZERO: qinit_event = qinit_event {
        kind: 0,
        name: [0; 97],
        id: 0,
        state: 0,
        detail: 0,
        report: 0,
        status: 0,
    };
}
