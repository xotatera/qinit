// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qinit-colony-core`: the node machine and the scheduler (spec 2026-11-02 §§3, 4), proved by
//! Verus (`proof:qinit-colony-core`). One small machine per database node over `Copy` data;
//! the scheduler reads the compiled database in place and decides what starts, stops,
//! restarts or is quarantined. There is no clock and no allocation: `now_ms` arrives with every
//! input, deadlines are `Arm`/`Cancel` actions, and the state is slices the caller owns.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod node;
mod sched;
mod spec;

pub use node::*;
pub use sched::*;
#[allow(unused_imports)] // the specification is erased outside verification
pub use spec::*;

use vstd::prelude::*;

verus! {

/// Actions a node can have pending after one input (cancel, arm, watch, stop, start and two
/// reports): the bound of obligation 9 is `K` per node.
pub const K: usize = 7;

/// The back-off cap is this many times the base delay.
pub const CAP_FACTOR: u32 = 10;

/// Why a node waits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// A dependency group is unsatisfied.
    Deps,
    /// The restart back-off has not elapsed.
    Backoff,
}

/// Why a node is quarantined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// More failures than `max` within the window.
    Breaker,
    /// A cascade-flagged `require_all` dependency is quarantined.
    Cascade,
    /// The start timeout fired on a node that is never restarted.
    StartTimeout,
    /// The cell failed while stopping.
    StopFailed,
}

/// Where a node is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Off,
    Waiting(Why),
    Starting,
    Ready,
    /// A `ready = exit` worker or a forager that exited 0: satisfied, no process.
    Done,
    Stopping,
    Quarantined(Reason),
}

/// Why a node last stopped being ready, as its dependents' `restart_on` sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Left {
    /// A failure.
    Error,
    /// Anything else: a request, a clean exit, propagation.
    Restart,
}

/// The timers a node can have armed. At most one at a time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerKind {
    StartTimeout,
    Backoff,
    /// The earliest pending async edge deadline of a waiting node.
    Edge,
}

/// How a stop asks politely first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopMode {
    Main,
    Cell,
}

/// What the cell layer tells colony about a node's cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellReport {
    Spawned,
    SpawnFailed,
    Ready,
    NotReady,
    MainExited(Option<i32>),
    Empty,
    CellFailed,
}

/// What an administrator (or the control protocol) asks of a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Start,
    Stop,
    Restart,
    Clear,
    Run,
}

/// What colony tells its caller happened to a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Report {
    Started,
    Ready,
    Done,
    Stopped,
    Failed(Option<i32>),
    Quarantined(Reason),
    Refused,
    ShutdownComplete { still_populated: u32 },
    /// Both report slots of the node were full: an earlier report was dropped.
    Lost,
}

/// One input to the whole colony.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    Request { node: u32, req: Request },
    Shutdown,
    Cell { node: u32, report: CellReport },
    Deadline { node: u32, timer: TimerKind },
    PathAppeared { edge: u32 },
}

/// What colony asks its caller to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Start(u32),
    Stop(u32, StopMode, u32),
    Arm(u32, TimerKind, u32),
    Cancel(u32, TimerKind),
    WatchPath(u32),
    Report(u32, Report),
}

/// The input to one node's machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeInput {
    Req(Request),
    Cell(CellReport),
    Deadline(TimerKind),
    Shutdown,
}

/// The words of a node's database record that its machine reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// 0 worker, 1 forager, 2 brood.
    pub kind: u32,
    /// 0 pipe, 1 exit, 2 socket, 3 path.
    pub ready_kind: u32,
    /// 0 never, 1 on-failure, 2 always.
    pub policy: u32,
    pub max: u32,
    pub window_ms: u32,
    pub delay_ms: u32,
    /// 0 main, 1 cell.
    pub stop_mode: u32,
    pub grace_ms: u32,
    /// 0 for none.
    pub start_timeout_ms: u32,
}

/// One node's state: the machine plus the actions it has pending.
#[allow(clippy::struct_excessive_bools)]  // a state machine's flags, each independent
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeState {
    pub state: State,
    /// Someone wants it running (enabled, started, or pulled in by a start).
    pub wanted: bool,
    /// Scheduled to stop: a request, a failure, propagation, an exclusion or shutdown.
    pub to_stop: bool,
    /// Start again once the stop is over.
    pub restart_after: bool,
    /// Why it last stopped being ready.
    pub left: Left,
    /// Its ready-by-exit or forager run succeeded.
    pub done: bool,
    /// The start timeout fired.
    pub timed_out: bool,
    /// The main process of a worker restarted `always` exited 0.
    pub exited_clean: bool,
    /// The wait status of the main process, once seen.
    pub status: Option<i32>,
    pub timer: Option<TimerKind>,
    pub last_start_ms: u64,
    pub wait_since_ms: u64,
    pub burst_begin_ms: u64,
    pub burst_count: u32,
    pub backoff_exp: u32,
    /// Scratch of `Start`'s closure walk: in the closure / its targets are marked.
    pub pulled: bool,
    pub expanded: bool,
    pub emit_start: bool,
    pub emit_stop: bool,
    pub emit_watch: bool,
    pub emit_cancel: Option<TimerKind>,
    pub emit_arm: Option<(TimerKind, u32)>,
    pub report_a: Option<Report>,
    pub report_b: Option<Report>,
}

/// What the scheduler remembers between inputs besides the node table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Meta {
    /// Colony is shutting down: nothing starts and nothing restarts.
    pub shutdown: bool,
    /// The next node `next_action` looks at.
    pub cursor: usize,
    /// `ShutdownComplete` was reported.
    pub reported: bool,
}

/// The scheduler's starting state.
#[must_use]
pub fn meta() -> (r: Meta)
    ensures
        !r.shutdown && r.cursor == 0 && !r.reported,
{
    Meta { shutdown: false, cursor: 0, reported: false }
}

/// A node that is off, wanted by nobody, with nothing pending.
#[must_use]
pub fn off() -> (r: NodeState)
    ensures
        r.state == State::Off,
        !r.wanted && !r.to_stop && !r.restart_after,
        r.timer is None,
        !r.emit_start && !r.emit_stop && !r.emit_watch,
        r.emit_cancel is None && r.emit_arm is None,
        r.report_a is None && r.report_b is None,
        r.burst_count == 0 && r.backoff_exp == 0,
{
    NodeState {
        state: State::Off,
        wanted: false,
        to_stop: false,
        restart_after: false,
        left: Left::Restart,
        done: false,
        timed_out: false,
        exited_clean: false,
        status: None,
        timer: None,
        last_start_ms: 0,
        wait_since_ms: 0,
        burst_begin_ms: 0,
        burst_count: 0,
        backoff_exp: 0,
        pulled: false,
        expanded: false,
        emit_start: false,
        emit_stop: false,
        emit_watch: false,
        emit_cancel: None,
        emit_arm: None,
        report_a: None,
        report_b: None,
    }
}

} // verus!
