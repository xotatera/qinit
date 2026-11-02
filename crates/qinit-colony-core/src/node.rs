// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The node machine (spec §3): what one input does to one node, over `Copy` data.
//! `node_step` never starts or stops anything itself: it records a stop (`to_stop`) and the
//! scheduler issues it in hard-dependency order. It owns the failure accounting: the breaker
//! (obligation 3), the back-off (obligation 4) and the forager rule (obligation 10).

#[allow(clippy::wildcard_imports)] // the shared types, used throughout
use crate::*;
use vstd::prelude::*;

verus! {

// ---- back-off arithmetic ----
/// The cap of the back-off: ten times the base delay.
pub open spec fn cap_of(delay: int) -> int {
    CAP_FACTOR as int * delay
}

/// The back-off after `exp` earlier fast failures: the base delay, doubling, capped.
pub open spec fn sb(delay: int, exp: nat) -> int
    decreases exp,
{
    if exp == 0 {
        delay
    } else {
        let p = sb(delay, (exp - 1) as nat);
        if 2 * p < cap_of(delay) {
            2 * p
        } else {
            cap_of(delay)
        }
    }
}

/// The back-off stays between the base delay and the cap.
pub proof fn lemma_sb_bounds(delay: int, exp: nat)
    requires
        delay >= 0,
    ensures
        delay <= sb(delay, exp) <= cap_of(delay),
    decreases exp,
{
    if exp > 0 {
        lemma_sb_bounds(delay, (exp - 1) as nat);
    }
}

/// Once the back-off is at the cap it stays there.
pub proof fn lemma_sb_stays(delay: int, k: nat, e: nat)
    requires
        delay >= 0,
        k <= e,
        sb(delay, k) == cap_of(delay),
    ensures
        sb(delay, e) == cap_of(delay),
    decreases e - k,
{
    if k < e {
        lemma_sb_stays(delay, (k + 1) as nat, e);
    }
}

/// The back-off in milliseconds after `exp` earlier fast failures (obligation 4).
#[must_use]
#[allow(clippy::cast_lossless)]  // `u64::from` is not available inside `verus!`
pub fn backoff_ms(delay: u32, exp: u32) -> (r: u64)
    ensures
        r as int == sb(delay as int, exp as nat),
        r as int <= cap_of(delay as int),
{
    let cap: u64 = 10 * (delay as u64);
    let mut d: u64 = delay as u64;
    let mut k: u32 = 0;
    while k < exp && d < cap
        invariant
            k <= exp,
            d as int == sb(delay as int, k as nat),
            d <= cap,
            cap == 10 * delay as u64,
        decreases exp - k,
    {
        let dd: u64 = d * 2;
        d =
        if dd < cap {
            dd
        } else {
            cap
        };
        k += 1;
    }
    proof {
        lemma_sb_bounds(delay as int, exp as nat);
        if k < exp {
            lemma_sb_stays(delay as int, k as nat, exp as nat);
        }
    }
    d
}

/// The wait the node's current failure count asks for between two starts.
pub open spec fn wait_of(ns: NodeState, delay: int) -> int {
    if ns.backoff_exp == 0 {
        0
    } else {
        sb(delay, (ns.backoff_exp - 1) as nat)
    }
}

/// Obligation 4: a start is allowed once the back-off has elapsed since the last start.
pub open spec fn spec_paced(ns: NodeState, delay: int, now: int) -> bool {
    now >= ns.last_start_ms && now - ns.last_start_ms >= wait_of(ns, delay)
}

/// The wait the node's current failure count asks for.
#[must_use]
#[allow(clippy::cast_lossless)]  // `u64::from` is not available inside `verus!`
pub fn wait_ms(ns: NodeState, delay: u32) -> (r: u64)
    ensures
        r as int == wait_of(ns, delay as int),
        r as int <= cap_of(delay as int),
{
    proof {
        lemma_sb_bounds(delay as int, 0);
    }
    if ns.backoff_exp == 0 {
        0
    } else {
        backoff_ms(delay, ns.backoff_exp - 1)
    }
}

/// Whether the back-off since the last start has elapsed.
#[must_use]
pub fn paced(ns: NodeState, delay: u32, now: u64) -> (r: bool)
    ensures
        r == spec_paced(ns, delay as int, now as int),
{
    let w = wait_ms(ns, delay);
    now >= ns.last_start_ms && now - ns.last_start_ms >= w
}

/// Milliseconds until the node may start; 0 exactly when it is paced.
#[must_use]
#[allow(clippy::cast_lossless, clippy::cast_possible_truncation)]  // `u64::from` is not available inside `verus!`; the narrowing casts follow a comparison with `u32::MAX`
pub fn remaining_ms(ns: NodeState, delay: u32, now: u64) -> (r: u32)
    ensures
        (r == 0) == spec_paced(ns, delay as int, now as int),
{
    let w = wait_ms(ns, delay);
    if now >= ns.last_start_ms {
        let elapsed = now - ns.last_start_ms;
        if elapsed >= w {
            0
        } else {
            let left = w - elapsed;
            if left > u32::MAX as u64 {
                u32::MAX
            } else {
                left as u32
            }
        }
    } else if w == 0 {
        1
    } else if w > u32::MAX as u64 {
        u32::MAX
    } else {
        w as u32
    }
}

// ---- the breaker ----
/// Obligation 3: the breaker is tripped exactly when there are more failures than `max`.
pub open spec fn tripped(ns: NodeState, max: u32) -> bool {
    max > 0 && ns.burst_count > max
}

/// Counts one failure at `now`: opens a new burst when the window has passed, counts it in the
/// burst, and advances the back-off exponent (a run at least as long as the cap resets it).
#[must_use]
#[allow(clippy::cast_lossless)]  // `u64::from` is not available inside `verus!`
pub fn count_failure(ns: NodeState, p: Params, now: u64) -> (r: NodeState)
    ensures
        r.burst_count >= 1,
        r.backoff_exp >= 1,
        (NodeState {
            burst_begin_ms: ns.burst_begin_ms,
            burst_count: ns.burst_count,
            backoff_exp: ns.backoff_exp,
            ..r
        } == ns),
{
    let cap: u64 = 10 * (p.delay_ms as u64);
    let long_run = now >= ns.last_start_ms && now - ns.last_start_ms >= cap;
    let exp0: u32 = if long_run {
        0
    } else {
        ns.backoff_exp
    };
    let exp1: u32 = if exp0 < u32::MAX {
        exp0 + 1
    } else {
        exp0
    };
    if ns.burst_count == 0 || now < ns.burst_begin_ms || now - ns.burst_begin_ms
        > p.window_ms as u64 {
        NodeState { burst_begin_ms: now, burst_count: 1, backoff_exp: exp1, ..ns }
    } else {
        let c: u32 = if ns.burst_count < u32::MAX {
            ns.burst_count + 1
        } else {
            ns.burst_count
        };
        NodeState { burst_count: c, backoff_exp: exp1, ..ns }
    }
}

// ---- invariants ----
/// Which timer a state owns. After the start timeout fires, `timed_out` records why none is armed.
pub open spec fn timer_matches(ns: NodeState, start_timeout: int) -> bool {
    match ns.state {
        State::Starting => ns.timer == Some(TimerKind::StartTimeout) || (ns.timer is None && (
        start_timeout == 0 || ns.timed_out)),
        State::Waiting(Why::Backoff) => ns.timer == Some(TimerKind::Backoff),
        State::Waiting(Why::Deps) => ns.timer is None || ns.timer == Some(TimerKind::Edge),
        _ => ns.timer is None,
    }
}

/// What holds of one node between inputs (obligations 3, 6 and 10 at the node level).
pub open spec fn inv_node(ns: NodeState, p: Params) -> bool {
    &&& timer_matches(ns, p.start_timeout_ms as int)
    &&& (ns.state == State::Quarantined(Reason::Breaker) ==> p.max > 0 && ns.burst_count > p.max)
    &&& (ns.to_stop ==> ns.state is Starting || ns.state is Ready)
    &&& (p.kind == 1 ==> !(ns.state is Quarantined) && ns.state != State::Waiting(Why::Backoff)
        && ns.backoff_exp == 0)
}

// ---- small constructors ----
/// Only the report slots differ between `n` and `ns`.
pub open spec fn keeps_but_reports(n: NodeState, ns: NodeState) -> bool {
    NodeState { report_a: ns.report_a, report_b: ns.report_b, ..n } == ns
}

/// Adds a report to the first free slot.
#[must_use]
pub fn push_report(ns: NodeState, r: Report) -> (n: NodeState)
    ensures
        keeps_but_reports(n, ns),
{
    if ns.report_a.is_none() {
        NodeState { report_a: Some(r), ..ns }
    } else {
        NodeState { report_b: Some(r), ..ns }
    }
}

/// Records that the node is to stop for `why`. The first reason stays: a failure after an
/// administrator's stop is not a failure.
#[must_use]
pub fn mark_stop(ns: NodeState, why: Left) -> (n: NodeState)
    requires
        ns.state is Starting || ns.state is Ready,
    ensures
        n.to_stop,
        (NodeState { to_stop: ns.to_stop, left: ns.left, ..n } == ns),
{
    if ns.to_stop {
        ns
    } else {
        NodeState { to_stop: true, left: why, ..ns }
    }
}

/// Cancels the node's armed timer, if any.
#[must_use]
pub fn cancel_timer(ns: NodeState) -> (n: NodeState)
    ensures
        n.timer is None,
        (NodeState { timer: ns.timer, emit_cancel: ns.emit_cancel, ..n } == ns),
        ns.timer is None ==> n == ns,
{
    match ns.timer {
        Some(t) => NodeState { timer: None, emit_cancel: Some(t), ..ns },
        None => ns,
    }
}

/// Answers a request the node cannot take.
#[must_use]
pub fn refused(ns: NodeState) -> (n: NodeState)
    ensures
        keeps_but_reports(n, ns),
{
    push_report(ns, Report::Refused)
}

// ---- the end of a run ----
/// Only the actions the scheduler owns (start, stop, watch) are untouched.
pub open spec fn keeps_emits(n: NodeState, ns: NodeState) -> bool {
    n.emit_start == ns.emit_start && n.emit_stop == ns.emit_stop && n.emit_watch == ns.emit_watch
}

/// Obligation 3: this stop is a failure of a node the policy restarts.
pub open spec fn counts(ns: NodeState, p: Params) -> bool {
    p.kind != 1 && p.policy != 0 && (ns.left == Left::Error || (ns.exited_clean && p.policy == 2))
}

/// A failure of a node the policy restarts: count it, then quarantine (breaker), wait out the
/// back-off, or go straight to waiting for its dependencies.
#[must_use]
pub fn failed_restart(ns: NodeState, p: Params, now: u64) -> (r: NodeState)
    requires
        ns.timer is None,
        p.kind != 1,
    ensures
        r.state != State::Quarantined(Reason::Cascade),
        r.timer is None || r.timer == Some(TimerKind::Backoff),
        !r.to_stop,
        r.state is Quarantined || r.state is Waiting,
        r.state != State::Quarantined(Reason::Breaker) || (p.max > 0 && r.burst_count > p.max),
        (p.max > 0 && r.burst_count > p.max) ==> r.state == State::Quarantined(Reason::Breaker),
        r.state == State::Waiting(Why::Backoff) ==> r.timer == Some(TimerKind::Backoff),
        r.state == State::Waiting(Why::Deps) ==> r.timer is None,
        r.state is Quarantined ==> r.timer is None,
        keeps_emits(r, ns),
        r.wanted == ns.wanted,
{
    let c = count_failure(ns, p, now);
    let c = push_report(c, Report::Failed(ns.status));
    if p.max > 0 && c.burst_count > p.max {
        let c = push_report(c, Report::Quarantined(Reason::Breaker));
        NodeState {
            state: State::Quarantined(Reason::Breaker),
            to_stop: false,
            restart_after: false,
            ..c
        }
    } else {
        let rem = remaining_ms(c, p.delay_ms, now);
        if rem == 0 {
            NodeState { state: State::Waiting(Why::Deps), wait_since_ms: now, to_stop: false, ..c }
        } else {
            NodeState {
                state: State::Waiting(Why::Backoff),
                timer: Some(TimerKind::Backoff),
                emit_arm: Some((TimerKind::Backoff, rem)),
                to_stop: false,
                ..c
            }
        }
    }
}

/// The cell is empty: decide what the node becomes (spec §3, failure classification).
#[must_use]
pub fn finalize(ns: NodeState, p: Params, shutdown: bool, now: u64) -> (r: NodeState)
    requires
        inv_node(ns, p),
        ns.state is Starting || ns.state is Ready || ns.state is Stopping,
    ensures
        r.state != State::Quarantined(Reason::Cascade),
        inv_node(r, p),
        !(r.state is Starting) && !(r.state is Ready) && !(r.state is Stopping),
        !r.to_stop,
        keeps_emits(r, ns),
        r.wanted ==> ns.wanted,
        !shutdown && counts(ns, p) && p.max > 0 && r.burst_count > p.max ==> r.state
            == State::Quarantined(Reason::Breaker),
        shutdown ==> r.state == State::Off,
        shutdown ==> r.emit_arm == ns.emit_arm,
{
    let n = cancel_timer(ns);
    let n = NodeState { to_stop: false, ..n };
    if shutdown {
        push_report(
            NodeState { state: State::Off, wanted: false, restart_after: false, ..n },
            Report::Stopped,
        )
    } else if p.kind != 1 && p.policy != 0 && (matches!(n.left, Left::Error) || (n.exited_clean
        && p.policy == 2)) {
        failed_restart(n, p, now)
    } else if matches!(n.left, Left::Error) {
        // Never restarted: a forager, or a worker whose policy is `never`.
        let n = NodeState { wanted: false, restart_after: false, ..n };
        if n.timed_out && p.kind != 1 {
            let n = push_report(n, Report::Failed(n.status));
            push_report(
                NodeState { state: State::Quarantined(Reason::StartTimeout), ..n },
                Report::Quarantined(Reason::StartTimeout),
            )
        } else {
            push_report(NodeState { state: State::Off, ..n }, Report::Failed(n.status))
        }
    } else if n.done {
        let w = n.wanted && p.kind != 1;
        push_report(
            NodeState { state: State::Done, wanted: w, restart_after: false, ..n },
            Report::Done,
        )
    } else if n.restart_after {
        NodeState {
            state: State::Waiting(Why::Deps),
            wait_since_ms: now,
            restart_after: false,
            ..n
        }
    } else {
        push_report(
            NodeState { state: State::Off, wanted: false, restart_after: false, ..n },
            Report::Stopped,
        )
    }
}

/// Starts the node: the scheduler calls this when every group is satisfied and the back-off
/// has elapsed (obligation 4).
#[must_use]
pub fn begin_start(ns: NodeState, p: Params, now: u64) -> (r: NodeState)
    requires
        inv_node(ns, p),
        ns.state is Off || ns.state is Waiting,
        spec_paced(ns, p.delay_ms as int, now as int),
    ensures
        r.emit_stop == ns.emit_stop,
        inv_node(r, p),
        r.state == State::Starting,
        r.emit_start,
        r.last_start_ms == now,
        !r.to_stop,
        r.wanted == ns.wanted,
        r.backoff_exp == ns.backoff_exp,
        r.burst_count == ns.burst_count,
{
    let n = cancel_timer(ns);
    let (timer, arm) = if p.start_timeout_ms > 0 {
        (Some(TimerKind::StartTimeout), Some((TimerKind::StartTimeout, p.start_timeout_ms)))
    } else {
        (None, None)
    };
    push_report(
        NodeState {
            state: State::Starting,
            timer,
            emit_arm: arm,
            emit_start: true,
            last_start_ms: now,
            left: Left::Restart,
            done: false,
            timed_out: false,
            exited_clean: false,
            status: None,
            to_stop: false,
            restart_after: false,
            ..n
        },
        Report::Started,
    )
}

// ---- requests ----
/// `Start`: the node is wanted. Foragers run on `Run`, a quarantined node waits for `Clear`.
fn on_start(ns: NodeState, p: Params, shutdown: bool) -> (r: NodeState)
    requires
        inv_node(ns, p),
    ensures
        inv_node(r, p),
        keeps_emits(r, ns),
        r.emit_arm == ns.emit_arm,
        shutdown ==> (r.wanted ==> ns.wanted),
{
    if shutdown || p.kind == 1 || matches!(ns.state, State::Quarantined(_)) {
        refused(ns)
    } else if ns.to_stop || matches!(ns.state, State::Stopping) {
        NodeState { wanted: true, restart_after: true, ..ns }
    } else {
        NodeState { wanted: true, ..ns }
    }
}

/// `Stop`: nobody wants the node; whatever runs stops in dependency order.
#[allow(unused_variables)]  // `p` appears only in the specification
fn on_stop(ns: NodeState, p: Params) -> (r: NodeState)
    requires
        inv_node(ns, p),
    ensures
        inv_node(r, p),
        keeps_emits(r, ns),
        r.emit_arm == ns.emit_arm,
        r.wanted ==> ns.wanted,
{
    match ns.state {
        State::Off | State::Quarantined(_) => NodeState { wanted: false, ..ns },
        State::Waiting(_) => {
            let n = cancel_timer(ns);
            NodeState {
                state: State::Off,
                wanted: false,
                restart_after: false,
                left: Left::Restart,
                ..n
            }
        },
        State::Starting | State::Ready => {
            let n = NodeState { wanted: false, restart_after: false, ..ns };
            mark_stop(n, Left::Restart)
        },
        State::Done => NodeState { state: State::Off, wanted: false, left: Left::Restart, ..ns },
        State::Stopping => NodeState { wanted: false, restart_after: false, ..ns },
    }
}

/// `Restart`: stop and start again; a plain restart is not a failure.
fn on_restart(ns: NodeState, p: Params, shutdown: bool) -> (r: NodeState)
    requires
        inv_node(ns, p),
    ensures
        inv_node(r, p),
        keeps_emits(r, ns),
        r.emit_arm == ns.emit_arm,
        shutdown ==> (r.wanted ==> ns.wanted),
{
    if shutdown || p.kind == 1 {
        return refused(ns);
    }
    match ns.state {
        State::Off | State::Waiting(_) => NodeState { wanted: true, ..ns },
        State::Starting | State::Ready => {
            let n = NodeState { wanted: true, restart_after: true, ..ns };
            mark_stop(n, Left::Restart)
        },
        State::Done => NodeState { state: State::Off, wanted: true, left: Left::Restart, ..ns },
        State::Stopping => NodeState { wanted: true, restart_after: true, ..ns },
        State::Quarantined(_) => refused(ns),
    }
}

/// `Clear`: leave quarantine with fresh counters.
#[allow(unused_variables)]  // `p` appears only in the specification
fn on_clear(ns: NodeState, p: Params) -> (r: NodeState)
    requires
        inv_node(ns, p),
    ensures
        inv_node(r, p),
        keeps_emits(r, ns),
        r.emit_arm == ns.emit_arm,
        r.wanted ==> ns.wanted,
{
    match ns.state {
        State::Quarantined(_) => NodeState {
            state: State::Off,
            burst_begin_ms: 0,
            burst_count: 0,
            backoff_exp: 0,
            left: Left::Restart,
            done: false,
            timed_out: false,
            exited_clean: false,
            status: None,
            ..ns
        },
        _ => refused(ns),
    }
}

/// `Run`: a forager runs once.
fn on_run(ns: NodeState, p: Params, shutdown: bool) -> (r: NodeState)
    requires
        inv_node(ns, p),
    ensures
        inv_node(r, p),
        keeps_emits(r, ns),
        r.emit_arm == ns.emit_arm,
        shutdown ==> (r.wanted ==> ns.wanted),
{
    if p.kind == 1 && !shutdown && matches!(ns.state, State::Off | State::Done) {
        NodeState { state: State::Off, wanted: true, done: false, left: Left::Restart, ..ns }
    } else {
        refused(ns)
    }
}

/// `Shutdown` as the node sees it: nobody wants it, whatever runs stops.
#[allow(unused_variables)]  // `p` appears only in the specification
fn on_shutdown(ns: NodeState, p: Params) -> (r: NodeState)
    requires
        inv_node(ns, p),
    ensures
        inv_node(r, p),
        keeps_emits(r, ns),
        r.emit_arm == ns.emit_arm,
        !r.wanted,
{
    match ns.state {
        State::Off | State::Quarantined(_) => NodeState { wanted: false, ..ns },
        State::Waiting(_) => {
            let n = cancel_timer(ns);
            NodeState { state: State::Off, wanted: false, restart_after: false, ..n }
        },
        State::Starting | State::Ready => {
            let n = NodeState { wanted: false, restart_after: false, ..ns };
            mark_stop(n, Left::Restart)
        },
        State::Done => NodeState { state: State::Off, wanted: false, left: Left::Restart, ..ns },
        State::Stopping => NodeState { wanted: false, restart_after: false, ..ns },
    }
}

// ---- cell reports ----
/// The main process exited (D18: before its ready line is a failure).
fn on_exit(ns: NodeState, p: Params, status: Option<i32>, starting: bool) -> (r: NodeState)
    requires
        inv_node(ns, p),
        ns.state is Starting || ns.state is Ready,
    ensures
        inv_node(r, p),
        keeps_emits(r, ns),
        r.emit_arm == ns.emit_arm,
        r.wanted ==> ns.wanted,
{
    let ns = NodeState { status, ..ns };
    if ns.to_stop {
        ns
    } else if p.ready_kind == 1 || p.kind == 1 {
        if matches!(status, Some(0)) {
            mark_stop(NodeState { done: true, ..ns }, Left::Restart)
        } else {
            mark_stop(ns, Left::Error)
        }
    } else if starting {
        mark_stop(ns, Left::Error)
    } else if matches!(status, Some(0)) {
        mark_stop(NodeState { exited_clean: true, ..ns }, Left::Restart)
    } else {
        mark_stop(ns, Left::Error)
    }
}

/// The cell failed: the node cannot be stopped cleanly.
fn on_cell_failed(ns: NodeState, p: Params) -> (r: NodeState)
    requires
        inv_node(ns, p),
    ensures
        inv_node(r, p),
        keeps_emits(r, ns),
        r.emit_arm == ns.emit_arm,
        r.wanted ==> ns.wanted,
{
    let n = cancel_timer(ns);
    let n = NodeState { to_stop: false, restart_after: false, ..n };
    if p.kind == 1 {
        push_report(NodeState { state: State::Off, wanted: false, ..n }, Report::Failed(n.status))
    } else {
        push_report(
            NodeState { state: State::Quarantined(Reason::StopFailed), ..n },
            Report::Quarantined(Reason::StopFailed),
        )
    }
}

fn on_cell(ns: NodeState, p: Params, shutdown: bool, rep: CellReport, now: u64) -> (r: NodeState)
    requires
        inv_node(ns, p),
    ensures
        inv_node(r, p),
        keeps_emits(r, ns),
        shutdown ==> r.emit_arm == ns.emit_arm,
        shutdown ==> (r.wanted ==> ns.wanted),
{
    match (ns.state, rep) {
        (State::Starting, CellReport::Ready) => {
            if ns.to_stop {
                ns
            } else if p.ready_kind == 1 || p.kind == 1 {
                // Ready by exit: wait for the exit itself.
                NodeState { done: true, ..ns }
            } else {
                let n = cancel_timer(ns);
                push_report(
                    NodeState { state: State::Ready, left: Left::Restart, ..n },
                    Report::Ready,
                )
            }
        },
        (State::Starting, CellReport::NotReady | CellReport::SpawnFailed) => {
            if ns.to_stop {
                ns
            } else {
                mark_stop(ns, Left::Error)
            }
        },
        (State::Starting, CellReport::MainExited(s)) => on_exit(ns, p, s, true),
        (State::Ready, CellReport::MainExited(s)) => on_exit(ns, p, s, false),
        (State::Stopping, CellReport::MainExited(s)) => NodeState { status: s, ..ns },
        (State::Starting | State::Ready | State::Stopping, CellReport::Empty) => finalize(
            ns,
            p,
            shutdown,
            now,
        ),
        (
            State::Starting
            | State::Ready
            | State::Stopping,
            CellReport::CellFailed,
        ) => on_cell_failed(ns, p),
        _ => ns,
    }
}

// ---- deadlines ----
#[allow(unused_variables)]  // `p` appears only in the specification
fn on_deadline(ns: NodeState, p: Params, t: TimerKind, now: u64) -> (r: NodeState)
    requires
        inv_node(ns, p),
    ensures
        inv_node(r, p),
        keeps_emits(r, ns),
        r.emit_arm == ns.emit_arm,
        r.wanted ==> ns.wanted,
{
    match (ns.state, t) {
        (State::Starting, TimerKind::StartTimeout) => {
            if matches!(ns.timer, Some(TimerKind::StartTimeout)) {
                let n = NodeState { timer: None, timed_out: true, ..ns };
                if n.to_stop {
                    n
                } else {
                    mark_stop(n, Left::Error)
                }
            } else {
                ns
            }
        },
        (State::Waiting(Why::Backoff), TimerKind::Backoff) => {
            if matches!(ns.timer, Some(TimerKind::Backoff)) {
                NodeState {
                    state: State::Waiting(Why::Deps),
                    timer: None,
                    wait_since_ms: now,
                    ..ns
                }
            } else {
                ns
            }
        },
        (State::Waiting(Why::Deps), TimerKind::Edge) => {
            if matches!(ns.timer, Some(TimerKind::Edge)) {
                NodeState { timer: None, ..ns }
            } else {
                ns
            }
        },
        _ => ns,
    }
}

/// What one input does to one node. It never starts or stops anything itself (`emit_start`,
/// `emit_stop` and `emit_watch` are the scheduler's); it records stops and failures.
#[must_use]
pub fn node_step(ns: NodeState, p: Params, shutdown: bool, input: NodeInput, now: u64) -> (r:
    NodeState)
    requires
        inv_node(ns, p),
    ensures
        inv_node(r, p),
        keeps_emits(r, ns),
        shutdown ==> r.emit_arm == ns.emit_arm,
        input == NodeInput::Shutdown ==> !r.wanted,
        shutdown ==> (r.wanted ==> ns.wanted),
{
    match input {
        NodeInput::Req(Request::Start) => on_start(ns, p, shutdown),
        NodeInput::Req(Request::Stop) => on_stop(ns, p),
        NodeInput::Req(Request::Restart) => on_restart(ns, p, shutdown),
        NodeInput::Req(Request::Clear) => on_clear(ns, p),
        NodeInput::Req(Request::Run) => on_run(ns, p, shutdown),
        NodeInput::Cell(rep) => on_cell(ns, p, shutdown, rep, now),
        NodeInput::Deadline(t) => on_deadline(ns, p, t, now),
        NodeInput::Shutdown => on_shutdown(ns, p),
    }
}

// ---- transitions the scheduler makes ----
/// A wanted node that was off starts waiting for its dependencies.
#[must_use]
#[allow(unused_variables)]  // `p` appears only in the specification
pub fn enter_waiting(ns: NodeState, p: Params, now: u64, watch: bool) -> (r: NodeState)
    requires
        inv_node(ns, p),
        ns.state is Off,
    ensures
        r.emit_stop == ns.emit_stop,
        inv_node(r, p),
        r.state == State::Waiting(Why::Deps),
        r.wait_since_ms == now,
        r.wanted == ns.wanted,
        r.last_start_ms == ns.last_start_ms,
        r.backoff_exp == ns.backoff_exp,
        r.emit_start == ns.emit_start,
{
    NodeState {
        state: State::Waiting(Why::Deps),
        wait_since_ms: now,
        emit_watch: watch || ns.emit_watch,
        ..ns
    }
}

/// A brood whose groups are satisfied is ready at once.
#[must_use]
#[allow(unused_variables)]  // `p` appears only in the specification
pub fn brood_ready(ns: NodeState, p: Params) -> (r: NodeState)
    requires
        inv_node(ns, p),
        ns.state is Waiting,
    ensures
        r.emit_stop == ns.emit_stop,
        inv_node(r, p),
        r.state == State::Ready,
        r.wanted == ns.wanted,
        r.emit_start == ns.emit_start,
{
    let n = cancel_timer(ns);
    push_report(NodeState { state: State::Ready, left: Left::Restart, ..n }, Report::Ready)
}

/// The groups are satisfied but the back-off has not elapsed: wait it out.
#[must_use]
pub fn to_backoff(ns: NodeState, p: Params, now: u64) -> (r: NodeState)
    requires
        inv_node(ns, p),
        ns.state == State::Waiting(Why::Deps),
        p.kind != 1,
    ensures
        r.emit_stop == ns.emit_stop,
        inv_node(r, p),
        r.state == State::Waiting(Why::Backoff),
        r.wanted == ns.wanted,
        r.emit_start == ns.emit_start,
{
    let rem = remaining_ms(ns, p.delay_ms, now);
    let n = cancel_timer(ns);
    NodeState {
        state: State::Waiting(Why::Backoff),
        timer: Some(TimerKind::Backoff),
        emit_arm: Some((TimerKind::Backoff, rem)),
        ..n
    }
}

/// A waiting node arms the timer of its earliest pending async deadline.
#[must_use]
#[allow(unused_variables)]  // `p` appears only in the specification
pub fn arm_edge(ns: NodeState, p: Params, ms: u32) -> (r: NodeState)
    requires
        inv_node(ns, p),
        ns.state == State::Waiting(Why::Deps),
        ns.timer is None,
    ensures
        r.emit_stop == ns.emit_stop,
        inv_node(r, p),
        r.state == ns.state,
        r.wanted == ns.wanted,
        r.emit_start == ns.emit_start,
{
    NodeState { timer: Some(TimerKind::Edge), emit_arm: Some((TimerKind::Edge, ms)), ..ns }
}

/// The scheduler issues the stop of a running node whose hard dependents have stopped. A brood
/// has no cell: it is finalized at once.
#[must_use]
pub fn begin_stop(ns: NodeState, p: Params, shutdown: bool, now: u64) -> (r: NodeState)
    requires
        inv_node(ns, p),
        ns.state is Starting || ns.state is Ready,
        ns.to_stop,
    ensures
        r.state != State::Quarantined(Reason::Cascade),
        r.wanted ==> ns.wanted,
        inv_node(r, p),
        p.kind != 2 ==> r.state == State::Stopping && r.emit_stop,
        !r.to_stop,
        r.emit_start == ns.emit_start,
        shutdown ==> r.emit_arm == ns.emit_arm,
{
    if p.kind == 2 {
        finalize(ns, p, shutdown, now)
    } else {
        let n = cancel_timer(ns);
        NodeState { state: State::Stopping, to_stop: false, emit_stop: true, ..n }
    }
}

/// A node that would run is quarantined because a cascade-flagged `require_all` dependency is
/// (spec §4, obligation 8).
#[must_use]
#[allow(unused_variables)]  // `p` appears only in the specification
pub fn quarantine_cascade(ns: NodeState, p: Params) -> (r: NodeState)
    requires
        inv_node(ns, p),
        ns.state is Off || ns.state is Waiting,
        p.kind != 1,
    ensures
        inv_node(r, p),
        r.state == State::Quarantined(Reason::Cascade),
        r.wanted == ns.wanted,
        r.emit_start == ns.emit_start,
        r.emit_stop == ns.emit_stop,
        r.emit_arm == ns.emit_arm,
{
    let n = cancel_timer(ns);
    push_report(
        NodeState { state: State::Quarantined(Reason::Cascade), ..n },
        Report::Quarantined(Reason::Cascade),
    )
}

} // verus!
