// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The scheduler's specification (spec §4): when an edge, a group and a node are satisfied,
//! when a node may start, and the invariant over the whole table. The executable code in
//! `sched` is proved equal to these.

#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use crate::*;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use qinit_db_core::*;
use vstd::prelude::*;

verus! {

/// The target is ready (or finished, for a run-to-completion node).
pub open spec fn sat(ns: Seq<NodeState>, t: int) -> bool {
    ns[t].state is Ready || ns[t].state is Done
}

/// The target holds a process or is on its way to or from holding one.
pub open spec fn active(ns: Seq<NodeState>, t: int) -> bool {
    ns[t].state is Starting || ns[t].state is Ready || ns[t].state is Stopping
}

/// The target will not run without a human: unwanted and off, or quarantined.
pub open spec fn wont_run(ns: Seq<NodeState>, t: int) -> bool {
    (ns[t].state is Off && !ns[t].wanted) || ns[t].state is Quarantined
}

/// Edge `x` is satisfied: its target is, or an async deadline measured from `since` passed.
pub open spec fn edge_ok(
    b: Seq<u8>,
    ns: Seq<NodeState>,
    paths: Seq<bool>,
    x: int,
    since: int,
    now: int,
) -> bool {
    let target_ok = if ef(b, x, E_TARGET_KIND) == 0 {
        sat(ns, ef(b, x, E_TARGET))
    } else {
        paths[x]
    };
    target_ok || (ef(b, x, E_MODE) == 1 && now >= since && now - since >= ef(b, x, E_DEADLINE_MS))
}

/// What edge `x` of a group of `kind` contributes to its group.
pub open spec fn edge_pred(
    b: Seq<u8>,
    ns: Seq<NodeState>,
    paths: Seq<bool>,
    kind: int,
    x: int,
    since: int,
    now: int,
) -> bool {
    let is_node = ef(b, x, E_TARGET_KIND) == 0;
    let t = ef(b, x, E_TARGET);
    if kind == 3 {
        !is_node || !(ns[t].wanted || active(ns, t))
    } else if kind == 2 {
        edge_ok(b, ns, paths, x, since, now) || (is_node && wont_run(ns, t))
    } else {
        edge_ok(b, ns, paths, x, since, now)
    }
}

/// Group `g` is satisfied (spec §4 table).
pub open spec fn group_ok(
    b: Seq<u8>,
    ns: Seq<NodeState>,
    paths: Seq<bool>,
    g: int,
    since: int,
    now: int,
) -> bool {
    let first = gf(b, g, G_EDGE_FIRST);
    let count = gf(b, g, G_EDGE_COUNT);
    let kind = gf(b, g, G_KIND);
    if kind == 1 {
        exists|x: int|
            first <= x < first + count && #[trigger] edge_pred(b, ns, paths, 1, x, since, now)
    } else {
        forall|x: int|
            first <= x < first + count ==> #[trigger] edge_pred(b, ns, paths, kind, x, since, now)
    }
}

/// Every group of node `i` is satisfied.
pub open spec fn node_ok(
    b: Seq<u8>,
    ns: Seq<NodeState>,
    paths: Seq<bool>,
    i: int,
    since: int,
    now: int,
) -> bool {
    forall|g: int|
        nf(b, i, N_GROUP_FIRST) <= g < nf(b, i, N_GROUP_FIRST) + nf(b, i, N_GROUP_COUNT)
            ==> #[trigger] group_ok(b, ns, paths, g, since, now)
}

/// The moment a node that is off or waiting counts its async deadlines from.
pub open spec fn since_of(ns: Seq<NodeState>, i: int, now: int) -> int {
    if ns[i].state is Off {
        now
    } else {
        ns[i].wait_since_ms as int
    }
}

/// Obligation 1: a node may start when it is wanted, off or waiting for its dependencies,
/// every group is satisfied and the back-off has elapsed. (Broods never start: they are ready.)
pub open spec fn startable(
    b: Seq<u8>,
    ns: Seq<NodeState>,
    paths: Seq<bool>,
    i: int,
    now: int,
) -> bool {
    &&& ns[i].wanted
    &&& (ns[i].state is Off || ns[i].state == State::Waiting(Why::Deps))
    &&& node_ok(b, ns, paths, i, since_of(ns, i, now), now)
    &&& spec_paced(ns[i], nf(b, i, N_RESTART_DELAY_MS), now)
}

/// Obligation 7: a node that may start has no `exclude_all` target that is wanted or active.
pub proof fn lemma_startable_excludes(
    b: Seq<u8>,
    ns: Seq<NodeState>,
    paths: Seq<bool>,
    i: int,
    now: int,
    g: int,
    x: int,
)
    requires
        startable(b, ns, paths, i, now),
        nf(b, i, N_GROUP_FIRST) <= g < nf(b, i, N_GROUP_FIRST) + nf(b, i, N_GROUP_COUNT),
        gf(b, g, G_KIND) == 3,
        gf(b, g, G_EDGE_FIRST) <= x < gf(b, g, G_EDGE_FIRST) + gf(b, g, G_EDGE_COUNT),
        ef(b, x, E_TARGET_KIND) == 0,
    ensures
        !(ns[ef(b, x, E_TARGET)].wanted || active(ns, ef(b, x, E_TARGET))),
{
    let since = since_of(ns, i, now);
    assert(group_ok(b, ns, paths, g, since, now));
    assert(edge_pred(b, ns, paths, 3, x, since, now));
}

/// The words of node `i`'s record that its machine reads.
pub open spec fn params_of(b: Seq<u8>, i: int) -> Params {
    Params {
        kind: nf(b, i, N_KIND) as u32,
        ready_kind: nf(b, i, N_READY_KIND) as u32,
        policy: nf(b, i, N_RESTART_POLICY) as u32,
        max: nf(b, i, N_RESTART_MAX) as u32,
        window_ms: nf(b, i, N_RESTART_WINDOW_MS) as u32,
        delay_ms: nf(b, i, N_RESTART_DELAY_MS) as u32,
        stop_mode: nf(b, i, N_STOP_MODE) as u32,
        grace_ms: nf(b, i, N_STOP_GRACE_MS) as u32,
        start_timeout_ms: nf(b, i, N_START_TIMEOUT_MS) as u32,
    }
}

/// The invariant of every node.
pub open spec fn inv_all(b: Seq<u8>, ns: Seq<NodeState>) -> bool {
    forall|i: int| 0 <= i < ns.len() ==> #[trigger] inv_node(ns[i], params_of(b, i))
}

/// The tables have the sizes of the database they belong to.
pub open spec fn sized(b: Seq<u8>, ns_len: int, paths_len: int, late_len: int) -> bool {
    &&& well_formed(b)
    &&& ns_len == nodes(b)
    &&& paths_len == tcnt(b, T_EDGES as int)
    &&& late_len == paths_len
}

} // verus!
