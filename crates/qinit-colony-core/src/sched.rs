// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The scheduler (spec §4): evaluates the groups over the observed node states, starts what
//! may start, and drains the actions one at a time. The state is slices the caller owns: the
//! node table, one bit per edge for "this path exists" and "this async edge was late", and the
//! small `Meta`.
#![allow(clippy::many_single_char_names)] // loop counters and the specification's own names (a, b, g, i, k, x)

#[allow(clippy::wildcard_imports)] // the shared types, used throughout
use crate::*;
#[allow(clippy::wildcard_imports)] // the database accessors and layout constants
use qinit_db_core::*;
use vstd::prelude::*;

verus! {

// ---- facts about a validated database ----
proof fn lemma_node_groups(b: Seq<u8>, i: int)
    requires
        well_formed(b),
        0 <= i < nodes(b),
    ensures
        nf(b, i, N_GROUP_FIRST) + nf(b, i, N_GROUP_COUNT) <= tcnt(b, T_GROUPS as int),
{
    lemma_accessors_in_bounds(b);
    assert(node_groups_in_range(b, i));
}

proof fn lemma_group_edges(b: Seq<u8>, g: int)
    requires
        well_formed(b),
        0 <= g < tcnt(b, T_GROUPS as int),
    ensures
        gf(b, g, G_EDGE_FIRST) + gf(b, g, G_EDGE_COUNT) <= tcnt(b, T_EDGES as int),
{
    lemma_accessors_in_bounds(b);
    assert(group_edges_in_range(b, g));
}

proof fn lemma_edge_target(b: Seq<u8>, x: int)
    requires
        well_formed(b),
        0 <= x < tcnt(b, T_EDGES as int),
    ensures
        ef(b, x, E_TARGET_KIND) == 0 ==> ef(b, x, E_TARGET) < nodes(b),
{
    assert(v3(b));
    assert(edge_index_ok(b, x));
}

/// The words of node `i`'s record that its machine reads.
#[must_use]
pub fn params(db: &[u8], i: usize) -> (p: Params)
    requires
        well_formed(db@),
        i < nodes(db@),
    ensures
        p == params_of(db@, i as int),
{
    Params {
        kind: node_word(db, i, N_KIND),
        ready_kind: node_word(db, i, N_READY_KIND),
        policy: node_word(db, i, N_RESTART_POLICY),
        max: node_word(db, i, N_RESTART_MAX),
        window_ms: node_word(db, i, N_RESTART_WINDOW_MS),
        delay_ms: node_word(db, i, N_RESTART_DELAY_MS),
        stop_mode: node_word(db, i, N_STOP_MODE),
        grace_ms: node_word(db, i, N_STOP_GRACE_MS),
        start_timeout_ms: node_word(db, i, N_START_TIMEOUT_MS),
    }
}

// ---- evaluation ----
/// A node is available to its dependents: ready and not about to stop, or finished.
fn is_sat(ns: NodeState) -> (r: bool)
    ensures
        r == ((ns.state is Ready && !ns.to_stop) || ns.state is Done),
{
    (matches!(ns.state, State::Ready) && !ns.to_stop) || matches!(ns.state, State::Done)
}

/// Edge `x` is satisfied.
#[allow(clippy::cast_lossless)]  // `u64::from` is not available inside `verus!`
fn edge_satisfied(
    db: &[u8],
    ns: &[NodeState],
    paths: &[bool],
    x: usize,
    since: u64,
    now: u64,
) -> (r: bool)
    requires
        sized(db@, ns@.len() as int, paths@.len() as int, paths@.len() as int),
        x < tcnt(db@, T_EDGES as int),
    ensures
        r == edge_ok(db@, ns@, paths@, x as int, since as int, now as int),
{
    proof {
        lemma_edge_target(db@, x as int);
    }
    let target_ok = if edge_word(db, x, E_TARGET_KIND) == 0 {
        let t = edge_word(db, x, E_TARGET) as usize;
        is_sat(ns[t])
    } else {
        paths[x]
    };
    target_ok || (edge_word(db, x, E_MODE) == 1 && now >= since && now - since >= edge_word(
        db,
        x,
        E_DEADLINE_MS,
    ) as u64)
}

/// What edge `x` of a group of `kind` contributes to its group.
fn edge_contributes(
    db: &[u8],
    ns: &[NodeState],
    paths: &[bool],
    kind: u32,
    x: usize,
    since: u64,
    now: u64,
) -> (r: bool)
    requires
        sized(db@, ns@.len() as int, paths@.len() as int, paths@.len() as int),
        x < tcnt(db@, T_EDGES as int),
    ensures
        r == edge_pred(db@, ns@, paths@, kind as int, x as int, since as int, now as int),
{
    proof {
        lemma_edge_target(db@, x as int);
    }
    let is_node = edge_word(db, x, E_TARGET_KIND) == 0;
    if kind == 3 {
        if is_node {
            let t = edge_word(db, x, E_TARGET) as usize;
            !(ns[t].wanted
                || matches!(ns[t].state, State::Starting | State::Ready | State::Stopping))
        } else {
            true
        }
    } else if kind == 2 {
        if edge_satisfied(db, ns, paths, x, since, now) {
            true
        } else if is_node {
            let t = edge_word(db, x, E_TARGET) as usize;
            (matches!(ns[t].state, State::Off) && !ns[t].wanted)
                || matches!(
                ns[t].state,
                State::Quarantined(_),
            )
        } else {
            false
        }
    } else {
        edge_satisfied(db, ns, paths, x, since, now)
    }
}

/// Group `g` is satisfied.
fn group_satisfied(
    db: &[u8],
    ns: &[NodeState],
    paths: &[bool],
    g: usize,
    since: u64,
    now: u64,
) -> (r: bool)
    requires
        sized(db@, ns@.len() as int, paths@.len() as int, paths@.len() as int),
        g < tcnt(db@, T_GROUPS as int),
    ensures
        r == group_ok(db@, ns@, paths@, g as int, since as int, now as int),
{
    proof {
        lemma_group_edges(db@, g as int);
    }
    let kind = group_word(db, g, G_KIND);
    let first = group_word(db, g, G_EDGE_FIRST) as usize;
    let count = group_word(db, g, G_EDGE_COUNT) as usize;
    let mut k: usize = 0;
    if kind == 1 {
        let mut any = false;
        while k < count
            invariant
                k <= count,
                first + count <= tcnt(db@, T_EDGES as int),
                sized(db@, ns@.len() as int, paths@.len() as int, paths@.len() as int),
                any == exists|x: int|
                    first <= x < first + k && #[trigger] edge_pred(
                        db@,
                        ns@,
                        paths@,
                        1,
                        x,
                        since as int,
                        now as int,
                    ),
                first == gf(db@, g as int, G_EDGE_FIRST),
                count == gf(db@, g as int, G_EDGE_COUNT),
            decreases count - k,
        {
            let ok = edge_contributes(db, ns, paths, 1, first + k, since, now);
            any = any || ok;
            k += 1;
        }
        any
    } else {
        let mut all = true;
        while k < count
            invariant
                k <= count,
                first + count <= tcnt(db@, T_EDGES as int),
                sized(db@, ns@.len() as int, paths@.len() as int, paths@.len() as int),
                all == forall|x: int|
                    first <= x < first + k ==> #[trigger] edge_pred(
                        db@,
                        ns@,
                        paths@,
                        kind as int,
                        x,
                        since as int,
                        now as int,
                    ),
                first == gf(db@, g as int, G_EDGE_FIRST),
                count == gf(db@, g as int, G_EDGE_COUNT),
                kind == gf(db@, g as int, G_KIND),
            decreases count - k,
        {
            let ok = edge_contributes(db, ns, paths, kind, first + k, since, now);
            all = all && ok;
            k += 1;
        }
        all
    }
}

/// Every group of node `i` is satisfied.
fn node_satisfied(
    db: &[u8],
    ns: &[NodeState],
    paths: &[bool],
    i: usize,
    since: u64,
    now: u64,
) -> (r: bool)
    requires
        sized(db@, ns@.len() as int, paths@.len() as int, paths@.len() as int),
        i < nodes(db@),
    ensures
        r == node_ok(db@, ns@, paths@, i as int, since as int, now as int),
{
    proof {
        lemma_node_groups(db@, i as int);
    }
    let first = node_word(db, i, N_GROUP_FIRST) as usize;
    let count = node_word(db, i, N_GROUP_COUNT) as usize;
    let mut k: usize = 0;
    let mut all = true;
    while k < count
        invariant
            k <= count,
            first + count <= tcnt(db@, T_GROUPS as int),
            sized(db@, ns@.len() as int, paths@.len() as int, paths@.len() as int),
            i < nodes(db@),
            all == forall|g: int|
                first <= g < first + k ==> #[trigger] group_ok(
                    db@,
                    ns@,
                    paths@,
                    g,
                    since as int,
                    now as int,
                ),
            first == nf(db@, i as int, N_GROUP_FIRST),
            count == nf(db@, i as int, N_GROUP_COUNT),
        decreases count - k,
    {
        let ok = group_satisfied(db, ns, paths, first + k, since, now);
        all = all && ok;
        k += 1;
    }
    all
}

// ---- scans of one node's edges ----
/// Whether node `i` has an edge to a filesystem path.
fn has_path_edge(db: &[u8], i: usize) -> (r: bool)
    requires
        well_formed(db@),
        i < nodes(db@),
{
    proof {
        lemma_node_groups(db@, i as int);
    }
    let gfirst = node_word(db, i, N_GROUP_FIRST) as usize;
    let gcount = node_word(db, i, N_GROUP_COUNT) as usize;
    let mut a: usize = 0;
    let mut found = false;
    while a < gcount
        invariant
            a <= gcount,
            gfirst + gcount <= tcnt(db@, T_GROUPS as int),
            well_formed(db@),
        decreases gcount - a,
    {
        let g = gfirst + a;
        proof {
            lemma_group_edges(db@, g as int);
        }
        let efirst = group_word(db, g, G_EDGE_FIRST) as usize;
        let ecount = group_word(db, g, G_EDGE_COUNT) as usize;
        let mut b: usize = 0;
        while b < ecount
            invariant
                b <= ecount,
                efirst + ecount <= tcnt(db@, T_EDGES as int),
                well_formed(db@),
            decreases ecount - b,
        {
            if edge_word(db, efirst + b, E_TARGET_KIND) == 1 {
                found = true;
            }
            b += 1;
        }
        a += 1;
    }
    found
}

/// The milliseconds until the earliest async edge deadline of node `i` that is still pending,
/// if there is one.
#[allow(clippy::cast_lossless)]  // `u64::from` is not available inside `verus!`
fn next_deadline(db: &[u8], ns: &[NodeState], paths: &[bool], i: usize, since: u64, now: u64) -> (r:
    Option<u32>)
    requires
        sized(db@, ns@.len() as int, paths@.len() as int, paths@.len() as int),
        i < nodes(db@),
{
    proof {
        lemma_node_groups(db@, i as int);
    }
    let gfirst = node_word(db, i, N_GROUP_FIRST) as usize;
    let gcount = node_word(db, i, N_GROUP_COUNT) as usize;
    let mut a: usize = 0;
    let mut best: u64 = u64::MAX;
    let mut found = false;
    while a < gcount
        invariant
            a <= gcount,
            gfirst + gcount <= tcnt(db@, T_GROUPS as int),
            sized(db@, ns@.len() as int, paths@.len() as int, paths@.len() as int),
        decreases gcount - a,
    {
        let g = gfirst + a;
        proof {
            lemma_group_edges(db@, g as int);
        }
        let efirst = group_word(db, g, G_EDGE_FIRST) as usize;
        let ecount = group_word(db, g, G_EDGE_COUNT) as usize;
        let mut b: usize = 0;
        while b < ecount
            invariant
                b <= ecount,
                efirst + ecount <= tcnt(db@, T_EDGES as int),
                sized(db@, ns@.len() as int, paths@.len() as int, paths@.len() as int),
            decreases ecount - b,
        {
            let x = efirst + b;
            let d = edge_word(db, x, E_DEADLINE_MS) as u64;
            if edge_word(db, x, E_MODE) == 1 && d > 0 && !edge_satisfied(
                db,
                ns,
                paths,
                x,
                since,
                now,
            ) {
                // Pending: the deadline has not passed (else the edge would be satisfied).
                let rem: u64 = if now >= since && now - since < d {
                    d - (now - since)
                } else {
                    d
                };
                if !found || rem < best {
                    best = rem;
                    found = true;
                }
            }
            b += 1;
        }
        a += 1;
    }
    if found {
        if best > u32::MAX as u64 {
            Some(u32::MAX)
        } else {
            #[allow(clippy::cast_possible_truncation)]  // guarded by the comparison above
            Some(best as u32)
        }
    } else {
        None
    }
}

/// Remembers which async edges of node `i` it started without: a late arrival of their target
/// restarts it (spec §4).
#[allow(unused_variables)]  // `paths` appears only in the specification
fn set_late(db: &[u8], ns: &[NodeState], paths: &[bool], late: &mut [bool], i: usize)
    requires
        sized(db@, ns@.len() as int, paths@.len() as int, old(late)@.len() as int),
        i < nodes(db@),
    ensures
        final(late)@.len() == old(late)@.len(),
{
    proof {
        lemma_node_groups(db@, i as int);
    }
    let gfirst = node_word(db, i, N_GROUP_FIRST) as usize;
    let gcount = node_word(db, i, N_GROUP_COUNT) as usize;
    let mut a: usize = 0;
    while a < gcount
        invariant
            a <= gcount,
            gfirst + gcount <= tcnt(db@, T_GROUPS as int),
            sized(db@, ns@.len() as int, paths@.len() as int, late@.len() as int),
            late@.len() == old(late)@.len(),
        decreases gcount - a,
    {
        let g = gfirst + a;
        proof {
            lemma_group_edges(db@, g as int);
        }
        let kind = group_word(db, g, G_KIND);
        let efirst = group_word(db, g, G_EDGE_FIRST) as usize;
        let ecount = group_word(db, g, G_EDGE_COUNT) as usize;
        let mut b: usize = 0;
        while b < ecount
            invariant
                b <= ecount,
                efirst + ecount <= tcnt(db@, T_EDGES as int),
                sized(db@, ns@.len() as int, paths@.len() as int, late@.len() as int),
                late@.len() == old(late)@.len(),
            decreases ecount - b,
        {
            let x = efirst + b;
            proof {
                lemma_edge_target(db@, x as int);
            }
            let is_late = if kind <= 2 && edge_word(db, x, E_TARGET_KIND) == 0 {
                let t = edge_word(db, x, E_TARGET) as usize;
                !is_sat(ns[t])
            } else {
                false
            };
            late[x] = is_late;
            b += 1;
        }
        a += 1;
    }
}

// ---- the wanted set ----
/// Marks the targets of node `i`'s `require_all` and `require_any` groups wanted (R11).
fn mark_edges(db: &[u8], tbl: &mut [NodeState], i: usize) -> (changed: bool)
    requires
        well_formed(db@),
        old(tbl)@.len() == nodes(db@),
        i < nodes(db@),
        inv_all(db@, old(tbl)@),
    ensures
        final(tbl)@.len() == old(tbl)@.len(),
        inv_all(db@, final(tbl)@),
        quiet_emits(final(tbl)@, old(tbl)@),
{
    proof {
        lemma_node_groups(db@, i as int);
    }
    let gfirst = node_word(db, i, N_GROUP_FIRST) as usize;
    let gcount = node_word(db, i, N_GROUP_COUNT) as usize;
    let mut a: usize = 0;
    let mut changed = false;
    while a < gcount
        invariant
            a <= gcount,
            gfirst + gcount <= tcnt(db@, T_GROUPS as int),
            well_formed(db@),
            tbl@.len() == nodes(db@),
            inv_all(db@, tbl@),
            quiet_emits(tbl@, old(tbl)@),
        decreases gcount - a,
    {
        let g = gfirst + a;
        proof {
            lemma_group_edges(db@, g as int);
        }
        let kind = group_word(db, g, G_KIND);
        let efirst = group_word(db, g, G_EDGE_FIRST) as usize;
        let ecount = group_word(db, g, G_EDGE_COUNT) as usize;
        let mut b: usize = 0;
        while b < ecount
            invariant
                b <= ecount,
                efirst + ecount <= tcnt(db@, T_EDGES as int),
                well_formed(db@),
                tbl@.len() == nodes(db@),
                inv_all(db@, tbl@),
                quiet_emits(tbl@, old(tbl)@),
            decreases ecount - b,
        {
            let x = efirst + b;
            proof {
                lemma_edge_target(db@, x as int);
            }
            if kind <= 1 && edge_word(db, x, E_TARGET_KIND) == 0 {
                let t = edge_word(db, x, E_TARGET) as usize;
                let old_t = tbl[t];
                if !old_t.wanted {
                    tbl[t] = NodeState { wanted: true, ..old_t };

                    proof {
                        assert forall|k: int| 0 <= k < tbl@.len() implies inv_node(
                            tbl@[k],
                            params_of(db@, k),
                        ) by {
                            if k == t as int {
                                assert(inv_node(old_t, params_of(db@, k)));
                            }
                        }
                    }
                    changed = true;
                }
            }
            b += 1;
        }
        a += 1;
    }
    changed
}

/// Marks the closure of `root` under `require_all` and `require_any` node targets wanted. Each
/// sweep over the tbl marks the targets of every wanted node; `n` sweeps reach any chain.
fn mark_closure(db: &[u8], tbl: &mut [NodeState])
    requires
        well_formed(db@),
        old(tbl)@.len() == nodes(db@),
        inv_all(db@, old(tbl)@),
    ensures
        final(tbl)@.len() == old(tbl)@.len(),
        inv_all(db@, final(tbl)@),
        quiet_emits(final(tbl)@, old(tbl)@),
{
    let n = tbl.len();
    let mut pass: usize = 0;
    let mut changed = true;
    while pass < n && changed
        invariant
            pass <= n,
            n == tbl@.len(),
            well_formed(db@),
            tbl@.len() == nodes(db@),
            inv_all(db@, tbl@),
            quiet_emits(tbl@, old(tbl)@),
        decreases n - pass,
    {
        changed = false;
        let mut i: usize = 0;
        while i < n
            invariant
                i <= n,
                n == tbl@.len(),
                well_formed(db@),
                tbl@.len() == nodes(db@),
                inv_all(db@, tbl@),
                quiet_emits(tbl@, old(tbl)@),
            decreases n - i,
        {
            let ghost before = tbl@;
            if tbl[i].wanted && mark_edges(db, tbl, i) {
                changed = true;
            }
            proof {
                // mark_edges, when called, keeps the emits of `before`.
                if !(before[i as int].wanted) {
                    assert(tbl@ == before);
                } else {
                    lemma_quiet_trans(tbl@, before, old(tbl)@);
                }
            }
            i += 1;
        }
        pass += 1;
    }
}

// ---- hard dependents (obligation 2) ----
/// Whether group `g` has a hard edge to node `t`.
fn group_blocks(db: &[u8], g: usize, t: usize) -> (r: bool)
    requires
        well_formed(db@),
        g < tcnt(db@, T_GROUPS as int),
    ensures
        r == group_hard_to(db@, g as int, t as int),
{
    proof {
        lemma_group_edges(db@, g as int);
    }
    let kind = group_word(db, g, G_KIND);
    let first = group_word(db, g, G_EDGE_FIRST) as usize;
    let count = group_word(db, g, G_EDGE_COUNT) as usize;
    let mut k: usize = 0;
    let mut found = false;
    while k < count
        invariant
            k <= count,
            first + count <= tcnt(db@, T_EDGES as int),
            well_formed(db@),
            first == gf(db@, g as int, G_EDGE_FIRST),
            count == gf(db@, g as int, G_EDGE_COUNT),
            kind == gf(db@, g as int, G_KIND),
            found == group_hard_upto(db@, g as int, t as int, k as nat),
        decreases count - k,
    {
        let x = first + k;
        if kind <= 1 && edge_word(db, x, E_MODE) == 0 && edge_word(db, x, E_TARGET_KIND) == 0
            && edge_word(db, x, E_TARGET) as usize == t {
            found = true;
        }
        k += 1;
    }
    found
}

/// Whether node `i` has a hard edge to node `t`.
fn node_blocks(db: &[u8], i: usize, t: usize) -> (r: bool)
    requires
        well_formed(db@),
        i < nodes(db@),
    ensures
        r == node_hard_to(db@, i as int, t as int),
{
    proof {
        lemma_node_groups(db@, i as int);
    }
    let first = node_word(db, i, N_GROUP_FIRST) as usize;
    let count = node_word(db, i, N_GROUP_COUNT) as usize;
    let mut k: usize = 0;
    let mut found = false;
    while k < count
        invariant
            k <= count,
            first + count <= tcnt(db@, T_GROUPS as int),
            well_formed(db@),
            i < nodes(db@),
            first == nf(db@, i as int, N_GROUP_FIRST),
            count == nf(db@, i as int, N_GROUP_COUNT),
            found == node_hard_upto(db@, i as int, t as int, k as nat),
        decreases count - k,
    {
        if group_blocks(db, first + k, t) {
            found = true;
        }
        k += 1;
    }
    found
}

/// Whether some node that is going away still has a hard edge to node `t`.
fn is_blocked(db: &[u8], tbl: &[NodeState], t: usize) -> (r: bool)
    requires
        well_formed(db@),
        tbl@.len() == nodes(db@),
    ensures
        r == hard_blocked(db@, tbl@, t as int),
{
    let n = tbl.len();
    let mut i: usize = 0;
    let mut found = false;
    while i < n
        invariant
            i <= n,
            n == tbl@.len(),
            well_formed(db@),
            tbl@.len() == nodes(db@),
            found == blocked_upto(db@, tbl@, t as int, i as nat),
        decreases n - i,
    {
        let ns = tbl[i];
        if (matches!(ns.state, State::Stopping) || ns.to_stop) && node_blocks(db, i, t) {
            found = true;
        }
        i += 1;
    }
    found
}

// ---- cascade (obligation 8) ----
/// Whether group `g` has a cascade edge to a quarantined node.
fn group_cascades(db: &[u8], tbl: &[NodeState], g: usize) -> (r: bool)
    requires
        well_formed(db@),
        tbl@.len() == nodes(db@),
        g < tcnt(db@, T_GROUPS as int),
    ensures
        r == group_cascade_upto(db@, tbl@, g as int, gf(db@, g as int, G_EDGE_COUNT) as nat),
{
    proof {
        lemma_group_edges(db@, g as int);
    }
    let kind = group_word(db, g, G_KIND);
    let first = group_word(db, g, G_EDGE_FIRST) as usize;
    let count = group_word(db, g, G_EDGE_COUNT) as usize;
    let mut k: usize = 0;
    let mut found = false;
    while k < count
        invariant
            k <= count,
            first + count <= tcnt(db@, T_EDGES as int),
            well_formed(db@),
            tbl@.len() == nodes(db@),
            first == gf(db@, g as int, G_EDGE_FIRST),
            count == gf(db@, g as int, G_EDGE_COUNT),
            kind == gf(db@, g as int, G_KIND),
            found == group_cascade_upto(db@, tbl@, g as int, k as nat),
        decreases count - k,
    {
        let x = first + k;
        proof {
            lemma_edge_target(db@, x as int);
        }
        if kind == 0 && edge_word(db, x, E_TARGET_KIND) == 0 && edge_word(db, x, E_FLAGS) >= 2 {
            let t = edge_word(db, x, E_TARGET) as usize;
            if matches!(tbl[t].state, State::Quarantined(_)) {
                found = true;
            }
        }
        k += 1;
    }
    found
}

/// Whether node `i` has a cascade edge to a quarantined node.
fn cascades(db: &[u8], tbl: &[NodeState], i: usize) -> (r: bool)
    requires
        well_formed(db@),
        tbl@.len() == nodes(db@),
        i < nodes(db@),
    ensures
        r == cascade_hit(db@, tbl@, i as int),
{
    proof {
        lemma_node_groups(db@, i as int);
    }
    let first = node_word(db, i, N_GROUP_FIRST) as usize;
    let count = node_word(db, i, N_GROUP_COUNT) as usize;
    let mut k: usize = 0;
    let mut found = false;
    while k < count
        invariant
            k <= count,
            first + count <= tcnt(db@, T_GROUPS as int),
            well_formed(db@),
            tbl@.len() == nodes(db@),
            i < nodes(db@),
            first == nf(db@, i as int, N_GROUP_FIRST),
            count == nf(db@, i as int, N_GROUP_COUNT),
            found == node_cascade_upto(db@, tbl@, i as int, k as nat),
        decreases count - k,
    {
        if group_cascades(db, tbl, first + k) {
            found = true;
        }
        k += 1;
    }
    found
}

// ---- propagation (spec §4) ----
/// Whether node `i`, which is running, has to stop and come back: an edge's target went away
/// and the edge's `restart_on` asks for it, an excluded node became wanted or active, or a
/// cascade-flagged dependency was quarantined. Also clears the `late` bit of an edge whose
/// target became ready at last, and asks for a restart if that edge says `restart` or `refresh`.
#[allow(unused_variables)]  // `paths` appears only in the specification
fn scan_running(db: &[u8], tbl: &[NodeState], paths: &[bool], late: &mut [bool], i: usize) -> (r:
    bool)
    requires
        sized(db@, tbl@.len() as int, paths@.len() as int, old(late)@.len() as int),
        i < nodes(db@),
    ensures
        final(late)@.len() == old(late)@.len(),
{
    proof {
        lemma_node_groups(db@, i as int);
    }
    let gfirst = node_word(db, i, N_GROUP_FIRST) as usize;
    let gcount = node_word(db, i, N_GROUP_COUNT) as usize;
    let mut a: usize = 0;
    let mut trig = false;
    while a < gcount
        invariant
            a <= gcount,
            gfirst + gcount <= tcnt(db@, T_GROUPS as int),
            sized(db@, tbl@.len() as int, paths@.len() as int, late@.len() as int),
            late@.len() == old(late)@.len(),
        decreases gcount - a,
    {
        let g = gfirst + a;
        proof {
            lemma_group_edges(db@, g as int);
        }
        let kind = group_word(db, g, G_KIND);
        let efirst = group_word(db, g, G_EDGE_FIRST) as usize;
        let ecount = group_word(db, g, G_EDGE_COUNT) as usize;
        let mut b: usize = 0;
        while b < ecount
            invariant
                b <= ecount,
                efirst + ecount <= tcnt(db@, T_EDGES as int),
                sized(db@, tbl@.len() as int, paths@.len() as int, late@.len() as int),
                late@.len() == old(late)@.len(),
            decreases ecount - b,
        {
            let x = efirst + b;
            proof {
                lemma_edge_target(db@, x as int);
            }
            if edge_word(db, x, E_TARGET_KIND) == 0 {
                let t = edge_word(db, x, E_TARGET) as usize;
                let tn = tbl[t];
                let on = edge_word(db, x, E_RESTART_ON);
                if kind == 3 {
                    if tn.wanted
                        || matches!(
                        tn.state,
                        State::Starting | State::Ready | State::Stopping,
                    ) {
                        trig = true;
                    }
                } else {
                    let ready = is_sat(tn);
                    if late[x] {
                        if ready {
                            late[x] = false;
                            if on >= 2 {
                                trig = true;
                            }
                        }
                    } else if !ready && (on >= 2 || (on == 1 && matches!(tn.left, Left::Error))) {
                        trig = true;
                    }
                }
            }
            b += 1;
        }
        a += 1;
    }
    trig
}

// ---- the pass ----
/// Brings node `i` forward: off becomes waiting, a waiting node whose groups are satisfied
/// starts (or becomes ready, for a brood), a satisfied node still inside its back-off waits it
/// out, an unsatisfied node arms its earliest async deadline. Returns whether the node moved in
/// a way other nodes can see.
///
/// Obligation 1: this is the only function that sets `emit_start`, and its postcondition says
/// it happens only to a node that was `startable` in the table it read.
#[allow(unused_variables)]  // `shutdown` appears only in the specification
fn reconcile_idle(
    db: &[u8],
    tbl: &mut [NodeState],
    paths: &[bool],
    late: &mut [bool],
    i: usize,
    shutdown: bool,
    now: u64,
) -> (changed: bool)
    requires
        sized(db@, old(tbl)@.len() as int, paths@.len() as int, old(late)@.len() as int),
        i < old(tbl)@.len(),
        inv_all(db@, old(tbl)@),
        shutdown_ok(shutdown, old(tbl)@),
    ensures
        final(tbl)@.len() == old(tbl)@.len(),
        final(late)@.len() == old(late)@.len(),
        inv_all(db@, final(tbl)@),
        forall|j: int| 0 <= j < old(tbl)@.len() && j != i ==> final(tbl)@[j] == old(tbl)@[j],
        final(tbl)@[i as int].emit_start && !old(tbl)@[i as int].emit_start ==> startable(
            db@,
            old(tbl)@,
            paths@,
            i as int,
            now as int,
        ),
        final(tbl)@[i as int].wanted == old(tbl)@[i as int].wanted,
        final(tbl)@[i as int].emit_stop == old(tbl)@[i as int].emit_stop,
        final(tbl)@[i as int].state == State::Quarantined(Reason::Cascade) && !(old(
            tbl,
        )@[i as int].state is Quarantined) ==> cascade_hit(db@, old(tbl)@, i as int),
        shutdown ==> final(tbl)@[i as int].emit_arm == old(tbl)@[i as int].emit_arm,
        shutdown ==> final(tbl)@[i as int].emit_start == old(tbl)@[i as int].emit_start,
{
    let ns = tbl[i];
    let p = params(db, i);
    proof {
        assert(inv_node(tbl@[i as int], params_of(db@, i as int)));
    }
    if !ns.wanted {
        return false;
    }
    let entered = matches!(ns.state, State::Off);
    let cur = match ns.state {
        State::Off => enter_waiting(ns, p, now, has_path_edge(db, i)),
        State::Waiting(Why::Deps) => ns,
        _ => {
            return false;
        },
    };
    if p.kind != 1 && cascades(db, tbl, i) {
        tbl[i] = quarantine_cascade(cur, p);
        return true;
    }
    let sat = node_satisfied(db, tbl, paths, i, cur.wait_since_ms, now);
    let ghost old_tbl = tbl@;
    if sat {
        if p.kind == 2 {
            set_late(db, tbl, paths, late, i);
            tbl[i] = brood_ready(cur, p);
            true
        } else if paced(cur, p.delay_ms, now) {
            set_late(db, tbl, paths, late, i);
            tbl[i] = begin_start(cur, p, now);
            proof {
                assert(startable(db@, old_tbl, paths@, i as int, now as int));
            }
            true
        } else if p.kind != 1 {
            tbl[i] = to_backoff(cur, p, now);
            true
        } else {
            tbl[i] = cur;
            entered
        }
    } else {
        let armed = if cur.timer.is_none() {
            match next_deadline(db, tbl, paths, i, cur.wait_since_ms, now) {
                Some(ms) => arm_edge(cur, p, ms),
                None => cur,
            }
        } else {
            cur
        };
        tbl[i] = armed;
        entered
    }
}

/// A running node first looks at its edges (propagation, exclusion, late arrival, cascade);
/// if it is to stop it stops once none of its hard dependents is still going away
/// (obligation 2).
#[allow(unused_variables)]  // `shutdown` appears only in the specification (and in `begin_stop`'s)
fn reconcile_running(
    db: &[u8],
    tbl: &mut [NodeState],
    paths: &[bool],
    late: &mut [bool],
    i: usize,
    shutdown: bool,
    now: u64,
) -> (changed: bool)
    requires
        sized(db@, old(tbl)@.len() as int, paths@.len() as int, old(late)@.len() as int),
        i < old(tbl)@.len(),
        inv_all(db@, old(tbl)@),
        old(tbl)@[i as int].state is Starting || old(tbl)@[i as int].state is Ready,
    ensures
        final(tbl)@.len() == old(tbl)@.len(),
        final(late)@.len() == old(late)@.len(),
        inv_all(db@, final(tbl)@),
        forall|j: int| 0 <= j < old(tbl)@.len() && j != i ==> final(tbl)@[j] == old(tbl)@[j],
        final(tbl)@[i as int].emit_stop && !old(tbl)@[i as int].emit_stop ==> !hard_blocked(
            db@,
            old(tbl)@,
            i as int,
        ),
        final(tbl)@[i as int].state != State::Quarantined(Reason::Cascade),
        final(tbl)@[i as int].emit_start == old(tbl)@[i as int].emit_start,
        final(tbl)@[i as int].wanted ==> old(tbl)@[i as int].wanted,
        shutdown ==> final(tbl)@[i as int].emit_arm == old(tbl)@[i as int].emit_arm,
{
    let ns = tbl[i];
    let p = params(db, i);
    proof {
        assert(inv_node(tbl@[i as int], params_of(db@, i as int)));
    }
    let mut cur = ns;
    if !cur.to_stop && (scan_running(db, tbl, paths, late, i) || cascades(db, tbl, i)) {
        cur = mark_stop(NodeState { restart_after: true, ..cur }, Left::Restart);
    }
    if cur.to_stop && !is_blocked(db, tbl, i) {
        tbl[i] = begin_stop(cur, p, shutdown, now);
        true
    } else {
        tbl[i] = cur;
        cur.to_stop && !ns.to_stop
    }
}

/// Brings node `i` forward (see `reconcile_idle` and `reconcile_running`).
fn reconcile_node(
    db: &[u8],
    tbl: &mut [NodeState],
    paths: &[bool],
    late: &mut [bool],
    i: usize,
    shutdown: bool,
    now: u64,
) -> (changed: bool)
    requires
        sized(db@, old(tbl)@.len() as int, paths@.len() as int, old(late)@.len() as int),
        i < old(tbl)@.len(),
        inv_all(db@, old(tbl)@),
        shutdown_ok(shutdown, old(tbl)@),
    ensures
        final(tbl)@.len() == old(tbl)@.len(),
        final(late)@.len() == old(late)@.len(),
        inv_all(db@, final(tbl)@),
        forall|j: int| 0 <= j < old(tbl)@.len() && j != i ==> final(tbl)@[j] == old(tbl)@[j],
        final(tbl)@[i as int].emit_start && !old(tbl)@[i as int].emit_start ==> startable(
            db@,
            old(tbl)@,
            paths@,
            i as int,
            now as int,
        ),
        final(tbl)@[i as int].emit_stop && !old(tbl)@[i as int].emit_stop ==> !hard_blocked(
            db@,
            old(tbl)@,
            i as int,
        ),
        final(tbl)@[i as int].state == State::Quarantined(Reason::Cascade) && !(old(
            tbl,
        )@[i as int].state is Quarantined) ==> cascade_hit(db@, old(tbl)@, i as int),
        shutdown ==> final(tbl)@[i as int].emit_arm == old(tbl)@[i as int].emit_arm,
        shutdown ==> final(tbl)@[i as int].emit_start == old(tbl)@[i as int].emit_start,
        shutdown_ok(shutdown, final(tbl)@),
{
    let ns = tbl[i];
    if matches!(ns.state, State::Starting | State::Ready) {
        reconcile_running(db, tbl, paths, late, i, shutdown, now)
    } else {
        reconcile_idle(db, tbl, paths, late, i, shutdown, now)
    }
}

/// Runs passes over the table until nothing changes, at most `n + 1` of them (a chain of
/// broods needs one pass per link). Returns whether it converged; the proof is of the
/// invariant, and of obligation 1 through `reconcile_node`.
pub fn reconcile(
    db: &[u8],
    tbl: &mut [NodeState],
    paths: &[bool],
    late: &mut [bool],
    shutdown: bool,
    now: u64,
) -> (converged: bool)
    requires
        sized(db@, old(tbl)@.len() as int, paths@.len() as int, old(late)@.len() as int),
        inv_all(db@, old(tbl)@),
        shutdown_ok(shutdown, old(tbl)@),
    ensures
        final(tbl)@.len() == old(tbl)@.len(),
        final(late)@.len() == old(late)@.len(),
        inv_all(db@, final(tbl)@),
        shutdown_ok(shutdown, final(tbl)@),
        shutdown ==> quiet_emits(final(tbl)@, old(tbl)@),
{
    let n = tbl.len();
    proof {
        assert(table_ok(db@, T_NODES as int));
    }
    let mut pass: usize = 0;
    while pass <= n
        invariant
            pass <= n + 1,
            n <= MAX_NODES,
            n == tbl@.len(),
            tbl@.len() == old(tbl)@.len(),
            sized(db@, tbl@.len() as int, paths@.len() as int, late@.len() as int),
            late@.len() == old(late)@.len(),
            inv_all(db@, tbl@),
            shutdown_ok(shutdown, tbl@),
            shutdown ==> quiet_emits(tbl@, old(tbl)@),
        decreases n + 1 - pass,
    {
        let mut changed = false;
        let mut i: usize = 0;
        while i < n
            invariant
                i <= n,
                n == tbl@.len(),
                tbl@.len() == old(tbl)@.len(),
                sized(db@, tbl@.len() as int, paths@.len() as int, late@.len() as int),
                late@.len() == old(late)@.len(),
                inv_all(db@, tbl@),
                shutdown_ok(shutdown, tbl@),
                shutdown ==> quiet_emits(tbl@, old(tbl)@),
            decreases n - i,
        {
            let ghost before = tbl@;
            if reconcile_node(db, tbl, paths, late, i, shutdown, now) {
                changed = true;
            }
            proof {
                if shutdown {
                    assert(quiet_emits(tbl@, before));
                    lemma_quiet_trans(tbl@, before, old(tbl)@);
                }
            }
            i += 1;
        }
        if !changed {
            return true;
        }
        pass += 1;
    }
    false
}

// ---- one input ----
/// Applies `input` to node `i`'s machine.
fn apply_node(
    db: &[u8],
    tbl: &mut [NodeState],
    i: usize,
    shutdown: bool,
    input: NodeInput,
    now: u64,
)
    requires
        well_formed(db@),
        old(tbl)@.len() == nodes(db@),
        i < old(tbl)@.len(),
        inv_all(db@, old(tbl)@),
    ensures
        final(tbl)@.len() == old(tbl)@.len(),
        inv_all(db@, final(tbl)@),
        shutdown ==> (final(tbl)@[i as int].wanted ==> old(tbl)@[i as int].wanted),
        shutdown ==> quiet_emits(final(tbl)@, old(tbl)@),
        forall|j: int| 0 <= j < old(tbl)@.len() && j != i ==> final(tbl)@[j] == old(tbl)@[j],
        input == NodeInput::Shutdown ==> !final(tbl)@[i as int].wanted,
{
    let p = params(db, i);
    proof {
        assert(inv_node(tbl@[i as int], params_of(db@, i as int)));
    }
    let s = node_step(tbl[i], p, shutdown, input, now);
    tbl[i] = s;
}

/// One input to the whole colony: apply it, then settle the table. Returns whether the
/// settling converged. `meta.cursor` is reset: call `next_action` until it returns `None`
/// before the next `step`.
#[allow(clippy::semicolon_if_nothing_returned)]  // a `proof` block ends one branch
pub fn step(
    db: &[u8],
    tbl: &mut [NodeState],
    paths: &mut [bool],
    late: &mut [bool],
    meta: &mut Meta,
    input: Input,
    now: u64,
) -> (converged: bool)
    requires
        sized(db@, old(tbl)@.len() as int, old(paths)@.len() as int, old(late)@.len() as int),
        inv_all(db@, old(tbl)@),
        shutdown_ok(old(meta).shutdown, old(tbl)@),
    ensures
        final(tbl)@.len() == old(tbl)@.len(),
        final(paths)@.len() == old(paths)@.len(),
        final(late)@.len() == old(late)@.len(),
        inv_all(db@, final(tbl)@),
        shutdown_ok(final(meta).shutdown, final(tbl)@),
        old(meta).shutdown ==> quiet_emits(final(tbl)@, old(tbl)@),
{
    let ghost t0 = tbl@;
    let ghost sd = meta.shutdown;
    meta.cursor = 0;
    let n = tbl.len();
    match input {
        Input::Request { node, req } => {
            let i = node as usize;
            if i < n {
                apply_node(db, tbl, i, meta.shutdown, NodeInput::Req(req), now);
                let ghost t1 = tbl@;
                if matches!(req, Request::Start) && tbl[i].wanted {
                    mark_closure(db, tbl);
                    proof {
                        if sd {
                            lemma_quiet_trans(tbl@, t1, t0);
                        }
                    }
                }
            }
        },
        Input::Shutdown => {
            if !meta.shutdown {
                meta.shutdown = true;
                let mut i: usize = 0;
                while i < n
                    invariant
                        i <= n,
                        n == tbl@.len(),
                        well_formed(db@),
                        tbl@.len() == nodes(db@),
                        inv_all(db@, tbl@),
                        forall|k: int| 0 <= k < i ==> !(#[trigger] tbl@[k]).wanted,
                    decreases n - i,
                {
                    apply_node(db, tbl, i, true, NodeInput::Shutdown, now);
                    i += 1;
                }
            }
        },
        Input::Cell { node, report } => {
            let i = node as usize;
            if i < n {
                apply_node(db, tbl, i, meta.shutdown, NodeInput::Cell(report), now);
            }
        },
        Input::Deadline { node, timer } => {
            let i = node as usize;
            if i < n {
                apply_node(db, tbl, i, meta.shutdown, NodeInput::Deadline(timer), now);
            }
        },
        Input::PathAppeared { edge } => {
            let x = edge as usize;
            if x < paths.len() {
                paths[x] = true;
            }
        },
    }
    let ghost t1 = tbl@;
    proof {
        if sd {
            assert(meta.shutdown);
            assert(quiet_emits(t1, t0));
        }
    }
    let converged = reconcile(db, tbl, paths, late, meta.shutdown, now);
    let ghost t2 = tbl@;
    report_shutdown(db, tbl, meta);
    proof {
        if sd {
            lemma_quiet_trans(t2, t1, t0);
            lemma_quiet_trans(tbl@, t2, t0);
        }
    }
    converged
}

// ---- the end of a shutdown ----
/// Whether no node holds a process or waits (`Off`, `Done` or `Quarantined` all round), and how
/// many are quarantined because their cell would not stop.
#[allow(clippy::implicit_saturating_add)]  // `saturating_add` is not available inside `verus!`
fn quiet_count(tbl: &[NodeState]) -> (r: (bool, u32)) {
    let n = tbl.len();
    let mut i: usize = 0;
    let mut quiet = true;
    let mut stuck: u32 = 0;
    while i < n
        invariant
            i <= n,
            n == tbl@.len(),
        decreases n - i,
    {
        match tbl[i].state {
            State::Quarantined(Reason::StopFailed) => {
                if stuck < u32::MAX {
                    stuck += 1;
                }
            },
            State::Off | State::Done | State::Quarantined(_) => {},
            _ => {
                quiet = false;
            },
        }
        i += 1;
    }
    (quiet, stuck)
}

/// Reports `ShutdownComplete` once, on node 0, when the whole graph has stopped.
#[allow(unused_variables)]  // `db` appears only in the specification
#[allow(clippy::len_zero)]  // `is_empty` is not available inside `verus!`
fn report_shutdown(db: &[u8], tbl: &mut [NodeState], meta: &mut Meta)
    requires
        well_formed(db@),
        old(tbl)@.len() == nodes(db@),
        inv_all(db@, old(tbl)@),
        shutdown_ok(old(meta).shutdown, old(tbl)@),
    ensures
        final(tbl)@.len() == old(tbl)@.len(),
        inv_all(db@, final(tbl)@),
        final(meta).shutdown == old(meta).shutdown,
        shutdown_ok(final(meta).shutdown, final(tbl)@),
        quiet_emits(final(tbl)@, old(tbl)@),
{
    if meta.shutdown && !meta.reported && tbl.len() > 0 {
        let (quiet, stuck) = quiet_count(tbl);
        if quiet {
            let s0 = tbl[0];
            let new = push_report(s0, Report::ShutdownComplete { still_populated: stuck });
            proof {
                assert(inv_node(s0, params_of(db@, 0)));
                assert(inv_node(new, params_of(db@, 0)));
            }
            tbl[0] = new;
            meta.reported = true;
        }
    }
}

// ---- the drain (obligation 9) ----
/// How many actions node `ns` still has pending: one per set flag. At most `K`.
pub open spec fn flags_of(ns: NodeState) -> int {
    (if ns.emit_start {
        1int
    } else {
        0int
    }) + (if ns.emit_stop {
        1int
    } else {
        0int
    }) + (if ns.emit_watch {
        1int
    } else {
        0int
    }) + (if ns.emit_cancel is Some {
        1int
    } else {
        0int
    }) + (if ns.emit_arm is Some {
        1int
    } else {
        0int
    }) + (if ns.report_a is Some {
        1int
    } else {
        0int
    }) + (if ns.report_b is Some {
        1int
    } else {
        0int
    })
}

/// The actions pending on the first `n` nodes.
pub open spec fn total_n(ns: Seq<NodeState>, n: nat) -> int
    decreases n,
{
    if n == 0 {
        0
    } else {
        total_n(ns, (n - 1) as nat) + flags_of(ns[n - 1])
    }
}

/// Every node has at most `K` actions, so the table has at most `K` per node.
pub proof fn lemma_total_bound(ns: Seq<NodeState>, n: nat)
    requires
        n <= ns.len(),
    ensures
        0 <= total_n(ns, n) <= K as int * n,
    decreases n,
{
    if n > 0 {
        lemma_total_bound(ns, (n - 1) as nat);
    }
}

/// Changing one node changes the total by the change in that node's flags.
pub proof fn lemma_total_update(ns: Seq<NodeState>, j: int, v: NodeState, n: nat)
    requires
        0 <= j < ns.len(),
        n <= ns.len(),
    ensures
        total_n(ns.update(j, v), n) == total_n(ns, n) + if j < n {
            flags_of(v) - flags_of(ns[j])
        } else {
            0int
        },
    decreases n,
{
    if n > 0 {
        lemma_total_update(ns, j, v, (n - 1) as nat);
    }
}

/// A table whose nodes all have nothing pending has nothing pending in total.
pub proof fn lemma_total_zero(ns: Seq<NodeState>, n: nat)
    requires
        n <= ns.len(),
        forall|k: int| 0 <= k < n ==> #[trigger] flags_of(ns[k]) == 0,
    ensures
        total_n(ns, n) == 0,
    decreases n,
{
    if n > 0 {
        lemma_total_zero(ns, (n - 1) as nat);
    }
}

/// Nodes before the cursor have been drained.
pub open spec fn drained(ns: Seq<NodeState>, cursor: int) -> bool {
    forall|k: int| 0 <= k < cursor ==> #[trigger] flags_of(ns[k]) == 0
}

/// One pending action of a node, without the node's index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pending {
    Cancel(TimerKind),
    Arm(TimerKind, u32),
    Watch,
    Stop,
    Start,
    Report(Report),
}

/// Takes the first pending action of a node, in the order cancel, arm, watch, stop, start,
/// report. Taking one clears exactly one flag; none left means nothing is pending.
#[must_use]
pub fn take_one(ns: NodeState) -> (r: (NodeState, Option<Pending>))
    ensures
        r.1 is Some ==> flags_of(r.0) + 1 == flags_of(ns),
        r.1 is None ==> flags_of(ns) == 0 && r.0 == ns,
{
    if let Some(t) = ns.emit_cancel {
        (NodeState { emit_cancel: None, ..ns }, Some(Pending::Cancel(t)))
    } else if let Some((t, ms)) = ns.emit_arm {
        (NodeState { emit_arm: None, ..ns }, Some(Pending::Arm(t, ms)))
    } else if ns.emit_watch {
        (NodeState { emit_watch: false, ..ns }, Some(Pending::Watch))
    } else if ns.emit_stop {
        (NodeState { emit_stop: false, ..ns }, Some(Pending::Stop))
    } else if ns.emit_start {
        (NodeState { emit_start: false, ..ns }, Some(Pending::Start))
    } else if let Some(rep) = ns.report_a {
        (NodeState { report_a: None, ..ns }, Some(Pending::Report(rep)))
    } else if let Some(rep) = ns.report_b {
        (NodeState { report_b: None, ..ns }, Some(Pending::Report(rep)))
    } else {
        (ns, None)
    }
}

/// The next pending action, one at a time, in node order. Each `Some` clears exactly one flag;
/// `None` means nothing is pending anywhere. So after one `step`, at most
/// `total_n(table, n) <= K * n` actions come out before `None` (`lemma_total_bound`).
#[allow(clippy::cast_possible_truncation)]  // `j < nodes(db)`, at most `MAX_NODES`, so it fits in `u32`
pub fn next_action(db: &[u8], tbl: &mut [NodeState], meta: &mut Meta) -> (r: Option<Action>)
    requires
        well_formed(db@),
        old(tbl)@.len() == nodes(db@),
        old(meta).cursor <= old(tbl)@.len(),
        drained(old(tbl)@, old(meta).cursor as int),
    ensures
        final(tbl)@.len() == old(tbl)@.len(),
        final(meta).cursor <= final(tbl)@.len(),
        drained(final(tbl)@, final(meta).cursor as int),
        r is Some ==> total_n(final(tbl)@, final(tbl)@.len()) + 1 == total_n(
            old(tbl)@,
            old(tbl)@.len(),
        ),
        r is None ==> total_n(old(tbl)@, old(tbl)@.len()) == 0 && final(tbl)@ == old(tbl)@,
{
    let n = tbl.len();
    while meta.cursor < n
        invariant
            meta.cursor <= n,
            n == tbl@.len(),
            tbl@ == old(tbl)@,
            drained(tbl@, meta.cursor as int),
            well_formed(db@),
            n == nodes(db@),
        decreases n - meta.cursor,
    {
        let j = meta.cursor;
        let ns = tbl[j];
        let ghost before = tbl@;
        let (new, act) = take_one(ns);
        match act {
            Some(a) => {
                tbl[j] = new;
                proof {
                    lemma_total_update(before, j as int, new, n as nat);
                    assert forall|k: int| 0 <= k < j implies flags_of(tbl@[k]) == 0 by {
                        assert(tbl@[k] == before[k]);
                    }
                }
                let jj = j as u32;
                return Some(
                    match a {
                        Pending::Cancel(t) => Action::Cancel(jj, t),
                        Pending::Arm(t, ms) => Action::Arm(jj, t, ms),
                        Pending::Watch => Action::WatchPath(jj),
                        Pending::Stop => {
                            let p = params(db, j);
                            let mode = if p.stop_mode == 0 {
                                StopMode::Main
                            } else {
                                StopMode::Cell
                            };
                            Action::Stop(jj, mode, p.grace_ms)
                        },
                        Pending::Start => Action::Start(jj),
                        Pending::Report(rep) => Action::Report(jj, rep),
                    },
                );
            },
            None => {
                meta.cursor = j + 1;
            },
        }
    }
    proof {
        lemma_total_zero(tbl@, n as nat);
    }
    None
}

// ---- loading ----
/// Every node is off with nothing pending, as `off()` makes it.
pub open spec fn all_off(ns: Seq<NodeState>) -> bool {
    forall|i: int| 0 <= i < ns.len() ==> #[trigger] ns[i] == off_spec()
}

/// `off()` as a specification.
pub open spec fn off_spec() -> NodeState {
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
        emit_start: false,
        emit_stop: false,
        emit_watch: false,
        emit_cancel: None,
        emit_arm: None,
        report_a: None,
        report_b: None,
    }
}

/// A table of nodes that are all off satisfies the invariant.
proof fn lemma_off_inv(b: Seq<u8>, ns: Seq<NodeState>)
    requires
        all_off(ns),
    ensures
        inv_all(b, ns),
{
    assert forall|i: int| 0 <= i < ns.len() implies inv_node(ns[i], params_of(b, i)) by {
        assert(ns[i] == off_spec());
    }
}

/// Marks the nodes of the database's enabled list wanted.
fn mark_enabled(db: &[u8], tbl: &mut [NodeState])
    requires
        well_formed(db@),
        old(tbl)@.len() == nodes(db@),
        inv_all(db@, old(tbl)@),
    ensures
        final(tbl)@.len() == old(tbl)@.len(),
        inv_all(db@, final(tbl)@),
{
    let count = enabled_count(db);
    let mut k: usize = 0;
    while k < count
        invariant
            k <= count,
            count == tcnt(db@, T_ENABLED as int),
            well_formed(db@),
            tbl@.len() == nodes(db@),
            inv_all(db@, tbl@),
        decreases count - k,
    {
        proof {
            assert(v3(db@));
            assert(list_index_ok(db@, T_ENABLED, k as int));
        }
        let t = enabled(db, k) as usize;
        let old_t = tbl[t];
        tbl[t] = NodeState { wanted: true, ..old_t };
        proof {
            assert forall|j: int| 0 <= j < tbl@.len() implies inv_node(
                tbl@[j],
                params_of(db@, j),
            ) by {
                if j == t as int {
                    assert(inv_node(old_t, params_of(db@, j)));
                }
            }
        }
        k += 1;
    }
}

/// Starts colony on a database: the enabled nodes are wanted, then the table settles. Every
/// node of `tbl` must be off (`off()`); `paths` and `late` are all false.
pub fn load(
    db: &[u8],
    tbl: &mut [NodeState],
    paths: &[bool],
    late: &mut [bool],
    meta: &mut Meta,
    now: u64,
) -> (converged: bool)
    requires
        sized(db@, old(tbl)@.len() as int, paths@.len() as int, old(late)@.len() as int),
        all_off(old(tbl)@),
    ensures
        final(tbl)@.len() == old(tbl)@.len(),
        final(late)@.len() == old(late)@.len(),
        inv_all(db@, final(tbl)@),
{
    proof {
        lemma_off_inv(db@, tbl@);
    }
    meta.cursor = 0;
    mark_enabled(db, tbl);
    reconcile(db, tbl, paths, late, false, now)
}

} // verus!
