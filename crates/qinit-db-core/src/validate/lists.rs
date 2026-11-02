// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! V8 (and the list part of V3): the enabled and pre-syslog lists are ascending node indices,
//! and the enabled set is closed under the `require_all` and `require_any` node targets of its
//! members.

#![allow(clippy::many_single_char_names)] // `b`, `n`, `i`, `g`, `x`, `k` follow the spec names

use super::header::{field, header_word};
#[allow(unused_imports, clippy::wildcard_imports)]
// spec-only items: Verus erases them outside verification
use super::spec::*;
use super::{DbError, rid, tid};
#[allow(clippy::wildcard_imports)] // the layout constants, used throughout
use crate::layout::*;
use vstd::prelude::*;

verus! {

/// Checks that list table `t` holds strictly ascending node indices.
fn check_list(b: &[u8], t: usize) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        t == T_ENABLED || t == T_PRESYSLOG,
    ensures
        r is Ok ==> (forall|k: int|
            0 <= k < tcnt(b@, t as int) ==> #[trigger] list_index_ok(b@, t, k)) && (forall|k: int|
            0 < k < tcnt(b@, t as int) ==> #[trigger] list_sorted(b@, t, k)),
{
    let n = header_word(b, 5 + 2 * T_NODES);
    let count = header_word(b, 5 + 2 * t) as usize;
    let mut prev: u32 = 0;
    let mut k: usize = 0;
    while k < count
        invariant
            v1(b@),
            t == T_ENABLED || t == T_PRESYSLOG,
            n == nodes(b@),
            count == tcnt(b@, t as int),
            k <= count,
            k > 0 ==> prev == lf(b@, t, k - 1),
            forall|j: int| 0 <= j < k ==> #[trigger] list_index_ok(b@, t, j),
            forall|j: int| 0 < j < k ==> #[trigger] list_sorted(b@, t, j),
        decreases count - k,
    {
        let v = field(b, t, k, 0);
        if v >= n {
            return Err(DbError::Index { table: tid(t), record: rid(k) });
        }
        if k > 0 && v <= prev {
            return Err(DbError::Order);
        }
        prev = v;
        k += 1;
    }
    Ok(())
}

/// Checks that the enabled set is closed (V8), marking its members in `mark`.
#[allow(clippy::too_many_lines)]  // three nested walks over the tiling, with their invariants
fn check_closure(b: &[u8], mark: &mut [u32]) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        tiled(b@),
        forall|x: int| 0 <= x < tcnt(b@, T_EDGES as int) ==> #[trigger] edge_index_ok(b@, x),
        forall|k: int|
            0 <= k < tcnt(b@, T_ENABLED as int) ==> #[trigger] list_index_ok(b@, T_ENABLED, k),
        old(mark)@.len() == nodes(b@),
    ensures
        r is Ok ==> forall|k: int|
            0 <= k < tcnt(b@, T_ENABLED as int) ==> #[trigger] node_closed(
                b@,
                lf(b@, T_ENABLED, k),
            ),
{
    let n = header_word(b, 5 + 2 * T_NODES) as usize;
    let count = header_word(b, 5 + 2 * T_ENABLED) as usize;
    let ghost gcnt = tcnt(b@, T_GROUPS as int);
    let ghost ecnt = tcnt(b@, T_EDGES as int);
    let mut v: usize = 0;
    while v < n
        invariant
            n == nodes(b@),
            mark@.len() == n,
            v <= n,
            forall|j: int| 0 <= j < v ==> #[trigger] mark@[j] == 0,
        decreases n - v,
    {
        mark[v] = 0;
        v += 1;
    }
    let mut k: usize = 0;
    while k < count
        invariant
            v1(b@),
            forall|j: int|
                0 <= j < tcnt(b@, T_ENABLED as int) ==> #[trigger] list_index_ok(b@, T_ENABLED, j),
            n == nodes(b@),
            count == tcnt(b@, T_ENABLED as int),
            mark@.len() == n,
            k <= count,
            forall|j: int| 0 <= j < n && #[trigger] mark@[j] != 0 ==> enabled_has(b@, j),
        decreases count - k,
    {
        let e = field(b, T_ENABLED, k, 0) as usize;
        assert(list_index_ok(b@, T_ENABLED, k as int));
        assert(lf(b@, T_ENABLED, k as int) == e);
        mark[e] = 1;
        k += 1;
    }
    let mut k: usize = 0;
    while k < count
        invariant
            v1(b@),
            tiled(b@),
            forall|x: int| 0 <= x < ecnt ==> #[trigger] edge_index_ok(b@, x),
            forall|j: int|
                0 <= j < tcnt(b@, T_ENABLED as int) ==> #[trigger] list_index_ok(b@, T_ENABLED, j),
            gcnt == tcnt(b@, T_GROUPS as int),
            ecnt == tcnt(b@, T_EDGES as int),
            n == nodes(b@),
            count == tcnt(b@, T_ENABLED as int),
            mark@.len() == n,
            k <= count,
            forall|j: int| 0 <= j < n && #[trigger] mark@[j] != 0 ==> enabled_has(b@, j),
            forall|j: int| 0 <= j < k ==> #[trigger] node_closed(b@, lf(b@, T_ENABLED, j)),
        decreases count - k,
    {
        let e = field(b, T_ENABLED, k, 0) as usize;
        assert(list_index_ok(b@, T_ENABLED, k as int));
        assert(node_tile_ok(b@, e as int));
        let gfirst = field(b, T_NODES, e, N_GROUP_FIRST) as usize;
        let gcount = field(b, T_NODES, e, N_GROUP_COUNT) as usize;
        proof {
            super::graph::lemma_ngsum_mono(b@, e + 1, n as int);
        }
        let mut gi: usize = 0;
        while gi < gcount
            invariant
                v1(b@),
                tiled(b@),
                forall|x: int| 0 <= x < ecnt ==> #[trigger] edge_index_ok(b@, x),
                gcnt == tcnt(b@, T_GROUPS as int),
                ecnt == tcnt(b@, T_EDGES as int),
                n == nodes(b@),
                mark@.len() == n,
                forall|j: int| 0 <= j < n && #[trigger] mark@[j] != 0 ==> enabled_has(b@, j),
                gfirst == nf(b@, e as int, N_GROUP_FIRST),
                gcount == nf(b@, e as int, N_GROUP_COUNT),
                gfirst + gcount <= gcnt,
                gi <= gcount,
                forall|g: int| gfirst <= g < gfirst + gi ==> #[trigger] group_closed(b@, g),
            decreases gcount - gi,
        {
            let g = gfirst + gi;
            if field(b, T_GROUPS, g, G_KIND) <= 1 {
                assert(group_tile_ok(b@, g as int));
                let efirst = field(b, T_GROUPS, g, G_EDGE_FIRST) as usize;
                let ecount = field(b, T_GROUPS, g, G_EDGE_COUNT) as usize;
                proof {
                    super::graph::lemma_gesum_mono(b@, g + 1, gcnt);
                }
                let mut xi: usize = 0;
                while xi < ecount
                    invariant
                        v1(b@),
                        forall|x: int| 0 <= x < ecnt ==> #[trigger] edge_index_ok(b@, x),
                        ecnt == tcnt(b@, T_EDGES as int),
                        n == nodes(b@),
                        mark@.len() == n,
                        forall|j: int|
                            0 <= j < n && #[trigger] mark@[j] != 0 ==> enabled_has(b@, j),
                        efirst + ecount <= ecnt,
                        xi <= ecount,
                        forall|x: int| efirst <= x < efirst + xi ==> #[trigger] edge_closed(b@, x),
                    decreases ecount - xi,
                {
                    let x = efirst + xi;
                    if field(b, T_EDGES, x, E_TARGET_KIND) == 0 {
                        assert(edge_index_ok(b@, x as int));
                        let to = field(b, T_EDGES, x, E_TARGET) as usize;
                        if mark[to] == 0 {
                            return Err(DbError::Closure);
                        }
                    }
                    xi += 1;
                }
            }
            gi += 1;
        }
        k += 1;
    }
    Ok(())
}

/// Checks both lists and the closure of the enabled set (V8, and the list part of V3).
pub(crate) fn check_lists(b: &[u8], mark: &mut [u32]) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        tiled(b@),
        forall|x: int| 0 <= x < tcnt(b@, T_EDGES as int) ==> #[trigger] edge_index_ok(b@, x),
        old(mark)@.len() == nodes(b@),
    ensures
        r is Ok ==> {
            &&& forall|k: int|
                0 <= k < tcnt(b@, T_ENABLED as int) ==> #[trigger] list_index_ok(b@, T_ENABLED, k)
            &&& forall|k: int|
                0 <= k < tcnt(b@, T_PRESYSLOG as int) ==> #[trigger] list_index_ok(
                    b@,
                    T_PRESYSLOG,
                    k,
                )
            &&& v8(b@)
        },
{
    check_list(b, T_ENABLED)?;
    check_list(b, T_PRESYSLOG)?;
    check_closure(b, mark)
}

} // verus!
