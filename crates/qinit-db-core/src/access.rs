// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! In-place accessors over a database that passed [`validate`](crate::validate): each reads one
//! word, count or name and is proved in bounds from `well_formed` (V9 made executable), so a
//! reader (colony) never copies the database and never needs a run-time check.

#[allow(clippy::wildcard_imports)] // the layout constants, used throughout
use crate::layout::*;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use crate::validate::*;
use vstd::prelude::*;

verus! {

/// Header count of table `t`.
fn count(b: &[u8], t: usize) -> (n: usize)
    requires
        well_formed(b@),
        t < 8,
    ensures
        n as int == tcnt(b@, t as int),
{
    header_word(b, 5 + 2 * t) as usize
}

/// The number of nodes.
#[must_use]
pub fn node_count(b: &[u8]) -> (n: usize)
    requires
        well_formed(b@),
    ensures
        n as int == nodes(b@),
{
    count(b, T_NODES)
}

/// Word `w` of node `i`.
#[must_use]
pub fn node_word(b: &[u8], i: usize, w: usize) -> (v: u32)
    requires
        well_formed(b@),
        i < nodes(b@),
        w < 24,
    ensures
        v as int == nf(b@, i as int, w),
{
    field(b, T_NODES, i, w)
}

/// Word `w` of group `g`.
#[must_use]
pub fn group_word(b: &[u8], g: usize, w: usize) -> (v: u32)
    requires
        well_formed(b@),
        g < tcnt(b@, T_GROUPS as int),
        w < 3,
    ensures
        v as int == gf(b@, g as int, w),
{
    field(b, T_GROUPS, g, w)
}

/// Word `w` of edge `x`.
#[must_use]
pub fn edge_word(b: &[u8], x: usize, w: usize) -> (v: u32)
    requires
        well_formed(b@),
        x < tcnt(b@, T_EDGES as int),
        w < 7,
    ensures
        v as int == ef(b@, x as int, w),
{
    field(b, T_EDGES, x, w)
}

/// The number of edges.
#[must_use]
pub fn edge_count(b: &[u8]) -> (n: usize)
    requires
        well_formed(b@),
    ensures
        n as int == tcnt(b@, T_EDGES as int),
{
    count(b, T_EDGES)
}

/// The number of entries of the enabled list.
#[must_use]
pub fn enabled_count(b: &[u8]) -> (n: usize)
    requires
        well_formed(b@),
    ensures
        n as int == tcnt(b@, T_ENABLED as int),
{
    count(b, T_ENABLED)
}

/// Entry `k` of the enabled list, a node index.
#[must_use]
pub fn enabled(b: &[u8], k: usize) -> (v: u32)
    requires
        well_formed(b@),
        k < tcnt(b@, T_ENABLED as int),
    ensures
        v as int == lf(b@, T_ENABLED, k as int),
{
    field(b, T_ENABLED, k, 0)
}

/// The name of node `i`.
#[must_use]
pub fn node_name(b: &[u8], i: usize) -> (s: &[u8])
    requires
        well_formed(b@),
        i < nodes(b@),
    ensures
        s@ == name(b@, i as int),
{
    proof {
        assert(table_ok(b@, T_POOL as int));
        assert(node_pool_ok(b@, i as int));
    }
    let off = node_word(b, i, N_NAME_OFF) as usize;
    let len = node_word(b, i, N_NAME_LEN) as usize;
    let base = header_word(b, 4 + 2 * T_POOL) as usize;
    vstd::slice::slice_subrange(b, base + off, base + off + len)
}

} // verus!
