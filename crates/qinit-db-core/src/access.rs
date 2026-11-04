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
        t <= T_POOL,
    ensures
        n as int == tcnt(b@, t as int),
{
    header_word(b, 5 + 2 * t) as usize
}

/// The number of policy rules.
#[must_use]
pub fn policy_rule_count(b: &[u8]) -> (n: usize)
    requires
        well_formed(b@),
    ensures
        n as int == tcnt(b@, T_POLICY as int),
{
    count(b, T_POLICY)
}

/// The number of policy header records: 0 or 1.
#[must_use]
pub fn policy_head_count(b: &[u8]) -> (n: usize)
    requires
        well_formed(b@),
    ensures
        n as int == tcnt(b@, T_POLICY_HEAD as int),
{
    count(b, T_POLICY_HEAD)
}

/// Word `w` of policy rule `p`.
#[must_use]
pub fn policy_word(b: &[u8], p: usize, w: usize) -> (v: u32)
    requires
        well_formed(b@),
        p < tcnt(b@, T_POLICY as int),
        w < spec_words(T_POLICY as int),
    ensures
        v as int == pf(b@, p as int, w),
{
    field(b, T_POLICY, p, w)
}

/// Word `w` of the policy header record.
#[must_use]
pub fn policy_head_word(b: &[u8], w: usize) -> (v: u32)
    requires
        well_formed(b@),
        0 < tcnt(b@, T_POLICY_HEAD as int),
        w < spec_words(T_POLICY_HEAD as int),
    ensures
        v as int == hf(b@, 0, w),
{
    field(b, T_POLICY_HEAD, 0, w)
}

/// The pattern of policy rule `p`.
#[must_use]
pub fn policy_pattern(b: &[u8], p: usize) -> (s: &[u8])
    requires
        well_formed(b@),
        p < tcnt(b@, T_POLICY as int),
    ensures
        s@ == pool_slice(b@, pf(b@, p as int, P_PATTERN_OFF), pf(b@, p as int, P_PATTERN_LEN)),
{
    assert(policy_pool_ok(b@, p as int));
    pool_bytes(b, field(b, T_POLICY, p, P_PATTERN_OFF), field(b, T_POLICY, p, P_PATTERN_LEN))
}

/// The NUL-separated users of policy rule `p`.
#[must_use]
pub fn policy_users(b: &[u8], p: usize) -> (s: &[u8])
    requires
        well_formed(b@),
        p < tcnt(b@, T_POLICY as int),
    ensures
        s@ == pool_slice(b@, pf(b@, p as int, P_USERS_OFF), pf(b@, p as int, P_USERS_LEN)),
{
    assert(policy_pool_ok(b@, p as int));
    pool_bytes(b, field(b, T_POLICY, p, P_USERS_OFF), field(b, T_POLICY, p, P_USERS_LEN))
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
        w < spec_words(T_NODES as int),
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
        w < spec_words(T_GROUPS as int),
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
        w < spec_words(T_EDGES as int),
    ensures
        v as int == ef(b@, x as int, w),
{
    field(b, T_EDGES, x, w)
}

/// The number of credential records.
#[must_use]
pub fn cred_count(b: &[u8]) -> (n: usize)
    requires
        well_formed(b@),
    ensures
        n as int == tcnt(b@, T_CREDS as int),
{
    count(b, T_CREDS)
}

/// Word `w` of credential `c`.
#[must_use]
pub fn cred_word(b: &[u8], c: usize, w: usize) -> (v: u32)
    requires
        well_formed(b@),
        c < tcnt(b@, T_CREDS as int),
        w < spec_words(T_CREDS as int),
    ensures
        v as int == cf(b@, c as int, w),
{
    field(b, T_CREDS, c, w)
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
