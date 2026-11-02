// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The validator's obligations V1-V8 as spec functions over the database bytes.

#[allow(unused_imports, clippy::wildcard_imports)]
// spec-only items: Verus erases them outside verification
use crate::layout::*;
#[allow(unused_imports)] // spec-only use: Verus erases it outside verification
use qinit_graph_core::GEdge;
use vstd::prelude::*;

verus! {

/// Word `i` of `b` as an integer.
pub open spec fn hw(b: Seq<u8>, i: int) -> int {
    spec_word(b, i) as int
}

/// Byte offset of table `t`.
pub open spec fn toff(b: Seq<u8>, t: int) -> int {
    hw(b, spec_offset_word(t))
}

/// Record count of table `t` (the pool: its length in bytes).
pub open spec fn tcnt(b: Seq<u8>, t: int) -> int {
    hw(b, spec_count_word(t))
}

/// Words per record of table `t` (`WORDS`).
pub open spec fn spec_words(t: int) -> int {
    if t == 0 {
        20
    } else if t == 1 {
        3
    } else if t == 2 {
        7
    } else if t == 3 {
        10
    } else if t == 4 {
        3
    } else {
        1
    }
}

/// Record limit of table `t` (the pool: its byte limit).
pub open spec fn spec_limit(t: int) -> int {
    if t == 0 {
        MAX_NODES as int
    } else if t == 1 {
        MAX_GROUPS as int
    } else if t == 2 {
        MAX_EDGES as int
    } else if t == 3 {
        MAX_CREDS as int
    } else if t == 4 {
        MAX_ROUTES as int
    } else if t == 5 || t == 6 {
        MAX_NODES as int
    } else {
        MAX_POOL as int
    }
}

/// Bytes table `t` occupies.
pub open spec fn tlen(b: Seq<u8>, t: int) -> int {
    if t == 7 {
        tcnt(b, t)
    } else {
        tcnt(b, t) * spec_words(t) * 4
    }
}

/// Where table `t` may start at the earliest: after the header or after the table before it.
pub open spec fn tmin(b: Seq<u8>, t: int) -> int {
    if t == 0 {
        4 * HEADER_WORDS as int
    } else {
        toff(b, t - 1) + tlen(b, t - 1)
    }
}

/// V1 for the header: long enough, magic, version, and the total length is the buffer's.
pub open spec fn header_ok(b: Seq<u8>) -> bool {
    &&& b.len() >= 4 * HEADER_WORDS
    &&& hw(b, H_MAGIC as int) == MAGIC as int
    &&& hw(b, H_VERSION as int) == VERSION as int
    &&& hw(b, H_TOTAL_LEN as int) == b.len()
}

/// V1 for table `t`: within its limit, inside the buffer, word-aligned (the pool excepted), and
/// after the table before it.
pub open spec fn table_ok(b: Seq<u8>, t: int) -> bool {
    &&& tcnt(b, t) <= spec_limit(t)
    &&& toff(b, t) + tlen(b, t) <= b.len()
    &&& (t < 7 ==> toff(b, t) % 4 == 0)
    &&& toff(b, t) >= tmin(b, t)
}

/// V1: the header and all eight tables.
pub open spec fn v1(b: Seq<u8>) -> bool {
    &&& header_ok(b)
    &&& forall|t: int| 0 <= t < 8 ==> #[trigger] table_ok(b, t)
}

/// Word index of word `w` of record `r` in table `t`.
pub open spec fn widx(b: Seq<u8>, t: int, r: int, w: int) -> int {
    toff(b, t) / 4 + r * spec_words(t) + w
}

/// Word `w` of record `r` in table `t`.
pub open spec fn rw(b: Seq<u8>, t: int, r: int, w: int) -> int {
    hw(b, widx(b, t, r, w))
}

/// Node `i`, word `w`.
pub open spec fn nf(b: Seq<u8>, i: int, w: usize) -> int {
    rw(b, T_NODES as int, i, w as int)
}

/// Group `g`, word `w`.
pub open spec fn gf(b: Seq<u8>, g: int, w: usize) -> int {
    rw(b, T_GROUPS as int, g, w as int)
}

/// Edge `x`, word `w`.
pub open spec fn ef(b: Seq<u8>, x: int, w: usize) -> int {
    rw(b, T_EDGES as int, x, w as int)
}

/// Credential `c`, word `w`.
pub open spec fn cf(b: Seq<u8>, c: int, w: usize) -> int {
    rw(b, T_CREDS as int, c, w as int)
}

/// Route `r`, word `w`.
pub open spec fn rf(b: Seq<u8>, r: int, w: usize) -> int {
    rw(b, T_ROUTES as int, r, w as int)
}

/// Entry `k` of list table `t` (enabled or pre-syslog).
pub open spec fn lf(b: Seq<u8>, t: usize, k: int) -> int {
    rw(b, t as int, k, 0)
}

/// Nodes.
pub open spec fn nodes(b: Seq<u8>) -> int {
    tcnt(b, T_NODES as int)
}

/// The pool bytes `off..off + len`.
pub open spec fn pool_slice(b: Seq<u8>, off: int, len: int) -> Seq<u8> {
    b.subrange(toff(b, T_POOL as int) + off, toff(b, T_POOL as int) + off + len)
}

/// V2 for one reference: inside the pool and valid UTF-8.
pub open spec fn pool_ref(b: Seq<u8>, off: int, len: int) -> bool {
    &&& 0 <= off
    &&& 0 <= len
    &&& off + len <= tcnt(b, T_POOL as int)
    &&& vstd::utf8::valid_utf8(pool_slice(b, off, len))
}

/// V2 for a name: a pool reference, non-empty and at most `MAX_NAME_LEN` bytes.
pub open spec fn name_ref(b: Seq<u8>, off: int, len: int) -> bool {
    &&& pool_ref(b, off, len)
    &&& 0 < len <= MAX_NAME_LEN
}

pub open spec fn node_pool_ok(b: Seq<u8>, i: int) -> bool {
    &&& name_ref(b, nf(b, i, N_NAME_OFF), nf(b, i, N_NAME_LEN))
    &&& pool_ref(b, nf(b, i, N_EXEC_OFF), nf(b, i, N_EXEC_LEN))
    &&& pool_ref(b, nf(b, i, N_READY_OFF), nf(b, i, N_READY_LEN))
    &&& pool_ref(b, nf(b, i, N_INSTANCE_OF_OFF), nf(b, i, N_INSTANCE_OF_LEN))
}

pub open spec fn edge_pool_ok(b: Seq<u8>, x: int) -> bool {
    ef(b, x, E_TARGET_KIND) == 1 ==> pool_ref(b, ef(b, x, E_TARGET), ef(b, x, E_TARGET_LEN))
}

pub open spec fn cred_pool_ok(b: Seq<u8>, c: int) -> bool {
    &&& pool_ref(b, cf(b, c, C_USER_OFF), cf(b, c, C_USER_LEN))
    &&& pool_ref(b, cf(b, c, C_LANDLOCK_OFF), cf(b, c, C_LANDLOCK_LEN))
}

pub open spec fn route_pool_ok(b: Seq<u8>, r: int) -> bool {
    rf(b, r, R_KIND) == 0 ==> pool_ref(b, rf(b, r, R_A), rf(b, r, R_B))
}

/// V2: every pool reference of every record.
pub open spec fn v2(b: Seq<u8>) -> bool {
    &&& forall|i: int| 0 <= i < nodes(b) ==> #[trigger] node_pool_ok(b, i)
    &&& forall|x: int| 0 <= x < tcnt(b, T_EDGES as int) ==> #[trigger] edge_pool_ok(b, x)
    &&& forall|c: int| 0 <= c < tcnt(b, T_CREDS as int) ==> #[trigger] cred_pool_ok(b, c)
    &&& forall|r: int| 0 <= r < tcnt(b, T_ROUTES as int) ==> #[trigger] route_pool_ok(b, r)
}

/// `NONE` or an index below `n`.
pub open spec fn index_or_none(v: int, n: int) -> bool {
    v == NONE as int || v < n
}

pub open spec fn node_index_ok(b: Seq<u8>, i: int) -> bool {
    &&& index_or_none(nf(b, i, N_OUTPUT), tcnt(b, T_ROUTES as int))
    &&& index_or_none(nf(b, i, N_ERRORS), tcnt(b, T_ROUTES as int))
    &&& index_or_none(nf(b, i, N_CRED), tcnt(b, T_CREDS as int))
}

pub open spec fn edge_index_ok(b: Seq<u8>, x: int) -> bool {
    ef(b, x, E_TARGET_KIND) == 0 ==> ef(b, x, E_TARGET) < nodes(b)
}

pub open spec fn route_index_ok(b: Seq<u8>, r: int) -> bool {
    rf(b, r, R_KIND) == 1 ==> rf(b, r, R_A) < nodes(b)
}

pub open spec fn list_index_ok(b: Seq<u8>, t: usize, k: int) -> bool {
    lf(b, t, k) < nodes(b)
}

/// The groups before node `i`: where node `i`'s groups start when the table is tiled.
pub open spec fn ngsum(b: Seq<u8>, i: int) -> int
    decreases i,
{
    if i <= 0 {
        0
    } else {
        ngsum(b, i - 1) + nf(b, i - 1, N_GROUP_COUNT)
    }
}

/// The edges before group `g`.
pub open spec fn gesum(b: Seq<u8>, g: int) -> int
    decreases g,
{
    if g <= 0 {
        0
    } else {
        gesum(b, g - 1) + gf(b, g - 1, G_EDGE_COUNT)
    }
}

/// Node `i`'s groups start at the running sum (Q3), and there are few enough.
pub open spec fn node_tile_ok(b: Seq<u8>, i: int) -> bool {
    &&& nf(b, i, N_GROUP_FIRST) == ngsum(b, i)
    &&& nf(b, i, N_GROUP_COUNT) <= MAX_GROUPS_PER_NODE
}

/// Group `g`'s edges start at the running sum (Q3), and there are few enough.
pub open spec fn group_tile_ok(b: Seq<u8>, g: int) -> bool {
    &&& gf(b, g, G_EDGE_FIRST) == gesum(b, g)
    &&& gf(b, g, G_EDGE_COUNT) <= MAX_EDGES_PER_GROUP
}

/// The nodes tile the group table and the groups tile the edge table.
pub open spec fn tiled(b: Seq<u8>) -> bool {
    &&& forall|i: int| 0 <= i < nodes(b) ==> #[trigger] node_tile_ok(b, i)
    &&& ngsum(b, nodes(b)) == tcnt(b, T_GROUPS as int)
    &&& forall|g: int| 0 <= g < tcnt(b, T_GROUPS as int) ==> #[trigger] group_tile_ok(b, g)
    &&& gesum(b, tcnt(b, T_GROUPS as int)) == tcnt(b, T_EDGES as int)
}

/// V3: every cross-table index is `NONE` (where allowed) or in range, and the group and edge
/// runs tile their tables.
pub open spec fn v3(b: Seq<u8>) -> bool {
    &&& forall|i: int| 0 <= i < nodes(b) ==> #[trigger] node_index_ok(b, i)
    &&& forall|x: int| 0 <= x < tcnt(b, T_EDGES as int) ==> #[trigger] edge_index_ok(b, x)
    &&& forall|r: int| 0 <= r < tcnt(b, T_ROUTES as int) ==> #[trigger] route_index_ok(b, r)
    &&& forall|k: int|
        0 <= k < tcnt(b, T_ENABLED as int) ==> #[trigger] list_index_ok(b, T_ENABLED, k)
    &&& forall|k: int|
        0 <= k < tcnt(b, T_PRESYSLOG as int) ==> #[trigger] list_index_ok(b, T_PRESYSLOG, k)
    &&& tiled(b)
}

pub open spec fn node_enum_ok(b: Seq<u8>, i: int) -> bool {
    &&& nf(b, i, N_KIND) <= 2
    &&& nf(b, i, N_READY_KIND) <= 3
    &&& nf(b, i, N_RESTART_POLICY) <= 2
    &&& (nf(b, i, N_KIND) != 0 ==> nf(b, i, N_RESTART_POLICY) == 0)
    &&& (nf(b, i, N_KIND) == 2 ==> nf(b, i, N_EXEC_LEN) == 0)
}

pub open spec fn group_enum_ok(b: Seq<u8>, g: int) -> bool {
    gf(b, g, G_KIND) <= 3
}

pub open spec fn edge_enum_ok(b: Seq<u8>, x: int) -> bool {
    &&& ef(b, x, E_TARGET_KIND) <= 1
    &&& ef(b, x, E_MODE) <= 1
    &&& ef(b, x, E_RESTART_ON) <= 3
    &&& ef(b, x, E_FLAGS) <= 1
    &&& (ef(b, x, E_TARGET_KIND) == 0 ==> ef(b, x, E_TARGET_LEN) == 0)
    &&& (ef(b, x, E_MODE) == 0 ==> ef(b, x, E_DEADLINE_MS) == 0)
}

pub open spec fn cred_enum_ok(b: Seq<u8>, c: int) -> bool {
    &&& cf(b, c, C_CAPS_HI) <= 0x1ff
    &&& cf(b, c, C_SECUREBITS) <= 2
    &&& cf(b, c, C_NNP) <= 1
    &&& cf(b, c, C_NS) <= 0x1f
    &&& cf(b, c, C_SECCOMP) <= 1
}

pub open spec fn route_enum_ok(b: Seq<u8>, r: int) -> bool {
    &&& rf(b, r, R_KIND) <= 1
    &&& (rf(b, r, R_KIND) == 1 ==> nf(b, rf(b, r, R_A), N_KIND) == 0 && rf(b, r, R_B) == 0)
}

/// `a` sorts strictly before `c`, bytewise.
pub open spec fn lex_lt(a: Seq<u8>, c: Seq<u8>) -> bool {
    exists|k: int|
        #![trigger a.subrange(0, k)]
        0 <= k <= a.len() && k <= c.len() && a.subrange(0, k) == c.subrange(0, k) && ((k == a.len()
            && k < c.len()) || (k < a.len() && k < c.len() && a[k] < c[k]))
}

/// Node `i`'s name.
pub open spec fn name(b: Seq<u8>, i: int) -> Seq<u8> {
    pool_slice(b, nf(b, i, N_NAME_OFF), nf(b, i, N_NAME_LEN))
}

/// Node `i`'s name sorts after node `i - 1`'s.
pub open spec fn name_sorted(b: Seq<u8>, i: int) -> bool {
    lex_lt(name(b, i - 1), name(b, i))
}

/// V4: enums in range, reserved bits clear, the kind-dependent fields consistent, and the
/// nodes sorted by name.
pub open spec fn v4(b: Seq<u8>) -> bool {
    &&& forall|i: int| 0 <= i < nodes(b) ==> #[trigger] node_enum_ok(b, i)
    &&& forall|g: int| 0 <= g < tcnt(b, T_GROUPS as int) ==> #[trigger] group_enum_ok(b, g)
    &&& forall|x: int| 0 <= x < tcnt(b, T_EDGES as int) ==> #[trigger] edge_enum_ok(b, x)
    &&& forall|c: int| 0 <= c < tcnt(b, T_CREDS as int) ==> #[trigger] cred_enum_ok(b, c)
    &&& forall|r: int| 0 <= r < tcnt(b, T_ROUTES as int) ==> #[trigger] route_enum_ok(b, r)
    &&& forall|i: int| 0 < i < nodes(b) ==> #[trigger] name_sorted(b, i)
}

/// Edge `x` of group `g` orders (Q2): a node target in a `require_all`, `require_any` or
/// `optional_all` group.
pub open spec fn is_ordering(b: Seq<u8>, g: int, x: int) -> bool {
    ef(b, x, E_TARGET_KIND) == 0 && gf(b, g, G_KIND) <= 2
}

/// The graph edge for edge `x` of group `g` of node `i` (Q2).
pub open spec fn ord_edge(b: Seq<u8>, i: int, g: int, x: int) -> GEdge {
    GEdge {
        from: i as u32,
        to: ef(b, x, E_TARGET) as u32,
        hard: gf(b, g, G_KIND) <= 1 && ef(b, x, E_MODE) == 0,
        parallel: ef(b, x, E_FLAGS) == 1,
    }
}

/// The ordering edges among the first `m` edges of group `g`, owned by node `i`.
pub open spec fn oe_group(b: Seq<u8>, i: int, g: int, m: int) -> Seq<GEdge>
    decreases m,
{
    if m <= 0 {
        Seq::empty()
    } else {
        let x = gf(b, g, G_EDGE_FIRST) + m - 1;
        if is_ordering(b, g, x) {
            oe_group(b, i, g, m - 1).push(ord_edge(b, i, g, x))
        } else {
            oe_group(b, i, g, m - 1)
        }
    }
}

/// The ordering edges of the first `m` groups of node `i`.
pub open spec fn oe_node(b: Seq<u8>, i: int, m: int) -> Seq<GEdge>
    decreases m,
{
    if m <= 0 {
        Seq::empty()
    } else {
        let g = nf(b, i, N_GROUP_FIRST) + m - 1;
        oe_node(b, i, m - 1) + oe_group(b, i, g, gf(b, g, G_EDGE_COUNT))
    }
}

/// The ordering edges of the first `m` nodes.
pub open spec fn oe(b: Seq<u8>, m: int) -> Seq<GEdge>
    decreases m,
{
    if m <= 0 {
        Seq::empty()
    } else {
        oe(b, m - 1) + oe_node(b, m - 1, nf(b, m - 1, N_GROUP_COUNT))
    }
}

/// The ordering-edge graph, in table order.
pub open spec fn ordering_edges(b: Seq<u8>) -> Seq<GEdge> {
    oe(b, nodes(b))
}

/// V5: the ordering-edge graph fits the graph core and is acyclic: some labelling sends every
/// ordering edge strictly up (`qinit_graph_core::labellable`, complete by G1).
pub open spec fn v5(b: Seq<u8>) -> bool {
    &&& ordering_edges(b).len() <= MAX_EDGES
    &&& qinit_graph_core::edges_in_range(nodes(b), ordering_edges(b))
    &&& qinit_graph_core::labellable(nodes(b), ordering_edges(b), false)
}

/// V6: the stop order exists: a labelling sends every edge but the parallel ones strictly up,
/// so with V7 every hard dependent stops before its dependency.
pub open spec fn v6(b: Seq<u8>) -> bool {
    qinit_graph_core::labellable(nodes(b), ordering_edges(b), true)
}

/// V7: no hard ordering edge carries `stop = "parallel"`.
pub open spec fn v7(b: Seq<u8>) -> bool {
    qinit_graph_core::no_hard_parallel(ordering_edges(b))
}

/// List table `t` is ascending and free of duplicates at entry `k`.
pub open spec fn list_sorted(b: Seq<u8>, t: usize, k: int) -> bool {
    lf(b, t, k - 1) < lf(b, t, k)
}

/// Node `v` is in the enabled closure.
pub open spec fn enabled_has(b: Seq<u8>, v: int) -> bool {
    exists|k: int| 0 <= k < tcnt(b, T_ENABLED as int) && #[trigger] lf(b, T_ENABLED, k) == v
}

pub open spec fn edge_closed(b: Seq<u8>, x: int) -> bool {
    ef(b, x, E_TARGET_KIND) == 0 ==> enabled_has(b, ef(b, x, E_TARGET))
}

pub open spec fn group_closed(b: Seq<u8>, g: int) -> bool {
    gf(b, g, G_KIND) <= 1 ==> forall|x: int|
        gf(b, g, G_EDGE_FIRST) <= x < gf(b, g, G_EDGE_FIRST) + gf(b, g, G_EDGE_COUNT)
            ==> #[trigger] edge_closed(b, x)
}

pub open spec fn node_closed(b: Seq<u8>, i: int) -> bool {
    forall|g: int|
        nf(b, i, N_GROUP_FIRST) <= g < nf(b, i, N_GROUP_FIRST) + nf(b, i, N_GROUP_COUNT)
            ==> #[trigger] group_closed(b, g)
}

/// V8: both lists ascending and free of duplicates, and the enabled set closed under the
/// `require_all` and `require_any` node targets of its members.
pub open spec fn v8(b: Seq<u8>) -> bool {
    &&& forall|k: int| 0 < k < tcnt(b, T_ENABLED as int) ==> #[trigger] list_sorted(b, T_ENABLED, k)
    &&& forall|k: int|
        0 < k < tcnt(b, T_PRESYSLOG as int) ==> #[trigger] list_sorted(b, T_PRESYSLOG, k)
    &&& forall|k: int|
        0 <= k < tcnt(b, T_ENABLED as int) ==> #[trigger] node_closed(b, lf(b, T_ENABLED, k))
}

/// A database the validator accepts: V1-V8.
pub open spec fn well_formed(b: Seq<u8>) -> bool {
    &&& v1(b)
    &&& v2(b)
    &&& v3(b)
    &&& v4(b)
    &&& v5(b)
    &&& v6(b)
    &&& v7(b)
    &&& v8(b)
}

} // verus!
