// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! V5-V7: the ordering-edge graph and its labellings.
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only use: Verus erases it
use super::tables::*;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use crate::layout::*;
#[allow(unused_imports)] // spec-only use: Verus erases it outside verification
use qinit_graph_core::GEdge;
use vstd::prelude::*;

verus! {

/// Edge `x` of group `g` orders: a node target in a `require_all`, `require_any` or
/// `optional_all` group.
pub open spec fn is_ordering(b: Seq<u8>, g: int, x: int) -> bool {
    ef(b, x, E_TARGET_KIND) == 0 && gf(b, g, G_KIND) <= 2
}

/// The graph edge for edge `x` of group `g` of node `i`.
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

} // verus!
