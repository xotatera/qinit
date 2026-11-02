// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! V5-V7: the ordering edges go through `qinit_graph_core::levels`, once for the start
//! order (every ordering edge) and once for the stop order (parallel edges skipped).

#![allow(clippy::many_single_char_names)] // `b`, `n`, `i`, `g`, `x`, `k` follow the spec names

use super::header::{field, header_word};
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use super::spec::*;
use super::{DbError, rid, tid};
#[allow(clippy::wildcard_imports)] // the layout constants, used throughout
use crate::layout::*;
use qinit_graph_core::{GEdge, GraphError};
use vstd::prelude::*;

verus! {

/// Group counts are non-negative, so the running group sum only grows.
pub proof fn lemma_ngsum_mono(b: Seq<u8>, i: int, j: int)
    requires
        0 <= i <= j,
    ensures
        ngsum(b, i) <= ngsum(b, j),
    decreases j - i,
{
    if i < j {
        lemma_ngsum_mono(b, i, j - 1);
    }
}

/// Edge counts are non-negative, so the running edge sum only grows.
pub proof fn lemma_gesum_mono(b: Seq<u8>, g: int, h: int)
    requires
        0 <= g <= h,
    ensures
        gesum(b, g) <= gesum(b, h),
    decreases h - g,
{
    if g < h {
        lemma_gesum_mono(b, g, h - 1);
    }
}

/// Levels that send every constraining edge up witness that a labelling exists.
proof fn lemma_labellable(n: int, edges: Seq<GEdge>, out: Seq<u32>, honour: bool)
    requires
        out.len() == n,
        qinit_graph_core::edges_in_range(n, edges),
        qinit_graph_core::labelled(out, edges, honour),
    ensures
        qinit_graph_core::labellable(n, edges, honour),
{
    let w = Seq::new(n as nat, |j: int| out[j] as int);
    assert forall|i: int| #![trigger edges[i]] 0 <= i < edges.len() implies ((honour
        && edges[i].parallel) || w[edges[i].from as int] < w[edges[i].to as int]) by {}
    assert(qinit_graph_core::labelling(n, edges, honour, w));
}

/// Builds the ordering edges into `edges` and checks both orders (V5, V6, V7).
#[allow(clippy::too_many_lines)]  // three nested walks over the tiling, with their invariants
pub(crate) fn check_graph(b: &[u8], edges: &mut [GEdge], lv: &mut [u32]) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        tiled(b@),
        forall|x: int| 0 <= x < tcnt(b@, T_EDGES as int) ==> #[trigger] edge_index_ok(b@, x),
        old(edges)@.len() >= MAX_EDGES,
        old(lv)@.len() == nodes(b@),
    ensures
        final(lv)@.len() == old(lv)@.len(),
        r is Ok ==> v5(b@) && v6(b@) && v7(b@),
{
    let n = header_word(b, 5 + 2 * T_NODES) as usize;
    let ghost gcnt = tcnt(b@, T_GROUPS as int);
    let ghost ecnt = tcnt(b@, T_EDGES as int);
    let ghost cap = edges@.len();
    assert(table_ok(b@, T_NODES as int));
    assert(table_ok(b@, T_EDGES as int));
    let mut k: usize = 0;
    let mut i: usize = 0;
    while i < n
        invariant
            v1(b@),
            tiled(b@),
            forall|x: int| 0 <= x < ecnt ==> #[trigger] edge_index_ok(b@, x),
            gcnt == tcnt(b@, T_GROUPS as int),
            ecnt == tcnt(b@, T_EDGES as int),
            ecnt <= MAX_EDGES,
            n == nodes(b@),
            n <= MAX_NODES,
            i <= n,
            edges@.len() == cap,
            cap >= MAX_EDGES,
            lv@.len() == n,
            k <= gesum(b@, ngsum(b@, i as int)),
            edges@.subrange(0, k as int) == oe(b@, i as int),
        decreases n - i,
    {
        assert(node_tile_ok(b@, i as int));
        let gfirst = field(b, T_NODES, i, N_GROUP_FIRST) as usize;
        let gcount = field(b, T_NODES, i, N_GROUP_COUNT) as usize;
        proof {
            lemma_ngsum_mono(b@, i + 1, n as int);
        }
        let mut gi: usize = 0;
        while gi < gcount
            invariant
                v1(b@),
                tiled(b@),
                forall|x: int| 0 <= x < ecnt ==> #[trigger] edge_index_ok(b@, x),
                gcnt == tcnt(b@, T_GROUPS as int),
                ecnt == tcnt(b@, T_EDGES as int),
                ecnt <= MAX_EDGES,
                n == nodes(b@),
                n <= MAX_NODES,
                i < n,
                edges@.len() == cap,
                cap >= MAX_EDGES,
                lv@.len() == n,
                gfirst == nf(b@, i as int, N_GROUP_FIRST),
                gcount == nf(b@, i as int, N_GROUP_COUNT),
                gfirst == ngsum(b@, i as int),
                gfirst + gcount == ngsum(b@, i + 1),
                gfirst + gcount <= gcnt,
                gi <= gcount,
                k <= gesum(b@, gfirst + gi),
                edges@.subrange(0, k as int) == oe(b@, i as int) + oe_node(b@, i as int, gi as int),
            decreases gcount - gi,
        {
            let g = gfirst + gi;
            assert(group_tile_ok(b@, g as int));
            let efirst = field(b, T_GROUPS, g, G_EDGE_FIRST) as usize;
            let ecount = field(b, T_GROUPS, g, G_EDGE_COUNT) as usize;
            let gkind = field(b, T_GROUPS, g, G_KIND);
            proof {
                lemma_gesum_mono(b@, g + 1, gcnt);
            }
            let ghost head = oe(b@, i as int) + oe_node(b@, i as int, gi as int);
            let mut xi: usize = 0;
            while xi < ecount
                invariant
                    v1(b@),
                    forall|x: int| 0 <= x < ecnt ==> #[trigger] edge_index_ok(b@, x),
                    ecnt == tcnt(b@, T_EDGES as int),
                    ecnt <= MAX_EDGES,
                    n == nodes(b@),
                    i < n,
                    g < gcnt,
                    edges@.len() == cap,
                    cap >= MAX_EDGES,
                    efirst == gf(b@, g as int, G_EDGE_FIRST),
                    ecount == gf(b@, g as int, G_EDGE_COUNT),
                    gkind == gf(b@, g as int, G_KIND),
                    efirst + ecount <= ecnt,
                    xi <= ecount,
                    k <= efirst + xi,
                    edges@.subrange(0, k as int) == head + oe_group(
                        b@,
                        i as int,
                        g as int,
                        xi as int,
                    ),
                decreases ecount - xi,
            {
                let x = efirst + xi;
                if field(b, T_EDGES, x, E_TARGET_KIND) == 0 && gkind <= 2 {
                    assert(edge_index_ok(b@, x as int));
                    let e = GEdge {
                        from: rid(i),
                        to: field(b, T_EDGES, x, E_TARGET),
                        hard: gkind <= 1 && field(b, T_EDGES, x, E_MODE) == 0,
                        parallel: field(b, T_EDGES, x, E_FLAGS) == 1,
                    };
                    let ghost before = edges@;
                    edges[k] = e;
                    proof {
                        let c = oe_group(b@, i as int, g as int, xi as int);
                        assert(e == ord_edge(b@, i as int, g as int, x as int));
                        assert(edges@.subrange(0, k + 1) =~= before.subrange(0, k as int).push(e));
                        assert((head + c).push(e) =~= head + c.push(e));
                    }
                    k += 1;
                }
                xi += 1;
            }
            proof {
                let c = oe_group(b@, i as int, g as int, ecount as int);
                assert(oe_node(b@, i as int, gi + 1) == oe_node(b@, i as int, gi as int) + c);
                assert(head + c =~= oe(b@, i as int) + oe_node(b@, i as int, gi + 1));
            }
            gi += 1;
        }
        i += 1;
    }
    assert(edges@.subrange(0, k as int) == ordering_edges(b@));
    let (head, _) = edges.split_at(k);
    match qinit_graph_core::levels(n, head, lv, false) {
        Ok(()) => {},
        Err(GraphError::Cycle) => {
            return Err(DbError::Cycle);
        },
        Err(GraphError::HardParallel) => {
            return Err(DbError::HardParallel);
        },
        Err(GraphError::BadIndex) => {
            return Err(DbError::Index { table: tid(T_EDGES), record: 0 });
        },
    }
    proof {
        lemma_labellable(n as int, head@, lv@, false);
    }
    match qinit_graph_core::levels(n, head, lv, true) {
        Ok(()) => {},
        Err(GraphError::Cycle) => {
            return Err(DbError::Cycle);
        },
        Err(GraphError::HardParallel) => {
            return Err(DbError::HardParallel);
        },
        Err(GraphError::BadIndex) => {
            return Err(DbError::Index { table: tid(T_EDGES), record: 0 });
        },
    }
    proof {
        lemma_labellable(n as int, head@, lv@, true);
    }
    Ok(())
}

} // verus!
