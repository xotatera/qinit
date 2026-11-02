// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qinit-graph-core`: the dependency graph model (spec 2026-11-02 §4, graph core), proved
//! by Verus (`proof:qinit-graph-core`). [`levels`] gives every node a level such that each
//! constraining edge goes strictly up: a dependent sits below its dependency, so stopping walks
//! the levels upwards and starting walks them downwards.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use vstd::prelude::*;

verus! {

/// Nodes one graph holds.
pub const MAX_NODES: usize = 4096;

/// Edges one graph holds.
pub const MAX_EDGES: usize = 32768;

/// `from` depends on `to`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GEdge {
    /// The dependent.
    pub from: u32,
    /// The dependency.
    pub to: u32,
    /// The dependent cannot run without the dependency.
    pub hard: bool,
    /// The two may stop in parallel: the edge does not order the stop.
    pub parallel: bool,
}

/// Why a graph has no levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphError {
    /// An edge names a node outside the table.
    BadIndex,
    /// An edge is both hard and parallel.
    HardParallel,
    /// The constraining edges form a cycle.
    Cycle,
}

pub open spec fn edges_in_range(n: int, edges: Seq<GEdge>) -> bool {
    forall|i: int|
        #![trigger edges[i]]
        0 <= i < edges.len() ==> edges[i].from < n && edges[i].to < n
}

pub open spec fn no_hard_parallel(edges: Seq<GEdge>) -> bool {
    forall|i: int|
        #![trigger edges[i]]
        0 <= i < edges.len() ==> !(edges[i].hard && edges[i].parallel)
}

/// Every constraining edge goes strictly up in level.
pub open spec fn labelled(levels: Seq<u32>, edges: Seq<GEdge>, honour: bool) -> bool {
    forall|i: int|
        #![trigger edges[i]]
        0 <= i < edges.len() ==> ((honour && edges[i].parallel) || levels[edges[i].from as int]
            < levels[edges[i].to as int])
}

/// Every level is at most `n`.
pub open spec fn bounded(levels: Seq<u32>, n: int) -> bool {
    forall|j: int| 0 <= j < levels.len() ==> levels[j] <= n
}

/// Some integer labelling sends every constraining edge strictly up.
pub open spec fn labellable(n: int, edges: Seq<GEdge>, honour: bool) -> bool {
    exists|lv: Seq<int>|
        lv.len() == n && forall|i: int|
            #![trigger edges[i]]
            0 <= i < edges.len() ==> ((honour && edges[i].parallel) || lv[edges[i].from as int]
                < lv[edges[i].to as int])
}

/// `lv` is a labelling that witnesses [`labellable`].
/// Keep this body identical to the body of [`labellable`] and the ghost `choose` in [`levels`].
pub open spec fn labelling(n: int, edges: Seq<GEdge>, honour: bool, lv: Seq<int>) -> bool {
    lv.len() == n && forall|i: int|
        #![trigger edges[i]]
        0 <= i < edges.len() ==> ((honour && edges[i].parallel) || lv[edges[i].from as int]
            < lv[edges[i].to as int])
}

/// The rank of `v` under `lv`: how many of the nodes `0..m` are labelled strictly below it.
pub open spec fn below(lv: Seq<int>, v: int, m: nat) -> nat
    decreases m,
{
    if m == 0 {
        0
    } else {
        below(lv, v, (m - 1) as nat) + if lv[m - 1] < lv[v] {
            1nat
        } else {
            0nat
        }
    }
}

proof fn lemma_below_le(lv: Seq<int>, v: int, m: nat)
    ensures
        below(lv, v, m) <= m,
    decreases m,
{
    if m > 0 {
        lemma_below_le(lv, v, (m - 1) as nat);
    }
}

/// A rank never counts the node itself, so a rank over `0..m` stays below `m`.
proof fn lemma_below_bound(lv: Seq<int>, v: int, m: nat)
    requires
        0 <= v < m,
    ensures
        below(lv, v, m) < m,
    decreases m,
{
    if m - 1 > v {
        lemma_below_bound(lv, v, (m - 1) as nat);
    } else {
        lemma_below_le(lv, v, (m - 1) as nat);
    }
}

/// Ranks follow the labelling: a node labelled strictly lower has a rank at most as high, and
/// strictly lower once the node itself is among those counted.
proof fn lemma_below_strict(lv: Seq<int>, a: int, b: int, m: nat)
    requires
        lv[a] < lv[b],
    ensures
        below(lv, a, m) <= below(lv, b, m),
        0 <= a < m ==> below(lv, a, m) < below(lv, b, m),
    decreases m,
{
    if m > 0 {
        lemma_below_strict(lv, a, b, (m - 1) as nat);
    }
}

/// Writes levels for `n` nodes over `edges` into `out`: `from` is the dependent, `to` the
/// dependency, and a constraining edge (every edge, less the parallel ones when
/// `honour_parallel`) gets `out[from] < out[to]`. A level that would exceed `n` is a cycle.
///
/// # Errors
/// [`GraphError::BadIndex`] for an edge outside the table, [`GraphError::HardParallel`] for a
/// hard parallel edge, [`GraphError::Cycle`] when the constraining edges admit no levels.
#[allow(clippy::too_many_lines)]  // most of the length is the Verus loop invariants
pub fn levels(n: usize, edges: &[GEdge], out: &mut [u32], honour_parallel: bool) -> (r: Result<
    (),
    GraphError,
>)
    requires
        n <= MAX_NODES,
        edges@.len() <= MAX_EDGES,
        old(out)@.len() == n,
    ensures
        final(out)@.len() == n,
        r is Ok ==> edges_in_range(n as int, edges@) && no_hard_parallel(edges@) && labelled(
            final(out)@,
            edges@,
            honour_parallel,
        ),
        r == Err::<(), GraphError>(GraphError::BadIndex) ==> !edges_in_range(n as int, edges@),
        r == Err::<(), GraphError>(GraphError::HardParallel) ==> !no_hard_parallel(edges@),
        r == Err::<(), GraphError>(GraphError::Cycle) ==> edges_in_range(n as int, edges@)
            && no_hard_parallel(edges@) && !labellable(n as int, edges@, honour_parallel),
{
    let mut i: usize = 0;
    while i < edges.len()
        invariant
            i <= edges@.len(),
            out@.len() == n,
            forall|j: int|
                #![trigger edges@[j]]
                0 <= j < i ==> edges@[j].from < n && edges@[j].to < n,
        decreases edges@.len() - i,
    {
        let edge = edges[i];
        if edge.from as usize >= n || edge.to as usize >= n {
            assert(!(edges@[i as int].from < n && edges@[i as int].to < n));
            return Err(GraphError::BadIndex);
        }
        i += 1;
    }
    assert(edges_in_range(n as int, edges@));
    let mut i: usize = 0;
    while i < edges.len()
        invariant
            i <= edges@.len(),
            out@.len() == n,
            forall|j: int|
                #![trigger edges@[j]]
                0 <= j < i ==> !(edges@[j].hard && edges@[j].parallel),
        decreases edges@.len() - i,
    {
        let edge = edges[i];
        if edge.hard && edge.parallel {
            assert(edges@[i as int].hard && edges@[i as int].parallel);
            return Err(GraphError::HardParallel);
        }
        i += 1;
    }
    assert(no_hard_parallel(edges@));
    let mut node: usize = 0;
    while node < n
        invariant
            node <= n,
            out@.len() == n,
            forall|j: int| 0 <= j < node ==> out@[j] == 0,
        decreases n - node,
    {
        out[node] = 0;
        node += 1;
    }
    // Completeness (G1). Suppose a labelling `lv` exists, and rank each node by `below`: the
    // number of nodes in `0..n` labelled strictly lower. Every constraining edge goes strictly up
    // in rank, and every rank is below `n`. Two facts follow. A level never exceeds its node's
    // rank, so no level reaches `n` and the early `Cycle` exit cannot fire. After `pass` passes,
    // every constraining edge into a node of rank below `pass` holds and those nodes no longer
    // change, so pass `n` changes nothing and returns `Ok` before the passes run out.
    let ghost lab = labellable(n as int, edges@, honour_parallel);
    proof {
        if lab {
            let w = choose|w: Seq<int>|
                w.len() == n && forall|i: int|
                    #![trigger edges@[i]]
                    0 <= i < edges@.len() ==> ((honour_parallel && edges@[i].parallel)
                        || w[edges@[i].from as int] < w[edges@[i].to as int]);
            assert(labelling(n as int, edges@, honour_parallel, w));
        }
    }
    let ghost lv: Seq<int> = if lab {
        choose|lv: Seq<int>| labelling(n as int, edges@, honour_parallel, lv)
    } else {
        Seq::empty()
    };
    let mut pass: usize = 0;
    while pass <= n
        invariant
            pass <= n + 1,
            n <= MAX_NODES,
            out@.len() == n,
            bounded(out@, n as int),
            edges_in_range(n as int, edges@),
            no_hard_parallel(edges@),
            lab == labellable(n as int, edges@, honour_parallel),
            lab ==> labelling(n as int, edges@, honour_parallel, lv),
            lab ==> pass <= n,
            lab ==> forall|v: int| 0 <= v < n ==> #[trigger] out@[v] <= below(lv, v, n as nat),
            lab ==> forall|j: int|
                #![trigger edges@[j]]
                0 <= j < edges@.len() && !(honour_parallel && edges@[j].parallel) && below(
                    lv,
                    edges@[j].to as int,
                    n as nat,
                ) < pass ==> out@[edges@[j].from as int] < out@[edges@[j].to as int],
        decreases n + 1 - pass,
    {
        let ghost start = out@;
        let mut changed = false;
        let mut i: usize = 0;
        while i < edges.len()
            invariant
                i <= edges@.len(),
                pass <= n,
                n <= MAX_NODES,
                out@.len() == n,
                start.len() == n,
                bounded(out@, n as int),
                edges_in_range(n as int, edges@),
                no_hard_parallel(edges@),
                !changed ==> forall|j: int|
                    #![trigger edges@[j]]
                    0 <= j < i ==> ((honour_parallel && edges@[j].parallel)
                        || out@[edges@[j].from as int] < out@[edges@[j].to as int]),
                lab == labellable(n as int, edges@, honour_parallel),
                lab ==> labelling(n as int, edges@, honour_parallel, lv),
                lab && pass == n ==> !changed,
                lab ==> forall|v: int| 0 <= v < n ==> #[trigger] out@[v] <= below(lv, v, n as nat),
                lab ==> forall|v: int|
                    0 <= v < n && below(lv, v, n as nat) < pass ==> #[trigger] out@[v] == start[v],
                lab ==> forall|j: int|
                    #![trigger edges@[j]]
                    0 <= j < edges@.len() && !(honour_parallel && edges@[j].parallel) && below(
                        lv,
                        edges@[j].to as int,
                        n as nat,
                    ) < pass ==> out@[edges@[j].from as int] < out@[edges@[j].to as int],
                lab ==> forall|j: int|
                    #![trigger edges@[j]]
                    0 <= j < i && !(honour_parallel && edges@[j].parallel) && below(
                        lv,
                        edges@[j].to as int,
                        n as nat,
                    ) == pass ==> out@[edges@[j].from as int] < out@[edges@[j].to as int],
            decreases edges@.len() - i,
        {
            let edge = edges[i];
            if !(honour_parallel && edge.parallel) {
                let low = out[edge.from as usize];
                if out[edge.to as usize] <= low {
                    proof {
                        if lab {
                            assert(edges@[i as int] == edge);
                            lemma_below_strict(lv, edge.from as int, edge.to as int, n as nat);
                            lemma_below_bound(lv, edge.to as int, n as nat);
                        }
                    }
                    if low as usize >= n {
                        return Err(GraphError::Cycle);
                    }
                    out[edge.to as usize] = low + 1;
                    proof {
                        if lab {
                            // No edge into a rank up to `pass` starts at the node just raised.
                            assert forall|j: int|
                                #![trigger edges@[j]]
                                0 <= j < edges@.len() && !(honour_parallel && edges@[j].parallel)
                                    && below(lv, edges@[j].to as int, n as nat)
                                    <= pass implies edges@[j].from != edge.to by {
                                lemma_below_strict(
                                    lv,
                                    edges@[j].from as int,
                                    edges@[j].to as int,
                                    n as nat,
                                );
                            }
                        }
                    }
                    changed = true;
                }
            }
            i += 1;
        }
        if !changed {
            return Ok(());
        }
        pass += 1;
    }
    Err(GraphError::Cycle)
}

} // verus!
