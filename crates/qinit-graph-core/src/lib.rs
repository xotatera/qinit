// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qinit-graph-core`: the dependency graph model (frames and compiled database spec), proved
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

/// Writes levels for `n` nodes over `edges` into `out`: `from` is the dependent, `to` the
/// dependency, and a constraining edge (every edge, less the parallel ones when
/// `honour_parallel`) gets `out[from] < out[to]`. A level that would exceed `n` is a cycle.
///
/// # Errors
/// [`GraphError::BadIndex`] for an edge outside the table, [`GraphError::HardParallel`] for a
/// hard parallel edge, [`GraphError::Cycle`] when the constraining edges admit no levels.
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
    let mut pass: usize = 0;
    while pass <= n
        invariant
            pass <= n + 1,
            n <= MAX_NODES,
            out@.len() == n,
            bounded(out@, n as int),
            edges_in_range(n as int, edges@),
            no_hard_parallel(edges@),
        decreases n + 1 - pass,
    {
        let mut changed = false;
        let mut i: usize = 0;
        while i < edges.len()
            invariant
                i <= edges@.len(),
                n <= MAX_NODES,
                out@.len() == n,
                bounded(out@, n as int),
                edges_in_range(n as int, edges@),
                !changed ==> forall|j: int|
                    #![trigger edges@[j]]
                    0 <= j < i ==> ((honour_parallel && edges@[j].parallel)
                        || out@[edges@[j].from as int] < out@[edges@[j].to as int]),
            decreases edges@.len() - i,
        {
            let edge = edges[i];
            if !(honour_parallel && edge.parallel) {
                let low = out[edge.from as usize];
                if out[edge.to as usize] <= low {
                    if low as usize >= n {
                        return Err(GraphError::Cycle);
                    }
                    out[edge.to as usize] = low + 1;
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
