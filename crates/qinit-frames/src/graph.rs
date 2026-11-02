// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The graph passes of the pipeline (spec §7 step 7): the proved `qinit_graph_core::levels`
//! over `qinit_db::ordering_edges`, first for the start order (every ordering edge constrains),
//! then for the stop order (`stop = "parallel"` edges do not).
use crate::error::{Code, Error};
use crate::expand::kind_name;
use qinit_db::{Model, ordering_edges};
use qinit_graph_core::{GEdge, GraphError, MAX_EDGES, MAX_NODES, levels};

/// Run both graph passes over `model`.
///
/// # Errors
/// `Cycle` keyed by the first node of one cycle (in table order) with the cycle as
/// `a -> b -> a` in `detail`; `HardParallel` keyed by the dependent of the first hard parallel
/// edge; `Limit` past the graph limits; `SelfCheck` for an edge outside the node table.
pub(crate) fn check(model: &Model) -> Result<(), Error> {
    let edges = ordering_edges(model);
    let n = model.nodes.len();
    if n > MAX_NODES || edges.len() > MAX_EDGES {
        let why = format!(
            "{n} nodes and {} ordering edges; the limits are {MAX_NODES} and {MAX_EDGES}",
            edges.len()
        );
        return Err(Error::new(Code::Limit, "", why));
    }
    let mut out = vec![0u32; n];
    for honour_parallel in [false, true] {
        match levels(n, &edges, &mut out, honour_parallel) {
            Ok(()) => {}
            Err(GraphError::Cycle) => return Err(cycle_error(model, &edges)),
            Err(GraphError::HardParallel) => return Err(hard_parallel_error(model, &edges)),
            Err(GraphError::BadIndex) => {
                let why = "an ordering edge names a node outside the table";
                return Err(Error::new(Code::SelfCheck, "", why));
            }
        }
    }
    Ok(())
}

fn name(model: &Model, i: usize) -> &str {
    model.nodes.get(i).map_or("?", |n| n.name.as_str())
}

fn key(model: &Model, i: usize) -> String {
    model
        .nodes
        .get(i)
        .map_or_else(String::new, |n| format!("{}.{}", kind_name(n.kind), n.name))
}

fn hard_parallel_error(model: &Model, edges: &[GEdge]) -> Error {
    let Some(e) = edges.iter().find(|e| e.hard && e.parallel) else {
        return Error::new(
            Code::HardParallel,
            "",
            "a hard edge has stop = \"parallel\"",
        );
    };
    let (from, to) = (e.from as usize, e.to as usize);
    let why = format!(
        "{} -> {} is a hard edge and cannot stop in parallel",
        name(model, from),
        name(model, to)
    );
    Error::new(Code::HardParallel, key(model, from), why)
}

fn cycle_error(model: &Model, edges: &[GEdge]) -> Error {
    let Some(mut cycle) = find_cycle(model.nodes.len(), edges) else {
        return Error::new(Code::Cycle, "", "the ordering edges form a cycle");
    };
    let first = cycle
        .iter()
        .enumerate()
        .min_by_key(|(_, v)| **v)
        .map_or(0, |(i, _)| i);
    cycle.rotate_left(first);
    let head = cycle.first().copied().unwrap_or(0);
    let mut detail: Vec<&str> = cycle.iter().map(|&v| name(model, v)).collect();
    detail.push(name(model, head));
    Error::new(Code::Cycle, key(model, head), detail.join(" -> "))
}

/// The nodes of one cycle over `edges` (`from` before `to`), found by an iterative depth-first
/// search; `None` if the edges are acyclic.
fn find_cycle(n: usize, edges: &[GEdge]) -> Option<Vec<usize>> {
    let mut adj = vec![Vec::new(); n];
    for e in edges {
        adj.get_mut(e.from as usize)?.push(e.to as usize);
    }
    // 0: unseen, 1: on the current path, 2: finished.
    let mut state = vec![0u8; n];
    for start in 0..n {
        if state[start] != 0 {
            continue;
        }
        state[start] = 1;
        let mut path: Vec<(usize, usize)> = vec![(start, 0)];
        while let Some(top) = path.last_mut() {
            let (v, i) = *top;
            let Some(&w) = adj[v].get(i) else {
                state[v] = 2;
                path.pop();
                continue;
            };
            top.1 += 1;
            match state.get(w)? {
                0 => {
                    state[w] = 1;
                    path.push((w, 0));
                }
                1 => {
                    let at = path.iter().position(|&(x, _)| x == w)?;
                    return Some(path[at..].iter().map(|&(x, _)| x).collect());
                }
                _ => {}
            }
        }
    }
    None
}
