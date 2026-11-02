// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Level assignment over dependency edges: the proof says `Ok` levels respect every
//! constraining edge; these pin the verdicts on small graphs.
use qinit_graph_core::{GEdge, GraphError, levels};

fn e(from: u32, to: u32) -> GEdge {
    GEdge {
        from,
        to,
        hard: false,
        parallel: false,
    }
}
fn hard(from: u32, to: u32) -> GEdge {
    GEdge {
        hard: true,
        ..e(from, to)
    }
}
fn par(from: u32, to: u32) -> GEdge {
    GEdge {
        parallel: true,
        ..e(from, to)
    }
}

fn run(n: usize, edges: &[GEdge], honour: bool) -> Result<Vec<u32>, GraphError> {
    let mut l = vec![0; n];
    levels(n, edges, &mut l, honour).map(|()| l)
}

#[test]
fn a_chain_stops_dependents_first() {
    // 0 depends on 1 depends on 2
    let l = run(3, &[hard(0, 1), hard(1, 2)], true).unwrap();
    assert_eq!(l, vec![0, 1, 2]);
}

#[test]
fn independent_branches_share_levels() {
    let l = run(4, &[e(0, 2), e(1, 3)], true).unwrap();
    assert_eq!((l[0], l[1]), (0, 0));
    assert_eq!((l[2], l[3]), (1, 1));
}

#[test]
fn a_two_node_cycle_is_a_cycle() {
    assert_eq!(run(2, &[e(0, 1), e(1, 0)], true), Err(GraphError::Cycle));
}

#[test]
fn a_self_loop_is_a_cycle() {
    assert_eq!(run(1, &[e(0, 0)], false), Err(GraphError::Cycle));
}

#[test]
fn a_parallel_edge_breaks_the_stop_order_but_not_the_start_cycle() {
    let edges = [e(0, 1), par(1, 0)];
    assert!(
        run(2, &edges, true).is_ok(),
        "stop order ignores the parallel edge"
    );
    assert_eq!(
        run(2, &edges, false),
        Err(GraphError::Cycle),
        "start order still sees it"
    );
}

#[test]
fn a_hard_parallel_edge_is_refused() {
    let edge = GEdge {
        from: 0,
        to: 1,
        hard: true,
        parallel: true,
    };
    assert_eq!(run(2, &[edge], true), Err(GraphError::HardParallel));
    assert_eq!(run(2, &[edge], false), Err(GraphError::HardParallel));
}

#[test]
fn an_edge_outside_the_table_is_refused() {
    assert_eq!(run(2, &[e(0, 2)], true), Err(GraphError::BadIndex));
}

#[test]
fn a_soft_parallel_edge_never_loosens_a_hard_edge() {
    // 0 -hard-> 1 and 0 -parallel-> 1: the hard edge still orders them.
    let l = run(2, &[hard(0, 1), par(0, 1)], true).unwrap();
    assert!(l[0] < l[1]);
}

/// Reference: DFS cycle detection over the constraining edges.
fn has_cycle(n: usize, edges: &[GEdge], honour: bool) -> bool {
    fn visit(v: usize, adj: &[Vec<usize>], state: &mut [u8]) -> bool {
        state[v] = 1;
        for &w in &adj[v] {
            if state[w] == 1 || (state[w] == 0 && visit(w, adj, state)) {
                return true;
            }
        }
        state[v] = 2;
        false
    }
    let mut adj = vec![Vec::new(); n];
    for ed in edges {
        if !(honour && ed.parallel) {
            adj[ed.from as usize].push(ed.to as usize);
        }
    }
    let mut state = vec![0u8; n];
    (0..n).any(|v| state[v] == 0 && visit(v, &adj, &mut state))
}

#[test]
fn levels_agree_with_a_dfs_reference_on_random_graphs() {
    // xorshift, fixed seed: deterministic.
    let mut s = 0x9E37_79B9_7F4A_7C15_u64;
    let mut next = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    for _ in 0..2000 {
        let n = 1 + (next() % 12) as usize;
        let m = (next() % 20) as usize;
        let edges: Vec<GEdge> = (0..m)
            .map(|_| GEdge {
                from: u32::try_from(next() % n as u64).unwrap(),
                to: u32::try_from(next() % n as u64).unwrap(),
                hard: false,
                parallel: next() % 4 == 0,
            })
            .collect();
        for honour in [false, true] {
            let got = run(n, &edges, honour);
            assert_eq!(
                got.is_err(),
                has_cycle(n, &edges, honour),
                "n={n} edges={edges:?} honour={honour}"
            );
            if let Ok(l) = got {
                for ed in edges.iter().filter(|e| !(honour && e.parallel)) {
                    assert!(l[ed.from as usize] < l[ed.to as usize]);
                }
            }
        }
    }
}
