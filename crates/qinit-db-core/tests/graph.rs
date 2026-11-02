// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The validator's graph rules: ordering cycles, hard parallel edges, and the edges that do not
//! order anything.
mod common;

use common::*;
use qinit_db_core::*;

fn two(a: Vec<GroupSpec>, b: Vec<GroupSpec>) -> DbSpec {
    DbSpec {
        nodes: vec![node("a", a), node("b", b)],
        enabled: vec![0, 1],
        ..DbSpec::default()
    }
}

#[test]
fn a_two_node_ordering_cycle_is_refused() {
    let spec = two(vec![group(0, vec![sync(1)])], vec![group(0, vec![sync(0)])]);
    assert_eq!(check(&build(&spec)), Err(DbError::Cycle));
}

#[test]
fn a_self_loop_is_refused() {
    let spec = two(vec![group(1, vec![sync(0)])], vec![]);
    assert_eq!(check(&build(&spec)), Err(DbError::Cycle));
}

#[test]
fn a_hard_edge_with_the_parallel_flag_is_refused() {
    let spec = two(vec![group(0, vec![parallel(1)])], vec![]);
    assert_eq!(check(&build(&spec)), Err(DbError::HardParallel));
    let spec = two(vec![group(1, vec![parallel(1)])], vec![]);
    assert_eq!(check(&build(&spec)), Err(DbError::HardParallel));
}

#[test]
fn an_async_or_optional_edge_may_stop_in_parallel() {
    let mut edge = parallel(1);
    edge.mode = 1;
    let spec = two(vec![group(0, vec![edge])], vec![]);
    assert_eq!(check(&build(&spec)), Ok(()));
    let spec = two(vec![group(2, vec![parallel(1)])], vec![]);
    assert_eq!(check(&build(&spec)), Ok(()));
}

#[test]
fn a_parallel_soft_edge_that_closes_a_cycle_is_refused() {
    let spec = two(
        vec![group(0, vec![sync(1)])],
        vec![group(2, vec![parallel(0)])],
    );
    assert_eq!(check(&build(&spec)), Err(DbError::Cycle));
}

#[test]
fn an_optional_edge_that_closes_a_cycle_is_refused() {
    let spec = two(vec![group(0, vec![sync(1)])], vec![group(2, vec![sync(0)])]);
    assert_eq!(check(&build(&spec)), Err(DbError::Cycle));
}

#[test]
fn an_exclude_all_edge_that_closes_a_loop_is_accepted() {
    let spec = two(vec![group(0, vec![sync(1)])], vec![group(3, vec![sync(0)])]);
    assert_eq!(check(&build(&spec)), Ok(()));
}

#[test]
fn an_optional_all_path_target_edge_is_accepted() {
    let spec = two(
        vec![group(0, vec![sync(1)])],
        vec![group(2, vec![path("/run/b.ready")])],
    );
    assert_eq!(check(&build(&spec)), Ok(()));
}

#[test]
fn a_longer_cycle_through_later_groups_is_refused() {
    let spec = DbSpec {
        nodes: vec![
            node("a", vec![group(2, vec![]), group(0, vec![sync(1)])]),
            node("b", vec![group(3, vec![sync(0)]), group(1, vec![sync(2)])]),
            node("c", vec![group(2, vec![path("/x"), sync(0)])]),
        ],
        enabled: vec![0, 1, 2],
        ..DbSpec::default()
    };
    assert_eq!(check(&build(&spec)), Err(DbError::Cycle));
}
