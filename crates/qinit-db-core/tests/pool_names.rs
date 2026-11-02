// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The validator's pool and name rules, one at a time: each test patches one string reference
//! or name of a valid database.
mod common;

use common::*;
use qinit_db_core::*;

#[test]
fn a_name_that_leaves_the_pool_is_refused() {
    let db = with(&valid_minimal(), |w| {
        let i = at(w, T_NODES, 1, N_NAME_LEN);
        w[i] = 1000;
    });
    assert_eq!(check(&db), Err(DbError::Pool));
    let db = with(&valid_minimal(), |w| {
        let i = at(w, T_NODES, 0, N_NAME_OFF);
        w[i] = u32::MAX;
    });
    assert_eq!(check(&db), Err(DbError::Pool));
}

#[test]
fn a_name_that_is_not_utf8_is_refused() {
    let mut db = valid_minimal();
    let i = pool_at(&db, 0);
    assert_eq!(db[i], b'a');
    db[i] = 0xff;
    assert_eq!(check(&db), Err(DbError::Utf8));
}

#[test]
fn a_path_that_is_not_utf8_is_refused() {
    let mut spec = minimal_spec();
    spec.nodes[1].groups.push(group(2, vec![path("/run/x")]));
    let mut db = build(&spec);
    let total = db.len();
    // The path is the last string in the pool.
    db[total - 1] = 0xc0;
    assert_eq!(check(&db), Err(DbError::Utf8));
}

#[test]
fn a_name_over_the_limit_is_refused() {
    let mut spec = minimal_spec();
    spec.nodes[0].name = vec![b'a'; MAX_NAME_LEN + 1];
    assert_eq!(check(&build(&spec)), Err(DbError::Pool));
    spec.nodes[0].name = vec![b'a'; MAX_NAME_LEN];
    assert_eq!(check(&build(&spec)), Ok(()));
    spec.nodes[0].name = vec![];
    assert_eq!(check(&build(&spec)), Err(DbError::Pool));
}

#[test]
fn unsorted_node_names_are_refused() {
    let mut spec = minimal_spec();
    spec.nodes[0].name = b"c".to_vec();
    assert_eq!(check(&build(&spec)), Err(DbError::Order));
    spec.nodes[0].name = b"b".to_vec();
    assert_eq!(check(&build(&spec)), Err(DbError::Order));
    spec.nodes[0].name = b"ab".to_vec();
    assert_eq!(check(&build(&spec)), Ok(()));
    spec.nodes[1].name = b"a".to_vec();
    assert_eq!(check(&build(&spec)), Err(DbError::Order));
}

#[test]
fn an_instance_of_name_over_the_limit_is_refused() {
    // A pool long enough that a reference of MAX_NAME_LEN + 1 bytes stays inside it, so only
    // the bound can refuse it.
    let mut spec = minimal_spec();
    spec.nodes[0].name = vec![b'a'; MAX_NAME_LEN];
    spec.nodes[1].name = b"b".to_vec();
    let db = build(&spec);
    for (len, expected) in [
        (0, Ok(())),
        (u32::try_from(MAX_NAME_LEN).unwrap(), Ok(())),
        (u32::try_from(MAX_NAME_LEN + 1).unwrap(), Err(DbError::Pool)),
    ] {
        let patched = with(&db, |w| {
            let off = at(w, T_NODES, 1, N_INSTANCE_OF_OFF);
            w[off] = 0;
            let l = at(w, T_NODES, 1, N_INSTANCE_OF_LEN);
            w[l] = len;
        });
        assert_eq!(check(&patched), expected, "instance_of length {len}");
    }
}

#[test]
fn scratch_smaller_than_the_limits_is_refused() {
    let db = valid_minimal();
    let edge = qinit_graph_core::GEdge {
        from: 0,
        to: 0,
        hard: false,
        parallel: false,
    };
    let mut edges = vec![edge; MAX_EDGES];
    let mut levels = vec![0u32; MAX_NODES];
    assert_eq!(validate(&db, &mut edges, &mut levels), Ok(()));
    assert_eq!(
        validate(&db, &mut edges[..MAX_EDGES - 1], &mut levels),
        Err(DbError::Scratch)
    );
    assert_eq!(
        validate(&db, &mut edges, &mut levels[..MAX_NODES - 1]),
        Err(DbError::Scratch)
    );
}
