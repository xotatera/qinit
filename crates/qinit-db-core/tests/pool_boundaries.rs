// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The pool is checked as UTF-8 once, and each reference must start and end on a character
//! boundary; pool and UTF-8 errors carry their position.
mod common;

use common::*;
use qinit_db_core::*;

fn tid(t: usize) -> u8 {
    u8::try_from(t).unwrap()
}

/// `db` with `extra` appended to its pool (the pool is the last table), and the pool's old size.
fn grow_pool(db: &[u8], extra: &[u8]) -> (Vec<u8>, u32) {
    let size_word = 5 + 2 * T_POOL;
    let mut old = 0;
    let n = u32::try_from(extra.len()).unwrap();
    let mut out = with(db, |w| {
        old = w[size_word];
        w[size_word] += n;
        w[H_TOTAL_LEN] += n;
    });
    out.extend_from_slice(extra);
    (out, old)
}

/// `db` with node `i`'s name pointing at `off`, `len`.
fn name_at(db: &[u8], i: usize, off: u32, len: u32) -> Vec<u8> {
    with(db, |w| {
        let o = at(w, T_NODES, i, N_NAME_OFF);
        w[o] = off;
        let l = at(w, T_NODES, i, N_NAME_LEN);
        w[l] = len;
    })
}

#[test]
fn garbage_in_an_unreferenced_part_of_the_pool_is_utf8_with_its_offset() {
    let (db, old) = grow_pool(&valid_minimal(), &[0xff]);
    assert_eq!(check(&db), Err(DbError::Utf8 { offset: old }));
}

#[test]
fn a_reference_that_splits_a_character_is_a_pool_error() {
    let (db, old) = grow_pool(&valid_minimal(), "\u{1D11E}".as_bytes());
    assert_eq!(check(&name_at(&db, 1, old, 4)), Ok(()));
    let split = Err(DbError::Pool {
        table: tid(T_NODES),
        record: 1,
    });
    assert_eq!(check(&name_at(&db, 1, old, 3)), split);
    assert_eq!(check(&name_at(&db, 1, old + 1, 3)), split);
}

#[test]
fn empty_references_at_the_pool_edges_are_accepted() {
    let (db, old) = grow_pool(&valid_minimal(), "\u{1D11E}".as_bytes());
    let end = with(&db, |w| {
        let o = at(w, T_NODES, 0, N_READY_OFF);
        w[o] = old + 4;
        let l = at(w, T_NODES, 0, N_READY_LEN);
        w[l] = 0;
    });
    assert_eq!(check(&end), Ok(()));
    assert_eq!(check(&build(&DbSpec::default())), Ok(()));
}

#[test]
fn an_edge_path_out_of_the_pool_names_the_edge() {
    let mut spec = minimal_spec();
    spec.nodes[1].groups.push(group(
        2,
        vec![path("/run/x"), path("/run/y"), path("/run/z")],
    ));
    let db = build(&spec);
    assert_eq!(check(&db), Ok(()));
    let bad = with(&db, |w| {
        let l = at(w, T_EDGES, 2, E_TARGET_LEN);
        w[l] = 1000;
    });
    assert_eq!(
        check(&bad),
        Err(DbError::Pool {
            table: tid(T_EDGES),
            record: 2
        })
    );
}
