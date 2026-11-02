// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! NUL-separated lists (argv and Landlock entries): no NUL at either end, no two in a row.
mod common;

use common::*;
use qinit_db_core::*;
use std::ops::Range;

/// The pool bytes of the string at words `off_w` and `len_w` of record `r` in table `t`.
fn string_range(db: &[u8], t: usize, r: usize, off_w: usize, len_w: usize) -> Range<usize> {
    let mut words = Vec::new();
    let _ = with(db, |w| words.clone_from(w));
    let off = words[at(&words, t, r, off_w)];
    let len = words[at(&words, t, r, len_w)] as usize;
    let start = pool_at(db, off);
    start..start + len
}

/// The minimal database and the pool bytes of node 0's argv, `/bin/true`.
fn argv_db() -> (Vec<u8>, Range<usize>) {
    let db = valid_minimal();
    let r = string_range(&db, T_NODES, 0, N_EXEC_OFF, N_EXEC_LEN);
    (db, r)
}

/// A database with one credential whose Landlock list is the bytes `ro:/etc/x` (shared with
/// its user name, which is a plain string), and the pool bytes of that list.
fn landlock_db() -> (Vec<u8>, Range<usize>) {
    let mut spec = minimal_spec();
    spec.creds.push(CredSpec {
        user: "ro:/etc/x",
        caps: 0,
    });
    let db = with(&build(&spec), |w| {
        let (uo, ul) = (at(w, T_CREDS, 0, C_USER_OFF), at(w, T_CREDS, 0, C_USER_LEN));
        let (lo, ll) = (
            at(w, T_CREDS, 0, C_LANDLOCK_OFF),
            at(w, T_CREDS, 0, C_LANDLOCK_LEN),
        );
        w[lo] = w[uo];
        w[ll] = w[ul];
    });
    let r = string_range(&db, T_CREDS, 0, C_LANDLOCK_OFF, C_LANDLOCK_LEN);
    (db, r)
}

/// `db` with NUL written at each of the list-relative positions `at`.
fn nul_at(db: &[u8], list: &Range<usize>, at: &[usize]) -> Vec<u8> {
    let mut out = db.to_vec();
    for i in at {
        out[list.start + i] = 0;
    }
    out
}

#[test]
fn the_lists_under_test_are_nine_bytes_and_valid() {
    for (db, r) in [argv_db(), landlock_db()] {
        assert_eq!(r.len(), 9);
        assert_eq!(check(&db), Ok(()));
    }
}

#[test]
fn a_leading_nul_in_argv_is_a_pool_error() {
    let (db, r) = argv_db();
    assert_eq!(check(&nul_at(&db, &r, &[0])), Err(DbError::Pool));
}

#[test]
fn a_trailing_nul_in_argv_is_a_pool_error() {
    let (db, r) = argv_db();
    assert_eq!(check(&nul_at(&db, &r, &[8])), Err(DbError::Pool));
}

#[test]
fn a_double_nul_in_argv_is_a_pool_error() {
    let (db, r) = argv_db();
    assert_eq!(check(&nul_at(&db, &r, &[4, 5])), Err(DbError::Pool));
}

#[test]
fn a_leading_nul_in_landlock_is_a_pool_error() {
    let (db, r) = landlock_db();
    assert_eq!(check(&nul_at(&db, &r, &[0])), Err(DbError::Pool));
}

#[test]
fn a_trailing_nul_in_landlock_is_a_pool_error() {
    let (db, r) = landlock_db();
    assert_eq!(check(&nul_at(&db, &r, &[8])), Err(DbError::Pool));
}

#[test]
fn a_double_nul_in_landlock_is_a_pool_error() {
    let (db, r) = landlock_db();
    assert_eq!(check(&nul_at(&db, &r, &[4, 5])), Err(DbError::Pool));
}

#[test]
fn one_and_two_element_lists_and_the_empty_list_are_valid() {
    for (db, r) in [argv_db(), landlock_db()] {
        // One element as built; two elements split by one NUL.
        assert_eq!(check(&db), Ok(()));
        assert_eq!(check(&nul_at(&db, &r, &[4])), Ok(()));
    }
    // The empty list: a brood has no argv and a credential without Landlock has length 0.
    let mut spec = minimal_spec();
    spec.nodes[1].kind = 2;
    spec.creds.push(CredSpec {
        user: "daemon",
        caps: 0,
    });
    assert_eq!(check(&build(&spec)), Ok(()));
}
