// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! NUL-separated lists (argv and Landlock entries): no NUL at either end, no two in a row.
mod common;

use common::*;
use qinit_db_core::*;

fn tid(t: usize) -> u8 {
    u8::try_from(t).unwrap()
}
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

/// A database whose credential 0 has the path list `ro:/ro:/a` (shared with its user name,
/// which is a plain string), and the pool bytes of that list.
fn landlock_db() -> (Vec<u8>, Range<usize>) {
    let mut spec = minimal_spec();
    spec.creds[0].user = "ro:/ro:/a";
    let db = with(&build(&spec), |w| {
        let (uo, ul) = (at(w, T_CREDS, 0, C_USER_OFF), at(w, T_CREDS, 0, C_USER_LEN));
        let (lo, ll) = (
            at(w, T_CREDS, 0, C_PATHS_OFF),
            at(w, T_CREDS, 0, C_PATHS_LEN),
        );
        w[lo] = w[uo];
        w[ll] = w[ul];
    });
    let r = string_range(&db, T_CREDS, 0, C_PATHS_OFF, C_PATHS_LEN);
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
    assert_eq!(
        check(&nul_at(&db, &r, &[0])),
        Err(DbError::Pool {
            table: tid(T_NODES),
            record: 0
        })
    );
}

#[test]
fn a_trailing_nul_in_argv_is_a_pool_error() {
    let (db, r) = argv_db();
    assert_eq!(
        check(&nul_at(&db, &r, &[8])),
        Err(DbError::Pool {
            table: tid(T_NODES),
            record: 0
        })
    );
}

#[test]
fn a_double_nul_in_argv_is_a_pool_error() {
    let (db, r) = argv_db();
    assert_eq!(
        check(&nul_at(&db, &r, &[4, 5])),
        Err(DbError::Pool {
            table: tid(T_NODES),
            record: 0
        })
    );
}

#[test]
fn a_leading_nul_in_landlock_is_a_pool_error() {
    let (db, r) = landlock_db();
    assert_eq!(
        check(&nul_at(&db, &r, &[0])),
        Err(DbError::Pool {
            table: tid(T_CREDS),
            record: 0
        })
    );
}

#[test]
fn a_trailing_nul_in_landlock_is_a_pool_error() {
    let (db, r) = landlock_db();
    assert_eq!(
        check(&nul_at(&db, &r, &[8])),
        Err(DbError::Pool {
            table: tid(T_CREDS),
            record: 0
        })
    );
}

#[test]
fn a_double_nul_in_landlock_is_a_pool_error() {
    let (db, r) = landlock_db();
    assert_eq!(
        check(&nul_at(&db, &r, &[4, 5])),
        Err(DbError::Pool {
            table: tid(T_CREDS),
            record: 0
        })
    );
}

#[test]
fn one_and_two_element_lists_and_the_empty_list_are_valid() {
    // One element as built; two elements split by one NUL (a path list's second element would
    // be `o:/a`, which is not a path entry, so only argv splits).
    let (db, r) = argv_db();
    assert_eq!(check(&db), Ok(()));
    assert_eq!(check(&nul_at(&db, &r, &[4])), Ok(()));
    assert_eq!(check(&landlock_db().0), Ok(()));
    // The empty list: a brood has no argv and a credential without Landlock has length 0.
    let mut spec = minimal_spec();
    spec.nodes[1].kind = 2;
    spec.nodes[1].cred = NONE;
    spec.creds.push(cred("daemon"));
    assert_eq!(check(&build(&spec)), Ok(()));
}
