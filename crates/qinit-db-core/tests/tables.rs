// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The validator, one rule at a time: each test patches one thing in a valid database.
mod common;

use common::*;
use qinit_db_core::*;

const LIMITS: [usize; 8] = [
    MAX_NODES, MAX_GROUPS, MAX_EDGES, MAX_CREDS, MAX_ROUTES, MAX_NODES, MAX_NODES, MAX_POOL,
];

fn tid(t: usize) -> u8 {
    u8::try_from(t).unwrap()
}

fn n32(x: usize) -> u32 {
    u32::try_from(x).unwrap()
}

#[test]
fn a_valid_database_validates() {
    assert_eq!(check(&valid_minimal()), Ok(()));
}

#[test]
fn a_richer_database_validates() {
    let mut spec = minimal_spec();
    spec.nodes.push(NodeSpec {
        kind: 2,
        ..node(
            "c",
            vec![group(3, vec![path("/run/x")]), group(2, vec![sync(0)])],
        )
    });
    spec.nodes[0].output = 0;
    spec.nodes[0].cred = 0;
    spec.nodes[1].output = 1;
    spec.creds.push(CredSpec {
        user: "daemon",
        caps: 1 << 40,
    });
    spec.routes = vec![RouteSpec::Path("/var/log/a"), RouteSpec::Pipe(1)];
    spec.enabled = vec![0, 1, 2];
    spec.presyslog = vec![0, 2];
    assert_eq!(check(&build(&spec)), Ok(()));
}

#[test]
fn an_empty_database_validates() {
    assert_eq!(check(&build(&DbSpec::default())), Ok(()));
}

#[test]
fn a_bad_magic_is_a_header_error() {
    let db = with(&valid_minimal(), |w| w[H_MAGIC] ^= 1);
    assert_eq!(check(&db), Err(DbError::Header));
    assert_eq!(check(&valid_minimal()[..79]), Err(DbError::Header));
    assert_eq!(check(&[]), Err(DbError::Header));
}

#[test]
fn an_unknown_version_is_refused() {
    let db = with(&valid_minimal(), |w| w[H_VERSION] = 2);
    assert_eq!(check(&db), Err(DbError::Version));
}

#[test]
fn a_total_length_that_disagrees_with_the_buffer_is_refused() {
    let db = with(&valid_minimal(), |w| w[H_TOTAL_LEN] += 1);
    assert_eq!(check(&db), Err(DbError::Length));
    let mut long = valid_minimal();
    long.push(0);
    assert_eq!(check(&long), Err(DbError::Length));
}

#[test]
fn a_table_past_the_end_is_refused() {
    for t in 0..8 {
        let base = valid_minimal();
        let end = n32(base.len().next_multiple_of(4) + 4);
        let db = with(&base, |w| w[4 + 2 * t] = end);
        assert_eq!(check(&db), Err(DbError::Table(tid(t))), "table {t}");
    }
}

#[test]
fn a_misaligned_table_is_refused() {
    let db = with(&valid_minimal(), |w| w[4 + 2 * T_GROUPS] += 1);
    assert_eq!(check(&db), Err(DbError::Table(tid(T_GROUPS))));
}

#[test]
fn overlapping_tables_are_refused() {
    // The edge table moved back onto the groups.
    let db = with(&valid_minimal(), |w| w[4 + 2 * T_EDGES] -= 4);
    assert_eq!(check(&db), Err(DbError::Overlap));
    // The node table moved onto the header.
    let db = with(&valid_minimal(), |w| w[4 + 2 * T_NODES] = 76);
    assert_eq!(check(&db), Err(DbError::Overlap));
}

#[test]
fn a_count_over_its_limit_is_refused() {
    for (t, limit) in LIMITS.iter().enumerate() {
        let db = with(&valid_minimal(), |w| w[5 + 2 * t] = n32(limit + 1));
        assert_eq!(check(&db), Err(DbError::Count(tid(t))), "table {t}");
    }
}

#[test]
fn an_unclosed_enabled_set_is_a_closure_error() {
    let mut spec = minimal_spec();
    spec.enabled = vec![0];
    assert_eq!(check(&build(&spec)), Err(DbError::Closure));
    spec.enabled = vec![1];
    assert_eq!(check(&build(&spec)), Ok(()));
}

#[test]
fn an_unsorted_or_duplicate_presyslog_list_is_refused() {
    let mut spec = minimal_spec();
    spec.presyslog = vec![1, 0];
    assert_eq!(check(&build(&spec)), Err(DbError::Order));
    spec.presyslog = vec![1, 1];
    assert_eq!(check(&build(&spec)), Err(DbError::Order));
    spec.presyslog = vec![0, 2];
    assert_eq!(
        check(&build(&spec)),
        Err(DbError::Index {
            table: tid(T_PRESYSLOG),
            record: 1
        })
    );
    spec.presyslog = vec![0, 1];
    assert_eq!(check(&build(&spec)), Ok(()));
}

#[test]
fn an_unsorted_enabled_list_is_refused() {
    let mut spec = minimal_spec();
    spec.enabled = vec![1, 0];
    assert_eq!(check(&build(&spec)), Err(DbError::Order));
}

#[test]
fn every_truncation_is_refused() {
    let db = valid_minimal();
    for len in 0..db.len() {
        assert!(check(&db[..len]).is_err(), "length {len}");
    }
}
