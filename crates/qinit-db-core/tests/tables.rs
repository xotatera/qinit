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
fn an_edge_target_past_the_node_table_is_an_index_error() {
    let db = with(&valid_minimal(), |w| {
        let i = at(w, T_EDGES, 0, E_TARGET);
        w[i] = 2;
    });
    assert_eq!(
        check(&db),
        Err(DbError::Index {
            table: tid(T_EDGES),
            record: 0
        })
    );
}

#[test]
fn a_dangling_route_or_credential_is_an_index_error() {
    let mut spec = minimal_spec();
    spec.nodes[1].output = 0;
    assert_eq!(
        check(&build(&spec)),
        Err(DbError::Index {
            table: tid(T_NODES),
            record: 1
        })
    );
    let mut spec = minimal_spec();
    spec.nodes[0].cred = 0;
    assert_eq!(
        check(&build(&spec)),
        Err(DbError::Index {
            table: tid(T_NODES),
            record: 0
        })
    );
}

#[test]
fn an_unknown_group_kind_is_an_enum_error() {
    let db = with(&valid_minimal(), |w| {
        let i = at(w, T_GROUPS, 0, G_KIND);
        w[i] = 4;
    });
    assert_eq!(
        check(&db),
        Err(DbError::Enum {
            table: tid(T_GROUPS),
            record: 0
        })
    );
}

#[test]
fn an_unknown_node_or_edge_enum_is_an_enum_error() {
    for (t, w_idx, value) in [
        (T_NODES, N_KIND, 3),
        (T_NODES, N_READY_KIND, 4),
        (T_NODES, N_RESTART_POLICY, 3),
        (T_EDGES, E_TARGET_KIND, 2),
        (T_EDGES, E_MODE, 2),
        (T_EDGES, E_RESTART_ON, 4),
    ] {
        let db = with(&valid_minimal(), |w| {
            let i = at(w, t, 0, w_idx);
            w[i] = value;
        });
        assert_eq!(
            check(&db),
            Err(DbError::Enum {
                table: tid(t),
                record: 0
            }),
            "table {t} word {w_idx}"
        );
    }
}

#[test]
fn a_sync_edge_with_a_deadline_is_a_consistency_error() {
    let db = with(&valid_minimal(), |w| {
        let i = at(w, T_EDGES, 0, E_DEADLINE_MS);
        w[i] = 1000;
    });
    assert_eq!(
        check(&db),
        Err(DbError::Consistency {
            table: tid(T_EDGES),
            record: 0
        })
    );
    // An async edge may carry one.
    let db = with(&db, |w| {
        let i = at(w, T_EDGES, 0, E_MODE);
        w[i] = 1;
    });
    assert_eq!(check(&db), Ok(()));
}

#[test]
fn a_node_target_with_a_length_is_a_consistency_error() {
    let db = with(&valid_minimal(), |w| {
        let i = at(w, T_EDGES, 0, E_TARGET_LEN);
        w[i] = 1;
    });
    assert_eq!(
        check(&db),
        Err(DbError::Consistency {
            table: tid(T_EDGES),
            record: 0
        })
    );
}

#[test]
fn a_node_whose_groups_do_not_tile_is_a_tiling_error() {
    let db = with(&valid_minimal(), |w| {
        let i = at(w, T_NODES, 0, N_GROUP_FIRST);
        w[i] = 1;
    });
    assert_eq!(
        check(&db),
        Err(DbError::Tiling {
            table: tid(T_NODES),
            record: 0
        })
    );
    // A group whose edges do not start at the running sum.
    let db = with(&valid_minimal(), |w| {
        let i = at(w, T_GROUPS, 0, G_EDGE_FIRST);
        w[i] = 1;
    });
    assert_eq!(
        check(&db),
        Err(DbError::Tiling {
            table: tid(T_GROUPS),
            record: 0
        })
    );
    // An edge no group owns.
    let db = with(&valid_minimal(), |w| {
        let i = at(w, T_GROUPS, 0, G_EDGE_COUNT);
        w[i] = 0;
    });
    // The group run ends short of the edge count, reported at the group count.
    assert_eq!(
        check(&db),
        Err(DbError::Tiling {
            table: tid(T_GROUPS),
            record: 1
        })
    );
}

#[test]
fn a_group_over_its_edge_limit_is_a_tiling_error() {
    let mut spec = minimal_spec();
    spec.nodes[0].groups[0].edges = vec![sync(1); MAX_EDGES_PER_GROUP + 1];
    assert_eq!(
        check(&build(&spec)),
        Err(DbError::Tiling {
            table: tid(T_GROUPS),
            record: 0
        })
    );
    spec.nodes[0].groups[0].edges = vec![sync(1); MAX_EDGES_PER_GROUP];
    assert_eq!(check(&build(&spec)), Ok(()));
    let mut spec = minimal_spec();
    spec.nodes[1].groups = vec![group(2, vec![]); MAX_GROUPS_PER_NODE + 1];
    assert_eq!(
        check(&build(&spec)),
        Err(DbError::Tiling {
            table: tid(T_NODES),
            record: 1
        })
    );
}

#[test]
fn a_reserved_flag_bit_is_an_enum_error() {
    let db = with(&valid_minimal(), |w| {
        let i = at(w, T_EDGES, 0, E_FLAGS);
        w[i] = 2;
    });
    assert_eq!(
        check(&db),
        Err(DbError::Enum {
            table: tid(T_EDGES),
            record: 0
        })
    );
}

#[test]
fn a_forager_or_brood_with_a_restart_policy_is_a_consistency_error() {
    for kind in [1, 2] {
        let db = with(&valid_minimal(), |w| {
            let i = at(w, T_NODES, 1, N_KIND);
            w[i] = kind;
            let i = at(w, T_NODES, 1, N_RESTART_POLICY);
            w[i] = 1;
        });
        assert_eq!(
            check(&db),
            Err(DbError::Consistency {
                table: tid(T_NODES),
                record: 1
            }),
            "kind {kind}"
        );
    }
    // A brood has no exec.
    let db = with(&valid_minimal(), |w| {
        let i = at(w, T_NODES, 1, N_KIND);
        w[i] = 2;
    });
    assert_eq!(
        check(&db),
        Err(DbError::Consistency {
            table: tid(T_NODES),
            record: 1
        })
    );
}

#[test]
fn a_bad_credential_field_is_refused() {
    let mut spec = minimal_spec();
    spec.creds.push(CredSpec {
        user: "daemon",
        caps: 1 << 41,
    });
    assert_eq!(
        check(&build(&spec)),
        Err(DbError::Enum {
            table: tid(T_CREDS),
            record: 0
        })
    );
}

#[test]
fn a_pipe_into_a_non_worker_is_a_consistency_error() {
    let mut spec = minimal_spec();
    spec.nodes[1].kind = 1;
    spec.routes.push(RouteSpec::Pipe(1));
    assert_eq!(
        check(&build(&spec)),
        Err(DbError::Consistency {
            table: tid(T_ROUTES),
            record: 0
        })
    );
    let mut spec = minimal_spec();
    spec.routes.push(RouteSpec::Pipe(2));
    assert_eq!(
        check(&build(&spec)),
        Err(DbError::Index {
            table: tid(T_ROUTES),
            record: 0
        })
    );
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
