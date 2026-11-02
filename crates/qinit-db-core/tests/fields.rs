// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The validator's record field rules, one at a time: each test patches one index, enum,
//! consistency or tiling field of a valid database.
mod common;

use common::*;
use qinit_db_core::*;

fn tid(t: usize) -> u8 {
    u8::try_from(t).unwrap()
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
        w[i] = 4;
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
fn a_node_record_has_24_words() {
    assert_eq!(WORDS[T_NODES], 24);
    assert_eq!(N_START_TIMEOUT_MS + 1, WORDS[T_NODES]);
}

#[test]
fn a_restart_delay_or_grace_under_the_floor_is_a_consistency_error() {
    for w in [N_RESTART_DELAY_MS, N_STOP_GRACE_MS] {
        let db = with(&valid_minimal(), |v| {
            let i = at(v, T_NODES, 0, w);
            v[i] = MIN_DELAY_MS - 1;
        });
        assert_eq!(
            check(&db),
            Err(DbError::Consistency {
                table: 0,
                record: 0
            }),
            "word {w}"
        );
        let db = with(&valid_minimal(), |v| {
            let i = at(v, T_NODES, 0, w);
            v[i] = MIN_DELAY_MS;
        });
        assert_eq!(check(&db), Ok(()), "word {w}");
    }
}

#[test]
fn a_stop_mode_above_1_is_an_enum_error() {
    let db = with(&valid_minimal(), |v| {
        let i = at(v, T_NODES, 0, N_STOP_MODE);
        v[i] = 2;
    });
    assert_eq!(
        check(&db),
        Err(DbError::Enum {
            table: 0,
            record: 0
        })
    );
}

#[test]
fn a_restart_limit_without_a_window_is_a_consistency_error() {
    let db = with(&valid_minimal(), |v| {
        let m = at(v, T_NODES, 0, N_RESTART_MAX);
        v[m] = 3;
        let p = at(v, T_NODES, 0, N_RESTART_POLICY);
        v[p] = 1;
    });
    assert_eq!(
        check(&db),
        Err(DbError::Consistency {
            table: 0,
            record: 0
        })
    );
    let db = with(&db, |v| {
        let w = at(v, T_NODES, 0, N_RESTART_WINDOW_MS);
        v[w] = 60_000;
    });
    assert_eq!(check(&db), Ok(()));
}

#[test]
fn the_cascade_flag_is_accepted_and_bit_2_is_not() {
    let db = with(&valid_minimal(), |v| {
        let i = at(v, T_EDGES, 0, E_FLAGS);
        v[i] = E_FLAG_CASCADE;
    });
    assert_eq!(check(&db), Ok(()));
    let db = with(&valid_minimal(), |v| {
        let i = at(v, T_EDGES, 0, E_FLAGS);
        v[i] = 4;
    });
    assert_eq!(
        check(&db),
        Err(DbError::Enum {
            table: 2,
            record: 0
        })
    );
}
