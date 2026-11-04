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
    spec.nodes[0].cred = 1;
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
        caps: 1 << 41,
        ..cred("daemon")
    });
    assert_eq!(
        check(&build(&spec)),
        Err(DbError::Enum {
            table: tid(T_CREDS),
            record: 1
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

#[test]
fn a_node_record_has_68_words_and_a_credential_12() {
    assert_eq!(WORDS[T_NODES], 68);
    assert_eq!(N_RLIMIT_BASE, N_LAUNCH_FDS + 1);
    assert_eq!(N_RLIMIT_BASE + 2 * RLIMIT_COUNT, WORDS[T_NODES]);
    assert_eq!(N_RELOAD, N_RLIMIT_MASK + 1);
    assert_eq!(WORDS[T_CREDS], 12);
    assert_eq!(C_SECCOMP_LEN + 1, WORDS[T_CREDS]);
}

#[test]
fn an_umask_above_0o777_is_an_enum_error() {
    let db = with(&valid_minimal(), |w| {
        let i = at(w, T_NODES, 0, N_UMASK);
        w[i] = 0o777;
    });
    assert_eq!(check(&db), Ok(()));
    let db = with(&valid_minimal(), |w| {
        let i = at(w, T_NODES, 0, N_UMASK);
        w[i] = 0o1000;
    });
    assert_eq!(
        check(&db),
        Err(DbError::Enum {
            table: tid(T_NODES),
            record: 0
        })
    );
}

#[test]
fn a_worker_or_forager_without_a_credential_is_a_consistency_error() {
    for kind in [0, 1] {
        let mut spec = minimal_spec();
        spec.nodes[1].kind = kind;
        spec.nodes[1].cred = NONE;
        assert_eq!(
            check(&build(&spec)),
            Err(DbError::Consistency {
                table: tid(T_NODES),
                record: 1
            }),
            "kind {kind}"
        );
    }
}

#[test]
fn a_brood_with_a_credential_is_a_consistency_error() {
    let mut spec = minimal_spec();
    spec.nodes[1].kind = 2;
    assert_eq!(
        check(&build(&spec)),
        Err(DbError::Consistency {
            table: tid(T_NODES),
            record: 1
        })
    );
    spec.nodes[1].cred = NONE;
    assert_eq!(check(&build(&spec)), Ok(()));
}

#[test]
fn a_relative_or_empty_cwd_is_a_consistency_error() {
    for bad in ["var/lib", ""] {
        let mut spec = minimal_spec();
        spec.nodes[0].cwd = bad;
        assert_eq!(
            check(&build(&spec)),
            Err(DbError::Consistency {
                table: tid(T_NODES),
                record: 0
            }),
            "{bad:?}"
        );
    }
}

#[test]
fn a_path_entry_without_its_prefix_is_consistency() {
    for bad in ["xx:/a", "/a", "ro:", "ro:a"] {
        let mut spec = minimal_spec();
        spec.creds[0].paths = bad;
        assert_eq!(
            check(&build(&spec)),
            Err(DbError::Consistency {
                table: tid(T_CREDS),
                record: 0
            }),
            "{bad:?}"
        );
    }
}

#[test]
fn a_non_canonical_path_entry_is_consistency() {
    for bad in [
        "ro:/a/..",
        "rw:/tmp/",
        "ro://x",
        "rw:/dev/.",
        "ro:/a//b",
        "ro:/a/./b",
        "ro:/a/../b",
    ] {
        let mut spec = minimal_spec();
        spec.creds[0].paths = bad;
        assert_eq!(
            check(&build(&spec)),
            Err(DbError::Consistency {
                table: tid(T_CREDS),
                record: 0
            }),
            "{bad:?}"
        );
    }
    let spec = with_paths("ro:/a/b\0ro:/bin\0rw:/c/.d/..e/f.", 1);
    assert_eq!(check(&build(&spec)), Ok(()));
}

fn with_paths(paths: &'static str, ns: u32) -> DbSpec {
    let mut spec = minimal_spec();
    spec.creds[0].paths = paths;
    spec.creds[0].ns = ns;
    spec
}

fn cred_consistency() -> Result<(), DbError> {
    Err(DbError::Consistency {
        table: tid(T_CREDS),
        record: 0,
    })
}

#[test]
fn an_unsorted_list_is_consistency() {
    for bad in [
        "ro:/b\0ro:/a",
        "ro:/a\0rw:/a",
        "ro:/a/b\0ro:/a",
        "ro:/b\0ro:/b",
    ] {
        assert_eq!(
            check(&build(&with_paths(bad, 1))),
            cred_consistency(),
            "{bad:?}"
        );
    }
}

#[test]
fn a_list_without_the_mount_bit_is_consistency() {
    assert_eq!(check(&build(&with_paths("ro:/bin", 0))), cred_consistency());
    assert_eq!(check(&build(&with_paths("ro:/bin", 1))), Ok(()));
}

#[test]
fn a_forbidden_entry_is_consistency() {
    for bad in [
        "ro:/",
        "rw:/dev",
        "ro:/tmp",
        "rw:/proc",
        "ro:/bin\0rw:/proc",
    ] {
        assert_eq!(
            check(&build(&with_paths(bad, 1))),
            cred_consistency(),
            "{bad:?}"
        );
    }
    assert_eq!(
        check(&build(&with_paths("ro:/bin\0ro:/dev/null\0ro:/proc", 1))),
        Ok(())
    );
}

#[test]
fn exec_outside_the_list_is_consistency() {
    let mut spec = with_paths("ro:/opt", 1);
    // The minimal node runs `/bin/true`.
    assert_eq!(check(&build(&spec)), consistency());
    spec = with_paths("ro:/bin", 1);
    assert_eq!(check(&build(&spec)), Ok(()));
    spec.nodes[0].cwd = "/srv";
    assert_eq!(check(&build(&spec)), consistency());
    spec.creds[0].paths = "ro:/bin\0ro:/srv";
    assert_eq!(check(&build(&spec)), Ok(()));
}

#[test]
fn a_non_canonical_cwd_is_consistency() {
    for bad in ["/a/..", "/a/", "//a", "/a/./b", "/a//b", "/.."] {
        let mut spec = minimal_spec();
        spec.nodes[0].cwd = bad;
        assert_eq!(check(&build(&spec)), consistency(), "{bad:?}");
    }
    let mut spec = minimal_spec();
    spec.nodes[0].cwd = "/a/.b/..c";
    assert_eq!(check(&build(&spec)), Ok(()));
}

#[test]
fn an_env_entry_without_a_key_or_without_an_equals_sign_is_a_consistency_error() {
    for bad in ["=x", "NOEQ", "A=1\0=b", "A=1\0B"] {
        let mut spec = minimal_spec();
        spec.nodes[0].env = bad;
        assert_eq!(
            check(&build(&spec)),
            Err(DbError::Consistency {
                table: tid(T_NODES),
                record: 0
            }),
            "{bad:?}"
        );
    }
    let mut spec = minimal_spec();
    spec.nodes[0].env = "A=1\0B=\0C=x=y";
    assert_eq!(check(&build(&spec)), Ok(()));
}

#[test]
fn an_env_list_with_an_empty_element_is_a_pool_error() {
    let mut spec = minimal_spec();
    spec.nodes[0].env = "A=1\0\0B=2";
    assert_eq!(
        check(&build(&spec)),
        Err(DbError::Pool {
            table: tid(T_NODES),
            record: 0
        })
    );
}

fn forager_with(launch: LaunchSpec) -> Vec<u8> {
    let mut spec = minimal_spec();
    spec.nodes[1].kind = 1;
    spec.nodes[1].launch = launch;
    build(&spec)
}

fn launch(concurrency: u32, argv_tail: u32, env: &'static str, fds: u32) -> LaunchSpec {
    LaunchSpec {
        concurrency,
        argv_tail,
        env,
        fds,
    }
}

fn node_error(kind: &str, record: u32) -> DbError {
    match kind {
        "enum" => DbError::Enum {
            table: tid(T_NODES),
            record,
        },
        _ => DbError::Consistency {
            table: tid(T_NODES),
            record,
        },
    }
}

#[test]
fn a_forager_with_a_launch_table_is_accepted() {
    let db = forager_with(launch(
        4,
        8,
        "TARGET\0VERBOSE",
        FD_STDIN | FD_STDOUT | FD_STDERR,
    ));
    assert_eq!(check(&db), Ok(()));
    assert_eq!(check(&forager_with(launch(64, 64, "", 0))), Ok(()));
}

#[test]
fn launch_ranges_are_enum_errors() {
    for bad in [
        launch(65, 0, "", 0),
        launch(1, 65, "", 0),
        launch(1, 0, "", 8),
    ] {
        assert_eq!(check(&forager_with(bad)), Err(node_error("enum", 1)));
    }
    let mut spec = minimal_spec();
    spec.nodes[1].reload = 4;
    assert_eq!(check(&build(&spec)), Err(node_error("enum", 1)));
    spec.nodes[1].reload = 3;
    assert_eq!(check(&build(&spec)), Ok(()));
}

#[test]
fn launch_words_on_a_worker_or_brood_are_a_consistency_error() {
    let mut spec = minimal_spec();
    spec.nodes[1].launch = launch(1, 0, "", 0);
    assert_eq!(check(&build(&spec)), Err(node_error("consistency", 1)));
    spec.nodes[1].kind = 2;
    spec.nodes[1].cred = NONE;
    assert_eq!(check(&build(&spec)), Err(node_error("consistency", 1)));
}

#[test]
fn launch_words_without_a_concurrency_are_a_consistency_error() {
    for bad in [
        launch(0, 1, "", 0),
        launch(0, 0, "A", 0),
        launch(0, 0, "", 1),
    ] {
        assert_eq!(check(&forager_with(bad)), Err(node_error("consistency", 1)));
    }
}

#[test]
fn launch_env_keys_must_be_strictly_ascending() {
    for bad in ["B\0A", "A\0A", "A\0C\0B"] {
        assert_eq!(
            check(&forager_with(launch(1, 0, bad, 0))),
            Err(node_error("consistency", 1)),
            "{bad:?}"
        );
    }
    assert_eq!(check(&forager_with(launch(1, 0, "A\0B\0C", 0))), Ok(()));
}

#[test]
fn a_launch_env_key_may_not_hold_an_equals_sign() {
    assert_eq!(
        check(&forager_with(launch(1, 0, "A=1", 0))),
        Err(node_error("consistency", 1))
    );
}

/// The minimal database with node 0's limit mask `mask` and the low and high words of the
/// limits in `values` (resource, low, high).
fn with_limits(mask: u32, values: &[(usize, u32, u32)]) -> Vec<u8> {
    with(&valid_minimal(), |w| {
        let m = at(w, T_NODES, 0, N_RLIMIT_MASK);
        w[m] = mask;
        for &(r, lo, hi) in values {
            let i = at(w, T_NODES, 0, N_RLIMIT_BASE + 2 * r);
            w[i] = lo;
            w[i + 1] = hi;
        }
    })
}

fn consistency() -> Result<(), DbError> {
    Err(DbError::Consistency {
        table: tid(T_NODES),
        record: 0,
    })
}

fn enum_error() -> Result<(), DbError> {
    Err(DbError::Enum {
        table: tid(T_NODES),
        record: 0,
    })
}

#[test]
fn core_bit_set_is_enum() {
    assert_eq!(check(&with_limits(1 << 4, &[(4, 0, 0)])), enum_error());
}

#[test]
fn bit_16_set_is_enum() {
    assert_eq!(check(&with_limits(1 << 16, &[])), enum_error());
}

#[test]
fn unset_limit_with_a_value_is_consistency() {
    assert_eq!(check(&with_limits(0, &[(6, 5, 0)])), consistency());
    assert_eq!(check(&with_limits(0, &[(6, 0, 1)])), consistency());
}

#[test]
fn nofile_zero_is_consistency() {
    assert_eq!(check(&with_limits(1 << 7, &[(7, 0, 0)])), consistency());
}

#[test]
fn nofile_infinity_is_consistency() {
    let db = with_limits(1 << 7, &[(7, u32::MAX, u32::MAX)]);
    assert_eq!(check(&db), consistency());
}

#[test]
fn nice_41_is_consistency() {
    assert_eq!(check(&with_limits(1 << 13, &[(13, 41, 0)])), consistency());
    assert_eq!(check(&with_limits(1 << 13, &[(13, 0, 1)])), consistency());
}

#[test]
fn rtprio_100_is_consistency() {
    assert_eq!(check(&with_limits(1 << 14, &[(14, 100, 0)])), consistency());
}

#[test]
fn nice_40_rtprio_99_nproc_infinity_are_valid() {
    let mask = (1 << 13) | (1 << 14) | (1 << 6) | (1 << 7);
    let db = with_limits(
        mask,
        &[(13, 40, 0), (14, 99, 0), (6, u32::MAX, u32::MAX), (7, 1, 1)],
    );
    assert_eq!(check(&db), Ok(()));
    assert_eq!(
        check(&with_limits(RLIMIT_MASK_ALLOWED, &[(13, 0, 0)])),
        consistency()
    );
}
