// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The record rules for credentials, routes and node route indices: each test patches one field
//! of a valid database to its first refused value, and checks the last accepted value passes.
mod common;

use common::*;
use qinit_db_core::*;

fn tid(t: usize) -> u8 {
    u8::try_from(t).unwrap()
}

/// [`minimal_spec`] with a path route 0 and a pipe route 1 into worker `b`.
fn spec() -> DbSpec {
    let mut spec = minimal_spec();
    spec.routes = vec![RouteSpec::Path("/var/log/a"), RouteSpec::Pipe(1)];
    spec
}

/// [`spec`] laid out, with word `w` of record `r` in table `t` set to `value`.
fn patched(t: usize, r: usize, w: usize, value: u32) -> Vec<u8> {
    with(&build(&spec()), |words| {
        let index = at(words, t, r, w);
        words[index] = value;
    })
}

fn enum_error(t: usize) -> Result<(), DbError> {
    Err(DbError::Enum {
        table: tid(t),
        record: 0,
    })
}

fn consistency_error(t: usize) -> Result<(), DbError> {
    Err(DbError::Consistency {
        table: tid(t),
        record: 0,
    })
}

#[test]
fn the_base_database_validates() {
    assert_eq!(check(&build(&spec())), Ok(()));
}

#[test]
fn an_error_route_past_the_route_table_is_an_index_error() {
    assert_eq!(check(&patched(T_NODES, 0, N_ERRORS, 1)), Ok(()));
    assert_eq!(
        check(&patched(T_NODES, 0, N_ERRORS, 2)),
        Err(DbError::Index {
            table: tid(T_NODES),
            record: 0
        })
    );
}

#[test]
fn an_unknown_route_kind_is_an_enum_error() {
    assert_eq!(
        check(&patched(T_ROUTES, 0, R_KIND, 2)),
        enum_error(T_ROUTES)
    );
}

#[test]
fn a_pipe_route_with_a_length_is_a_consistency_error() {
    assert_eq!(
        check(&patched(T_ROUTES, 1, R_B, 1)),
        Err(DbError::Consistency {
            table: tid(T_ROUTES),
            record: 1
        })
    );
}

#[test]
fn securebits_above_2_is_an_enum_error() {
    assert_eq!(check(&patched(T_CREDS, 0, C_SECUREBITS, 2)), Ok(()));
    assert_eq!(
        check(&patched(T_CREDS, 0, C_SECUREBITS, 3)),
        enum_error(T_CREDS)
    );
}

#[test]
fn nnp_above_1_is_an_enum_error() {
    assert_eq!(check(&patched(T_CREDS, 0, C_NNP, 1)), Ok(()));
    assert_eq!(check(&patched(T_CREDS, 0, C_NNP, 2)), enum_error(T_CREDS));
}

#[test]
fn namespace_bits_above_0x3f_are_an_enum_error() {
    assert_eq!(check(&patched(T_CREDS, 0, C_NS, 0x1f)), Ok(()));
    assert_eq!(check(&patched(T_CREDS, 0, C_NS, 0x40)), enum_error(T_CREDS));
}

#[test]
fn capability_bits_above_40_are_an_enum_error() {
    // `caps_lo` holds bits 0..=31, all valid; `caps_hi` holds bits 32..=40 in its bits 0..=8.
    assert_eq!(check(&patched(T_CREDS, 0, C_CAPS_LO, u32::MAX)), Ok(()));
    assert_eq!(check(&patched(T_CREDS, 0, C_CAPS_HI, 0x1ff)), Ok(()));
    assert_eq!(
        check(&patched(T_CREDS, 0, C_CAPS_HI, 0x200)),
        enum_error(T_CREDS)
    );
    assert_eq!(
        check(&patched(T_CREDS, 0, C_CAPS_HI, 0x8000_0000)),
        enum_error(T_CREDS)
    );
}

#[test]
fn an_empty_user_is_an_enum_error() {
    let mut spec = spec();
    spec.creds[0].user = "";
    assert_eq!(check(&build(&spec)), enum_error(T_CREDS));
}

#[test]
fn seccomp_mode_and_list_agree() {
    let mut spec = spec();
    spec.creds[0].seccomp = 4;
    assert_eq!(check(&build(&spec)), enum_error(T_CREDS));
    spec.creds[0].seccomp = 1;
    spec.creds[0].seccomp_list = "101";
    assert_eq!(check(&build(&spec)), enum_error(T_CREDS));
    spec.creds[0].seccomp = 2;
    spec.creds[0].seccomp_list = "";
    assert_eq!(check(&build(&spec)), enum_error(T_CREDS));
    spec.creds[0].seccomp_list = "0\x00101\x00511";
    assert_eq!(check(&build(&spec)), Ok(()));
    spec.creds[0].seccomp = 3;
    assert_eq!(check(&build(&spec)), Ok(()));
    for bad in ["512", "01", "1a", "1000", "-1", ""] {
        spec.creds[0].seccomp_list = bad;
        assert_eq!(
            check(&build(&spec)),
            if bad.is_empty() {
                enum_error(T_CREDS)
            } else {
                consistency_error(T_CREDS)
            },
            "{bad:?}"
        );
    }
}

#[test]
fn nnp_off_with_a_sandbox_needs_sys_admin() {
    let mut spec = spec();
    spec.creds[0].nnp = 0;
    assert_eq!(check(&build(&spec)), Ok(()));
    spec.creds[0].seccomp = 1;
    assert_eq!(check(&build(&spec)), consistency_error(T_CREDS));
    spec.creds[0].caps = 1 << CAP_SYS_ADMIN_BIT;
    assert_eq!(check(&build(&spec)), Ok(()));
    spec.creds[0].caps = 1 << 20;
    assert_eq!(check(&build(&spec)), consistency_error(T_CREDS));
}
