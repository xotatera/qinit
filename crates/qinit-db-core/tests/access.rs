// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The in-place accessors read what the builder wrote; they are only called on a database that
//! passed `validate`, the precondition their proofs assume.
mod common;

use common::*;
use qinit_db_core::*;

#[test]
fn accessors_read_what_the_builder_wrote() {
    let db = valid_minimal();
    assert_eq!(check(&db), Ok(()));
    assert_eq!(node_count(&db), 2);
    assert_eq!(node_name(&db, 0), b"a");
    assert_eq!(node_name(&db, 1), b"b");
    assert_eq!(node_word(&db, 0, N_GROUP_COUNT), 1);
    assert_eq!(node_word(&db, 0, N_RESTART_DELAY_MS), 1000);
    let g = node_word(&db, 0, N_GROUP_FIRST) as usize;
    assert_eq!(group_word(&db, g, G_KIND), 0);
    let x = group_word(&db, g, G_EDGE_FIRST) as usize;
    assert_eq!(edge_word(&db, x, E_TARGET), 1);
    assert_eq!(edge_word(&db, x, E_MODE), 0);
    assert_eq!(enabled_count(&db), 2);
    assert_eq!((enabled(&db, 0), enabled(&db, 1)), (0, 1));
}
