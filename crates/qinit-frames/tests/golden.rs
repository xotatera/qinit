// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The golden tree compiles to `tests/golden/expected.db` byte for byte.
//!
//! `UPDATE_GOLDEN=1 cargo test -p qinit-frames --test golden` rewrites `expected.db` and
//! `expected.dump`; review the dump against the frames before committing both.
mod common;

use common::{golden_dir, golden_input};
use qinit_frames::compile::compile;

#[test]
fn the_golden_tree_compiles_to_the_expected_bytes() {
    let c = compile(&golden_input()).expect("golden compiles");
    let dir = golden_dir();
    if std::env::var_os("UPDATE_GOLDEN").is_some_and(|v| v == "1") {
        std::fs::write(dir.join("expected.db"), &c.bytes).expect("write expected.db");
        std::fs::write(dir.join("expected.dump"), &c.dump).expect("write expected.dump");
    }
    let want = std::fs::read(dir.join("expected.db")).expect("expected.db");
    assert!(c.bytes == want, "bytes differ from expected.db");
    let m = qinit_db::open(&c.bytes).expect("validates").decode();
    assert_eq!(m.nodes.len(), 8);
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);
}
