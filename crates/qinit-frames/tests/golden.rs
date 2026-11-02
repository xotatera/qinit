// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The golden tree compiles to `tests/golden/expected.db` byte for byte.
//!
//! `UPDATE_GOLDEN=1 cargo test -p qinit-frames --test golden` rewrites `expected.db` and
//! `expected.dump`, then fails on purpose so an update run never passes; review the dump
//! against the frames, re-run without `UPDATE_GOLDEN`, and commit both. Run the update with
//! `--test golden` only: `pipeline::the_dump_is_stable` reads `expected.dump` and must not run
//! while it is being rewritten.
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
        panic!("golden files updated; re-run without UPDATE_GOLDEN");
    }
    let want = std::fs::read(dir.join("expected.db")).expect("expected.db");
    assert!(c.bytes == want, "bytes differ from expected.db");
    let m = qinit_db::open(&c.bytes).expect("validates").decode();
    assert_eq!(m.nodes.len(), 8);
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);
}
