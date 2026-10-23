// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The runner locates qinit's repository root, whose product workspace is empty.

#[test]
fn repository_root_is_the_empty_product_workspace() {
    let root = qinit_xtask::repo_root();
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    assert!(manifest.contains("[workspace]"));
    assert!(!manifest.contains("[package]"));
}
