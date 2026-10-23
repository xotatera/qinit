// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The runner locates qinit's repository root, whose product workspace is empty.

#[test]
fn repository_root_is_the_empty_product_workspace() {
    let root = qinit_xtask::repo_root();
    let expected =
        std::fs::canonicalize(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
            .unwrap();
    assert_eq!(root, expected);
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    assert!(manifest.contains("[workspace]"));
    assert!(!manifest.contains("[package]"));
}

fn read(path: &str) -> String {
    std::fs::read_to_string(qinit_xtask::repo_root().join(path)).unwrap()
}

#[test]
fn root_manifest_uses_resolver_three() {
    assert!(
        read("Cargo.toml")
            .lines()
            .any(|line| line == "resolver = \"3\"")
    );
}

#[test]
fn toolchain_pins_rust_rustfmt_and_clippy() {
    let toolchain = read("rust-toolchain.toml");
    assert!(toolchain.lines().any(|line| line == "channel = \"1.98.1\""));
    assert!(
        toolchain
            .lines()
            .any(|line| line == "components = [\"rustfmt\", \"clippy\"]")
    );
}

#[test]
fn pinned_toolchain_is_selected_in_the_repository() {
    let output = std::process::Command::new("rustc")
        .arg("--version")
        .current_dir(qinit_xtask::repo_root())
        .env_remove("RUSTUP_TOOLCHAIN")
        .output()
        .expect("run rustc");
    assert!(output.status.success());
    let version = String::from_utf8_lossy(&output.stdout);
    assert!(version.starts_with("rustc 1.98.1 "), "{version}");
}

#[test]
fn cargo_alias_runs_the_separate_runner_workspace() {
    assert!(read(".cargo/config.toml").lines().any(|line| line
        == "xtask = \"run --manifest-path xtask/Cargo.toml --package qinit-xtask --quiet --\""));
}

#[test]
fn readme_documents_the_setup_without_claiming_more() {
    let readme = read("README.md");
    for expected in [
        "cargo xtask gate --no-cache",
        "sh .githooks/setup-hooks.sh",
        "hooks are opt-in",
        "There is no CI",
        "not usable yet",
        "0.2026.10.04.426d8b0",
    ] {
        assert!(
            readme.contains(expected),
            "README.md must mention {expected}"
        );
    }
}

#[test]
fn root_manifest_sets_the_strict_clippy_policy() {
    let manifest = read("Cargo.toml");
    let policy = "[workspace.lints.clippy]\nall = { level = \"warn\", priority = -1 }\npedantic = { level = \"warn\", priority = -1 }\n";
    assert!(manifest.contains(policy), "{manifest}");
}
