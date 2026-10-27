// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `lint` gate end to end on a scratch workspace of two lint tables:
//! `a` ratchets `clippy::unwrap_used` in its own table and depends on `b`,
//! whose workspace table does not enable it. Clippy then runs once per
//! table's group, and `a`'s run also lints `b` with `a`'s flags; only each
//! run's own packages are judged. The workspace's build directory stays
//! inside it; atc is hidden (a stand-in that is not available), so the
//! test re-runs itself as a child with that `PATH` (`set_var` is `unsafe`,
//! which the workspace forbids).
use std::fs;
mod common;
use std::path::{Path, PathBuf};
use std::process::Command;

const CHILD: &str = "XTASK_LINT_GATE_ROOT";

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

/// The workspace, with `a`'s source `lib`.
fn scratch(lib: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("xtask-lint-gate-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    write(
        &root.join(".cargo/config.toml"),
        "[build]\nbuild-dir = \"build\"\n",
    );
    write(
        &root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"a\", \"b\"]\nresolver = \"3\"\n\n[workspace.lints.clippy]\nall = { level = \"warn\", priority = -1 }\n",
    );
    write(
        &root.join("a/Cargo.toml"),
        "[package]\nname = \"a\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\nb = { path = \"../b\" }\n\n[lints.clippy]\nall = { level = \"warn\", priority = -1 }\nunwrap_used = \"allow\"  # ratchet: 1\n",
    );
    write(&root.join("a/src/lib.rs"), lib);
    write(
        &root.join("b/Cargo.toml"),
        "[package]\nname = \"b\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lints]\nworkspace = true\n",
    );
    write(
        &root.join("b/src/lib.rs"),
        "#[must_use]\npub fn g(x: Option<u32>) -> u32 {\n    x.unwrap()\n}\n",
    );
    let bin = root.join("bin");
    common::exe(&bin.join("atc"), "#!/bin/sh\nexit 1\n");
    let lock = Command::new("cargo")
        .args(["generate-lockfile", "--offline"])
        .current_dir(&root)
        .status()
        .unwrap();
    assert!(lock.success());
    root
}

#[test]
fn each_tables_group_is_judged_on_its_own_packages() {
    let Some(root) = std::env::var_os(CHILD).map(PathBuf::from) else {
        let root = scratch(
            "#[must_use]\npub fn f(x: Option<u32>) -> u32 {\n    x.unwrap() + b::g(None)\n}\n",
        );
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut dirs = vec![root.join("bin")];
        dirs.extend(std::env::split_paths(&path));
        let out = Command::new(std::env::current_exe().unwrap())
            .args([
                "each_tables_group_is_judged_on_its_own_packages",
                "--exact",
                "--nocapture",
            ])
            .env(CHILD, &root)
            .env("PATH", std::env::join_paths(dirs).unwrap())
            .output()
            .unwrap();
        let _ = fs::remove_dir_all(&root);
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    };
    // `a`'s one unwrap is its ratchet; `b`'s, linted in `a`'s run with
    // `-W clippy::unwrap_used`, is not `a`'s to count nor `b`'s to fail.
    assert_eq!(xtask::gates::lint(&root), Ok(()));
    // A second unwrap in `a` moves the count.
    write(
        &root.join("a/src/lib.rs"),
        "#[must_use]\npub fn f(x: Option<u32>) -> u32 {\n    x.unwrap() + x.unwrap()\n}\n",
    );
    let e = xtask::gates::lint(&root).unwrap_err();
    assert!(
        e.contains("`unwrap_used` has 2 findings, the ratchet allows 1"),
        "{e}"
    );
    // A run that fails to build says so, and no count advice follows.
    write(
        &root.join("a/src/lib.rs"),
        "pub fn f() -> u32 {\n    \"x\"\n}\n",
    );
    let e = xtask::gates::lint(&root).unwrap_err();
    assert!(e.contains("mismatched types"), "{e}");
    assert!(!e.contains("no findings left"), "{e}");
}
