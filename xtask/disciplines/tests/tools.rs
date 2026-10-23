// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use xtask::tools::{missing, report};

const REQUIRED: &[(&str, &str)] = &[("a", "install a"), ("b", "install b")];

#[test]
fn names_every_missing_tool_with_its_install_line() {
    let gone = missing(REQUIRED, &|t| t == "a");
    assert_eq!(gone, [&("b", "install b")]);
    assert_eq!(report(&gone), "missing: b  (install: install b)");
}

#[test]
fn nothing_missing_when_all_present() {
    assert_eq!(missing(REQUIRED, &|_| true).len(), 0);
}

#[test]
fn path_scan_finds_sh_and_not_nonsense() {
    assert!(xtask::tools::on_path("sh"));
    assert!(!xtask::tools::on_path("no-such-tool-xtask"));
}

/// A scratch directory removed when the test ends, pass or fail.
struct Scratch(std::path::PathBuf);

/// A scratch directory unique to `test` and this process.
fn scratch(test: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!("xtask-tools-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    Scratch(dir)
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn resolve_in_finds_the_first_executable_only() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = scratch("resolve_in_finds_the_first_executable_only");
    let dir = &scratch.0;
    let (a, b) = (dir.join("a"), dir.join("b"));
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    std::fs::write(a.join("tool"), "not executable").unwrap();
    std::fs::write(b.join("tool"), "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(b.join("tool"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = std::env::join_paths([&a, &b]).unwrap();
    assert_eq!(
        xtask::tools::resolve_in(&path, "tool"),
        Some(b.join("tool"))
    );
    assert_eq!(xtask::tools::resolve_in(&path, "absent"), None);
}
