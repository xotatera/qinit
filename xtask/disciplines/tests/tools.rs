// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

mod common;
use common::exe as write_script;
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
    let scratch = scratch("resolve_in_finds_the_first_executable_only");
    let dir = &scratch.0;
    let (a, b) = (dir.join("a"), dir.join("b"));
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    std::fs::write(a.join("tool"), "not executable").unwrap();
    write_script(&b.join("tool"), "#!/bin/sh\n");
    let path = std::env::join_paths([&a, &b]).unwrap();
    assert_eq!(
        xtask::tools::resolve_in(&path, "tool"),
        Some(b.join("tool"))
    );
    assert_eq!(xtask::tools::resolve_in(&path, "absent"), None);
}

#[test]
fn cargo_verus_version_requires_the_selected_release() {
    let scratch = scratch("cargo_verus_version_requires_the_selected_release");
    std::fs::create_dir_all(&scratch.0).unwrap();
    let cargo_verus = scratch.0.join("cargo-verus");
    write_script(&cargo_verus, "#!/bin/sh\n");
    let verus = scratch.0.join("verus");
    write_script(
        &verus,
        "#!/bin/sh\nprintf '%s\\n' 'Verus' '  Version: 0.2026.10.04.426d8b0'\n",
    );
    assert_eq!(xtask::tools::cargo_verus_version(&cargo_verus), Ok(()));

    write_script(
        &verus,
        "#!/bin/sh\nprintf '%s\\n' 'Verus' '  Version: 0.2026.10.05.next'\n",
    );
    let error = xtask::tools::cargo_verus_version(&cargo_verus).unwrap_err();
    assert!(error.contains("cargo-verus driver"), "{error}");
    assert!(
        error.contains("reported Verus 0.2026.10.05.next"),
        "{error}"
    );
    assert!(error.contains("expected 0.2026.10.04.426d8b0"), "{error}");
}

#[test]
fn cargo_verus_version_reports_a_missing_driver() {
    let scratch = scratch("cargo_verus_version_reports_a_missing_driver");
    let error =
        xtask::tools::cargo_verus_version(&scratch.0.join("missing-cargo-verus")).unwrap_err();
    assert!(
        error.contains("cannot resolve cargo-verus driver"),
        "{error}"
    );
    assert!(error.contains("missing-cargo-verus"), "{error}");
}

#[test]
fn verusfmt_is_pinned_beside_the_selected_verus_release() {
    assert_eq!(xtask::tools::VERUSFMT_VERSION, "0.7.4");
    assert_eq!(
        xtask::tools::VERUSFMT_INSTALL,
        "cargo install --locked verusfmt --version 0.7.4"
    );
}

#[test]
fn verusfmt_version_requires_the_pinned_release() {
    let scratch = scratch("verusfmt_version_requires_the_pinned_release");
    std::fs::create_dir_all(&scratch.0).unwrap();
    let verusfmt = scratch.0.join("verusfmt");
    write_script(&verusfmt, "#!/bin/sh\necho 'verusfmt 0.7.4'\n");
    assert_eq!(xtask::tools::verusfmt_version(&verusfmt), Ok(()));

    write_script(&verusfmt, "#!/bin/sh\necho 'verusfmt 0.7.5'\n");
    let error = xtask::tools::verusfmt_version(&verusfmt).unwrap_err();
    assert!(error.contains("reported verusfmt 0.7.5"), "{error}");
    assert!(error.contains("expected 0.7.4"), "{error}");
    assert!(error.contains("--version 0.7.4"), "{error}");

    write_script(&verusfmt, "#!/bin/sh\necho 'something else'\n");
    let error = xtask::tools::verusfmt_version(&verusfmt).unwrap_err();
    assert!(error.contains("did not report a version"), "{error}");

    write_script(&verusfmt, "#!/bin/sh\necho broken >&2\nexit 3\n");
    let error = xtask::tools::verusfmt_version(&verusfmt).unwrap_err();
    assert!(error.contains("--version failed"), "{error}");
    assert!(error.contains("broken"), "{error}");
}

#[test]
fn verusfmt_version_reports_a_missing_binary() {
    let scratch = scratch("verusfmt_version_reports_a_missing_binary");
    let error = xtask::tools::verusfmt_version(&scratch.0.join("verusfmt")).unwrap_err();
    assert!(error.contains("cannot run verusfmt"), "{error}");
}
