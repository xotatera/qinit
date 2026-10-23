// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use xtask::shell::is_shell_script;

#[test]
fn shell_scripts_are_recognised_by_extension_or_shebang() {
    assert!(is_shell_script("tests/test-hooks.sh", ""));
    assert!(is_shell_script("githooks/pre-commit", "#!/bin/sh"));
    assert!(is_shell_script(
        "githooks/pre-commit",
        "#!/usr/bin/env bash"
    ));
    assert!(is_shell_script("x", "#! /bin/bash -eu"));
}

#[test]
fn other_files_are_not() {
    assert!(!is_shell_script("notes/x.py", "#!/usr/bin/env python3"));
    assert!(!is_shell_script("src/lib.rs", "//! doc"));
    assert!(!is_shell_script("x", "#!/bin/zsh"));
    assert!(!is_shell_script("x", "#!/usr/bin/env"));
    assert!(!is_shell_script("README.md", "# sh"));
}
