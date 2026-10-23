// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! preflight: which required tools are missing from PATH.
use std::path::Path;

/// (binary, install line). List the tools of planned gates too.
pub const REQUIRED: &[(&str, &str)] = &[
    ("cargo", "https://rustup.rs"),
    ("rustfmt", "rustup component add rustfmt"),
    ("cargo-clippy", "rustup component add clippy"),
    ("git", "your package manager"),
];

#[must_use]
pub fn missing<'a>(
    required: &'a [(&'a str, &'a str)],
    present: &dyn Fn(&str) -> bool,
) -> Vec<&'a (&'a str, &'a str)> {
    required.iter().filter(|(tool, _)| !present(tool)).collect()
}

/// Scans PATH. Never runs `--version`: subcommand shims (`cargo-clippy`)
/// exit non-zero when run directly.
#[must_use]
pub fn on_path(tool: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| resolve_in(&paths, tool).is_some())
}

/// The first executable named `tool` in a PATH-style list.
#[must_use]
pub fn resolve_in(path: &std::ffi::OsStr, tool: &str) -> Option<std::path::PathBuf> {
    std::env::split_paths(path)
        .map(|dir| dir.join(tool))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[must_use]
pub fn report(missing: &[&(&str, &str)]) -> String {
    missing
        .iter()
        .map(|(tool, install)| format!("missing: {tool}  (install: {install})"))
        .collect::<Vec<_>>()
        .join("\n")
}
