// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! preflight: which required tools are missing from PATH.
use std::path::Path;
use std::process::Command;

/// The Verus release selected by qinit's approved setup design.
pub const VERUS_VERSION: &str = "0.2026.10.04.426d8b0";
/// How a contributor identifies the selected release when preflight finds no
/// `verus` command.
pub const VERUS_INSTALL: &str = "the selected Verus 0.2026.10.04.426d8b0 release";

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

/// Runs the selected `verus --version` command and rejects every release
/// other than [`VERUS_VERSION`].
///
/// # Errors
/// When the command cannot run, exits unsuccessfully, does not identify a
/// Verus release, or reports a different release.
pub fn verus_version(verus: &Path) -> Result<(), String> {
    let output = Command::new(verus)
        .arg("--version")
        .output()
        .map_err(|e| format!("cannot run `{}` --version: {e}", verus.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr
            .trim()
            .is_empty()
            .then(String::new)
            .unwrap_or_else(|| format!(": {}", stderr.trim()));
        return Err(format!(
            "`{} --version` failed ({}){detail}",
            verus.display(),
            output.status,
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let actual = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("Version: "));
    match actual {
        Some(version) if version == VERUS_VERSION => Ok(()),
        Some(version) => Err(format!(
            "`{} --version` reported Verus {version}; expected {VERUS_VERSION}",
            verus.display()
        )),
        None => Err(format!(
            "`{} --version` did not report a Verus version; expected {VERUS_VERSION}",
            verus.display()
        )),
    }
}
