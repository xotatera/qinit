// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The files the scans read: tracked and untracked-but-not-ignored, via git.
use std::path::Path;

/// # Errors
/// A git failure, or a non-UTF-8 path.
pub fn files(root: &Path) -> Result<Vec<String>, String> {
    let out = crate::git::command()
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .current_dir(root)
        .output()
        .map_err(|e| format!("git ls-files: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let text = String::from_utf8(out.stdout).map_err(|e| format!("git ls-files: {e}"))?;
    let mut files: Vec<String> = text
        .split('\0')
        .filter(|f| !f.is_empty() && root.join(f).is_file())
        .map(str::to_string)
        .collect();
    files.sort();
    files.dedup();
    Ok(files)
}

/// The first line of a listed file; empty when unreadable or binary.
#[must_use]
pub fn first_line(root: &Path, file: &str) -> String {
    use std::io::BufRead;
    std::fs::File::open(root.join(file))
        .ok()
        .and_then(|f| std::io::BufReader::new(f).lines().next()?.ok())
        .unwrap_or_default()
}
