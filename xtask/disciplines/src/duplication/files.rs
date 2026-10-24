// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The Rust files the duplication gate reads: relative to the root,
//! `/`-separated, sorted.
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use crate::git;

/// Directories never scanned, at the root or anywhere below: vendored or
/// generated code.
pub const EXCLUDE: &[&str] = &["vendor/", "third_party/"];

/// Tracked and untracked-but-not-ignored `.rs` files, via git. When `root`
/// is not in a git repository: a walk skipping hidden directories and `target`.
///
/// # Errors
/// An unreadable directory during the walk, a non-UTF-8 file name, or a
/// git failure other than "not a git repository".
pub fn rust_files(root: &Path) -> Result<Vec<String>, String> {
    let listed = git::command()
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "*.rs",
        ])
        .current_dir(root)
        .output()
        .map_err(|e| format!("git ls-files: {e}"))?;
    let mut files: Vec<String> = if listed.status.success() {
        let mut out = Vec::new();
        for p in listed.stdout.split(|b| *b == 0).filter(|p| !p.is_empty()) {
            let Ok(p) = std::str::from_utf8(p) else {
                return Err(format!(
                    "{}: a non-UTF-8 file name; the duplication gate cannot read it (rename it)",
                    String::from_utf8_lossy(p)
                ));
            };
            if root.join(p).is_file() {
                out.push(p.to_string());
            }
        }
        out
    } else if String::from_utf8_lossy(&listed.stderr).contains("not a git repository") {
        let mut found = Vec::new();
        walk(
            root,
            "",
            &|name| Path::new(name).extension().is_some_and(|e| e == "rs"),
            &mut found,
        )?;
        found
    } else {
        return Err(format!(
            "git ls-files: {}",
            String::from_utf8_lossy(&listed.stderr).trim()
        ));
    };
    files.retain(|p| !excluded(p));
    files.sort();
    files.dedup();
    Ok(files)
}

fn excluded(path: &str) -> bool {
    EXCLUDE
        .iter()
        .any(|e| path.starts_with(e) || path.contains(&format!("/{e}")))
}

/// Collects the files below `root/rel` whose name `keep` accepts, skipping
/// hidden directories and `target`. Names are converted lossily; see
/// `walk_paths` for byte-exact paths.
pub(crate) fn walk(
    root: &Path,
    rel: &str,
    keep: &dyn Fn(&str) -> bool,
    out: &mut Vec<String>,
) -> Result<(), String> {
    walk_paths(root, Path::new(rel), Walk::Source, &mut |path| {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if keep(&name) {
            out.push(path.to_string_lossy().into_owned());
        }
        Ok(())
    })
}

/// How `walk_paths` treats build output and symlinks.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Walk {
    /// Source files: hidden directories and `target` skipped, symlinks ignored.
    Source,
    /// An outside dependency: only `.git` and directories holding cargo's
    /// `CACHEDIR.TAG` (build output) skipped; a symlinked file is followed, a
    /// symlinked directory is an error.
    Outside,
    /// A declared extra directory: every file, symlinked files followed, a
    /// symlinked directory an error.
    Full,
}

/// Calls `visit` with every file below `root/rel`, as a path relative to
/// `root` that keeps each name byte for byte. An `Err` from `visit` stops
/// the walk. Special files (FIFOs, sockets, devices) are never visited.
///
/// # Errors
/// An unreadable directory; outside `Walk::Source`, a symlinked directory
/// or a dangling symlink.
pub(crate) fn walk_paths(
    root: &Path,
    rel: &Path,
    mode: Walk,
    visit: &mut dyn FnMut(PathBuf) -> Result<(), String>,
) -> Result<(), String> {
    let dir = root.join(rel);
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let path = rel.join(&name);
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        let full = root.join(&path);
        if kind.is_dir() {
            if !skipped(mode, &full) {
                walk_paths(root, &path, mode, visit)?;
            }
        } else if kind.is_file() {
            visit(path)?;
        } else if kind.is_symlink() && mode != Walk::Source {
            match full.metadata() {
                Ok(meta) if meta.is_file() => visit(path)?,
                Ok(meta) if meta.is_dir() && skipped(mode, &full) => {}
                Ok(meta) if meta.is_dir() => {
                    return Err(format!(
                        "{}: symlinked directory; the cache cannot fingerprint it",
                        full.display()
                    ));
                }
                Ok(_) => {}
                Err(e) => return Err(format!("{}: {e}", full.display())),
            }
        }
    }
    Ok(())
}

/// Whether `walk_paths` skips the directory `dir` in `mode`.
fn skipped(mode: Walk, dir: &Path) -> bool {
    let name = dir.file_name().unwrap_or_default();
    match mode {
        Walk::Source => name.as_bytes().starts_with(b".") || name == "target",
        Walk::Outside => name == ".git" || dir.join("CACHEDIR.TAG").is_file(),
        Walk::Full => false,
    }
}
