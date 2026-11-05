// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! D26: a root compile reads only what is root's and not writable by group or other.
//!
//! The check is against misconfiguration, not a concurrent writer: the compiler reads the same
//! paths by name afterwards, and a tree that passed can then be changed only by root.
use std::collections::HashSet;
use std::fmt;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// One `lstat`ed path.
#[derive(Clone, Debug)]
pub struct Entry {
    /// The path, absolute.
    pub path: PathBuf,
    /// The owner uid.
    pub uid: u32,
    /// The permission bits and the sticky, setuid and setgid bits (`st_mode & 0o7777`).
    pub mode: u32,
    /// Whether the path is a symbolic link.
    pub symlink: bool,
}

/// Why the check refuses.
#[derive(Debug)]
pub enum Refusal {
    /// Not root's, or writable by group or other.
    Owner {
        /// The path.
        path: PathBuf,
        /// Its owner.
        uid: u32,
        /// Its mode.
        mode: u32,
    },
    /// A symbolic link in the set.
    Symlink(PathBuf),
    /// A path that could not be examined or listed.
    Io(PathBuf, io::Error),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Owner { path, uid, mode } => write!(
                f,
                "qctl: {}: owned by uid {uid}, mode {mode:o}: the policy and the layers must be root's and not writable by group or other",
                path.display()
            ),
            Self::Symlink(path) => write!(f, "qctl: {}: is a symbolic link", path.display()),
            Self::Io(path, e) => write!(f, "qctl: {}: {e}", path.display()),
        }
    }
}

impl std::error::Error for Refusal {}

/// The rule, applied in order: no symbolic link, uid 0, `mode & 0o022 == 0`; the first failure.
///
/// # Errors
/// The first entry that breaks the rule.
pub fn judge(entries: &[Entry]) -> Result<(), Refusal> {
    for e in entries {
        if e.symlink {
            return Err(Refusal::Symlink(e.path.clone()));
        }
        if e.uid != 0 || e.mode & 0o022 != 0 {
            return Err(Refusal::Owner {
                path: e.path.clone(),
                uid: e.uid,
                mode: e.mode,
            });
        }
    }
    Ok(())
}

fn lstat(path: &Path) -> Result<(Entry, bool), Refusal> {
    let m = std::fs::symlink_metadata(path).map_err(|e| Refusal::Io(path.to_owned(), e))?;
    let entry = Entry {
        path: path.to_owned(),
        uid: m.uid(),
        mode: m.mode() & 0o7777,
        symlink: m.file_type().is_symlink(),
    };
    Ok((entry, m.is_dir()))
}

fn walk(dir: &Path, seen: &mut HashSet<PathBuf>, out: &mut Vec<Entry>) -> Result<(), Refusal> {
    let rd = std::fs::read_dir(dir).map_err(|e| Refusal::Io(dir.to_owned(), e))?;
    let mut children = Vec::new();
    for item in rd {
        let item = item.map_err(|e| Refusal::Io(dir.to_owned(), e))?;
        children.push(item.path());
    }
    children.sort();
    for child in children {
        let (entry, is_dir) = lstat(&child)?;
        if !seen.insert(child.clone()) {
            continue;
        }
        out.push(entry);
        // A symbolic link is recorded and never followed (`lstat` reports it as no directory).
        if is_dir {
            walk(&child, seen, out)?;
        }
    }
    Ok(())
}

/// Every root, everything below each root, and every ancestor of each root up to `/`, by `lstat`.
/// Ancestors come first (from `/` down) for each root; a path appears once.
///
/// # Errors
/// [`Refusal::Io`] for a path that cannot be examined or a directory that cannot be listed.
pub fn collect(roots: &[&Path]) -> Result<Vec<Entry>, Refusal> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for root in roots {
        let abs = std::path::absolute(root).map_err(|e| Refusal::Io((*root).to_owned(), e))?;
        let mut chain: Vec<&Path> = abs.ancestors().collect();
        chain.reverse();
        let mut root_is_dir = false;
        for p in chain {
            let (entry, is_dir) = lstat(p)?;
            root_is_dir = is_dir;
            if seen.insert(p.to_owned()) {
                out.push(entry);
            }
        }
        if root_is_dir {
            walk(&abs, &mut seen, &mut out)?;
        }
    }
    Ok(out)
}

/// The check: as root, collect and judge; otherwise one notice line and success.
///
/// # Errors
/// The [`Refusal`] of a root run.
pub fn check(roots: &[&Path], euid: u32, err: &mut dyn Write) -> Result<(), Refusal> {
    if euid != 0 {
        let _ = writeln!(
            err,
            "qctl: not root: the ownership of the policy and layers is not checked"
        );
        return Ok(());
    }
    judge(&collect(roots)?)
}

/// The effective user id: the owner of `/proc/self` (no `libc`). Fails closed: when `/proc/self`
/// cannot be read the user is taken as root, so the ownership check runs rather than being skipped.
#[must_use]
pub fn geteuid() -> u32 {
    euid_from(std::fs::metadata("/proc/self"))
}

/// [`geteuid`] over the given `metadata` result; an error gives 0 (root), failing closed.
#[must_use]
pub fn euid_from(metadata: io::Result<std::fs::Metadata>) -> u32 {
    metadata.map_or(0, |m| m.uid())
}
