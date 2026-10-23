// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Cache entries: one file per (gate, key) under the git common dir, which
//! every worktree of a clone shares. Each file holds the unix time of the
//! pass. Only passes are stored.
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::git;

/// Entries kept per gate. A disk-use bound, not a gate threshold.
pub const KEEP: usize = 20;
pub const DIR_NAME: &str = "disciplines-gate-cache";
/// Last run time per proof gate, for the parallel batch's start order.
const DURATIONS: &str = "proof-durations";

pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// # Errors
    /// When git cannot name the repository's common dir.
    pub fn open(root: &Path) -> Result<Store, String> {
        let out = git::command()
            .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
            .current_dir(root)
            .output()
            .map_err(|e| format!("git rev-parse: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "git rev-parse: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let mut bytes = out.stdout;
        while bytes.last().is_some_and(|b| matches!(b, b'\n' | b'\r')) {
            bytes.pop();
        }
        Ok(Store::at(
            PathBuf::from(OsString::from_vec(bytes)).join(DIR_NAME),
        ))
    }

    #[must_use]
    pub fn at(dir: PathBuf) -> Store {
        Store { dir }
    }

    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The unix time `gate` passed with `key`, if it did.
    ///
    /// # Errors
    /// An invalid name, or an entry that exists but cannot be read or parsed.
    pub fn hit(&self, gate: &str, key: &str) -> Result<Option<u64>, String> {
        check_name(gate)?;
        check_name(key)?;
        let path = self.dir.join(gate).join(key);
        match std::fs::read_to_string(&path) {
            Ok(text) => text
                .strip_prefix("passed ")
                .and_then(|t| t.trim().parse().ok())
                .map(Some)
                .ok_or_else(|| format!("{}: corrupt cache entry", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// Writes a temp file and renames it, so readers never see half an
    /// entry. Then prunes the gate's directory, keeping this entry.
    ///
    /// # Errors
    /// An invalid name, or when the directory or the entry cannot be written.
    pub fn record(&self, gate: &str, key: &str, when: u64) -> Result<(), String> {
        check_name(gate)?;
        check_name(key)?;
        let dir = self.dir.join(gate);
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let tmp = dir.join(format!(".tmp-{key}-{}", std::process::id()));
        let dest = dir.join(key);
        if let Err(e) = std::fs::write(&tmp, format!("passed {when}\n")) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("{}: {e}", tmp.display()));
        }
        if let Err(e) = std::fs::rename(&tmp, &dest) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("{}: {e}", dest.display()));
        }
        prune(&dir, key);
        Ok(())
    }

    /// Last run time in seconds per proof gate; empty when the file is
    /// missing or unreadable, and malformed lines are skipped.
    #[must_use]
    pub fn durations(&self) -> std::collections::BTreeMap<String, u64> {
        let Ok(text) = std::fs::read_to_string(self.dir.join(DURATIONS)) else {
            return std::collections::BTreeMap::new();
        };
        text.lines()
            .filter_map(|l| {
                let (gate, secs) = l.rsplit_once(' ')?;
                Some((gate.to_string(), secs.parse().ok()?))
            })
            .collect()
    }

    /// # Errors
    /// When the file cannot be written.
    pub fn record_duration(&self, gate: &str, secs: u64) -> Result<(), String> {
        let mut all = self.durations();
        all.insert(gate.to_string(), secs);
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("{}: {e}", self.dir.display()))?;
        let text = all.iter().fold(String::new(), |mut out, (g, s)| {
            out.push_str(g);
            out.push(' ');
            out.push_str(&s.to_string());
            out.push('\n');
            out
        });
        let tmp = self
            .dir
            .join(format!(".tmp-{DURATIONS}-{}", std::process::id()));
        if let Err(e) = std::fs::write(&tmp, text) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("{}: {e}", tmp.display()));
        }
        std::fs::rename(&tmp, self.dir.join(DURATIONS)).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("{DURATIONS}: {e}")
        })
    }

    /// # Errors
    /// When the directory exists but cannot be removed.
    pub fn clear(&self) -> Result<(), String> {
        match std::fs::remove_dir_all(&self.dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("{}: {e}", self.dir.display())),
        }
    }
}

/// A gate or key becomes a path component, so it must be one plain name.
fn check_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']) {
        return Err(format!("invalid cache name {name:?}"));
    }
    Ok(())
}

/// Keeps the just-written `fresh` entry and the `KEEP - 1` newest others, so
/// an mtime tie can never delete the entry that was just recorded.
/// Best effort: an entry that cannot be removed only costs disk.
fn prune(dir: &Path, fresh: &str) {
    // A temp file over an hour old is a crashed write; a newer one may be
    // another run's, still being renamed into place.
    let stale = SystemTime::now() - std::time::Duration::from_hours(1);
    if let Ok(all) = std::fs::read_dir(dir) {
        for e in all.filter_map(Result::ok) {
            if e.file_name().to_string_lossy().starts_with(".tmp-")
                && e.metadata()
                    .and_then(|m| m.modified())
                    .is_ok_and(|t| t < stale)
            {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<(SystemTime, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
        .filter(|e| e.file_name() != OsStr::new(fresh))
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .collect();
    entries.sort_by_key(|e| std::cmp::Reverse(e.0));
    for (_, path) in entries.into_iter().skip(KEEP - 1) {
        let _ = std::fs::remove_file(path);
    }
}

#[must_use]
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[must_use]
pub fn ago(when: u64, now: u64) -> String {
    let secs = now.saturating_sub(when);
    match secs {
        0..120 => format!("{secs} s ago"),
        120..7_200 => format!("{} min ago", secs / 60),
        7_200..172_800 => format!("{} h ago", secs / 3_600),
        _ => format!("{} days ago", secs / 86_400),
    }
}
