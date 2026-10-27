// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The cgroup v2 memory cap for a proof run, where the user may create
//! cgroups (elogind `DelegateSessionCgroups`, a systemd user delegation).
//! `fs_root` is `/sys/fs/cgroup` outside tests.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Every run's cgroup name starts with this.
pub const PREFIX: &str = "xtask-proof-";

/// What a finished run used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    /// `memory.peak`; `None` when the kernel has no such file.
    pub peak: Option<u64>,
    /// The run's `memory.max`.
    pub cap: u64,
    /// `oom_kill` from `memory.events`.
    pub oom_kills: u64,
}

/// The process's cgroup v2 path, from `/proc/self/cgroup`.
///
/// # Errors
/// `cgroup v1` without a `0::` line; `root cgroup` at `/`.
pub fn own(proc_self_cgroup: &str) -> Result<String, String> {
    let path = proc_self_cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .ok_or_else(|| "cgroup v1".to_string())?;
    if path.is_empty() || path == "/" {
        return Err("root cgroup".to_string());
    }
    Ok(path.to_string())
}

/// Whether `own` is in atc's tree (`<sid>/delegated/atc/…`), where a run's
/// own cgroup would escape the job's pausing, accounting and `cgroup.kill`.
#[must_use]
pub fn in_atc_tree(own: &str) -> bool {
    own.ends_with("/delegated/atc") || own.contains("/delegated/atc/")
}

/// Where a run's cgroup may go: the `delegated` sibling elogind creates,
/// then the parent itself. None under the root cgroup.
#[must_use]
pub fn candidates(own: &str) -> Vec<String> {
    match own.rsplit_once('/') {
        Some((parent, _)) if !parent.is_empty() => {
            vec![format!("{parent}/delegated"), parent.to_string()]
        }
        _ => Vec::new(),
    }
}

/// The directory of cgroup `cgroup` under `fs_root`.
#[must_use]
pub fn dir(fs_root: &Path, cgroup: &str) -> PathBuf {
    fs_root.join(cgroup.trim_start_matches('/'))
}

/// `xtask-proof-<proof>-<pid namespace>-<pid>`: the sweep judges only runs
/// whose pids it can see.
#[must_use]
pub fn run_name(proof: &str, ns: u64, pid: u32) -> String {
    format!("{PREFIX}{proof}-{ns}-{pid}")
}

/// The inode in a `/proc/self/ns/pid` link (`pid:[4026531836]`).
#[must_use]
pub fn pid_ns(link: &str) -> Option<u64> {
    link.strip_prefix("pid:[")?.strip_suffix(']')?.parse().ok()
}

/// Creates the run's cgroup `name` with `memory.max = cap` and no swap, in
/// the first candidate that allows it, after proving a process can move in.
/// Enabling `+memory` on a candidate is not undone when it is then rejected:
/// another run may already rely on it.
///
/// # Errors
/// Why no cgroup could be made, per candidate: the reason in
/// `memory cap: prlimit (…)`.
pub fn create(
    fs_root: &Path,
    proc_self_cgroup: &str,
    name: &str,
    cap: u64,
    ns: u64,
    alive: &dyn Fn(u32) -> bool,
) -> Result<PathBuf, String> {
    let own = own(proc_self_cgroup)?;
    if in_atc_tree(&own) {
        return Err("inside an atc job, whose cgroup caps the run".to_string());
    }
    let mut reasons = Vec::new();
    for candidate in candidates(&own) {
        match try_candidate(&dir(fs_root, &candidate), name, cap, ns, alive) {
            Ok(path) => return Ok(path),
            Err(why) => reasons.push(format!("{candidate}: {why}")),
        }
    }
    if reasons.is_empty() {
        Err("no writable cgroup".to_string())
    } else {
        Err(format!("no writable cgroup: {}", reasons.join("; ")))
    }
}

fn try_candidate(
    parent: &Path,
    name: &str,
    cap: u64,
    ns: u64,
    alive: &dyn Fn(u32) -> bool,
) -> Result<PathBuf, String> {
    // The argv carries the path as a string.
    if parent.to_str().is_none() {
        return Err("path is not UTF-8".to_string());
    }
    memory_delegated(parent)?;
    sweep(parent, ns, alive);
    let path = parent.join(name);
    fs::create_dir(&path).map_err(|e| format!("cannot create {name}: {e}"))?;
    let ready = limit(&path, cap).and_then(|()| {
        if moves_in(&path) {
            Ok(())
        } else {
            Err("a process cannot move in".to_string())
        }
    });
    match ready {
        Ok(()) => Ok(path),
        Err(why) => {
            let _ = fs::remove_dir(&path);
            Err(why)
        }
    }
}

/// `parent` offers the memory controller and passes it to its children,
/// enabling it there if needed. Enabling fails while `parent` holds
/// processes of its own.
fn memory_delegated(parent: &Path) -> Result<(), String> {
    let lists = |file: &str| {
        fs::read_to_string(parent.join(file))
            .is_ok_and(|t| t.split_whitespace().any(|c| c == "memory"))
    };
    if !lists("cgroup.controllers") {
        return Err("no memory controller".to_string());
    }
    if lists("cgroup.subtree_control") {
        return Ok(());
    }
    fs::write(parent.join("cgroup.subtree_control"), "+memory")
        .map_err(|e| format!("cannot enable memory for children: {e}"))
}

fn limit(path: &Path, cap: u64) -> Result<(), String> {
    let set = |file: &str, value: String| {
        fs::write(path.join(file), value).map_err(|e| format!("cannot set {file}: {e}"))
    };
    set("memory.max", cap.to_string())?;
    set("memory.swap.max", "0".to_string())
}

/// A shell moves itself in and exits. The kernel also checks the common
/// ancestor's `cgroup.procs`, so only a real move proves the run can.
fn moves_in(path: &Path) -> bool {
    Command::new("sh")
        .args(["-c", r#"echo $$ > "$0/cgroup.procs""#])
        .arg(path)
        .status()
        .is_ok_and(|s| s.success())
}

/// Removes the cgroups of earlier runs whose xtask is gone, killing what an
/// interrupted run left running in them. A live run's cgroup can be empty
/// before its wrapper moves in, so the pid decides, and only for runs in
/// pid namespace `ns`: other pids it cannot see.
pub fn sweep(parent: &Path, ns: u64, alive: &dyn Fn(u32) -> bool) {
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let owner = name.strip_prefix(PREFIX).and_then(|rest| {
            let mut parts = rest.rsplitn(3, '-');
            let pid = parts.next()?.parse::<u32>().ok()?;
            let run_ns = parts.next()?.parse::<u64>().ok()?;
            parts.next()?;
            Some((run_ns, pid))
        });
        if let Some((run_ns, pid)) = owner
            && run_ns == ns
            && !alive(pid)
        {
            let path = entry.path();
            let _ = kill_all(&path);
            wait_empty(&path);
            let _ = fs::remove_dir(&path);
        }
    }
}

/// What the run in `path` used, read from its files.
#[must_use]
pub fn usage(path: &Path, cap: u64) -> Usage {
    let read = |file: &str| fs::read_to_string(path.join(file)).ok();
    Usage {
        peak: read("memory.peak").and_then(|t| t.trim().parse().ok()),
        cap,
        oom_kills: read("memory.events").map_or(0, |t| oom_kills(&t)),
    }
}

/// Reads what the run used, kills anything left in it, waits up to 5 s for
/// it to empty, and removes it. Problems come back as warnings.
#[must_use]
pub fn finish(path: &Path, cap: u64) -> (Usage, Vec<String>) {
    let used = usage(path, cap);
    let mut warnings = Vec::new();
    if let Err(e) = kill_all(path) {
        warnings.push(format!("{}: cannot kill what is left: {e}", path.display()));
    }
    wait_empty(path);
    if let Err(e) = fs::remove_dir(path) {
        warnings.push(format!("{}: cannot remove: {e}", path.display()));
    }
    (used, warnings)
}

/// A run's cgroup that is finished exactly once: by `finish`, or, if the
/// run unwinds first, when dropped.
pub struct Guard {
    path: PathBuf,
    cap: u64,
    finished: bool,
}

impl Guard {
    #[must_use]
    pub fn new(path: PathBuf, cap: u64) -> Guard {
        Guard {
            path,
            cap,
            finished: false,
        }
    }

    /// See the free function `finish`.
    #[must_use]
    pub fn finish(mut self) -> (Usage, Vec<String>) {
        self.finished = true;
        finish(&self.path, self.cap)
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if !self.finished {
            let _ = finish(&self.path, self.cap);
        }
    }
}

/// Kills every process in the cgroup: through `cgroup.kill`, or, on kernels
/// before 5.14, `kill -KILL` on each pid in `cgroup.procs`. Never creates a
/// file; an empty cgroup needs nothing.
fn kill_all(path: &Path) -> std::io::Result<()> {
    if fs::read_to_string(path.join("cgroup.events")).is_ok_and(|t| !populated(&t)) {
        return Ok(());
    }
    match fs::OpenOptions::new()
        .write(true)
        .open(path.join("cgroup.kill"))
    {
        Ok(mut f) => std::io::Write::write_all(&mut f, b"1"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let procs = match fs::read_to_string(path.join("cgroup.procs")) {
                Ok(text) => text,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e),
            };
            let pids: Vec<&str> = procs.split_whitespace().collect();
            if pids.is_empty() {
                return Ok(());
            }
            // A pid may exit first; `kill` then fails for it alone. The
            // shell's `kill` (a POSIX built-in): a base system without
            // procps has no `kill` binary.
            Command::new("sh")
                .args(["-c", "kill -KILL \"$@\"", "sh"])
                .args(&pids)
                .status()
                .map(|_| ())
        }
        Err(e) => Err(e),
    }
}

/// Waits up to 5 s for the cgroup in `path` to have no processes: the
/// kernel signals each change of `cgroup.events` as a modify event. A
/// missing file ends the wait at once; a fake tree's file never changes, so
/// one that reads populated waits the full 5 s.
fn wait_empty(path: &Path) {
    let events = path.join("cgroup.events");
    let _ = crate::watch::wait_until(
        &events,
        crate::watch::WatchMask::MODIFY,
        Duration::from_secs(5),
        &mut || !fs::read_to_string(&events).is_ok_and(|t| populated(&t)),
    );
}

/// `oom_kill` from `memory.events`; 0 when absent.
#[must_use]
pub fn oom_kills(events: &str) -> u64 {
    events
        .lines()
        .find_map(|l| l.strip_prefix("oom_kill "))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(0)
}

/// `cgroup.events` says processes remain.
#[must_use]
pub fn populated(events: &str) -> bool {
    events.lines().any(|l| l.trim() == "populated 1")
}
