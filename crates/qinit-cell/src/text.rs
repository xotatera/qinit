// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The text the runtime reads: `cgroup.events`, `cgroup.procs`, a pidfd's fdinfo, the kernel
//! release, cell names and the readiness pipe. Pure functions.

/// The kernel floor (spec R9): `PIDFD_GET_INFO`.
pub const FLOOR: (u32, u32) = (6, 13);

/// `(populated, frozen)` from `cgroup.events`; `None` unless both keys are there.
#[must_use]
pub fn parse_events(text: &[u8]) -> Option<(bool, bool)> {
    let text = std::str::from_utf8(text).ok()?;
    let flag = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key))
            .map(|v| v.trim() == "1")
    };
    Some((flag("populated ")?, flag("frozen ")?))
}

/// The pids of `cgroup.procs`, one positive decimal per line.
///
/// # Errors
///
/// A message naming the first line that is not a positive pid, or the UTF-8 error.
pub fn parse_procs(text: &[u8]) -> Result<Vec<libc::pid_t>, String> {
    let text = std::str::from_utf8(text).map_err(|e| format!("cgroup.procs is not UTF-8: {e}"))?;
    text.lines()
        .map(|l| match l.trim().parse::<libc::pid_t>() {
            Ok(p) if p > 0 => Ok(p),
            _ => Err(format!("cgroup.procs line {l:?} is not a pid")),
        })
        .collect()
}

/// The `Pid:` of a pidfd's `/proc/self/fdinfo` entry; `None` when absent or -1 (exited).
#[must_use]
pub fn parse_fdinfo_pid(text: &str) -> Option<libc::pid_t> {
    let v: libc::pid_t = text
        .lines()
        .find_map(|l| l.strip_prefix("Pid:"))?
        .trim()
        .parse()
        .ok()?;
    (v > 0).then_some(v)
}

/// `Ok` for a release at or above [`FLOOR`].
///
/// # Errors
///
/// A message naming the release and the floor, or saying no version could be read.
pub fn kernel_supported(release: &str) -> Result<(), String> {
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    let major = parts.next().and_then(|p| p.parse::<u32>().ok());
    let minor = parts.next().and_then(|p| p.parse::<u32>().ok());
    match (major, minor) {
        (Some(a), Some(b)) if (a, b) >= FLOOR => Ok(()),
        (Some(_), Some(_)) => Err(format!(
            "Linux {release} is older than qinit's floor {}.{} (PIDFD_GET_INFO)",
            FLOOR.0, FLOOR.1
        )),
        _ => Err(format!(
            "cannot read a version from the kernel release {release:?}"
        )),
    }
}

/// A cell name: 1 to 64 of `[A-Za-z0-9._-]`, not `.` or `..`, so it never leaves the comb.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// Readiness on a pipe: the first newline, in whatever chunk it arrives.
#[derive(Debug, Default)]
pub struct ReadyBuf {
    seen: bool,
}

impl ReadyBuf {
    #[must_use]
    pub fn new() -> ReadyBuf {
        ReadyBuf::default()
    }

    /// True exactly once: for the chunk holding the first newline.
    pub fn push(&mut self, chunk: &[u8]) -> bool {
        if self.seen || !chunk.contains(&b'\n') {
            return false;
        }
        self.seen = true;
        true
    }

    /// At EOF: whether the pipe closed without ever showing a newline (not ready).
    #[must_use]
    pub fn at_eof(&self) -> bool {
        !self.seen
    }
}
