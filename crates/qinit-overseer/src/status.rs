// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The failure record on fd 4: eight bytes, `(step, errno)`, little-endian (spec R3). Success
//! is EOF on the pipe after `execve`.
use qinit_overseer_core::{MAX_STEPS, Step, decode, plan};
use qinit_sys::Errno;
use qinit_sys::event;
use qinit_sys::fd::write_all;
use std::os::fd::BorrowedFd;

/// The request did not decode.
pub const STEP_DECODE: u32 = u32::MAX;
/// The identity did not resolve.
pub const STEP_IDENTITY: u32 = u32::MAX - 1;

/// One failure record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    /// The index into the plan, or [`STEP_DECODE`] or [`STEP_IDENTITY`].
    pub step: u32,
    pub errno: i32,
}

impl Status {
    /// Writes the record; a closed pipe is not an error worth reporting from a dying launch.
    pub fn write(&self, fd: BorrowedFd<'_>) {
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&self.step.to_le_bytes());
        b[4..].copy_from_slice(&self.errno.to_le_bytes());
        let _ = write_all(fd, &b);
    }

    /// Reads one record; `None` at EOF (the launch succeeded) or on a short record.
    #[must_use]
    pub fn read(fd: BorrowedFd<'_>) -> Option<Status> {
        let mut b = [0u8; 8];
        let mut have = 0;
        while have < b.len() {
            match event::read(fd, &mut b[have..]) {
                Ok(0) => return None,
                Ok(n) => have += n,
                Err(Errno(libc::EINTR)) => {}
                Err(_) => return None,
            }
        }
        Some(Status {
            step: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            errno: i32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        })
    }
}

/// The name of a step for a notice.
#[must_use]
pub fn name(s: Step) -> &'static str {
    match s {
        Step::Setsid => "setsid",
        Step::Unshare(_) => "unshare",
        Step::MountSlaveRoot => "mount-slave-root",
        Step::MountTmp => "mount-tmp",
        Step::LoopbackUp => "loopback-up",
        Step::Fork => "fork",
        Step::ArmDeadline(_) => "arm-deadline",
        Step::OpenStdin => "open-stdin",
        Step::OpenStdout => "open-stdout",
        Step::OpenStderr => "open-stderr",
        Step::RouteReady(_) => "route-ready",
        Step::Umask(_) => "umask",
        Step::Rlimit(r, _) => rlimit_name(r),
        Step::RlimitCore0 => "rlimit-core",
        Step::Setgroups => "setgroups",
        Step::Setgid => "setgid",
        Step::Securebits(_) => "securebits",
        Step::DropBounding(_) => "drop-bounding",
        Step::Setuid => "setuid",
        Step::Capset => "capset",
        Step::AmbientRaise(_) => "ambient-raise",
        Step::Pdeathsig => "pdeathsig",
        Step::NoNewPrivs => "no-new-privs",
        Step::Chdir => "chdir",
        Step::LandlockRuleset => "landlock-ruleset",
        Step::LandlockRule(_) => "landlock-rule",
        Step::LandlockRestrict => "landlock-restrict",
        Step::Seccomp => "seccomp",
        Step::CloseRange => "close-range",
        Step::Exec => "exec",
    }
}

/// The name of `step` in the plan of request `b`: `"decode"`, `"identity"`, the plan step's
/// name, or `"?"` for an index outside the plan or a request that does not decode.
#[must_use]
pub fn step_name(b: &[u8], step: u32) -> &'static str {
    match step {
        STEP_DECODE => "decode",
        STEP_IDENTITY => "identity",
        _ if decode(b).is_err() => "?",
        _ => {
            let mut out = [Step::Setsid; MAX_STEPS];
            let n = plan(b, &mut out);
            out[..n].get(step as usize).map_or("?", |s| name(*s))
        }
    }
}

/// The status name of the step that sets resource `r`: `rlimit-<key>`.
fn rlimit_name(r: u32) -> &'static str {
    const NAMES: [&str; 16] = [
        "rlimit-cpu",
        "rlimit-fsize",
        "rlimit-data",
        "rlimit-stack",
        "rlimit-core",
        "rlimit-rss",
        "rlimit-nproc",
        "rlimit-nofile",
        "rlimit-memlock",
        "rlimit-as",
        "rlimit-locks",
        "rlimit-sigpending",
        "rlimit-msgqueue",
        "rlimit-nice",
        "rlimit-rtprio",
        "rlimit-rttime",
    ];
    NAMES.get(r as usize).copied().unwrap_or("rlimit")
}
