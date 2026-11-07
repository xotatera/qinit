// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The three programs queen runs, at their fixed paths, and how a child is started: console on
//! 0, 1 and 2, the channel (for colony) on 3, a fresh signal state, the descriptor limit queen was started
//! with (not the raised one it holds the store under), everything else closed.
use qinit_queen_core::Mode;
use qinit_sys::spawn::{Prepared, Session, spawn};
use qinit_sys::{Errno, fd};
use std::ffi::OsStr;
use std::os::fd::{AsFd, BorrowedFd};
use std::path::Path;

pub const COLONY: &str = "/usr/lib/qinit/colony";
pub const RESCUE: &str = "/etc/qinit/rescue";
pub const ZERO: &str = "/usr/lib/qinit/zero";

/// The descriptor colony finds its channel on.
pub const CHANNEL_FD: i32 = 3;

/// `halt`, `poweroff` or `reboot`: the word zero's command line takes.
#[must_use]
pub fn mode_word(mode: Mode) -> &'static str {
    match mode {
        Mode::Halt => "halt",
        Mode::Poweroff => "poweroff",
        Mode::Reboot => "reboot",
    }
}

/// Colony's command line.
#[must_use]
pub fn colony_argv() -> [&'static str; 3] {
    ["colony", "--queen-fd", "3"]
}

/// Zero's command line.
#[must_use]
pub fn zero_argv(mode: Mode) -> [&'static str; 3] {
    ["zero", "final", mode_word(mode)]
}

/// Starts `path` with `argv` and `env`, in session `session`: the console on 0, 1 and 2,
/// `channel` on 3 when given, and `RLIMIT_NOFILE` set to `nofile` when given. Returns the pid. The exec-error pipe is made and dropped
/// unread: an exec failure shows up as the child's exit (127).
///
/// # Errors
/// The errno of the step that failed: the clone itself, or building the arguments.
pub fn start(
    path: &str,
    argv: &[&str],
    env: &[&OsStr],
    console: BorrowedFd<'_>,
    channel: Option<BorrowedFd<'_>>,
    session: Session,
    nofile: Option<(u64, u64)>,
) -> Result<i32, Errno> {
    let argv: Vec<&OsStr> = argv.iter().map(OsStr::new).collect();
    let mut routes = vec![(console, 0), (console, 1), (console, 2)];
    if let Some(c) = channel {
        routes.push((c, CHANNEL_FD));
    }
    let mut p = Prepared::new(Path::new(path), &argv, env, &routes)?;
    p.session(session);
    if let Some((cur, max)) = nofile {
        p.nofile(cur, max);
    }
    let (err_r, err_w) = fd::pipe(libc::O_CLOEXEC)?;
    let (pid, _pidfd) = spawn(&p, None, err_w.as_fd())?;
    drop((err_r, err_w));
    Ok(pid)
}
