// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Processes: identity, signals by pid and pidfd, reaping, the subreaper role, the kernel
//! release.
use crate::fd::owned;
use crate::{Errno, Result, check, check_long};
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

#[must_use]
pub fn pid() -> libc::pid_t {
    // SAFETY: getpid takes no arguments and cannot fail.
    unsafe { libc::getpid() }
}

/// `kill(2)`; a negative `pid` signals that process group, signal 0 only probes.
pub fn kill(pid: libc::pid_t, sig: libc::c_int) -> Result<()> {
    // SAFETY: kill takes integers only.
    check(unsafe { libc::kill(pid, sig) })?;
    Ok(())
}

/// Sends `sig` to the calling thread (`tgkill`), for tests of per-thread signal masks.
pub fn kill_thread_self(sig: libc::c_int) -> Result<()> {
    // SAFETY: gettid takes no arguments and cannot fail.
    let tid = unsafe { libc::gettid() };
    // SAFETY: tgkill takes integers only.
    check_long(unsafe { libc::syscall(libc::SYS_tgkill, pid(), tid, sig) })?;
    Ok(())
}

/// A pidfd for `pid`, for signalling and reaping it without the risk of a reused pid.
pub fn pidfd_open(pid: libc::pid_t) -> Result<OwnedFd> {
    // SAFETY: pidfd_open takes a pid and flags; no pointers.
    let fd = check_long(unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) })?;
    owned(libc::c_int::try_from(fd).map_err(|_| Errno(libc::EBADF))?)
}

/// Sends `sig` through a pidfd; `Ok(false)` when the process is already gone.
pub fn pidfd_signal(fd: impl AsFd, sig: libc::c_int) -> Result<bool> {
    // SAFETY: pidfd_send_signal with a borrowed pidfd, a null siginfo and no flags.
    let r = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_fd().as_raw_fd(),
            sig,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if r == 0 {
        return Ok(true);
    }
    match Errno::last() {
        Errno(libc::ESRCH) => Ok(false),
        e => Err(e),
    }
}

/// The `waitpid` encoding of a `waitid` result: `(code, status)` of `siginfo_t`.
#[must_use]
pub fn wait_status(code: libc::c_int, status: libc::c_int) -> i32 {
    match code {
        libc::CLD_EXITED => (status & 0xff) << 8,
        libc::CLD_DUMPED => (status & 0x7f) | 0x80,
        _ => status & 0x7f,
    }
}

/// `waitid(idtype, id, WEXITED | WNOHANG)`: `Some((pid, wait status))` of a reaped child.
fn reap(idtype: libc::idtype_t, id: libc::id_t) -> Result<Option<(libc::pid_t, i32)>> {
    let mut info = MaybeUninit::<libc::siginfo_t>::zeroed();
    // SAFETY: `info` is a zeroed siginfo_t the kernel fills.
    check(unsafe { libc::waitid(idtype, id, info.as_mut_ptr(), libc::WEXITED | libc::WNOHANG) })?;
    // SAFETY: zero-initialised and possibly filled by waitid; every bit pattern is valid.
    let info = unsafe { info.assume_init() };
    // SAFETY: for WEXITED si_pid is the field the kernel set (0 when nothing was reaped).
    let who = unsafe { info.si_pid() };
    if who == 0 {
        return Ok(None);
    }
    // SAFETY: as above, si_status is set together with si_pid.
    let status = unsafe { info.si_status() };
    Ok(Some((who, wait_status(info.si_code, status))))
}

/// Reaps the process behind `pidfd` if it has exited: its wait status, `None` while it runs.
pub fn reap_pidfd(pidfd: impl AsFd) -> Result<Option<i32>> {
    #[allow(clippy::cast_sign_loss)] // a descriptor number is non-negative
    let id = pidfd.as_fd().as_raw_fd() as libc::id_t;
    Ok(reap(libc::P_PIDFD, id)?.map(|(_, status)| status))
}

/// Reaps any one exited child (an orphan a subreaper inherited, or an untracked child):
/// `None` when none has exited, or when there are no children at all.
pub fn reap_any() -> Result<Option<(libc::pid_t, i32)>> {
    match reap(libc::P_ALL, 0) {
        Err(Errno(libc::ECHILD)) => Ok(None),
        r => r,
    }
}

/// `PR_SET_CHILD_SUBREAPER`: orphaned descendants are re-parented to this process.
pub fn set_child_subreaper() -> Result<()> {
    // SAFETY: the prctl option takes integer arguments only.
    check(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) })?;
    Ok(())
}

/// `uname -r`.
pub fn kernel_release() -> Result<String> {
    let mut u = MaybeUninit::<libc::utsname>::zeroed();
    // SAFETY: `u` is a utsname the kernel fills.
    check(unsafe { libc::uname(u.as_mut_ptr()) })?;
    // SAFETY: uname succeeded, so the struct is initialised.
    let u = unsafe { u.assume_init() };
    // SAFETY: `release` is NUL-terminated within its array after a successful uname.
    let r = unsafe { CStr::from_ptr(u.release.as_ptr()) };
    Ok(r.to_string_lossy().into_owned())
}
