// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Event sources for an epoll loop: epoll, timerfd, signalfd and inotify.
use crate::fd::owned;
use crate::{Errno, Result, check};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::time::Duration;

pub fn epoll() -> Result<OwnedFd> {
    // SAFETY: epoll_create1 takes integer flags.
    owned(unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) })
}

/// Adds descriptor number `fd` (which the caller keeps open while it is registered).
pub fn epoll_add(ep: impl AsFd, fd: RawFd, events: u32, token: u64) -> Result<()> {
    let mut ev = libc::epoll_event { events, u64: token };
    // SAFETY: `ev` is a valid epoll_event for the call.
    check(unsafe {
        libc::epoll_ctl(ep.as_fd().as_raw_fd(), libc::EPOLL_CTL_ADD, fd, &raw mut ev)
    })?;
    Ok(())
}

pub fn epoll_del(ep: impl AsFd, fd: RawFd) -> Result<()> {
    // SAFETY: EPOLL_CTL_DEL ignores the event pointer.
    check(unsafe {
        libc::epoll_ctl(
            ep.as_fd().as_raw_fd(),
            libc::EPOLL_CTL_DEL,
            fd,
            std::ptr::null_mut(),
        )
    })?;
    Ok(())
}

/// Waits without a timeout (callers arm a timerfd) and fills `out`; retries EINTR.
pub fn epoll_wait(ep: impl AsFd, out: &mut [libc::epoll_event]) -> Result<usize> {
    let max = libc::c_int::try_from(out.len()).unwrap_or(libc::c_int::MAX);
    loop {
        // SAFETY: `out` has room for `max` events.
        match check(unsafe { libc::epoll_wait(ep.as_fd().as_raw_fd(), out.as_mut_ptr(), max, -1) })
        {
            #[allow(clippy::cast_sign_loss)] // check() returned a non-negative count
            Ok(n) => return Ok(n as usize),
            Err(Errno(libc::EINTR)) => {}
            Err(e) => return Err(e),
        }
    }
}

/// A nonblocking one-shot timerfd on the monotonic clock, armed to fire `after` from now.
pub fn timer(after: Duration) -> Result<OwnedFd> {
    // SAFETY: timerfd_create takes integers.
    let t = owned(unsafe {
        libc::timerfd_create(
            libc::CLOCK_MONOTONIC,
            libc::TFD_CLOEXEC | libc::TFD_NONBLOCK,
        )
    })?;
    let after = after.max(Duration::from_nanos(1));
    let spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: after
                .as_secs()
                .try_into()
                .map_err(|_| Errno(libc::EINVAL))?,
            tv_nsec: after.subsec_nanos().into(),
        },
    };
    // SAFETY: `spec` is valid; the old value is not requested.
    check(unsafe {
        libc::timerfd_settime(t.as_raw_fd(), 0, &raw const spec, std::ptr::null_mut())
    })?;
    Ok(t)
}

/// Blocks `sigs` in the calling thread and returns a nonblocking signalfd for them.
pub fn signalfd_blocking(sigs: &[libc::c_int]) -> Result<OwnedFd> {
    crate::signal::block_in_thread(sigs)?;
    let set = crate::signal::set_of(sigs)?;
    // SAFETY: a new signalfd for an initialised set.
    owned(unsafe { libc::signalfd(-1, &raw const set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) })
}

/// The signal number of the next pending `signalfd_siginfo`, if any.
pub fn read_signal(fd: impl AsFd) -> Option<u32> {
    let mut info = MaybeUninit::<libc::signalfd_siginfo>::zeroed();
    let size = std::mem::size_of::<libc::signalfd_siginfo>();
    // SAFETY: `info` has `size` writable bytes.
    let n = unsafe { libc::read(fd.as_fd().as_raw_fd(), info.as_mut_ptr().cast(), size) };
    #[allow(clippy::cast_possible_wrap)] // a struct size is far below isize::MAX
    if n != size as isize {
        return None;
    }
    // SAFETY: fully written by the read above.
    Some(unsafe { info.assume_init() }.ssi_signo)
}

/// A nonblocking inotify instance watching the file or directory `path` for `mask`.
pub fn inotify(path: &Path, mask: u32) -> Result<OwnedFd> {
    // SAFETY: inotify_init1 takes integer flags.
    let f = owned(unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) })?;
    let path = crate::cpath(path)?;
    // SAFETY: a NUL-terminated path that outlives the call.
    check(unsafe { libc::inotify_add_watch(f.as_raw_fd(), path.as_ptr(), mask) })?;
    Ok(f)
}

/// `read(2)` into `buf`.
pub fn read(fd: impl AsFd, buf: &mut [u8]) -> Result<usize> {
    // SAFETY: `buf` has its length in writable bytes.
    let n = unsafe { libc::read(fd.as_fd().as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(Errno::last())
    } else {
        #[allow(clippy::cast_sign_loss)] // checked non-negative above
        Ok(n as usize)
    }
}
