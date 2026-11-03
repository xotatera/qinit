// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! A one-shot `SIGALRM` on the monotonic clock.
use crate::{Result, check};
use std::mem::MaybeUninit;

/// Arms a `CLOCK_MONOTONIC` timer that delivers `SIGALRM` to this process after `after_ms`.
/// The timer is never deleted: an `execve` disposes of it, and a process that fails before
/// exits.
pub fn arm_alarm(after_ms: u32) -> Result<()> {
    // SAFETY: sigevent is a plain C struct; zeroed is a valid starting value.
    let mut ev: libc::sigevent = unsafe { std::mem::zeroed() };
    ev.sigev_notify = libc::SIGEV_SIGNAL;
    ev.sigev_signo = libc::SIGALRM;
    let mut id = MaybeUninit::<libc::timer_t>::uninit();
    // SAFETY: a readable sigevent and a writable timer id slot.
    check(unsafe { libc::timer_create(libc::CLOCK_MONOTONIC, &raw mut ev, id.as_mut_ptr()) })?;
    // SAFETY: timer_create succeeded and wrote the id.
    let id = unsafe { id.assume_init() };
    let spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: i64::from(after_ms / 1000),
            tv_nsec: libc::c_long::from(after_ms % 1000) * 1_000_000,
        },
    };
    // SAFETY: a valid timer id, a readable spec and no old-value pointer.
    check(unsafe { libc::timer_settime(id, 0, &raw const spec, std::ptr::null_mut()) })?;
    Ok(())
}
