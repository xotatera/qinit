// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! A one-shot `SIGALRM` on the monotonic clock.
use crate::{Result, check};
use std::mem::MaybeUninit;

/// The monotonic clock in nanoseconds.
#[must_use]
pub fn now_monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a writable timespec; CLOCK_MONOTONIC cannot fail.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts) };
    u64::try_from(ts.tv_sec).unwrap_or(0) * 1_000_000_000 + u64::try_from(ts.tv_nsec).unwrap_or(0)
}

/// An armed `CLOCK_MONOTONIC` timer.
pub struct Alarm(libc::timer_t);

impl Alarm {
    /// Deletes the timer: it never fires.
    pub fn delete(self) -> Result<()> {
        // SAFETY: the id came from a successful timer_create and is deleted once.
        check(unsafe { libc::timer_delete(self.0) })?;
        Ok(())
    }
}

/// Arms a timer that delivers `SIGALRM` to this process when the monotonic clock reaches
/// `deadline_ns` (absolute; a past instant fires at once).
pub fn arm_alarm_at(deadline_ns: u64) -> Result<Alarm> {
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
            tv_sec: i64::try_from(deadline_ns / 1_000_000_000).unwrap_or(i64::MAX),
            // A zero it_value disarms; one nanosecond is already past.
            tv_nsec: libc::c_long::try_from(deadline_ns % 1_000_000_000)
                .unwrap_or(0)
                .max(i64::from(deadline_ns == 0)),
        },
    };
    // SAFETY: a valid timer id, a readable spec and no old-value pointer.
    check(unsafe {
        libc::timer_settime(
            id,
            libc::TIMER_ABSTIME,
            &raw const spec,
            std::ptr::null_mut(),
        )
    })?;
    Ok(Alarm(id))
}
