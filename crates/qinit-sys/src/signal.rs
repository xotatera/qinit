// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Signal masks of the calling thread.
use crate::{Errno, Result, check};
use std::mem::MaybeUninit;

fn empty_set() -> libc::sigset_t {
    let mut s = MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: sigemptyset initialises the set it is given.
    unsafe { libc::sigemptyset(s.as_mut_ptr()) };
    // SAFETY: initialised by sigemptyset above.
    unsafe { s.assume_init() }
}

pub(crate) fn set_of(sigs: &[libc::c_int]) -> Result<libc::sigset_t> {
    let mut s = empty_set();
    for &sig in sigs {
        // SAFETY: `s` is an initialised set.
        check(unsafe { libc::sigaddset(&raw mut s, sig) })?;
    }
    Ok(s)
}

/// Blocks `sigs` in the calling thread.
pub fn block_in_thread(sigs: &[libc::c_int]) -> Result<()> {
    let set = set_of(sigs)?;
    // SAFETY: `set` is initialised; the old mask is not requested.
    match unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut()) } {
        0 => Ok(()),
        e => Err(Errno(e)),
    }
}

/// Unblocks every signal in the calling thread.
pub fn unblock_all() -> Result<()> {
    let empty = empty_set();
    // SAFETY: `empty` is initialised; the old mask is not requested.
    match unsafe {
        libc::pthread_sigmask(libc::SIG_SETMASK, &raw const empty, std::ptr::null_mut())
    } {
        0 => Ok(()),
        e => Err(Errno(e)),
    }
}
