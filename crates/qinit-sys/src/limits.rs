// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Resource limits, the file-mode mask and the working directory.
use crate::{Result, check, check_long};
use std::ffi::CStr;

/// `RLIMIT_CORE` (`asm-generic/resource.h`).
pub const RLIMIT_CORE: libc::c_int = 4;
/// `RLIMIT_NOFILE`.
pub const RLIMIT_NOFILE: libc::c_int = 7;

/// `setrlimit(resource, { cur, max })`, as the raw system call so the resource is a plain
/// integer on every libc.
pub fn set_rlimit(resource: libc::c_int, cur: u64, max: u64) -> Result<()> {
    let lim = libc::rlimit {
        rlim_cur: cur,
        rlim_max: max,
    };
    // SAFETY: a readable two-field struct for the call.
    check_long(unsafe { libc::syscall(libc::SYS_setrlimit, resource, &raw const lim) })?;
    Ok(())
}

/// `umask(mask)`: the previous mask.
#[must_use]
pub fn umask(mask: u32) -> u32 {
    // SAFETY: an integer argument; umask cannot fail.
    unsafe { libc::umask(mask) }
}

/// `chdir(path)`.
pub fn chdir(path: &CStr) -> Result<()> {
    // SAFETY: a NUL-terminated path that outlives the call.
    check(unsafe { libc::chdir(path.as_ptr()) })?;
    Ok(())
}
