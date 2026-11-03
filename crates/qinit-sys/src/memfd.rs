// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Sealed memory files: written once, then immutable in size and content.
use crate::fd::owned;
use crate::{Errno, Result, check, check_long};
use std::ffi::CStr;
use std::io::Write;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};

/// `memfd_create` flag `MFD_ALLOW_SEALING` (`linux/memfd.h`).
const MFD_ALLOW_SEALING: libc::c_uint = 2;

/// A close-on-exec memfd named `name` holding `bytes`, sealed against shrinking, growing,
/// writing and further sealing, with its offset back at 0 so a reader starts at the first byte.
pub fn sealed(name: &CStr, bytes: &[u8]) -> Result<OwnedFd> {
    // SAFETY: a NUL-terminated name and integer flags.
    let fd =
        owned(unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | MFD_ALLOW_SEALING) })?;
    let mut file = std::fs::File::from(fd);
    file.write_all(bytes)
        .map_err(|e| Errno(e.raw_os_error().unwrap_or(libc::EIO)))?;
    let fd = OwnedFd::from(file);
    // SAFETY: lseek with integer arguments.
    check_long(unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_SET) })?;
    let all = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL;
    // SAFETY: F_ADD_SEALS with an integer argument.
    check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, all) })?;
    Ok(fd)
}

/// The seals on `fd` (`F_GET_SEALS`).
pub fn seals(fd: BorrowedFd<'_>) -> Result<i32> {
    // SAFETY: F_GET_SEALS only queries.
    check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) })
}
