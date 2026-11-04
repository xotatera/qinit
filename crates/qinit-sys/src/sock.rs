// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unix-domain sockets.
use crate::fd::owned;
use crate::{Errno, Result, check};
use std::ffi::CStr;
use std::os::fd::{AsRawFd, OwnedFd};

fn address(path: &CStr) -> Result<libc::sockaddr_un> {
    qinit_ipc::unix_address(path).map_err(|e| Errno(e.0))
}

/// A close-on-exec `AF_UNIX` stream socket bound to `path` and listening with `backlog`.
pub fn listen_unix(path: &CStr, backlog: libc::c_int) -> Result<OwnedFd> {
    let addr = address(path)?;
    // SAFETY: integer arguments; the descriptor is owned.
    let fd =
        owned(unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) })?;
    let len = libc::socklen_t::try_from(core::mem::size_of::<libc::sockaddr_un>())
        .map_err(|_| Errno(libc::EINVAL))?;
    // SAFETY: a readable sockaddr_un of the length given.
    check(unsafe { libc::bind(fd.as_raw_fd(), (&raw const addr).cast(), len) })?;
    // SAFETY: integer arguments.
    check(unsafe { libc::listen(fd.as_raw_fd(), backlog) })?;
    Ok(fd)
}

/// A close-on-exec `AF_UNIX` socket of type `ty` connected to `path`.
pub fn connect_unix(path: &CStr, ty: libc::c_int) -> Result<OwnedFd> {
    let addr = address(path)?;
    // SAFETY: integer arguments; the descriptor is owned.
    let fd = owned(unsafe { libc::socket(libc::AF_UNIX, ty | libc::SOCK_CLOEXEC, 0) })?;
    let len = libc::socklen_t::try_from(core::mem::size_of::<libc::sockaddr_un>())
        .map_err(|_| Errno(libc::EINVAL))?;
    // SAFETY: a readable sockaddr_un of the length given.
    check(unsafe { libc::connect(fd.as_raw_fd(), (&raw const addr).cast(), len) })?;
    Ok(fd)
}
