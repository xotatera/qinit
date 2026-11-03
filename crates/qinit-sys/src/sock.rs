// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unix-domain sockets.
use crate::fd::owned;
use crate::{Errno, Result, check};
use std::ffi::CStr;
use std::os::fd::{AsRawFd, OwnedFd};

/// A close-on-exec `AF_UNIX` socket of type `ty` connected to `path`.
pub fn connect_unix(path: &CStr, ty: libc::c_int) -> Result<OwnedFd> {
    // SAFETY: sockaddr_un is a plain C struct; zeroed is a valid value.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family =
        libc::sa_family_t::try_from(libc::AF_UNIX).map_err(|_| Errno(libc::EINVAL))?;
    let bytes = path.to_bytes_with_nul();
    if bytes.len() > addr.sun_path.len() {
        return Err(Errno(libc::ENAMETOOLONG));
    }
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
        #[allow(clippy::cast_possible_wrap)] // the kernel's path field is `c_char`
        let c = *src as libc::c_char;
        *dst = c;
    }
    // SAFETY: integer arguments; the descriptor is owned.
    let fd = owned(unsafe { libc::socket(libc::AF_UNIX, ty | libc::SOCK_CLOEXEC, 0) })?;
    let len = libc::socklen_t::try_from(core::mem::size_of::<libc::sockaddr_un>())
        .map_err(|_| Errno(libc::EINVAL))?;
    // SAFETY: a readable sockaddr_un of the length given.
    check(unsafe { libc::connect(fd.as_raw_fd(), (&raw const addr).cast(), len) })?;
    Ok(fd)
}
