// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0

//! Creating, connecting and accepting sequenced-packet sockets.
use crate::{Errno, Result, check, owned};
use std::ffi::CStr;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};

/// The `AF_UNIX` socket address of `path`.
///
/// # Errors
/// `ENAMETOOLONG` when the path does not fit `sun_path`.
pub fn unix_address(path: &CStr) -> Result<libc::sockaddr_un> {
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
    Ok(addr)
}

fn socket() -> Result<OwnedFd> {
    // SAFETY: integer arguments; the descriptor is owned.
    owned(unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) })
}

fn sockaddr_len() -> Result<libc::socklen_t> {
    libc::socklen_t::try_from(core::mem::size_of::<libc::sockaddr_un>())
        .map_err(|_| Errno(libc::EINVAL))
}

/// A close-on-exec `SOCK_SEQPACKET` socket bound to `path` and listening with `backlog`.
pub fn listen_seqpacket(path: &CStr, backlog: libc::c_int) -> Result<OwnedFd> {
    let addr = unix_address(path)?;
    let fd = socket()?;
    let len = sockaddr_len()?;
    // SAFETY: a readable sockaddr_un of the length given.
    check(unsafe { libc::bind(fd.as_raw_fd(), (&raw const addr).cast(), len) })?;
    // SAFETY: integer arguments.
    check(unsafe { libc::listen(fd.as_raw_fd(), backlog) })?;
    Ok(fd)
}

/// A close-on-exec `SOCK_SEQPACKET` socket connected to `path`.
pub fn connect_seqpacket(path: &CStr) -> Result<OwnedFd> {
    let addr = unix_address(path)?;
    let fd = socket()?;
    let len = sockaddr_len()?;
    // SAFETY: a readable sockaddr_un of the length given.
    check(unsafe { libc::connect(fd.as_raw_fd(), (&raw const addr).cast(), len) })?;
    Ok(fd)
}

/// The next connection on `listener`, close-on-exec.
pub fn accept(listener: BorrowedFd<'_>) -> Result<OwnedFd> {
    // SAFETY: null address pointers ask the kernel not to report the peer address.
    owned(unsafe {
        libc::accept4(
            listener.as_raw_fd(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    })
}

/// A connected pair of close-on-exec `SOCK_SEQPACKET` sockets.
pub fn seqpacket_pair() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: socketpair writes two descriptors into the two-element array.
    check(unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    })?;
    Ok((owned(fds[0])?, owned(fds[1])?))
}
