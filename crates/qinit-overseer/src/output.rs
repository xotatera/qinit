// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Output routes by file type (spec R7).
use qinit_sys::fd::{clear_nonblocking, file_type, open_cloexec};
use qinit_sys::sock::connect_unix;
use qinit_sys::{Errno, Result};
use std::ffi::CStr;
use std::os::fd::{AsFd, OwnedFd};

/// Opens `path` for writing as its file type asks: a regular file is appended to and created
/// when absent (the umask decides its mode), a character device is opened, a Unix socket is
/// connected (`SOCK_STREAM`, then `SOCK_DGRAM` on `EPROTOTYPE`) and a FIFO is opened
/// non-blocking (`ENXIO` without a reader) and then made blocking. Any other type is `ENOTSUP`.
///
/// # Errors
/// The errno of the failing system call, or `ENOTSUP` for a type with no route.
pub fn open_route(path: &CStr) -> Result<OwnedFd> {
    let probe = match open_cloexec(path, libc::O_PATH, 0) {
        Ok(fd) => fd,
        Err(Errno(libc::ENOENT)) => return append(path),
        Err(e) => return Err(e),
    };
    match file_type(probe.as_fd())? {
        libc::S_IFREG => append(path),
        libc::S_IFCHR => open_cloexec(path, libc::O_WRONLY, 0),
        libc::S_IFSOCK => match connect_unix(path, libc::SOCK_STREAM) {
            Err(Errno(libc::EPROTOTYPE)) => connect_unix(path, libc::SOCK_DGRAM),
            r => r,
        },
        libc::S_IFIFO => {
            let fd = open_cloexec(path, libc::O_WRONLY | libc::O_NONBLOCK, 0)?;
            clear_nonblocking(fd.as_fd())?;
            Ok(fd)
        }
        _ => Err(Errno(libc::ENOTSUP)),
    }
}

fn append(path: &CStr) -> Result<OwnedFd> {
    open_cloexec(path, libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT, 0o666)
}
