// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Output routes by file type (spec R7).
use qinit_sys::fd::{clear_nonblocking, file_type, open_cloexec};
use qinit_sys::sock::connect_unix;
use qinit_sys::{Errno, Result};
use std::ffi::{CStr, CString};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

/// Opens `path` for writing as its file type asks: a regular file is appended to and created
/// when absent (the umask decides its mode), a character device is opened, a Unix socket is
/// connected (`SOCK_STREAM`, then `SOCK_DGRAM` on `EPROTOTYPE`) and a FIFO is opened
/// non-blocking (`ENXIO` without a reader) and then made blocking. Any other type is `ENOTSUP`.
///
/// The caller is root and the directory may belong to the service, so the last component is
/// never followed: a symlink there is `ELOOP`, and the file is then opened through the
/// descriptor the type was read from, so that the type checked is the type opened.
///
/// # Errors
/// The errno of the failing system call, `ELOOP` for a symlink, or `ENOTSUP` for a type with
/// no route.
pub fn open_route(path: &CStr) -> Result<OwnedFd> {
    let probe = match open_cloexec(path, libc::O_PATH | libc::O_NOFOLLOW, 0) {
        Ok(fd) => fd,
        Err(Errno(libc::ENOENT)) => return create(path),
        Err(e) => return Err(e),
    };
    let held = CString::new(format!("/proc/self/fd/{}", probe.as_raw_fd()))
        .map_err(|_| Errno(libc::EINVAL))?;
    match file_type(probe.as_fd())? {
        libc::S_IFLNK => Err(Errno(libc::ELOOP)),
        libc::S_IFREG => open_cloexec(&held, libc::O_WRONLY | libc::O_APPEND, 0),
        libc::S_IFCHR => open_cloexec(&held, libc::O_WRONLY, 0),
        libc::S_IFSOCK => match connect_unix(&held, libc::SOCK_STREAM) {
            Err(Errno(libc::EPROTOTYPE)) => connect_unix(&held, libc::SOCK_DGRAM),
            r => r,
        },
        libc::S_IFIFO => {
            let fd = open_cloexec(&held, libc::O_WRONLY | libc::O_NONBLOCK, 0)?;
            clear_nonblocking(fd.as_fd())?;
            Ok(fd)
        }
        _ => Err(Errno(libc::ENOTSUP)),
    }
}

/// Creates the regular file at `path`; whatever was put there since the probe is refused.
fn create(path: &CStr) -> Result<OwnedFd> {
    let fd = open_cloexec(
        path,
        libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0o666,
    )?;
    if file_type(fd.as_fd())? != libc::S_IFREG {
        return Err(Errno(libc::ENOTSUP));
    }
    clear_nonblocking(fd.as_fd())?;
    Ok(fd)
}
