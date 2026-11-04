// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0

//! Who is on the other end of a connected socket.
use crate::{Errno, Result, check, owned};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};

/// `SO_PEERPIDFD` in `<asm-generic/socket.h>`.
const SO_PEERPIDFD: libc::c_int = 77;

/// The process, user and group that connected, as the kernel recorded them at `connect`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCred {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

/// `SO_PEERCRED` of `fd`.
pub fn peer_cred(fd: BorrowedFd<'_>) -> Result<PeerCred> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = libc::socklen_t::try_from(core::mem::size_of::<libc::ucred>())
        .map_err(|_| Errno(libc::EINVAL))?;
    // SAFETY: a writable ucred and its length.
    check(unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &raw mut len,
        )
    })?;
    Ok(PeerCred {
        pid: cred.pid,
        uid: cred.uid,
        gid: cred.gid,
    })
}

/// A pidfd for the process that connected (`SO_PEERPIDFD`, Linux 6.5): it names the process
/// even after the pid is reused.
pub fn peer_pidfd(fd: BorrowedFd<'_>) -> Result<OwnedFd> {
    let mut pidfd: libc::c_int = -1;
    let mut len = libc::socklen_t::try_from(core::mem::size_of::<libc::c_int>())
        .map_err(|_| Errno(libc::EINVAL))?;
    // SAFETY: a writable int and its length.
    check(unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            (&raw mut pidfd).cast(),
            &raw mut len,
        )
    })?;
    owned(pidfd)
}
