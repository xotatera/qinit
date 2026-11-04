// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0

//! `qinit-ipc`: the control socket's system calls. `AF_UNIX` `SOCK_SEQPACKET` sockets, one
//! message with up to three descriptors per call, and the identity of the peer. Each `unsafe`
//! block holds one operation and states in its `SAFETY` comment what it relies on.
// Every fallible function returns the errno of the one system call it wraps.
#![allow(clippy::missing_errors_doc)] // syscall wrappers propagate Errno unchanged

#[cfg(not(target_arch = "x86_64"))]
compile_error!("qinit-ipc's socket structures are written for x86_64");

pub mod memfd;
mod msg;
mod peer;
pub mod pidfd;
mod sock;

pub use msg::{MAX_FDS, Received, recv, send, send_nowait, send_unchecked};
pub use peer::{PeerCred, peer_cred, peer_pidfd};
pub use sock::{accept, connect_seqpacket, listen_seqpacket, seqpacket_pair, unix_address};

/// An OS error number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

pub type Result<T> = core::result::Result<T, Errno>;

impl Errno {
    /// The calling thread's current errno.
    #[must_use]
    pub fn last() -> Errno {
        // SAFETY: __errno_location has no preconditions.
        let slot = unsafe { libc::__errno_location() };
        // SAFETY: the slot is this thread's errno, valid for the thread's life.
        Errno(unsafe { *slot })
    }
}

impl core::fmt::Display for Errno {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        std::io::Error::from_raw_os_error(self.0).fmt(f)
    }
}

impl std::error::Error for Errno {}

impl From<Errno> for std::io::Error {
    fn from(e: Errno) -> std::io::Error {
        std::io::Error::from_raw_os_error(e.0)
    }
}

/// `Ok(r)` for a non-negative return, the thread's errno otherwise.
pub(crate) fn check(r: libc::c_int) -> Result<libc::c_int> {
    if r < 0 { Err(Errno::last()) } else { Ok(r) }
}

/// Wraps a descriptor the kernel just returned (or the error it reported).
pub(crate) fn owned(fd: libc::c_int) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let fd = check(fd)?;
    // SAFETY: the kernel just created `fd`; nothing else owns it.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}
