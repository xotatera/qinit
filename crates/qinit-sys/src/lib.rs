// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! `qinit-sys`: the one crate that may use `unsafe` (spec 2026-10-27 R1). Every public function
//! is a safe wrapper around system calls; each `unsafe` block holds one operation and states in
//! its `SAFETY` comment what it relies on. Seeded from alloy's `common-sys`.
// Every fallible function returns the errno of the one system call it wraps; a per-function
// `# Errors` section would only repeat that.
#![allow(clippy::missing_errors_doc)] // syscall wrappers propagate Errno unchanged; individual docs name the operations

#[cfg(not(target_arch = "x86_64"))]
compile_error!("qinit-sys's raw child path and kernel structures are written for x86_64");

pub mod cgroup;
pub mod event;
pub mod fd;
pub mod mount;
pub mod proc;
pub mod signal;
pub mod spawn;

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

/// `check` for `syscall(2)`'s `long` return.
pub(crate) fn check_long(r: libc::c_long) -> Result<libc::c_long> {
    if r < 0 { Err(Errno::last()) } else { Ok(r) }
}

/// `p` as a C string; `EINVAL` when it holds a NUL byte.
pub(crate) fn cpath(p: &std::path::Path) -> Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(|_| Errno(libc::EINVAL))
}
