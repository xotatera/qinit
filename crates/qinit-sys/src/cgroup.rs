// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! cgroup v2 operations through directory descriptors: cells are made, read and removed
//! relative to the comb root's dirfd, never by path strings joined at run time.
use crate::fd::owned;
use crate::{Errno, Result, check, cpath};
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::Path;

/// Opens directory `path` for `*at` calls.
pub fn open_dir(path: &Path) -> Result<OwnedFd> {
    let c = cpath(path)?;
    // SAFETY: a NUL-terminated path that outlives the call.
    owned(unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    })
}

/// Opens directory `name` inside `dir`.
pub fn open_dir_at(dir: impl AsFd, name: &CStr) -> Result<OwnedFd> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    // SAFETY: a borrowed dirfd and a NUL-terminated name that outlive the call.
    owned(unsafe { libc::openat(dir.as_fd().as_raw_fd(), name.as_ptr(), flags) })
}

/// `mkdirat(dir, name, mode)`: in a cgroup2 hierarchy this creates a cgroup.
pub fn mkdir_at(dir: impl AsFd, name: &CStr, mode: u32) -> Result<()> {
    // SAFETY: a borrowed dirfd and a NUL-terminated name that outlive the call.
    check(unsafe { libc::mkdirat(dir.as_fd().as_raw_fd(), name.as_ptr(), mode) })?;
    Ok(())
}

/// `unlinkat(dir, name, AT_REMOVEDIR)`: removes an empty cgroup (`EBUSY` while populated).
pub fn rmdir_at(dir: impl AsFd, name: &CStr) -> Result<()> {
    // SAFETY: a borrowed dirfd and a NUL-terminated name that outlive the call.
    check(unsafe { libc::unlinkat(dir.as_fd().as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) })?;
    Ok(())
}

/// Opens file `name` inside `dir` with `flags` (close-on-exec added).
pub fn open_file_at(dir: impl AsFd, name: &CStr, flags: libc::c_int) -> Result<OwnedFd> {
    let flags = flags | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    // SAFETY: a borrowed dirfd and a NUL-terminated name that outlive the call.
    owned(unsafe { libc::openat(dir.as_fd().as_raw_fd(), name.as_ptr(), flags) })
}

/// Writes `bytes` to file `name` inside `dir` in one `write` (a cgroup control file takes its
/// value in one write); a short write is `EIO`.
pub fn write_file_at(dir: impl AsFd, name: &CStr, bytes: &[u8]) -> Result<()> {
    let f = open_file_at(dir, name, libc::O_WRONLY)?;
    // SAFETY: `bytes` is readable for its length; the descriptor is owned for the call.
    let n = unsafe { libc::write(f.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
    match usize::try_from(n) {
        Ok(n) if n == bytes.len() => Ok(()),
        Ok(_) => Err(Errno(libc::EIO)),
        Err(_) => Err(Errno::last()),
    }
}

/// `pread(fd, buf, 0)`: re-reads a file such as `cgroup.events` from its start (which also
/// clears a kernfs priority notification).
pub fn read_from_start(fd: impl AsFd, buf: &mut [u8]) -> Result<usize> {
    // SAFETY: `buf` has its length in writable bytes.
    let n = unsafe {
        libc::pread(
            fd.as_fd().as_raw_fd(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            0,
        )
    };
    usize::try_from(n).map_err(|_| Errno::last())
}

/// The inode number of `fd`: for a cgroup2 directory, its cgroup id (plan P9).
pub fn inode(fd: impl AsFd) -> Result<u64> {
    let mut st = MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `st` is a stat buffer the kernel fills.
    check(unsafe { libc::fstat(fd.as_fd().as_raw_fd(), st.as_mut_ptr()) })?;
    // SAFETY: filled by the successful fstat (and zeroed before).
    Ok(unsafe { st.assume_init() }.st_ino)
}
