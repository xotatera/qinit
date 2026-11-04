// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! File-system calls the sandbox view needs that `std::fs` follows links for or hides:
//! `lstat` kinds, symlinks and exclusive file creation.
use crate::{Errno, Result, check, cpath};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

/// What a path is, without following a final symlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Dir,
    File,
    Symlink,
    Other,
}

/// `lstat(path)` reduced to its kind.
pub fn lstat_kind(path: &Path) -> Result<Kind> {
    let p = cpath(path)?;
    // SAFETY: stat is a plain C struct; zeroed is a valid starting value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated path and a writable stat.
    check(unsafe { libc::lstat(p.as_ptr(), &raw mut st) })?;
    Ok(match st.st_mode & libc::S_IFMT {
        libc::S_IFDIR => Kind::Dir,
        libc::S_IFREG => Kind::File,
        libc::S_IFLNK => Kind::Symlink,
        _ => Kind::Other,
    })
}

/// `readlink(path)`.
pub fn readlink(path: &Path) -> Result<PathBuf> {
    let p = cpath(path)?;
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: a NUL-terminated path and a writable buffer of the length passed.
    let n = unsafe { libc::readlink(p.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(Errno::last());
    }
    buf.truncate(usize::try_from(n).map_err(|_| Errno(libc::EINVAL))?);
    Ok(PathBuf::from(std::ffi::OsString::from_vec(buf)))
}

/// `symlink(target, link)`.
pub fn symlink(target: &Path, link: &Path) -> Result<()> {
    let t = cpath(target)?;
    let l = cpath(link)?;
    // SAFETY: NUL-terminated paths that outlive the call.
    check(unsafe { libc::symlink(t.as_ptr(), l.as_ptr()) })?;
    Ok(())
}

/// Creates an empty file that must not exist yet, and closes it.
pub fn create_file(path: &Path, mode: u32) -> Result<()> {
    let p = cpath(path)?;
    // SAFETY: a NUL-terminated path; the mode is read as an unsigned int.
    let fd = check(unsafe {
        libc::open(
            p.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC,
            mode,
        )
    })?;
    // SAFETY: the descriptor was just opened and is closed once.
    check(unsafe { libc::close(fd) })?;
    Ok(())
}

/// `mkdir -p`: creates `path` and its missing parents; an existing directory is fine.
pub fn mkdir_all(path: &Path, mode: u32) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && lstat_kind(parent).is_err()
    {
        mkdir_all(parent, mode)?;
    }
    match crate::mount::mkdir(path, mode) {
        Err(Errno(libc::EEXIST)) | Ok(()) => Ok(()),
        Err(e) => Err(e),
    }
}
