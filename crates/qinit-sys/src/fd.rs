// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Descriptors: creation and flags.
use crate::{Result, check};
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

/// Wraps a descriptor the kernel just returned (or the error it reported).
pub(crate) fn owned(fd: libc::c_int) -> Result<OwnedFd> {
    let fd = check(fd)?;
    // SAFETY: the kernel just created `fd`; nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// A pipe with `flags` (`O_CLOEXEC`, `O_NONBLOCK`): (read end, write end).
pub fn pipe(flags: libc::c_int) -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: pipe2 writes two descriptors into the two-element array.
    check(unsafe { libc::pipe2(fds.as_mut_ptr(), flags) })?;
    Ok((owned(fds[0])?, owned(fds[1])?))
}

/// A close-on-exec duplicate of `fd` numbered `floor` or higher.
pub fn dup_above(fd: impl AsFd, floor: RawFd) -> Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC on a descriptor borrowed for the call; no memory is passed.
    owned(unsafe { libc::fcntl(fd.as_fd().as_raw_fd(), libc::F_DUPFD_CLOEXEC, floor) })
}

/// Whether descriptor number `n` is open in this process.
#[must_use]
pub fn is_open(n: RawFd) -> bool {
    // SAFETY: F_GETFD only queries; an unused number gives EBADF.
    unsafe { libc::fcntl(n, libc::F_GETFD) >= 0 }
}

/// Sets `O_NONBLOCK` (shared by every descriptor of the open file).
pub fn set_nonblocking(fd: impl AsFd) -> Result<()> {
    let raw = fd.as_fd().as_raw_fd();
    // SAFETY: F_GETFL on a descriptor borrowed for the call.
    let old = check(unsafe { libc::fcntl(raw, libc::F_GETFL) })?;
    // SAFETY: F_SETFL with an integer argument.
    check(unsafe { libc::fcntl(raw, libc::F_SETFL, old | libc::O_NONBLOCK) })?;
    Ok(())
}

/// Sets `FD_CLOEXEC` on descriptor number `n` (a helper closing an inherited descriptor at its
/// next exec). Changing the flag leaves ownership untouched, so this is safe on any number.
pub fn set_cloexec_raw(n: RawFd) -> Result<()> {
    // SAFETY: F_GETFD only reads the descriptor's flags.
    let old = check(unsafe { libc::fcntl(n, libc::F_GETFD) })?;
    // SAFETY: F_SETFD with an integer argument.
    check(unsafe { libc::fcntl(n, libc::F_SETFD, old | libc::FD_CLOEXEC) })?;
    Ok(())
}

/// `open(path, flags | O_CLOEXEC | O_NOCTTY, mode)`.
pub fn open_cloexec(path: &CStr, flags: libc::c_int, mode: u32) -> Result<OwnedFd> {
    // SAFETY: a NUL-terminated path that outlives the call and integer flags and mode.
    owned(unsafe {
        libc::open(
            path.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOCTTY,
            mode,
        )
    })
}

/// `dup3(from, to, 0)`: `to` becomes a copy of `from` without close-on-exec, replacing what
/// was there. Changing a numbered slot is safe: the caller owns the number it names.
pub fn dup2(from: BorrowedFd<'_>, to: RawFd) -> Result<()> {
    dup2_raw(from.as_raw_fd(), to)
}

/// Moves `fd` onto number `to` without close-on-exec and closes the original. When `fd`
/// already is `to` (a program started with 0-2 closed gets them back from `open`), it stays
/// open and only loses close-on-exec: `dup3` refuses equal numbers and dropping `fd` would
/// close the slot just filled.
pub fn place(fd: OwnedFd, to: RawFd) -> Result<()> {
    if fd.as_raw_fd() == to {
        // The number stays open: ownership passes to the slot.
        return dup2_raw(fd.into_raw_fd(), to);
    }
    dup2(fd.as_fd(), to)
}

/// The file type of `fd`: `st_mode & S_IFMT` (`S_IFREG`, `S_IFIFO`, `S_IFSOCK`, `S_IFCHR`, ...).
pub fn file_type(fd: BorrowedFd<'_>) -> Result<u32> {
    let mut st = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat writes a stat into the slot on success.
    check(unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) })?;
    // SAFETY: fstat succeeded and filled the struct.
    let st = unsafe { st.assume_init() };
    Ok(st.st_mode & libc::S_IFMT)
}

/// Clears `O_NONBLOCK` (shared by every descriptor of the open file).
pub fn clear_nonblocking(fd: BorrowedFd<'_>) -> Result<()> {
    let raw = fd.as_raw_fd();
    // SAFETY: F_GETFL on a descriptor borrowed for the call.
    let old = check(unsafe { libc::fcntl(raw, libc::F_GETFL) })?;
    // SAFETY: F_SETFL with an integer argument.
    check(unsafe { libc::fcntl(raw, libc::F_SETFL, old & !libc::O_NONBLOCK) })?;
    Ok(())
}

/// `close_range(first, ~0, 0)`: closes every descriptor numbered `first` or higher.
pub fn close_from(first: RawFd) -> Result<()> {
    let first = libc::c_uint::try_from(first).map_err(|_| crate::Errno(libc::EINVAL))?;
    // SAFETY: close_range takes integers.
    crate::check_long(unsafe {
        libc::syscall(libc::SYS_close_range, first, libc::c_uint::MAX, 0)
    })?;
    Ok(())
}

/// Takes ownership of descriptor number `n`, which the program that started this one
/// guarantees is open and used by nothing else (the overseer's request and status
/// descriptors). `EBADF` when `n` is not open.
pub fn inherit(n: RawFd) -> Result<OwnedFd> {
    if !is_open(n) {
        return Err(crate::Errno(libc::EBADF));
    }
    // SAFETY: `n` is open (checked above) and, by this function's contract, owned by no
    // other value in the process.
    Ok(unsafe { OwnedFd::from_raw_fd(n) })
}

/// Writes all of `bytes` to `fd`, retrying on `EINTR` and short writes.
pub fn write_all(fd: BorrowedFd<'_>, mut bytes: &[u8]) -> Result<()> {
    while !bytes.is_empty() {
        // SAFETY: `bytes` has its length in readable bytes.
        let n = unsafe { libc::write(fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        if n < 0 {
            match crate::Errno::last() {
                crate::Errno(libc::EINTR) => {}
                e => return Err(e),
            }
        } else {
            #[allow(clippy::cast_sign_loss)] // checked non-negative above
            {
                bytes = &bytes[n as usize..];
            }
        }
    }
    Ok(())
}

/// `dup3(from, to, 0)` between descriptor numbers: `to` becomes a copy of `from` without
/// close-on-exec. Both numbers belong to the caller's own table.
pub fn dup2_raw(from: RawFd, to: RawFd) -> Result<()> {
    if from == to {
        // `dup3` refuses equal numbers; the copy is the descriptor itself, minus close-on-exec.
        // SAFETY: F_GETFD only reads the descriptor's flags.
        let flags = check(unsafe { libc::fcntl(from, libc::F_GETFD) })?;
        // SAFETY: F_SETFD with an integer argument on a number the caller owns.
        check(unsafe { libc::fcntl(from, libc::F_SETFD, flags & !libc::FD_CLOEXEC) })?;
        return Ok(());
    }
    // SAFETY: dup3 with integer arguments.
    check(unsafe { libc::dup3(from, to, 0) })?;
    Ok(())
}

/// `mkfifo(path, mode)`.
pub fn mkfifo(path: &CStr, mode: u32) -> Result<()> {
    // SAFETY: a NUL-terminated path that outlives the call and an integer mode.
    check(unsafe { libc::mkfifo(path.as_ptr(), mode) })?;
    Ok(())
}

/// Whether `O_NONBLOCK` is set on the open file behind `fd`.
pub fn is_nonblocking(fd: BorrowedFd<'_>) -> Result<bool> {
    // SAFETY: F_GETFL only reads the flags.
    let flags = check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) })?;
    Ok(flags & libc::O_NONBLOCK != 0)
}

/// `chown(path, uid, gid)`.
pub fn chown(path: &CStr, uid: u32, gid: u32) -> Result<()> {
    // SAFETY: a NUL-terminated path that outlives the call and integer ids.
    check(unsafe { libc::chown(path.as_ptr(), uid, gid) })?;
    Ok(())
}
