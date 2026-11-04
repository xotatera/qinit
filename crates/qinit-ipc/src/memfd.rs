// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0

//! Sealed memory files, the carrier of a whole launch request in the control protocol: written
//! once, then immutable in size and content.
use crate::{Errno, Result, check, owned};
use std::ffi::CStr;
use std::io::Write;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};

/// `memfd_create` flag `MFD_ALLOW_SEALING` (`linux/memfd.h`).
const MFD_ALLOW_SEALING: libc::c_uint = 2;

/// `memfd_create` flag `MFD_NOEXEC_SEAL` (`linux/memfd.h`, Linux 6.3): the file can never be
/// executed, and carries `F_SEAL_EXEC`.
const MFD_NOEXEC_SEAL: libc::c_uint = 8;

/// Every seal a sender sets: no shrinking, growing, writing or further sealing.
pub const ALL_SEALS: i32 =
    libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL;

/// A close-on-exec, non-executable memfd named `name` holding `bytes`, carrying [`ALL_SEALS`]
/// (and `F_SEAL_EXEC`), with its offset back at 0.
pub fn sealed(name: &CStr, bytes: &[u8]) -> Result<OwnedFd> {
    // SAFETY: a NUL-terminated name and integer flags.
    let fd = owned(unsafe {
        libc::memfd_create(
            name.as_ptr(),
            libc::MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL,
        )
    })?;
    let mut file = std::fs::File::from(fd);
    file.write_all(bytes)
        .map_err(|e| Errno(e.raw_os_error().unwrap_or(libc::EIO)))?;
    let fd = OwnedFd::from(file);
    // SAFETY: lseek with integer arguments.
    if unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
        return Err(Errno::last());
    }
    // SAFETY: F_ADD_SEALS with an integer argument.
    check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, ALL_SEALS) })?;
    Ok(fd)
}

/// The seals on `fd` (`F_GET_SEALS`); `EINVAL` for a file that does not support sealing.
pub fn seals(fd: BorrowedFd<'_>) -> Result<i32> {
    // SAFETY: F_GET_SEALS only queries.
    check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) })
}

/// The whole content of `fd` read from offset 0 with `pread`, at most `max` bytes: `EFBIG` when
/// the file is longer.
pub fn read_all(fd: BorrowedFd<'_>, max: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; max + 1];
    let mut have = 0usize;
    loop {
        let off = libc::off_t::try_from(have).map_err(|_| Errno(libc::EFBIG))?;
        // SAFETY: the tail of `out` is writable for its length.
        let n = unsafe {
            libc::pread(
                fd.as_raw_fd(),
                out[have..].as_mut_ptr().cast(),
                out.len() - have,
                off,
            )
        };
        if n < 0 {
            match Errno::last() {
                Errno(libc::EINTR) => continue,
                e => return Err(e),
            }
        }
        if n == 0 {
            out.truncate(have);
            return Ok(out);
        }
        #[allow(clippy::cast_sign_loss)] // checked non-negative above
        {
            have += n as usize;
        }
        if have > max {
            return Err(Errno(libc::EFBIG));
        }
    }
}
