// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Namespaces and what a fresh one needs: a slave mount tree, a private `/tmp`, loopback up.
use crate::{Errno, Result, check};
use std::os::fd::AsRawFd;

/// `unshare(flags)`.
pub fn unshare(flags: libc::c_int) -> Result<()> {
    // SAFETY: an integer flag set.
    check(unsafe { libc::unshare(flags) })?;
    Ok(())
}

/// `mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL)`: mount events of the host no longer reach
/// this namespace's tree, and nothing done here reaches the host.
pub fn mount_slave_rec_root() -> Result<()> {
    // SAFETY: a NUL-terminated target and null source, type and data, as a propagation change
    // takes.
    check(unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_SLAVE | libc::MS_REC,
            std::ptr::null(),
        )
    })?;
    Ok(())
}

/// A fresh `tmpfs` on `/tmp` (`MS_NOSUID | MS_NODEV`, mode 1777).
pub fn mount_private_tmp() -> Result<()> {
    // SAFETY: NUL-terminated source, target, type and data strings that outlive the call.
    check(unsafe {
        libc::mount(
            c"tmpfs".as_ptr(),
            c"/tmp".as_ptr(),
            c"tmpfs".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            c"mode=1777".as_ptr().cast(),
        )
    })?;
    Ok(())
}

/// `sethostname(name)`.
pub fn sethostname(name: &str) -> Result<()> {
    // SAFETY: the pointer and length describe `name`.
    check(unsafe { libc::sethostname(name.as_ptr().cast(), name.len()) })?;
    Ok(())
}

/// `ioctl`'s request argument: `unsigned long` in glibc, `int` in musl.
#[cfg(target_env = "musl")]
type Request = libc::c_int;
#[cfg(not(target_env = "musl"))]
type Request = libc::c_ulong;

/// Brings `lo` up in this network namespace: `SIOCGIFFLAGS` then `SIOCSIFFLAGS` with `IFF_UP`
/// on an `AF_INET` socket.
pub fn loopback_up() -> Result<()> {
    // SAFETY: integer arguments; the descriptor is owned below.
    let sock = crate::fd::owned(unsafe {
        libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0)
    })?;
    // SAFETY: ifreq is a plain C struct; zeroed is a valid value.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    let name = c"lo".to_bytes_with_nul();
    if name.len() > req.ifr_name.len() {
        return Err(Errno(libc::EINVAL));
    }
    for (dst, src) in req.ifr_name.iter_mut().zip(name) {
        #[allow(clippy::cast_possible_wrap)] // the kernel's name field is `c_char`
        let c = *src as libc::c_char;
        *dst = c;
    }
    // SAFETY: SIOCGIFFLAGS reads the name and writes the flags of a borrowed ifreq.
    check(unsafe {
        libc::ioctl(
            sock.as_raw_fd(),
            libc::SIOCGIFFLAGS as Request,
            &raw mut req,
        )
    })?;
    // SAFETY: ifr_flags is the active member after SIOCGIFFLAGS.
    let flags = unsafe { req.ifr_ifru.ifru_flags };
    #[allow(clippy::cast_possible_truncation)] // IFF_UP is a 16-bit flag
    let up = libc::IFF_UP as libc::c_short;
    req.ifr_ifru.ifru_flags = flags | up;
    // SAFETY: SIOCSIFFLAGS reads the name and flags of a borrowed ifreq.
    check(unsafe {
        libc::ioctl(
            sock.as_raw_fd(),
            libc::SIOCSIFFLAGS as Request,
            &raw const req,
        )
    })?;
    Ok(())
}

/// Whether interface `name` has `IFF_UP` set in this network namespace (`SIOCGIFFLAGS`).
pub fn interface_is_up(name: &str) -> Result<bool> {
    // SAFETY: integer arguments; the descriptor is owned below.
    let sock = crate::fd::owned(unsafe {
        libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0)
    })?;
    // SAFETY: ifreq is a plain C struct; zeroed is a valid value.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    if name.len() >= req.ifr_name.len() {
        return Err(Errno(libc::ENAMETOOLONG));
    }
    for (dst, src) in req.ifr_name.iter_mut().zip(name.bytes()) {
        #[allow(clippy::cast_possible_wrap)] // the kernel's name field is `c_char`
        let c = src as libc::c_char;
        *dst = c;
    }
    // SAFETY: SIOCGIFFLAGS reads the name and writes the flags of a borrowed ifreq.
    check(unsafe {
        libc::ioctl(
            sock.as_raw_fd(),
            libc::SIOCGIFFLAGS as Request,
            &raw mut req,
        )
    })?;
    // SAFETY: ifr_flags is the active member after SIOCGIFFLAGS.
    let flags = unsafe { req.ifr_ifru.ifru_flags };
    Ok(i32::from(flags) & libc::IFF_UP != 0)
}
