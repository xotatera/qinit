// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a guest `/init` needs: mounts, directories, sync and powering off from a child.
use crate::{Result, check, cpath};
use std::ffi::CString;
use std::path::Path;

/// `mount(source, target, fstype, flags, NULL)`.
pub fn mount(source: &str, target: &Path, fstype: &str, flags: libc::c_ulong) -> Result<()> {
    let s = CString::new(source).map_err(|_| crate::Errno(libc::EINVAL))?;
    let t = cpath(target)?;
    let f = CString::new(fstype).map_err(|_| crate::Errno(libc::EINVAL))?;
    // SAFETY: NUL-terminated strings that outlive the call and no data argument.
    check(unsafe { libc::mount(s.as_ptr(), t.as_ptr(), f.as_ptr(), flags, std::ptr::null()) })?;
    Ok(())
}

/// `mkdir(path, mode)`.
pub fn mkdir(path: &Path, mode: u32) -> Result<()> {
    let p = cpath(path)?;
    // SAFETY: a NUL-terminated path that outlives the call.
    check(unsafe { libc::mkdir(p.as_ptr(), mode) })?;
    Ok(())
}

/// `sync(2)`.
pub fn sync() {
    // SAFETY: sync takes no arguments and cannot fail.
    unsafe { libc::sync() };
}

/// Syncs, then powers the machine off from a forked child: `reboot(2)` with `POWER_OFF` ends
/// the calling process, which must never be PID 1 (parent spec §2). The parent waits forever.
pub fn power_off_from_child() -> ! {
    sync();
    // SAFETY: fork in a single-threaded guest init; the child only calls reboot.
    if unsafe { libc::fork() } == 0 {
        // SAFETY: reboot takes an integer command.
        unsafe { libc::reboot(libc::RB_POWER_OFF) };
        // SAFETY: _exit never returns.
        unsafe { libc::_exit(1) }
    }
    loop {
        let mut status = 0;
        // SAFETY: waits for any child with a valid out-pointer.
        unsafe { libc::wait(&raw mut status) };
    }
}
