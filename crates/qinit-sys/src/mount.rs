// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a guest `/init` needs: mounts, directories, sync and powering off from a child.
use crate::{Errno, Result, check, check_long, cpath};
use std::ffi::{CStr, CString};
use std::path::Path;

/// `mount(source, target, fstype, flags, NULL)`.
pub fn mount(source: &str, target: &Path, fstype: &str, flags: libc::c_ulong) -> Result<()> {
    let s = CString::new(source).map_err(|_| Errno(libc::EINVAL))?;
    let t = cpath(target)?;
    let f = CString::new(fstype).map_err(|_| Errno(libc::EINVAL))?;
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
/// the calling process, which must never be PID 1 (parent spec §2). The parent waits for the
/// power-off; when there is no child to wait for (the fork failed, or the child's reboot did
/// and it was reaped) it says so on stderr and sleeps in `pause`, so the guest fails at its
/// harness deadline without spinning.
pub fn power_off_from_child() -> ! {
    sync();
    // SAFETY: fork in a single-threaded guest init; the child only calls reboot.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY: reboot takes an integer command.
        unsafe { libc::reboot(libc::RB_POWER_OFF) };
        // SAFETY: _exit never returns.
        unsafe { libc::_exit(1) }
    }
    if pid < 0 {
        eprintln!("qinit-sys: power-off fork failed: {}", Errno::last());
    } else {
        loop {
            let mut status = 0;
            // SAFETY: waits for any child with a valid out-pointer.
            if unsafe { libc::wait(&raw mut status) } < 0 && Errno::last() != Errno(libc::EINTR) {
                break;
            }
        }
        eprintln!("qinit-sys: the power-off child exited without powering off");
    }
    loop {
        // SAFETY: pause takes no arguments; it returns only after a caught signal.
        unsafe { libc::pause() };
    }
}

/// `mount(source, target, fstype, flags, data)` with a data string (`mode=1777`, `size=..`).
pub fn mount_data(
    source: &str,
    target: &Path,
    fstype: &str,
    flags: libc::c_ulong,
    data: Option<&CStr>,
) -> Result<()> {
    let s = CString::new(source).map_err(|_| Errno(libc::EINVAL))?;
    let t = cpath(target)?;
    let f = CString::new(fstype).map_err(|_| Errno(libc::EINVAL))?;
    let d = data.map_or(std::ptr::null(), |d| d.as_ptr().cast());
    // SAFETY: NUL-terminated strings that outlive the call; `d` is null or a NUL-terminated
    // data string.
    check(unsafe { libc::mount(s.as_ptr(), t.as_ptr(), f.as_ptr(), flags, d) })?;
    Ok(())
}

/// `mount(source, target, NULL, MS_BIND | MS_REC, NULL)`: the whole tree below `source`
/// appears at `target`.
pub fn bind_rec(source: &Path, target: &Path) -> Result<()> {
    let s = cpath(source)?;
    let t = cpath(target)?;
    // SAFETY: NUL-terminated paths that outlive the call, no type and no data.
    check(unsafe {
        libc::mount(
            s.as_ptr(),
            t.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )
    })?;
    Ok(())
}

/// `MOUNT_ATTR_RDONLY`.
pub const MOUNT_ATTR_RDONLY: u64 = 0x1;
/// `MOUNT_ATTR_NOSUID`.
pub const MOUNT_ATTR_NOSUID: u64 = 0x2;
/// `MOUNT_ATTR_NODEV`.
pub const MOUNT_ATTR_NODEV: u64 = 0x4;
/// `MOUNT_ATTR_NOEXEC`.
pub const MOUNT_ATTR_NOEXEC: u64 = 0x8;

/// `struct mount_attr` of `mount_setattr(2)`.
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// `mount_setattr(AT_FDCWD, path, AT_RECURSIVE, {set, clear})`: changes the attributes of the
/// mount at `path` and of every mount below it.
pub fn setattr_rec(path: &Path, set: u64, clear: u64) -> Result<()> {
    setattr_with(path, set, clear, libc::AT_RECURSIVE)
}

/// `mount_setattr(AT_FDCWD, path, 0, {set, clear})`: changes the attributes of the mount at
/// `path` only.
pub fn setattr(path: &Path, set: u64, clear: u64) -> Result<()> {
    setattr_with(path, set, clear, 0)
}

fn setattr_with(path: &Path, set: u64, clear: u64, flags: libc::c_int) -> Result<()> {
    let p = cpath(path)?;
    let attr = MountAttr {
        attr_set: set,
        attr_clr: clear,
        propagation: 0,
        userns_fd: 0,
    };
    // SAFETY: a NUL-terminated path and a readable `mount_attr` of the size passed.
    check_long(unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            p.as_ptr(),
            flags,
            &raw const attr,
            std::mem::size_of::<MountAttr>(),
        )
    })?;
    Ok(())
}

/// `pivot_root(new_root, put_old)`.
pub fn pivot_root(new_root: &Path, put_old: &Path) -> Result<()> {
    let n = cpath(new_root)?;
    let o = cpath(put_old)?;
    // SAFETY: NUL-terminated paths that outlive the call.
    check_long(unsafe { libc::syscall(libc::SYS_pivot_root, n.as_ptr(), o.as_ptr()) })?;
    Ok(())
}

/// `umount2(path, MNT_DETACH)`.
pub fn umount_detach(path: &Path) -> Result<()> {
    let p = cpath(path)?;
    // SAFETY: a NUL-terminated path that outlives the call.
    check(unsafe { libc::umount2(p.as_ptr(), libc::MNT_DETACH) })?;
    Ok(())
}

/// `mount(source, target, NULL, MS_MOVE, NULL)`: the mount at `source` moves to `target`.
pub fn mount_move(source: &Path, target: &Path) -> Result<()> {
    let s = cpath(source)?;
    let t = cpath(target)?;
    // SAFETY: NUL-terminated paths that outlive the call, no type and no data.
    check(unsafe {
        libc::mount(
            s.as_ptr(),
            t.as_ptr(),
            std::ptr::null(),
            libc::MS_MOVE,
            std::ptr::null(),
        )
    })?;
    Ok(())
}

/// `chroot(path)`.
pub fn chroot(path: &Path) -> Result<()> {
    let p = cpath(path)?;
    // SAFETY: a NUL-terminated path that outlives the call.
    check(unsafe { libc::chroot(p.as_ptr()) })?;
    Ok(())
}

/// `rmdir(path)`.
pub fn rmdir(path: &Path) -> Result<()> {
    let p = cpath(path)?;
    // SAFETY: a NUL-terminated path that outlives the call.
    check(unsafe { libc::rmdir(p.as_ptr()) })?;
    Ok(())
}
