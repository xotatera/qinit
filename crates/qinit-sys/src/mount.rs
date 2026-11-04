// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a guest `/init` needs: mounts, directories, sync and powering off from a child.
use crate::{Errno, Result, check, check_long, cpath};
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
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

/// `MOUNT_ATTR_RDONLY`.
pub const MOUNT_ATTR_RDONLY: u64 = 0x1;
/// `MOUNT_ATTR_NOSUID`.
pub const MOUNT_ATTR_NOSUID: u64 = 0x2;
/// `MOUNT_ATTR_NODEV`.
pub const MOUNT_ATTR_NODEV: u64 = 0x4;
/// `MOUNT_ATTR_NOEXEC`.
pub const MOUNT_ATTR_NOEXEC: u64 = 0x8;

/// `MS_PRIVATE`, as a `mount_attr` propagation value.
const MS_PRIVATE: u64 = 1 << 18;

/// `struct mount_attr` of `mount_setattr(2)`.
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// `mount_setattr(AT_FDCWD, path, AT_RECURSIVE, {propagation: MS_PRIVATE})`: the mount at `path`
/// and every mount below it stop receiving mounts from, and sending them to, any peer group.
pub fn private_rec(path: &Path) -> Result<()> {
    setattr_with(path, 0, 0, libc::AT_RECURSIVE, MS_PRIVATE)
}

/// `mount_setattr(AT_FDCWD, path, 0, {set, clear})`: changes the attributes of the mount at
/// `path` only.
pub fn setattr(path: &Path, set: u64, clear: u64) -> Result<()> {
    setattr_with(path, set, clear, 0, 0)
}

fn setattr_with(
    path: &Path,
    set: u64,
    clear: u64,
    flags: libc::c_int,
    propagation: u64,
) -> Result<()> {
    let p = cpath(path)?;
    let attr = MountAttr {
        attr_set: set,
        attr_clr: clear,
        propagation,
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

/// `OPEN_TREE_CLONE`: `open_tree` returns a detached copy of the mount.
pub const OPEN_TREE_CLONE: u32 = 1;
/// `OPEN_TREE_CLOEXEC`.
const OPEN_TREE_CLOEXEC: u32 = libc::O_CLOEXEC as u32;
/// `MOUNT_ATTR_IDMAP`: with `userns_fd`, the mount maps ids through that user namespace.
pub const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;
/// The `mount_attr` propagation value for a private mount (`MS_PRIVATE`).
pub const PROPAGATION_PRIVATE: u64 = MS_PRIVATE;
/// `MOVE_MOUNT_F_EMPTY_PATH`: the source is the descriptor itself.
const MOVE_MOUNT_F_EMPTY_PATH: u32 = 0x4;
/// `MOVE_MOUNT_T_EMPTY_PATH`: the target is the descriptor itself.
const MOVE_MOUNT_T_EMPTY_PATH: u32 = 0x40;

/// `open_tree(dir, path, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC [| AT_RECURSIVE])`: a detached
/// copy of the mount at `path` below `dir` (the mount `dir` itself when `path` is empty), with
/// every mount below it when `recursive`. The copy is in no namespace until `move_mount_to`.
pub fn open_tree(dir: BorrowedFd<'_>, path: &CStr, recursive: bool) -> Result<OwnedFd> {
    let mut flags = OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC;
    if recursive {
        flags |= libc::AT_RECURSIVE as u32;
    }
    if path.is_empty() {
        flags |= libc::AT_EMPTY_PATH as u32;
    }
    // SAFETY: a valid descriptor, a NUL-terminated path and an integer flag set.
    let fd = check_long(unsafe {
        libc::syscall(libc::SYS_open_tree, dir.as_raw_fd(), path.as_ptr(), flags)
    })?;
    let fd = RawFd::try_from(fd).map_err(|_| Errno(libc::EBADF))?;
    // SAFETY: open_tree returned a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `mount_setattr(tree, "", AT_EMPTY_PATH [| AT_RECURSIVE], {set, clear, propagation, userns})`:
/// changes the attributes of the mount behind `tree`, attached or detached, and of every mount
/// below it when `recursive`. `userns` is the namespace of `MOUNT_ATTR_IDMAP`.
pub fn setattr_fd(
    tree: BorrowedFd<'_>,
    set: u64,
    clear: u64,
    propagation: u64,
    userns: Option<BorrowedFd<'_>>,
    recursive: bool,
) -> Result<()> {
    let mut flags = libc::AT_EMPTY_PATH;
    if recursive {
        flags |= libc::AT_RECURSIVE;
    }
    let attr = MountAttr {
        attr_set: set,
        attr_clr: clear,
        propagation,
        userns_fd: userns.map_or(0, |u| u64::from(u.as_raw_fd().unsigned_abs())),
    };
    // SAFETY: a valid descriptor, an empty NUL-terminated path and a readable `mount_attr` of
    // the size passed.
    check_long(unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            tree.as_raw_fd(),
            c"".as_ptr(),
            flags,
            &raw const attr,
            std::mem::size_of::<MountAttr>(),
        )
    })?;
    Ok(())
}

/// `move_mount(tree, "", AT_FDCWD, target, MOVE_MOUNT_F_EMPTY_PATH)`: attaches the detached
/// mount behind `tree` at the absolute path `target`.
pub fn move_mount_to(tree: BorrowedFd<'_>, target: &Path) -> Result<()> {
    let t = cpath(target)?;
    // SAFETY: a valid descriptor, NUL-terminated paths that outlive the call and an integer
    // flag set.
    check_long(unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            tree.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_FDCWD,
            t.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    })?;
    Ok(())
}

/// `move_mount(tree, "", target, "", MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH)`: attaches
/// the detached mount behind `tree` on the directory or file that `target` is open on, with no
/// path to resolve (and so no symlink to follow).
pub fn move_mount_to_fd(tree: BorrowedFd<'_>, target: BorrowedFd<'_>) -> Result<()> {
    // SAFETY: valid descriptors, empty NUL-terminated paths and an integer flag set.
    check_long(unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            tree.as_raw_fd(),
            c"".as_ptr(),
            target.as_raw_fd(),
            c"".as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        )
    })?;
    Ok(())
}
