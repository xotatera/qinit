// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The path view (sandbox design §2.3): an empty tmpfs root holding the fixed `/dev` and `/tmp`
//! and a bind of each listed path, pivoted into before the credentials are changed. Every
//! function performs one plan step.
#![allow(clippy::missing_errors_doc)] // each step returns the errno of the call that failed
use qinit_sys::fs::{Kind, create_file, lstat_kind, mkdir_all, open_path, readlink, symlink};
use qinit_sys::landlock::{LANDLOCK_ACCESS_FS_ALL_V3, add_path_rule};
use qinit_sys::mount::{
    MOUNT_ATTR_NODEV, MOUNT_ATTR_NOSUID, MOUNT_ATTR_RDONLY, mount_data, move_mount_to, open_tree,
    pivot_root, private_rec, rmdir, setattr, setattr_fd, umount_detach,
};
use qinit_sys::{Errno, Result};
use std::ffi::CString;
use std::os::fd::{AsFd, BorrowedFd};
use std::path::{Path, PathBuf};

/// Where the view's root is built: below `/run`, which is a writable `tmpfs` even when the host's
/// root filesystem is read-only.
pub const VIEW_ROOT: &str = "/run/qinit/view";

/// The five device nodes the view's `/dev` binds from the host.
const DEV_NODES: [&str; 5] = ["null", "zero", "full", "random", "urandom"];

/// `path` inside the view being built.
fn at(path: &str) -> PathBuf {
    Path::new(VIEW_ROOT).join(path.trim_start_matches('/'))
}

fn tmpfs(target: &Path, flags: libc::c_ulong, data: &str) -> Result<()> {
    let data = CString::new(data).map_err(|_| Errno(libc::EINVAL))?;
    mount_data("tmpfs", target, "tmpfs", flags, Some(data.as_c_str()))
}

/// `ViewRoot`: the root's `tmpfs`.
pub fn root() -> Result<()> {
    let root = Path::new(VIEW_ROOT);
    mkdir_all(root, 0o700)?;
    tmpfs(root, libc::MS_NOSUID | libc::MS_NODEV, "mode=0755")
}

/// `ViewDev`: `/dev` with the five nodes, `/dev/shm` and the descriptor links.
pub fn dev() -> Result<()> {
    let dev = at("/dev");
    mkdir_all(&dev, 0o755)?;
    tmpfs(&dev, libc::MS_NOSUID | libc::MS_NOEXEC, "mode=0755")?;
    for node in DEV_NODES {
        let target = dev.join(node);
        create_file(&target, 0o644)?;
        attach(&Path::new("/dev").join(node), &target, 0)?;
    }
    let shm = dev.join("shm");
    mkdir_all(&shm, 0o755)?;
    tmpfs(
        &shm,
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "mode=1777",
    )?;
    symlink(Path::new("/proc/self/fd"), &dev.join("fd"))?;
    for (name, n) in [("stdin", 0), ("stdout", 1), ("stderr", 2)] {
        symlink(Path::new(&format!("/proc/self/fd/{n}")), &dev.join(name))?;
    }
    Ok(())
}

/// `ViewTmp`: a private `/tmp`.
pub fn tmp() -> Result<()> {
    let tmp = at("/tmp");
    mkdir_all(&tmp, 0o755)?;
    tmpfs(&tmp, libc::MS_NOSUID | libc::MS_NODEV, "mode=1777")
}

/// Splits a list entry into whether it is read-only and its path.
pub fn split(entry: &str) -> Result<(bool, &str)> {
    if let Some(p) = entry.strip_prefix("ro:") {
        Ok((true, p))
    } else if let Some(p) = entry.strip_prefix("rw:") {
        Ok((false, p))
    } else {
        Err(Errno(libc::EINVAL))
    }
}

/// `path` is `/dev` or below it: devices must work there.
fn below_dev(path: &str) -> bool {
    path == "/dev" || path.starts_with("/dev/")
}

/// `ViewEntry`: one listed path. `pid`: the request has a pid namespace, so `ro:/proc` is a
/// fresh `proc` instead of a bind of the host's.
pub fn entry(entry: &str, pid: bool) -> Result<()> {
    let (ro, path) = split(entry)?;
    let host = Path::new(path);
    let target = at(path);
    let kind = lstat_kind(host)?;
    if let Some(parent) = target.parent() {
        mkdir_all(parent, 0o755)?;
    }
    if kind == Kind::Symlink {
        return symlink(&readlink(host)?, &target);
    }
    if kind == Kind::Dir {
        mkdir_all(&target, 0o755)?;
    } else if lstat_kind(&target).is_err() {
        create_file(&target, 0o644)?;
    }
    if path == "/proc" && ro && pid {
        return mount_data(
            "proc",
            &target,
            "proc",
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_RDONLY,
            None,
        );
    }
    let mut set = MOUNT_ATTR_NOSUID;
    if !below_dev(path) {
        set |= MOUNT_ATTR_NODEV;
    }
    if ro {
        set |= MOUNT_ATTR_RDONLY;
    }
    attach(host, &target, set)
}

/// Binds `host` (and every mount below it) at `target` as a detached clone that gets the
/// attributes `set` before it is attached, so it is never visible without them. Attaching under
/// a shared parent joins the clone to its peer group whatever the clone's own propagation was,
/// so it is made private afterwards: a mount the host makes later below `host` must not
/// appear in the view, writable and without `nosuid`.
fn attach(host: &Path, target: &Path, set: u64) -> Result<()> {
    let source = open_path(host)?;
    let clone = open_tree(source.as_fd(), c"", true)?;
    setattr_fd(clone.as_fd(), set, 0, 0, None, true)?;
    move_mount_to(clone.as_fd(), target)?;
    private_rec(target)
}

/// `ViewPivot`: the view becomes the root and the old root is gone.
pub fn pivot() -> Result<()> {
    let new = Path::new(VIEW_ROOT);
    let old = new.join(".old");
    mkdir_all(&old, 0o755)?;
    pivot_root(new, &old)?;
    qinit_sys::limits::chdir(c"/")?;
    umount_detach(Path::new("/.old"))?;
    rmdir(Path::new("/.old"))
}

/// `ViewSeal`: the root mount, and only it, becomes read-only.
pub fn seal() -> Result<()> {
    setattr(Path::new("/"), MOUNT_ATTR_RDONLY, 0)
}

/// `LandlockViewRules`: read and write on the five device nodes, everything on `/tmp` and
/// `/dev/shm`.
pub fn landlock_rules(ruleset: BorrowedFd<'_>) -> Result<()> {
    const READ_WRITE_FILE: u64 = (1 << 1) | (1 << 2);
    for node in DEV_NODES {
        let path = CString::new(format!("/dev/{node}")).map_err(|_| Errno(libc::EINVAL))?;
        add_path_rule(ruleset, &path, READ_WRITE_FILE)?;
    }
    for dir in [c"/tmp", c"/dev/shm"] {
        add_path_rule(ruleset, dir, LANDLOCK_ACCESS_FS_ALL_V3)?;
    }
    Ok(())
}
