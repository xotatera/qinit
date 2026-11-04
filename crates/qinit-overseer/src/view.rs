// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The path view (sandbox design §2.3): an empty tmpfs root holding the fixed `/dev` and `/tmp`
//! and a bind of each listed path, pivoted into before the credentials are changed. Every
//! function performs one plan step.
#![allow(clippy::missing_errors_doc)] // each step returns the errno of the call that failed
use qinit_sys::fs::{
    Kind, create_file, lstat_kind, mkdir_all, open_beneath, open_path, readlink, symlink,
};
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

/// How a list entry is bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// `ro:` read-only.
    Ro,
    /// `rw:` writable.
    Rw,
    /// `ri:` read-only, ids mapped through the helper user namespace.
    Ri,
    /// `wi:` writable, ids mapped.
    Wi,
    /// `rs:` read-only, and the mounts the host makes below it later appear in the view.
    Rs,
    /// `ws:` writable, and following the host's later mounts.
    Ws,
}

impl Mode {
    /// The entry is bound read-only.
    #[must_use]
    pub fn read_only(self) -> bool {
        matches!(self, Mode::Ro | Mode::Ri | Mode::Rs)
    }

    /// The entry is bound writable.
    #[must_use]
    pub fn writable(self) -> bool {
        !self.read_only()
    }

    /// The entry's ids are mapped through a user namespace.
    #[must_use]
    pub fn idmapped(self) -> bool {
        matches!(self, Mode::Ri | Mode::Wi)
    }

    /// The entry follows the host's later mounts instead of being cut off from them.
    #[must_use]
    pub fn follows(self) -> bool {
        matches!(self, Mode::Rs | Mode::Ws)
    }
}

/// Splits a list entry into its mode and its path.
pub fn split(entry: &str) -> Result<(Mode, &str)> {
    let (mode, path) = entry.split_at_checked(3).ok_or(Errno(libc::EINVAL))?;
    let mode = match mode {
        "ro:" => Mode::Ro,
        "rw:" => Mode::Rw,
        "ri:" => Mode::Ri,
        "wi:" => Mode::Wi,
        "rs:" => Mode::Rs,
        "ws:" => Mode::Ws,
        _ => return Err(Errno(libc::EINVAL)),
    };
    Ok((mode, path))
}

/// `path` is `/dev` or below it: devices must work there.
fn below_dev(path: &str) -> bool {
    path == "/dev" || path.starts_with("/dev/")
}

/// The index of the nearest entry before `i` in `list` that is writable and whose path is a
/// whole-component prefix of entry `i`'s path: the entry below which a service could have planted
/// a symlink before this launch.
#[must_use]
pub fn writable_ancestor(list: &[&str], i: usize) -> Option<usize> {
    let (_, path) = split(list.get(i)?).ok()?;
    (0..i).rev().find(|&j| {
        split(list[j]).is_ok_and(|(mode, p)| {
            mode.writable()
                && path
                    .strip_prefix(p)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
    })
}

/// `ViewEntry`: one listed path. `pid`: the request has a pid namespace, so `ro:/proc` is a
/// fresh `proc` instead of a bind of the host's. `beneath`: the host path of the writable entry
/// above this one; the path is then opened below it without following any symlink, the last
/// component included (`ELOOP`), so nothing planted there redirects the bind.
pub fn entry(entry: &str, pid: bool, beneath: Option<&Path>) -> Result<()> {
    let (mode, path) = split(entry)?;
    let ro = mode.read_only();
    let host = Path::new(path);
    let target = at(path);
    let source = match beneath {
        Some(above) => {
            let rest = host.strip_prefix(above).map_err(|_| Errno(libc::EINVAL))?;
            Some(open_beneath(open_path(above)?.as_fd(), rest)?)
        }
        None => None,
    };
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
    match source {
        Some(fd) => attach_fd(fd.as_fd(), &target, set),
        None => attach(host, &target, set),
    }
}

/// Binds `host` (and every mount below it) at `target` as a detached clone that gets the
/// attributes `set` before it is attached, so it is never visible without them. Attaching under
/// a shared parent joins the clone to its peer group whatever the clone's own propagation was,
/// so it is made private afterwards: a mount the host makes later below `host` must not
/// appear in the view, writable and without `nosuid`.
fn attach(host: &Path, target: &Path, set: u64) -> Result<()> {
    attach_fd(open_path(host)?.as_fd(), target, set)
}

/// `attach` for a source already opened.
fn attach_fd(source: BorrowedFd<'_>, target: &Path, set: u64) -> Result<()> {
    let clone = open_tree(source, c"", true)?;
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
