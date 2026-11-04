// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The path view (sandbox design §2.3): an empty tmpfs root holding the fixed `/dev` and `/tmp`
//! and a bind of each listed path, pivoted into before the credentials are changed. Every
//! function performs one plan step.
#![allow(clippy::missing_errors_doc)] // each step returns the errno of the call that failed
use qinit_sys::fd::file_type;
use qinit_sys::fs::{
    Kind, create_at, create_file, lstat_kind, mkdir_all, mkdirat, open_beneath, open_path,
    readlink, symlink,
};
use qinit_sys::landlock::{LANDLOCK_ACCESS_FS_ALL_V3, add_path_rule};
use qinit_sys::mount::{
    MOUNT_ATTR_IDMAP, MOUNT_ATTR_NODEV, MOUNT_ATTR_NOSUID, MOUNT_ATTR_RDONLY, PROPAGATION_PRIVATE,
    mount_data, move_mount_to, move_mount_to_fd, open_tree, pivot_root, private_rec, rmdir,
    setattr, setattr_fd, umount_detach,
};
use qinit_sys::{Errno, Result};
use std::ffi::CString;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
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
    // The directory of the colony's socket too: only the view itself is private.
    mkdir_all(Path::new("/run/qinit"), 0o755)?;
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
        let clone = clone_of(
            open_path(&Path::new("/dev").join(node))?.as_fd(),
            0,
            Mode::Rw,
            None,
        )?;
        move_mount_to(clone.as_fd(), &target)?;
        private_rec(&target)?;
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
/// component included (`ELOOP`), so nothing planted there redirects the bind. `idmap`: the
/// helper user namespace an idmapped entry (`ri:`, `wi:`) is mapped through; without it such an
/// entry fails (`EINVAL`) instead of being bound plain.
pub fn entry(
    entry: &str,
    pid: bool,
    beneath: Option<&Path>,
    idmap: Option<BorrowedFd<'_>>,
) -> Result<()> {
    let (mode, path) = split(entry)?;
    let host = Path::new(path);
    let mut set = MOUNT_ATTR_NOSUID;
    if !below_dev(path) {
        set |= MOUNT_ATTR_NODEV;
    }
    if mode.read_only() {
        set |= MOUNT_ATTR_RDONLY;
    }
    let map = match (mode.idmapped(), idmap) {
        (false, _) => None,
        (true, Some(ns)) => Some(ns),
        (true, None) => return Err(Errno(libc::EINVAL)),
    };
    if let Some(above) = beneath {
        // Neither the source nor the place it goes to is looked up by a path a symlink in a
        // directory the service can write could redirect.
        let rest = host.strip_prefix(above).map_err(|_| Errno(libc::EINVAL))?;
        let source = open_beneath(open_path(above)?.as_fd(), rest)?;
        return attach_beneath(
            &at(&above.to_string_lossy()),
            rest,
            source.as_fd(),
            set,
            mode,
            map,
        );
    }
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
    if path == "/proc" && mode == Mode::Ro && pid {
        return mount_data(
            "proc",
            &target,
            "proc",
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_RDONLY,
            None,
        );
    }
    let clone = clone_of(open_path(host)?.as_fd(), set, mode, map)?;
    move_mount_to(clone.as_fd(), &target)?;
    if mode.follows() {
        Ok(())
    } else {
        private_rec(&target)
    }
}

/// The detached clone of the tree behind `source` (and every mount below it) with the attributes
/// `set` already on it, so it is never visible without them; with `idmap` it is idmapped through
/// that user namespace, which fails (`EINVAL`) when a filesystem below does not support it. It
/// is made private unless the mode follows the host's later mounts (`rs:`, `ws:`).
fn clone_of(
    source: BorrowedFd<'_>,
    set: u64,
    mode: Mode,
    idmap: Option<BorrowedFd<'_>>,
) -> Result<OwnedFd> {
    let clone = open_tree(source, c"", true)?;
    let set = if idmap.is_some() {
        set | MOUNT_ATTR_IDMAP
    } else {
        set
    };
    let propagation = if mode.follows() {
        0
    } else {
        PROPAGATION_PRIVATE
    };
    setattr_fd(clone.as_fd(), set, 0, propagation, idmap, true)?;
    Ok(clone)
}

/// Attaches the clone of `source` at `rest` below `base` (the writable entry's directory in the
/// view), walking and creating the path one component at a time with `openat2` that refuses
/// every symlink, and moving the mount onto the descriptor of the last component. Attaching
/// under a shared parent joins the clone to its peer group whatever its own propagation was, so
/// a mode that does not follow makes the attached mount private again.
fn attach_beneath(
    base: &Path,
    rest: &Path,
    source: BorrowedFd<'_>,
    set: u64,
    mode: Mode,
    idmap: Option<BorrowedFd<'_>>,
) -> Result<()> {
    let is_dir = file_type(source)? == libc::S_IFDIR;
    let names: Vec<CString> = rest
        .components()
        .map(|c| CString::new(c.as_os_str().as_bytes()).map_err(|_| Errno(libc::EINVAL)))
        .collect::<Result<_>>()?;
    let mut dir = open_path(base)?;
    let mut parent = None;
    for (i, name) in names.iter().enumerate() {
        let last = i + 1 == names.len();
        let rel = Path::new(std::ffi::OsStr::from_bytes(name.to_bytes()));
        let next = match open_beneath(dir.as_fd(), rel) {
            Ok(fd) => fd,
            Err(Errno(libc::ENOENT)) => {
                if last && !is_dir {
                    create_at(dir.as_fd(), name, 0o644)?;
                } else {
                    mkdirat(dir.as_fd(), name, 0o755)?;
                }
                open_beneath(dir.as_fd(), rel)?
            }
            Err(e) => return Err(e),
        };
        if !last && file_type(next.as_fd())? != libc::S_IFDIR {
            return Err(Errno(libc::ENOTDIR));
        }
        parent = Some(dir);
        dir = next;
    }
    let clone = clone_of(source, set, mode, idmap)?;
    move_mount_to_fd(clone.as_fd(), dir.as_fd())?;
    if mode.follows() {
        return Ok(());
    }
    // The descriptor is the mount point underneath; the name now leads into the new mount.
    let parent = parent.ok_or(Errno(libc::EINVAL))?;
    let last = names.last().ok_or(Errno(libc::EINVAL))?;
    let attached = open_beneath(
        parent.as_fd(),
        Path::new(std::ffi::OsStr::from_bytes(last.to_bytes())),
    )?;
    setattr_fd(attached.as_fd(), 0, 0, PROPAGATION_PRIVATE, None, true)
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
