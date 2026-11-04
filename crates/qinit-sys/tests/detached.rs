// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Detached mount clones and symlink-free opens. The mount cases run in a child that is in a new
//! user and mount namespace (the test binary re-runs itself with `QINIT_SYS_ROLE` set, as the
//! other test files do), so they change nothing on the host.
use qinit_sys::Errno;
use qinit_sys::fs::{is_readonly, open_beneath, open_path};
use qinit_sys::mount::{
    MOUNT_ATTR_NODEV, MOUNT_ATTR_NOSUID, MOUNT_ATTR_RDONLY, PROPAGATION_PRIVATE, mkdir, mount_data,
    move_mount_to, move_mount_to_fd, open_tree, setattr_fd,
};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

fn scratch(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("qinit-sys-det-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// `"0 <id> 1\n"` as bytes, built without allocating (it runs between fork and exec).
fn map_line(id: u32) -> ([u8; 32], usize) {
    let mut buf = [0u8; 32];
    let mut n = 0;
    for b in b"0 " {
        buf[n] = *b;
        n += 1;
    }
    let mut digits = [0u8; 10];
    let (mut v, mut d) = (id, 0);
    loop {
        digits[d] = b'0' + (v % 10) as u8;
        d += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    while d > 0 {
        d -= 1;
        buf[n] = digits[d];
        n += 1;
    }
    for b in b" 1\n" {
        buf[n] = *b;
        n += 1;
    }
    (buf, n)
}

/// Re-runs this binary as `role` in fresh user and mount namespaces; true when it exited 0.
fn in_namespaces(role: &str, dir: &Path) -> bool {
    let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", "child_roles", "--nocapture"])
        .env("QINIT_SYS_ROLE", role)
        .env("QINIT_SYS_DIR", dir);
    let own = std::fs::metadata("/proc/self").unwrap();
    let (uid, gid) = (own.uid(), own.gid());
    // SAFETY: the closure runs between fork and exec in a single-threaded child; it unshares and
    // writes short proc files from stack buffers. Mapping the caller's ids to 0 keeps the
    // capabilities across the exec and lets the child create files, which unmapped ids do not.
    unsafe {
        cmd.pre_exec(move || {
            qinit_sys::ns::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS)
                .map_err(std::io::Error::from)?;
            let (u, un) = map_line(uid);
            std::fs::write("/proc/self/uid_map", &u[..un])?;
            std::fs::write("/proc/self/setgroups", b"deny")?;
            let (g, gn) = map_line(gid);
            std::fs::write("/proc/self/gid_map", &g[..gn])
        });
    }
    cmd.status().unwrap().success()
}

/// A tmpfs at `dir/base/view` (the attach target's parent) below a shared tmpfs `dir/base`, so a
/// clone that is not made private would join a peer group.
fn view_tmpfs(dir: &Path) -> PathBuf {
    let base = dir.join("base");
    std::fs::create_dir_all(&base).unwrap();
    mount_data("tmpfs", &base, "tmpfs", 0, Some(c"mode=1777")).unwrap();
    let b = std::ffi::CString::new(base.to_str().unwrap()).unwrap();
    // SAFETY: NUL-terminated strings, no data argument.
    let r = unsafe {
        libc::mount(
            std::ptr::null(),
            b.as_ptr(),
            std::ptr::null(),
            libc::MS_SHARED | libc::MS_REC,
            std::ptr::null(),
        )
    };
    assert_eq!(r, 0, "making the base shared: {}", Errno::last());
    let view = base.join("view");
    mkdir(&view, 0o755).unwrap();
    mount_data("tmpfs", &view, "tmpfs", 0, Some(c"mode=1777")).unwrap();
    mkdir(&view.join("t"), 0o755).unwrap();
    view
}

fn attached_line(target: &Path) -> String {
    let mi = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    let t = target.to_str().unwrap();
    mi.lines()
        .find(|l| l.split(' ').nth(4) == Some(t))
        .unwrap_or_else(|| panic!("no mount at {t} in {mi}"))
        .to_owned()
}

#[test]
fn child_roles() {
    let Ok(role) = std::env::var("QINIT_SYS_ROLE") else {
        return;
    };
    let dir = PathBuf::from(std::env::var("QINIT_SYS_DIR").unwrap());
    let view = view_tmpfs(&dir);
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    let clone = open_tree(open_path(&src).unwrap().as_fd(), c"", true).unwrap();
    let target = view.join("t");
    match role.as_str() {
        "attach-ro" => {
            setattr_fd(
                clone.as_fd(),
                MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
                0,
                0,
                None,
                true,
            )
            .unwrap();
            move_mount_to(clone.as_fd(), &target).unwrap();
            assert!(is_readonly(&target).unwrap());
            assert!(!is_readonly(&src).unwrap());
            std::fs::write(src.join("still-writable"), b"x").unwrap();
        }
        "attach-private" => {
            // Attaching under a shared parent joins the clone to its peer group even when the
            // detached clone was made private first, so privacy is set after the attach.
            setattr_fd(clone.as_fd(), 0, 0, PROPAGATION_PRIVATE, None, true).unwrap();
            move_mount_to(clone.as_fd(), &target).unwrap();
            assert!(attached_line(&target).contains("shared:"));
            let attached = open_path(&target).unwrap();
            setattr_fd(attached.as_fd(), 0, 0, PROPAGATION_PRIVATE, None, true).unwrap();
            let line = attached_line(&target);
            assert!(
                !line.contains("shared:") && !line.contains("master:"),
                "peer group: {line}"
            );
        }
        "attach-fd" => {
            let to = open_path(&target).unwrap();
            move_mount_to_fd(clone.as_fd(), to.as_fd()).unwrap();
            // Opening the same name again crosses into the new mount: it is the clone's root.
            let again = open_path(&target).unwrap();
            assert_eq!(
                qinit_sys::fd::file_type(again.as_fd()).unwrap(),
                libc::S_IFDIR
            );
            assert!(!attached_line(&target).is_empty());
        }
        _ => std::process::exit(99),
    }
    std::process::exit(0);
}

#[test]
fn open_beneath_refuses_a_symlink_component() {
    let d = scratch("beneath");
    std::fs::create_dir_all(d.join("d")).unwrap();
    std::fs::write(d.join("d/f"), b"x").unwrap();
    std::os::unix::fs::symlink("..", d.join("d/s")).unwrap();
    let dfd = open_path(&d.join("d")).unwrap();
    assert!(open_beneath(dfd.as_fd(), Path::new("f")).is_ok());
    assert_eq!(
        open_beneath(dfd.as_fd(), Path::new("s")).unwrap_err(),
        Errno(libc::ELOOP)
    );
    assert_eq!(
        open_beneath(dfd.as_fd(), Path::new("s/x")).unwrap_err(),
        Errno(libc::ELOOP)
    );
}

#[test]
fn open_beneath_refuses_dotdot_out() {
    let d = scratch("dotdot");
    std::fs::create_dir_all(d.join("d")).unwrap();
    std::fs::write(d.join("x"), b"x").unwrap();
    let dfd = open_path(&d.join("d")).unwrap();
    assert_eq!(
        open_beneath(dfd.as_fd(), Path::new("../x")).unwrap_err(),
        Errno(libc::EXDEV)
    );
}

#[test]
fn a_detached_clone_attaches_read_only() {
    let d = scratch("ro");
    assert!(in_namespaces("attach-ro", &d));
}

#[test]
fn setattr_fd_propagation_private_leaves_no_peer_group() {
    let d = scratch("private");
    assert!(in_namespaces("attach-private", &d));
}

#[test]
fn create_at_and_mkdirat_make_entries_beneath_a_descriptor() {
    use qinit_sys::fs::{create_at, mkdirat};
    let d = scratch("create");
    let dfd = open_path(&d).unwrap();
    mkdirat(dfd.as_fd(), c"sub", 0o755).unwrap();
    create_at(dfd.as_fd(), c"file", 0o644).unwrap();
    assert!(d.join("sub").is_dir() && d.join("file").is_file());
    // A second create of the same name, and one through a planted symlink, are refused.
    assert_eq!(
        create_at(dfd.as_fd(), c"file", 0o644).unwrap_err(),
        Errno(libc::EEXIST)
    );
    std::os::unix::fs::symlink("/etc/x", d.join("link")).unwrap();
    assert!(create_at(dfd.as_fd(), c"link", 0o644).is_err());
    assert!(!Path::new("/etc/x").exists());
}

#[test]
fn a_clone_attaches_on_a_descriptor() {
    let d = scratch("tofd");
    assert!(in_namespaces("attach-fd", &d));
}
