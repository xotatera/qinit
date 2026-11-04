// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The file-system and absolute-alarm primitives. Alarm cases run in a child: the test binary
//! re-runs itself with `QINIT_SYS_ROLE` set, and `child_roles` dispatches the role.
use qinit_sys::fs::{Kind, create_file, lstat_kind, mkdir_all, readlink, symlink};
use qinit_sys::timer::{arm_alarm_at, now_monotonic_ns};
use qinit_sys::{Errno, proc};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::ExitStatus;

fn scratch(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("qinit-sys-fs-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn child_status(role: &str) -> ExitStatus {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_roles"])
        .env("QINIT_SYS_ROLE", role)
        .status()
        .unwrap()
}

/// The child half: with `QINIT_SYS_ROLE` set it runs the role and exits; otherwise it passes.
#[test]
fn child_roles() {
    let Ok(role) = std::env::var("QINIT_SYS_ROLE") else {
        return;
    };
    let code = match role.as_str() {
        "alarm-past" => {
            arm_alarm_at(now_monotonic_ns()).unwrap();
            loop {
                proc::pause();
            }
        }
        "alarm-deleted" => {
            let a = arm_alarm_at(now_monotonic_ns() + 50_000_000).unwrap();
            a.delete().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(150));
            0
        }
        _ => 99,
    };
    std::process::exit(code);
}

#[test]
fn lstat_tells_dirs_files_and_symlinks() {
    let d = scratch("lstat");
    std::fs::create_dir(d.join("dir")).unwrap();
    std::fs::write(d.join("file"), b"x").unwrap();
    std::os::unix::fs::symlink("file", d.join("link")).unwrap();
    assert_eq!(lstat_kind(&d.join("dir")).unwrap(), Kind::Dir);
    assert_eq!(lstat_kind(&d.join("file")).unwrap(), Kind::File);
    assert_eq!(lstat_kind(&d.join("link")).unwrap(), Kind::Symlink);
    assert_eq!(
        lstat_kind(&d.join("missing")).unwrap_err(),
        Errno(libc::ENOENT)
    );
}

#[test]
fn readlink_returns_the_target() {
    let d = scratch("readlink");
    symlink(std::path::Path::new("/proc/self/fd"), &d.join("fd")).unwrap();
    assert_eq!(
        readlink(&d.join("fd")).unwrap(),
        PathBuf::from("/proc/self/fd")
    );
}

#[test]
fn create_file_refuses_an_existing_file() {
    let d = scratch("create");
    create_file(&d.join("f"), 0o644).unwrap();
    assert_eq!(lstat_kind(&d.join("f")).unwrap(), Kind::File);
    assert_eq!(
        create_file(&d.join("f"), 0o644).unwrap_err(),
        Errno(libc::EEXIST)
    );
}

#[test]
fn mkdir_all_creates_parents() {
    let d = scratch("mkdirall");
    mkdir_all(&d.join("a/b/c"), 0o755).unwrap();
    assert_eq!(lstat_kind(&d.join("a/b/c")).unwrap(), Kind::Dir);
    mkdir_all(&d.join("a/b/c"), 0o755).unwrap();
}

#[test]
fn an_absolute_alarm_in_the_past_fires_at_once() {
    assert_eq!(child_status("alarm-past").signal(), Some(libc::SIGALRM));
}

#[test]
fn a_deleted_alarm_never_fires() {
    assert_eq!(child_status("alarm-deleted").code(), Some(0));
}
