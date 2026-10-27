// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The spawn path on the host, without a cgroup (plan P7: cells are tested in guests).
use qinit_sys::{Errno, fd, proc, signal, spawn};
use std::ffi::OsStr;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::Path;

fn sh(script: &str) -> Vec<&OsStr> {
    vec![OsStr::new("sh"), OsStr::new("-c"), OsStr::new(script)]
}

fn read_all(fd: OwnedFd) -> String {
    let mut s = String::new();
    std::fs::File::from(fd).read_to_string(&mut s).unwrap();
    s
}

/// Spawns `/bin/sh -c script` with `routes`; returns the exec-error pipe's bytes and the
/// child's wait status.
fn run(script: &str, routes: &[(std::os::fd::BorrowedFd<'_>, i32)]) -> (Vec<u8>, i32) {
    let p = spawn::Prepared::new(Path::new("/bin/sh"), &sh(script), &[], routes).unwrap();
    let (err_r, err_w) = fd::pipe(libc::O_CLOEXEC).unwrap();
    let (_pid, pidfd) = spawn::spawn(&p, None, err_w.as_fd()).unwrap();
    drop(err_w);
    let mut bytes = Vec::new();
    std::fs::File::from(err_r).read_to_end(&mut bytes).unwrap();
    let status = proc::wait_pidfd(&pidfd).unwrap();
    (bytes, status)
}

#[test]
fn only_routed_descriptors_arrive() {
    let (r, w) = fd::pipe(libc::O_CLOEXEC).unwrap();
    let script = "for n in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do [ -e /proc/self/fd/$n ] && echo $n; done; true";
    let (err, status) = run(script, &[(w.as_fd(), 1)]);
    drop(w);
    assert!(err.is_empty(), "exec succeeded");
    assert_eq!(libc::WEXITSTATUS(status), 0);
    assert_eq!(
        read_all(r),
        "1\n",
        "stdin, stderr and every unrouted descriptor are closed"
    );
}

#[test]
fn swapped_routes_arrive_swapped() {
    let (ar, aw) = fd::pipe(libc::O_CLOEXEC).unwrap();
    let (br, bw) = fd::pipe(libc::O_CLOEXEC).unwrap();
    let (x, y) = (aw.as_raw_fd(), bw.as_raw_fd());
    // A's write end arrives as number y, B's as number x: each route's target is the other
    // route's source. Writes go through /proc (dash redirects only single-digit numbers).
    let script = format!("echo a > /proc/self/fd/{y}; echo b > /proc/self/fd/{x}");
    let (err, status) = run(&script, &[(aw.as_fd(), y), (bw.as_fd(), x)]);
    drop((aw, bw));
    assert!(err.is_empty());
    assert_eq!(libc::WEXITSTATUS(status), 0);
    assert_eq!(read_all(ar), "a\n");
    assert_eq!(read_all(br), "b\n");
}

#[test]
fn a_source_routed_to_its_own_number_survives() {
    let (r, w) = fd::pipe(libc::O_CLOEXEC).unwrap();
    let n = w.as_raw_fd();
    let (err, _) = run(&format!("echo same > /proc/self/fd/{n}"), &[(w.as_fd(), n)]);
    drop(w);
    assert!(err.is_empty());
    assert_eq!(read_all(r), "same\n");
}

#[test]
fn an_exec_failure_reports_its_errno() {
    let p = spawn::Prepared::new(Path::new("/nonexistent/qinit"), &sh("true"), &[], &[]).unwrap();
    let (err_r, err_w) = fd::pipe(libc::O_CLOEXEC).unwrap();
    let (_pid, pidfd) = spawn::spawn(&p, None, err_w.as_fd()).unwrap();
    drop(err_w);
    let mut bytes = Vec::new();
    std::fs::File::from(err_r).read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, libc::ENOENT.to_ne_bytes());
    assert_eq!(libc::WEXITSTATUS(proc::wait_pidfd(&pidfd).unwrap()), 127);
}

#[test]
fn routes_over_the_error_pipes_number_still_report_an_exec_failure() {
    let (_r, w) = fd::pipe(libc::O_CLOEXEC).unwrap();
    let (err_r, err_w) = fd::pipe(libc::O_CLOEXEC).unwrap();
    // Run alone so parallel tests cannot allocate the deliberate descriptor hole.
    if std::env::var_os("QINIT_ERROR_FLOOR_CHILD").is_none() {
        assert!(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "routes_over_the_error_pipes_number_still_report_an_exec_failure"
                ])
                .env("QINIT_ERROR_FLOOR_CHILD", "1")
                .status()
                .unwrap()
                .success()
        );
        return;
    }
    // The next free number becomes a route target. A floor=0 error-pipe copy would
    // occupy this hole and dup3 would overwrite it; the protected floor must avoid it.
    let hole = fd::dup_above(&w, 0).unwrap();
    let n = hole.as_raw_fd();
    let routes = [(w.as_fd(), n)];
    let p =
        spawn::Prepared::new(Path::new("/nonexistent/qinit"), &sh("true"), &[], &routes).unwrap();
    drop(hole);
    let (_pid, pidfd) = spawn::spawn(&p, None, err_w.as_fd()).unwrap();
    drop(err_w);
    let mut bytes = Vec::new();
    std::fs::File::from(err_r).read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, libc::ENOENT.to_ne_bytes());
    assert_eq!(libc::WEXITSTATUS(proc::wait_pidfd(&pidfd).unwrap()), 127);
}

#[test]
fn the_child_starts_with_no_signal_blocked_or_ignored() {
    signal::block_in_thread(&[libc::SIGUSR1]).unwrap();
    let (r, w) = fd::pipe(libc::O_CLOEXEC).unwrap();
    let (err, _) = run(
        "grep -E '^Sig(Blk|Ign):' /proc/self/status",
        &[(w.as_fd(), 1)],
    );
    drop(w);
    signal::unblock_all().unwrap();
    assert!(err.is_empty());
    assert_eq!(
        read_all(r),
        "SigBlk:\t0000000000000000\nSigIgn:\t0000000000000000\n"
    );
}

#[test]
fn prepared_refuses_bad_targets() {
    let (_r, w) = fd::pipe(libc::O_CLOEXEC).unwrap();
    let bad = |routes: &[(std::os::fd::BorrowedFd<'_>, i32)]| {
        spawn::Prepared::new(Path::new("/bin/sh"), &sh("true"), &[], routes).err()
    };
    assert_eq!(
        bad(&[(w.as_fd(), 3), (w.as_fd(), 3)]),
        Some(Errno(libc::EINVAL)),
        "duplicate target"
    );
    assert_eq!(
        bad(&[(w.as_fd(), -1)]),
        Some(Errno(libc::EINVAL)),
        "negative target"
    );
    assert_eq!(
        bad(&[(w.as_fd(), spawn::MAX_TARGET + 1)]),
        Some(Errno(libc::EINVAL)),
        "target too high"
    );
    let count = i32::try_from(spawn::MAX_ROUTES).unwrap();
    let many: Vec<_> = (0..=count).map(|n| (w.as_fd(), n)).collect();
    assert_eq!(bad(&many), Some(Errno(libc::EINVAL)), "too many routes");
}
