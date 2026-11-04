// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The exit status of a process from its pidfd (`PIDFD_INFO_EXIT`, Linux 6.15).
use qinit_sys::proc::{PidfdExit, pidfd_exit, pidfd_open};
use std::os::fd::AsFd;
use std::process::{Child, Command};

fn spawn(script: &str) -> Child {
    Command::new("sh").args(["-c", script]).spawn().unwrap()
}

/// Polls the pidfd until the process has exited (without reaping it).
fn until_exited(fd: impl AsFd) {
    let mut p = libc::pollfd {
        fd: std::os::fd::AsRawFd::as_raw_fd(&fd.as_fd()),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd and a count of one.
    assert_eq!(unsafe { libc::poll(&raw mut p, 1, 5000) }, 1);
}

#[test]
fn a_live_child_is_running() {
    let mut c = spawn("sleep 5");
    let fd = pidfd_open(c.id().cast_signed()).unwrap();
    assert_eq!(pidfd_exit(&fd).unwrap(), PidfdExit::Running);
    c.kill().unwrap();
    c.wait().unwrap();
}

/// Whether this kernel reports exit statuses through a pidfd (Linux 6.15).
fn kernel_reports() -> bool {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
    let mut n = release
        .split(|c: char| !c.is_ascii_digit())
        .filter_map(|s| s.parse::<u32>().ok());
    (n.next().unwrap(), n.next().unwrap()) >= (6, 15)
}

#[test]
fn a_reaped_child_reports_its_status() {
    let mut c = spawn("exit 7");
    let fd = pidfd_open(c.id().cast_signed()).unwrap();
    until_exited(&fd);
    c.wait().unwrap();
    match pidfd_exit(&fd).unwrap() {
        PidfdExit::Exited(status) => {
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 7);
        }
        other => assert!(
            !kernel_reports() && other == PidfdExit::Unsupported,
            "{other:?}"
        ),
    }
    assert_eq!(
        pidfd_exit(&fd).unwrap() == PidfdExit::Unsupported,
        !kernel_reports()
    );
}

#[test]
fn a_child_killed_by_a_signal_reports_it() {
    let mut c = spawn("kill -KILL $$");
    let fd = pidfd_open(c.id().cast_signed()).unwrap();
    until_exited(&fd);
    c.wait().unwrap();
    if kernel_reports() {
        let PidfdExit::Exited(status) = pidfd_exit(&fd).unwrap() else {
            panic!("no status");
        };
        assert!(libc::WIFSIGNALED(status));
        assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
    }
}

#[test]
fn an_exited_child_not_yet_reaped_has_no_status_yet() {
    let mut c = spawn("exit 3");
    let fd = pidfd_open(c.id().cast_signed()).unwrap();
    until_exited(&fd);
    if kernel_reports() {
        assert_eq!(pidfd_exit(&fd).unwrap(), PidfdExit::Running);
    }
    c.wait().unwrap();
    if kernel_reports() {
        let PidfdExit::Exited(status) = pidfd_exit(&fd).unwrap() else {
            panic!("no status after the reap");
        };
        assert_eq!(libc::WEXITSTATUS(status), 3);
    }
}
