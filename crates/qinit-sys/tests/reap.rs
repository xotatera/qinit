// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! `peek_any` and `reap_pid` on the host. Its own test binary: a peek at every child must not
//! see another test's.
use qinit_sys::{event, proc};
use std::os::fd::AsRawFd;

#[test]
fn a_peeked_child_stays_waitable_until_reaped_by_pid() {
    assert_eq!(proc::peek_any(), Ok(None), "no children yet");
    let child = std::process::Command::new("sh")
        .args(["-c", "exit 3"])
        .spawn()
        .unwrap();
    let pid = child.id() as libc::pid_t;
    // Wait for the exit through a pidfd's readiness, which reaps nothing.
    let pidfd = proc::pidfd_open(pid).unwrap();
    let ep = event::epoll().unwrap();
    event::epoll_add(&ep, pidfd.as_raw_fd(), libc::EPOLLIN as u32, 1).unwrap();
    let mut evs = [libc::epoll_event { events: 0, u64: 0 }; 1];
    assert_eq!(event::epoll_wait(&ep, &mut evs).unwrap(), 1);
    let (who, raw) = proc::peek_any().unwrap().expect("an exited child");
    assert_eq!(who, pid);
    assert!(libc::WIFEXITED(raw) && libc::WEXITSTATUS(raw) == 3);
    assert_eq!(
        proc::peek_any(),
        Ok(Some((pid, raw))),
        "a peek leaves it waitable"
    );
    assert_eq!(proc::reap_pid(pid), Ok(Some(raw)));
    assert_eq!(proc::peek_any(), Ok(None));
    // `child` is never waited for by std: `reap_pid` reaped it.
    std::mem::forget(child);
}
