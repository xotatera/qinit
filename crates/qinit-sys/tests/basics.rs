// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The shim's foundations on the host: descriptors, epoll, timers, signals and pidfd reaping.
//! Only kernel features far below qinit's floor (plan P7).
use qinit_sys::{event, fd, proc, signal};
use std::os::fd::AsRawFd;
use std::time::Duration;

fn wait_one(ep: &std::os::fd::OwnedFd) -> u64 {
    let mut evs = [libc::epoll_event { events: 0, u64: 0 }; 4];
    let n = event::epoll_wait(ep, &mut evs).unwrap();
    assert_eq!(n, 1, "one ready source");
    evs[0].u64
}

#[test]
fn a_written_pipe_is_readable_under_its_token() {
    let (r, w) = fd::pipe(libc::O_CLOEXEC).unwrap();
    let ep = event::epoll().unwrap();
    event::epoll_add(&ep, r.as_raw_fd(), libc::EPOLLIN as u32, 7).unwrap();
    assert_eq!(write_bytes(&w, b"x"), 1);
    assert_eq!(wait_one(&ep), 7);
    let mut buf = [0u8; 4];
    assert_eq!(event::read(&r, &mut buf).unwrap(), 1);
}

fn write_bytes(fd: &std::os::fd::OwnedFd, bytes: &[u8]) -> usize {
    use std::io::Write;
    let mut f = std::fs::File::from(fd.try_clone().unwrap());
    f.write(bytes).unwrap()
}

#[test]
fn a_timer_fires_once() {
    let t = event::timer(Duration::from_millis(1)).unwrap();
    let ep = event::epoll().unwrap();
    event::epoll_add(&ep, t.as_raw_fd(), libc::EPOLLIN as u32, 3).unwrap();
    assert_eq!(wait_one(&ep), 3);
}

#[test]
fn a_blocked_signal_arrives_on_its_signalfd() {
    // Signals are per thread here: the test thread blocks SIGUSR2 and sends it to itself.
    let sfd = event::signalfd_blocking(&[libc::SIGUSR2]).unwrap();
    proc::kill_thread_self(libc::SIGUSR2).unwrap();
    let ep = event::epoll().unwrap();
    event::epoll_add(&ep, sfd.as_raw_fd(), libc::EPOLLIN as u32, 9).unwrap();
    assert_eq!(wait_one(&ep), 9);
    assert_eq!(event::read_signal(&sfd), Some(libc::SIGUSR2 as u32));
    signal::unblock_all().unwrap();
}

#[test]
fn a_child_is_reaped_through_its_pidfd_with_its_status() {
    let child = std::process::Command::new("sh")
        .args(["-c", "exit 3"])
        .spawn()
        .unwrap();
    let pidfd = proc::pidfd_open(child.id() as libc::pid_t).unwrap();
    let ep = event::epoll().unwrap();
    event::epoll_add(&ep, pidfd.as_raw_fd(), libc::EPOLLIN as u32, 1).unwrap();
    assert_eq!(wait_one(&ep), 1);
    let raw = proc::reap_pidfd(&pidfd).unwrap().expect("exited");
    assert!(libc::WIFEXITED(raw));
    assert_eq!(libc::WEXITSTATUS(raw), 3);
    // `child` is never waited for by std: the pidfd reaped it.
    std::mem::forget(child);
}

struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn a_killed_child_reports_its_signal() {
    let child = KillOnDrop(
        std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap(),
    );
    let pidfd = proc::pidfd_open(child.0.id() as libc::pid_t).unwrap();
    assert!(proc::pidfd_signal(&pidfd, libc::SIGKILL).unwrap());
    let ep = event::epoll().unwrap();
    event::epoll_add(&ep, pidfd.as_raw_fd(), libc::EPOLLIN as u32, 1).unwrap();
    wait_one(&ep);
    let raw = proc::reap_pidfd(&pidfd).unwrap().expect("exited");
    assert!(libc::WIFSIGNALED(raw));
    assert_eq!(libc::WTERMSIG(raw), libc::SIGKILL);
}

#[test]
fn wait_status_matches_the_waitpid_encoding() {
    assert_eq!(proc::wait_status(libc::CLD_EXITED, 3), 3 << 8);
    assert_eq!(
        proc::wait_status(libc::CLD_KILLED, libc::SIGTERM),
        libc::SIGTERM
    );
    assert_eq!(
        proc::wait_status(libc::CLD_DUMPED, libc::SIGSEGV),
        libc::SIGSEGV | 0x80
    );
}

#[test]
fn the_kernel_release_is_named() {
    assert!(!proc::kernel_release().unwrap().is_empty());
}

#[test]
fn dup_above_lands_above_the_floor() {
    let (r, _w) = fd::pipe(libc::O_CLOEXEC).unwrap();
    let high = fd::dup_above(&r, 100).unwrap();
    assert!(high.as_raw_fd() >= 100);
    assert!(fd::is_open(high.as_raw_fd()));
}

/// The `flags:` field of `/proc/self/fdinfo/<n>` (octal).
fn fdinfo_flags(n: std::os::fd::RawFd) -> u32 {
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{n}")).unwrap();
    let flags = info.lines().find_map(|l| l.strip_prefix("flags:")).unwrap();
    u32::from_str_radix(flags.trim(), 8).unwrap()
}

#[test]
fn set_cloexec_raw_marks_a_descriptor_close_on_exec() {
    let (r, _w) = fd::pipe(0).unwrap();
    let cloexec = u32::try_from(libc::O_CLOEXEC).unwrap();
    assert_eq!(fdinfo_flags(r.as_raw_fd()) & cloexec, 0);
    fd::set_cloexec_raw(r.as_raw_fd()).unwrap();
    assert_ne!(fdinfo_flags(r.as_raw_fd()) & cloexec, 0);
    assert!(
        fd::is_open(r.as_raw_fd()),
        "the flag leaves the descriptor open"
    );
}

#[test]
fn set_cloexec_raw_on_a_number_never_open_is_ebadf() {
    // Above any descriptor limit, so no concurrent test can have it open.
    assert_eq!(
        fd::set_cloexec_raw(std::os::fd::RawFd::MAX),
        Err(qinit_sys::Errno(libc::EBADF))
    );
}
