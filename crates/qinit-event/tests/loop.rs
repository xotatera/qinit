// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use qinit_event::{Error, Loop, Ready, exit_code, parse_inotify};
use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};
use std::time::Duration;

#[test]
fn readable_then_hangup() {
    // A pipe: a socket whose peer closed stays `EPOLLIN` (EOF to read), so it reports
    // `Readable`, never `Hangup`.
    let (a, b) = qinit_sys::fd::pipe(libc::O_CLOEXEC).unwrap();
    let (a, mut b) = (std::fs::File::from(a), std::fs::File::from(b));
    let mut l = Loop::new().unwrap();
    l.add_fd(a.as_fd(), 1).unwrap();
    b.write_all(b"x").unwrap();
    assert_eq!(l.wait().unwrap(), [Ready::Readable(1)]);
    let mut buf = [0u8; 1];
    std::io::Read::read(&mut &a, &mut buf).unwrap();
    drop(b);
    assert_eq!(l.wait().unwrap(), [Ready::Hangup(1)]);
}

#[test]
fn a_deadline_reports_once_and_removes_itself() {
    let mut l = Loop::new().unwrap();
    l.add_deadline(Duration::from_millis(1), 4).unwrap();
    assert_eq!(l.wait().unwrap(), [Ready::Deadline(4)]);
    assert_eq!(l.wait(), Err(Error::Empty));
}

#[test]
fn a_pidfd_reports_exit_with_its_code_and_reaps() {
    let child = std::process::Command::new("sh")
        .args(["-c", "exit 5"])
        .spawn()
        .unwrap();
    let pidfd: OwnedFd = qinit_sys::proc::pidfd_open(child.id() as libc::pid_t).unwrap();
    let mut l = Loop::new().unwrap();
    l.add_pidfd(pidfd.as_fd(), 2).unwrap();
    let got = l.wait().unwrap();
    let [Ready::Exited(2, raw)] = got.as_slice() else {
        panic!("{got:?}")
    };
    assert_eq!(exit_code(*raw), 5);
    std::mem::forget(child);
}

#[test]
fn exits_come_before_other_events_in_one_batch() {
    let child = std::process::Command::new("true").spawn().unwrap();
    let pidfd: OwnedFd = qinit_sys::proc::pidfd_open(child.id() as libc::pid_t).unwrap();
    let (a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
    b.write_all(b"x").unwrap();
    // Wait until the child has exited, so both sources are ready in the same batch.
    let mut probe = Loop::new().unwrap();
    let dup = pidfd.try_clone().unwrap();
    probe.add_fd(dup.as_fd(), 9).unwrap();
    assert_eq!(probe.wait().unwrap(), [Ready::Readable(9)]);
    let mut l = Loop::new().unwrap();
    l.add_fd(a.as_fd(), 1).unwrap();
    l.add_pidfd(pidfd.as_fd(), 2).unwrap();
    let got = l.wait().unwrap();
    assert!(matches!(got[0], Ready::Exited(2, _)), "{got:?}");
    std::mem::forget(child);
}

#[test]
fn a_blocked_signal_is_reported() {
    let mut l = Loop::new().unwrap();
    l.add_signal(&[libc::SIGUSR1], 3).unwrap();
    qinit_sys::proc::kill_thread_self(libc::SIGUSR1).unwrap();
    assert_eq!(l.wait().unwrap(), [Ready::Signal(3, libc::SIGUSR1 as u32)]);
    qinit_sys::signal::unblock_all().unwrap();
}

#[test]
fn inotify_reports_a_modified_file() {
    let dir = std::env::temp_dir().join(format!("qinit-event-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("f");
    std::fs::write(&file, b"a").unwrap();
    let mut l = Loop::new().unwrap();
    l.add_inotify(&file, libc::IN_MODIFY, 6).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&file)
        .unwrap()
        .write_all(b"b")
        .unwrap();
    let got = l.wait().unwrap();
    assert!(
        matches!(&got[..], [Ready::Inotify(6, evs)] if evs.iter().any(|(m, _)| m & libc::IN_MODIFY != 0)),
        "{got:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn duplicate_tokens_and_empty_waits_are_errors() {
    let mut l = Loop::new().unwrap();
    assert_eq!(l.wait(), Err(Error::Empty));
    l.add_deadline(Duration::from_secs(60), 1).unwrap();
    assert_eq!(
        l.add_deadline(Duration::from_secs(60), 1),
        Err(Error::DuplicateToken(1))
    );
}

#[test]
fn parse_inotify_stops_at_a_truncated_record() {
    let mut b = Vec::new();
    b.extend_from_slice(&1i32.to_ne_bytes());
    b.extend_from_slice(&libc::IN_MODIFY.to_ne_bytes());
    b.extend_from_slice(&0u32.to_ne_bytes());
    b.extend_from_slice(&0u32.to_ne_bytes());
    assert_eq!(parse_inotify(&b).len(), 1);
    assert!(parse_inotify(&b[..10]).is_empty());
}
