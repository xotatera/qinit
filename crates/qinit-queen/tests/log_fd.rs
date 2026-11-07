// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Queen's log descriptor never blocks PID 1: a console stopped by flow control must cost a
//! line, not the machine.
use qinit_queen::real::open_log;
use std::os::fd::AsRawFd;

/// `O_NONBLOCK` in `/proc/self/fdinfo`'s octal `flags:` line.
fn nonblocking(fd: i32) -> bool {
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).unwrap();
    let flags = info
        .lines()
        .find_map(|l| l.strip_prefix("flags:"))
        .unwrap()
        .trim();
    u32::from_str_radix(flags, 8).unwrap() & libc::O_NONBLOCK as u32 != 0
}

#[test]
fn the_log_falls_back_to_the_next_path_and_never_blocks() {
    let fd = open_log(&[c"/nonexistent/kmsg", c"/dev/null"]).unwrap();
    assert!(
        nonblocking(fd.as_raw_fd()),
        "a write to a stopped tty would block PID 1"
    );
}

#[test]
fn the_first_path_that_opens_wins() {
    let fd = open_log(&[c"/dev/null", c"/nonexistent"]).unwrap();
    let link = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
    assert_eq!(link, std::path::Path::new("/dev/null"));
}

#[test]
fn no_path_that_opens_is_an_error() {
    assert!(open_log(&[c"/nonexistent/a", c"/nonexistent/b"]).is_err());
}
