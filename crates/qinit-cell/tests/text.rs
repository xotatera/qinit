// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use qinit_cell::text::{
    ReadyBuf, kernel_supported, parse_events, parse_fdinfo_pid, parse_procs, valid_name,
};

#[test]
fn cgroup_events_in_either_order() {
    assert_eq!(
        parse_events(b"populated 1\nfrozen 0\n"),
        Some((true, false))
    );
    assert_eq!(
        parse_events(b"frozen 1\npopulated 0\n"),
        Some((false, true))
    );
    assert_eq!(parse_events(b"populated 1\n"), None, "frozen missing");
    assert_eq!(
        parse_events(b"populated 1\nfrozen 0\nother 7\n"),
        Some((true, false))
    );
}

#[test]
fn cgroup_procs_lines() {
    assert_eq!(parse_procs(b""), Ok(vec![]));
    assert_eq!(parse_procs(b"12\n34\n"), Ok(vec![12, 34]));
    assert!(parse_procs(b"12\nx\n").is_err());
    assert!(parse_procs(b"0\n").is_err(), "pid 0 is never a member");
}

#[test]
fn the_pid_of_a_pidfd_from_fdinfo() {
    assert_eq!(
        parse_fdinfo_pid(
            "pos:\t0\nflags:\t02000002\nmnt_id:\t15\nino:\t1\nPid:\t1234\nNSpid:\t1234\n"
        ),
        Some(1234)
    );
    assert_eq!(parse_fdinfo_pid("Pid:\t-1\n"), None, "an exited process");
    assert_eq!(parse_fdinfo_pid("pos:\t0\n"), None);
}

#[test]
fn the_kernel_floor_is_6_13() {
    assert!(kernel_supported("6.18.59").is_ok());
    assert!(kernel_supported("6.13.0").is_ok());
    assert!(kernel_supported("7.3.0-4.1-cachyos-eevdf").is_ok());
    let e = kernel_supported("6.12.114").unwrap_err();
    assert!(e.contains("6.12.114") && e.contains("6.13"), "{e}");
    assert!(kernel_supported("banana").is_err());
}

#[test]
fn a_name_that_leaves_the_comb_is_refused() {
    for good in ["worker", "a.b-c_1", "x"] {
        assert!(valid_name(good), "{good}");
    }
    for bad in ["", ".", "..", "../x", "a/b", "a\0b", " x", &"x".repeat(65)] {
        assert!(!valid_name(bad), "{bad:?}");
    }
}

#[test]
fn ready_lines_are_found_across_reads() {
    let mut r = ReadyBuf::new();
    assert!(!r.push(b"ab"));
    assert!(
        r.push(b"c\nmore"),
        "the chunk that brings the first newline"
    );
    assert!(!r.push(b"\n\n"), "only once");
    assert!(!r.at_eof(), "EOF after a newline is not NotReady");
    let mut quiet = ReadyBuf::new();
    assert!(!quiet.push(b"no newline"));
    assert!(quiet.at_eof());
    let mut both = ReadyBuf::new();
    assert!(both.push(b"\n"));
    assert!(!both.at_eof());
}
