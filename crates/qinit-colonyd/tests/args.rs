// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The colony program's command line.
use qinit_colonyd::args::{Args, parse};
use std::ffi::OsString;
use std::path::PathBuf;

fn argv(words: &[&str]) -> Vec<OsString> {
    words.iter().map(OsString::from).collect()
}

#[test]
fn the_defaults_are_the_paths_the_rest_of_qinit_expects() {
    let a = parse(&[]).unwrap();
    assert_eq!(a, Args::default());
    assert_eq!(a.db, PathBuf::from("/etc/qinit/colony.db"));
    assert_eq!(a.comb, PathBuf::from("/sys/fs/cgroup/qinit"));
    assert_eq!(a.socket, PathBuf::from("/run/qinit/colony"));
    assert_eq!(a.overseer, PathBuf::from("/usr/lib/qinit/overseer"));
    assert_eq!(a.syslog, PathBuf::from("/dev/log"));
    assert_eq!(a.console, PathBuf::from("/dev/console"));
    assert_eq!(a.run, PathBuf::from("/run/qinit"));
}

#[test]
fn every_flag_overrides_its_field() {
    let a = parse(&argv(&[
        "--db",
        "/d",
        "--comb",
        "/c",
        "--socket",
        "/s",
        "--overseer",
        "/o",
        "--syslog",
        "/l",
        "--console",
        "/t",
        "--run",
        "/r",
    ]))
    .unwrap();
    let want = Args {
        db: "/d".into(),
        comb: "/c".into(),
        socket: "/s".into(),
        overseer: "/o".into(),
        syslog: "/l".into(),
        console: "/t".into(),
        run: "/r".into(),
        queen_fd: None,
    };
    assert_eq!(a, want);
}

#[test]
fn a_value_may_follow_an_equals_sign_or_a_space() {
    assert_eq!(parse(&argv(&["--db=x"])).unwrap().db, PathBuf::from("x"));
    assert_eq!(parse(&argv(&["--db", "x"])).unwrap().db, PathBuf::from("x"));
    assert_eq!(
        parse(&argv(&["--db="])).err().as_deref(),
        Some("--db needs a value")
    );
}

#[test]
fn a_bad_command_line_names_what_is_wrong() {
    let err = |w: &[&str]| parse(&argv(w)).unwrap_err();
    assert!(err(&["--bogus"]).contains("--bogus"), "unknown flag");
    assert!(err(&["--db"]).contains("--db"), "missing value");
    assert!(err(&["stray"]).contains("stray"), "positional argument");
    assert!(
        err(&["--db", "a", "--db", "b"]).contains("--db"),
        "repeated flag"
    );
    assert!(
        err(&["--db=a", "--db", "b"]).contains("repeated"),
        "repeated, mixed forms"
    );
}

#[test]
fn queen_fd_is_a_number() {
    assert_eq!(parse(&[]).unwrap().queen_fd, None);
    assert_eq!(
        parse(&argv(&["--queen-fd", "3"])).unwrap().queen_fd,
        Some(3)
    );
    assert_eq!(parse(&argv(&["--queen-fd=7"])).unwrap().queen_fd, Some(7));
    let e = parse(&argv(&["--queen-fd", "3", "--queen-fd", "4"])).unwrap_err();
    assert!(e.contains("--queen-fd") && e.contains("repeated"), "{e}");
    let e = parse(&argv(&["--queen-fd"])).unwrap_err();
    assert!(e.contains("needs a value"), "{e}");
}

#[test]
fn queen_fd_refuses_a_word() {
    for bad in ["x", "-1", "3x", "", "99999999999"] {
        let e = parse(&argv(&["--queen-fd", bad])).unwrap_err();
        assert!(e.contains("--queen-fd"), "{bad}: {e}");
    }
}
