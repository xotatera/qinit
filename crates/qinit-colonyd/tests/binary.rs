// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The colony binary, started for real: its start-up refusals and its descriptor limit.
//!
//! These tests have a test binary of their own because they start processes. A fork copies
//! every descriptor of the test process, close-on-exec ones too, and the child holds the copies
//! until its exec. In `daemon.rs` a test that closes one end of a socket and then looks for the
//! hang-up (a queen gone, a client gone) would find the other end still open while a child of
//! some other test held the copy. Cargo runs the test binaries one after the other, so nothing
//! here can fork while those tests run.
mod common;

use common::*;
use qinit_colonyd::exit;
use qinit_ipc::send;
use qinit_queen_core::ToColony;
use std::os::fd::AsFd;
use std::os::unix::net::UnixDatagram;
use std::process::Command;

fn colony_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_colony"))
}

// ---- start-up refusals, through the binary ----

#[test]
fn usage_errors_exit_2() {
    let out = colony_bin().arg("--bogus").output().unwrap();
    assert_eq!(out.status.code(), Some(i32::from(exit::USAGE)));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--bogus") && err.contains("usage"), "{err}");
    for flag in [
        "--db",
        "--comb",
        "--socket",
        "--overseer",
        "--syslog",
        "--console",
        "--run",
        "--queen-fd",
    ] {
        assert!(
            err.contains(flag),
            "the usage line leaves out {flag}: {err}"
        );
    }
    assert_eq!(
        colony_bin().args(["--db"]).output().unwrap().status.code(),
        Some(i32::from(exit::USAGE))
    );
}

fn own_cgroup() -> Option<String> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::to_owned)
}

#[test]
fn colony_inside_the_comb_refuses_to_start() {
    let Some(own) = own_cgroup() else {
        eprintln!("skipped: no cgroup v2 line in /proc/self/cgroup");
        return;
    };
    let tmp = Tmp::new("inside");
    let comb = format!("/sys/fs/cgroup{own}");
    let out = colony_bin()
        .args(["--comb", &comb, "--run"])
        .arg(&tmp.0)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(i32::from(exit::STARTUP)), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("inside the comb"), "{err}");
}

#[test]
fn a_refused_database_exits_3_before_anything_else_is_touched() {
    let tmp = Tmp::new("baddb");
    let db = tmp.0.join("colony.db");
    std::fs::write(&db, b"not a database").unwrap();
    let comb = tmp.0.join("comb");
    let out = colony_bin()
        .arg("--db")
        .arg(&db)
        .arg("--run")
        .arg(tmp.0.join("run"))
        .arg("--comb")
        .arg(&comb)
        .arg("--syslog")
        .arg(tmp.0.join("nolog"))
        .arg("--console")
        .arg(tmp.0.join("console"))
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(i32::from(exit::DATABASE)),
        "{out:?}"
    );
    assert!(!comb.exists(), "the comb was not touched");
    let missing = colony_bin()
        .arg("--db")
        .arg(tmp.0.join("absent.db"))
        .arg("--run")
        .arg(tmp.0.join("run"))
        .output()
        .unwrap();
    assert_eq!(
        missing.status.code(),
        Some(i32::from(exit::DATABASE)),
        "{missing:?}"
    );
}

// ---- the descriptor limit, through the binary ----

/// What colony did when run with `RLIMIT_NOFILE` set to `nofile` and handed `held` descriptors
/// by a queen: its exit code and what it logged. No database is there, so a colony that took
/// the whole hand-over exits 3.
fn hand_over_under(nofile: (u64, u64), held: u32, tag: &str) -> (Option<i32>, Vec<String>) {
    use qinit_sys::spawn::{Prepared, spawn};
    let tmp = Tmp::new(tag);
    let log = UnixDatagram::bind(tmp.0.join("log")).unwrap();
    let (queen, link) = qinit_ipc::seqpacket_pair().unwrap();
    let arg = |p: &str| tmp.0.join(p).into_os_string();
    let argv: Vec<std::ffi::OsString> = vec![
        "colony".into(),
        "--queen-fd".into(),
        "3".into(),
        "--db".into(),
        arg("absent.db"),
        "--run".into(),
        arg("run"),
        "--comb".into(),
        arg("comb"),
        "--syslog".into(),
        arg("log"),
        "--console".into(),
        arg("console"),
    ];
    let argv: Vec<&std::ffi::OsStr> = argv.iter().map(std::ffi::OsString::as_os_str).collect();
    let routes = [(link.as_fd(), 3)];
    let mut p = Prepared::new(
        std::path::Path::new(env!("CARGO_BIN_EXE_colony")),
        &argv,
        &[],
        &routes,
    )
    .unwrap();
    p.nofile(nofile.0, nofile.1);
    let (err_r, err_w) = qinit_sys::fd::pipe(libc::O_CLOEXEC).unwrap();
    let (_, pidfd) = spawn(&p, None, err_w.as_fd()).unwrap();
    drop((p, routes, err_w));
    drop(link);
    assert_eq!(
        qinit_sys::fd::read_byte(err_r.as_fd()).unwrap(),
        None,
        "colony was not executed"
    );
    // One descriptor, sent `held` times: each arrives in colony as a descriptor of its own.
    let null = std::fs::File::open("/dev/null").unwrap();
    for key in 16..16 + u64::from(held) {
        let rec = qinit_queen_core::encode_to_colony(ToColony::Held { key });
        if send(queen.as_fd(), &rec, &[null.as_fd()]).is_err() {
            break;
        }
    }
    let end = qinit_queen_core::encode_to_colony(ToColony::HeldEnd { count: held });
    let _ = send(queen.as_fd(), &end, &[]);
    let status = qinit_sys::proc::wait_pidfd(&pidfd).unwrap();
    let code = libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status));
    (code, lines_of(&log))
}

/// Whether this process may raise a hard limit (`CAP_SYS_RESOURCE` in its effective set), as
/// the colony it starts may then too.
fn may_raise_hard_limits() -> bool {
    const CAP_SYS_RESOURCE: u32 = 24;
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let eff = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        .unwrap();
    eff & (1 << CAP_SYS_RESOURCE) != 0
}

/// Queen holds more than the kernel's 1024 for colony: colony raises its own limit before it
/// reads the hand-over, so it takes every entry back. It needs a colony that can reach 65536: a
/// hard limit that high already, or the right to raise it.
#[test]
fn colony_raises_its_descriptor_limit_before_it_takes_back_queens_store() {
    let (_, hard) = qinit_sys::limits::get_rlimit(qinit_sys::limits::RLIMIT_NOFILE).unwrap();
    if hard < 65_536 && !may_raise_hard_limits() {
        eprintln!("skipped: a hard RLIMIT_NOFILE of {hard}, and no CAP_SYS_RESOURCE to raise it");
        return;
    }
    let (code, lines) = hand_over_under((1024, hard.max(65_536)), 1100, "nofile-raise");
    assert!(
        !lines.iter().any(|l| l.contains("did not fit")),
        "a held descriptor was lost: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("descriptor limit")),
        "{lines:?}"
    );
    assert_eq!(code, Some(i32::from(exit::DATABASE)), "{lines:?}");
}

/// A colony that may not raise its hard limit (not root, a hard limit below 65536) raises its
/// soft one up to the hard one, says so in one line, and takes back what fits under that. It
/// needs a colony without the right to raise a hard limit, and a hard limit of 4096 to give it.
#[test]
fn a_colony_that_cannot_raise_its_hard_limit_raises_its_soft_one_and_logs_one_line() {
    let (_, hard) = qinit_sys::limits::get_rlimit(qinit_sys::limits::RLIMIT_NOFILE).unwrap();
    if may_raise_hard_limits() || hard < 4096 {
        eprintln!("skipped: this process may raise a hard limit, or its hard limit {hard} < 4096");
        return;
    }
    // More than the soft 1024, less than the hard 4096.
    let (code, lines) = hand_over_under((1024, 4096), 2000, "nofile-keep");
    assert!(
        !lines.iter().any(|l| l.contains("did not fit")),
        "a held descriptor was lost: {lines:?}"
    );
    assert_eq!(code, Some(i32::from(exit::DATABASE)), "{lines:?}");
    let said: Vec<&String> = lines
        .iter()
        .filter(|l| l.contains("descriptor limit"))
        .collect();
    assert_eq!(said.len(), 1, "{lines:?}");
    assert!(
        said[0].contains("from 1024 soft, 4096 hard")
            && said[0].contains("raises its soft limit to 4096, its services keep 1024"),
        "{said:?}"
    );
}
