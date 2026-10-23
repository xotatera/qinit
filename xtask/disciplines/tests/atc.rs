// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! atc: detection, profile names, the gate wrap and atc's own exit codes.
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use xtask::atc::{self, Atc, Reserve};

/// A scratch directory removed when the test ends, pass or fail.
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(test: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!("xtask-atc-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

/// A fake `atc` in `dir` that exits `code` for `status`. `install` writes the
/// binary from a source file, so this process never holds it open for
/// writing: a thread of another test that forks meanwhile would otherwise
/// carry that descriptor into its child until it execs, and running the
/// fake then would fail with ETXTBSY.
fn fake_atc(dir: &Path, code: i32) {
    let src = dir.join("atc.src");
    std::fs::write(
        &src,
        format!("#!/bin/sh\n[ \"$1\" = status ] && exit {code}\nexit 64\n"),
    )
    .unwrap();
    assert!(
        std::process::Command::new("install")
            .args(["-m", "755"])
            .arg(&src)
            .arg(dir.join("atc"))
            .status()
            .unwrap()
            .success()
    );
}

/// `probe` with the real spawn, on a PATH of just `dir`.
fn probe_in(dir: &Path) -> Atc {
    let path = OsString::from(dir);
    atc::probe(Some(&path), &|bin| {
        std::process::Command::new(bin)
            .arg("status")
            .status()
            .map(|s| s.code())
    })
}

#[test]
fn a_daemon_that_answers_is_available() {
    let s = scratch("up");
    fake_atc(&s.0, 0);
    assert_eq!(probe_in(&s.0), Atc::Available);
}

#[test]
fn a_daemon_that_does_not_answer_is_absent() {
    let s = scratch("down");
    fake_atc(&s.0, 69);
    assert_eq!(
        probe_in(&s.0),
        Atc::Absent("`atc status` exited 69".to_string())
    );
}

#[test]
fn no_atc_on_path_is_absent() {
    let s = scratch("none");
    assert_eq!(probe_in(&s.0), Atc::Absent("not on PATH".to_string()));
    assert_eq!(
        atc::probe(None, &|_| Ok(Some(0))),
        Atc::Absent("not on PATH".to_string())
    );
}

#[test]
fn a_status_killed_or_unrunnable_is_absent() {
    let s = scratch("odd");
    fake_atc(&s.0, 0);
    let path = OsString::from(&s.0);
    assert_eq!(
        atc::probe(Some(&path), &|_| Ok(None)),
        Atc::Absent("`atc status` was killed by a signal".to_string())
    );
    assert_eq!(
        atc::probe(Some(&path), &|_| Err(std::io::Error::other("boom"))),
        Atc::Absent("cannot run `atc status`: boom".to_string())
    );
}

#[test]
fn repo_name_canonicalizes_the_root() {
    let s = scratch("name");
    let ws = s.0.join("my-repo");
    std::fs::create_dir_all(ws.join("xtask")).unwrap();
    assert_eq!(atc::repo_name(&ws.join("xtask").join("..")), "my-repo");
    assert_eq!(atc::repo_name(&ws), "my-repo");
}

#[test]
fn wrap_prefixes_a_gate_only_under_atc() {
    let argv = vec!["cargo".to_string(), "test".to_string()];
    assert_eq!(atc::wrap(&Reserve::None, "test", false, argv.clone()), argv);
    let r = Reserve::Atc {
        repo: "my repo".to_string(),
    };
    assert_eq!(
        atc::wrap(&r, "no-std:core", false, argv),
        [
            "atc",
            "run",
            "--name",
            "my repo/gate:no-std:core",
            "--gpu-min",
            "0",
            "--vram-min",
            "0",
            "--",
            "cargo",
            "test"
        ]
        .map(String::from)
    );
}

#[test]
fn atcs_own_codes_have_messages() {
    let m = |c| atc::exit_message(c, Some("1G"), false);
    assert_eq!(m(64).unwrap(), "atc usage error (see atc's line above)");
    assert_eq!(
        m(69).unwrap(),
        "atc daemon unavailable, or its protocol changed (atc was upgraded: rerun)"
    );
    assert!(
        m(75)
            .unwrap()
            .starts_with("gave up waiting for atc at ATC_MAX_WAIT: the host was busy")
    );
    assert_eq!(
        m(76).unwrap(),
        "exceeded its memory cap of 1G (atc --ram-max)"
    );
    assert_eq!(
        atc::exit_message(76, None, false).unwrap(),
        "exceeded its memory cap (atc --ram-max)"
    );
    assert_eq!(m(77).unwrap(), "never fits this host's RAM budget");
    assert_eq!(
        m(78).unwrap(),
        "atc refused the reservation (see atc's line above)"
    );
    assert_eq!(m(79).unwrap(), "atc: the run was disturbed");
}

#[test]
fn a_refusal_inside_an_atc_run_names_the_nesting_rule() {
    assert_eq!(
        atc::exit_message(78, None, true).unwrap(),
        "atc refused the reservation (see atc's line above); xtask runs inside an `atc run`: xtask wraps its steps, nothing wraps xtask"
    );
}

#[test]
fn the_commands_own_codes_pass_through() {
    for c in [0, 1, 2, 101, 124, 137] {
        assert_eq!(atc::exit_message(c, Some("1G"), false), None, "{c}");
    }
}

#[test]
fn a_failed_cargo_gate_reads_atcs_codes_only_under_atc() {
    let r = Reserve::Atc {
        repo: "r".to_string(),
    };
    assert_eq!(
        atc::gate_failure(&r, "cargo test --workspace", Some(69), false),
        "`cargo test --workspace`: atc daemon unavailable, or its protocol changed (atc was upgraded: rerun)"
    );
    assert_eq!(
        atc::gate_failure(&r, "cargo test --workspace", Some(101), false),
        "`cargo test --workspace` failed (exit 101)"
    );
    assert_eq!(
        atc::gate_failure(&Reserve::None, "cargo test --workspace", Some(69), false),
        "`cargo test --workspace` failed (exit 69)"
    );
    assert_eq!(
        atc::gate_failure(&r, "cargo test --workspace", None, false),
        "`cargo test --workspace` was killed by a signal"
    );
}

#[test]
fn a_gpu_repos_gates_leave_gpu_use_to_atc() {
    let r = Reserve::Atc {
        repo: "r".to_string(),
    };
    let argv = vec!["cargo".to_string(), "test".to_string()];
    assert_eq!(
        atc::wrap(&r, "test", true, argv),
        ["atc", "run", "--name", "r/gate:test", "--", "cargo", "test"].map(String::from)
    );
}

#[test]
fn a_linked_worktree_is_named_for_its_main_repository() {
    let s = scratch("worktree");
    let main = s.0.join("main-repo");
    std::fs::create_dir_all(&main).unwrap();
    let git = |dir: &Path, args: &[&str]| {
        let ok = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "git {args:?}");
    };
    git(&main, &["init", "-q", "-b", "main"]);
    git(
        &main,
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "i",
        ],
    );
    let wt = s.0.join("some-worktree");
    git(&main, &["worktree", "add", "-q", wt.to_str().unwrap()]);
    assert_eq!(atc::repo_name(&wt), "main-repo");
    assert_eq!(atc::repo_name(&main.join(".")), "main-repo");
}

#[test]
fn names_come_from_the_git_common_dir() {
    assert_eq!(
        atc::name_of(Some(Path::new("/r/my-repo/.git")), Path::new("/w/wt")),
        "my-repo"
    );
    assert_eq!(
        atc::name_of(Some(Path::new("/srv/bare.git")), Path::new("/w/wt")),
        "bare"
    );
    assert_eq!(atc::name_of(None, Path::new("/w/plain")), "plain");
}

#[test]
fn a_signal_kill_of_a_cargo_gate_under_atc_reads_as_one() {
    let r = Reserve::Atc {
        repo: "r".to_string(),
    };
    assert_eq!(
        atc::gate_failure(&r, "cargo test", Some(137), false),
        "`cargo test` was killed by signal 9"
    );
    assert_eq!(
        atc::gate_failure(&Reserve::None, "cargo test", Some(137), false),
        "`cargo test` failed (exit 137)"
    );
}

#[test]
fn never_pause_is_asked_by_a_set_value_other_than_zero() {
    use std::ffi::OsStr;
    assert!(atc::never_pause(Some(OsStr::new("1"))));
    assert!(atc::never_pause(Some(OsStr::new("yes"))));
    assert!(!atc::never_pause(Some(OsStr::new("0"))));
    assert!(!atc::never_pause(Some(OsStr::new(""))));
    assert!(!atc::never_pause(None));
}
