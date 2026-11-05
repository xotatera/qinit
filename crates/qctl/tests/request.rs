// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The TOML request file of `qctl run` (spec 2026-11-05 §4.6).
mod common;

use common::TempDir;
use qctl::request::parse;
use qinit_launch::{RequestSpec, Seccomp, Securebits, Stream, UserMap};

#[test]
fn a_minimal_file_gives_the_defaults() {
    let got = parse("argv = [\"/bin/true\"]\n").unwrap();
    assert_eq!(
        got,
        RequestSpec {
            argv: vec!["/bin/true".into()],
            ..RequestSpec::default()
        }
    );
}

#[test]
fn every_key_is_read() {
    let text = r#"
argv = ["/usr/bin/job", "--once"]
env = ["LANG=C"]
cwd = "/work"
umask = 0o022
user = "svc"
caps = ["net_bind_service", "sys_admin"]
securebits = "noroot-locked"
nnp = false
namespaces = ["mount", "user"]
user_map = "range"
inside_uid = 1000
inside_gid = 1001
seccomp = "deny"
syscalls = ["ptrace", "reboot"]
paths = ["ro:/usr", "rw:/work"]
stdin = "/dev/zero"
stdout = "fd:6"
stderr = "same"
ready_fd = 7
die_with_parent = true
deadline_ms = 5000

[rlimits]
nofile = 1024
cpu = "infinity"
as = "64M"
"#;
    let got = parse(text).unwrap();
    let nr = |n| qinit_frames::syscalls::number(n).unwrap();
    let mut rlimits = [None; 16];
    rlimits[0] = Some(u64::MAX);
    rlimits[7] = Some(1024);
    rlimits[9] = Some(64 << 20);
    assert_eq!(
        got,
        RequestSpec {
            argv: vec!["/usr/bin/job".into(), "--once".into()],
            env: vec!["LANG=C".into()],
            cwd: "/work".into(),
            umask: 0o022,
            rlimits,
            user: "svc".into(),
            caps: (1 << 10) | (1 << 21),
            securebits: Securebits::NorootLocked,
            nnp: false,
            ns: 1 | 32,
            user_map: UserMap::Range,
            inside_uid: 1000,
            inside_gid: 1001,
            seccomp: Seccomp::Deny(vec![nr("ptrace"), nr("reboot")]),
            paths: vec!["ro:/usr".into(), "rw:/work".into()],
            stdin: Stream::Path("/dev/zero".into()),
            stdout: Stream::Fd(6),
            stderr: Stream::Same,
            ready_fd: Some(7),
            die_with_parent: true,
            deadline_ms: 5000,
        }
    );
    // The other seccomp modes.
    let base = "argv = [\"/bin/x\"]\n";
    assert_eq!(
        parse(&format!("{base}seccomp = \"default\"\n"))
            .unwrap()
            .seccomp,
        Seccomp::Default
    );
    assert_eq!(
        parse(&format!(
            "{base}seccomp = \"allow\"\nsyscalls = [\"read\"]\n"
        ))
        .unwrap()
        .seccomp,
        Seccomp::Allow(vec![nr("read")])
    );
}

#[test]
fn an_unknown_key_is_refused() {
    let err = parse("argv = [\"/bin/true\"]\nargs = [\"x\"]\n").unwrap_err();
    assert!(err.contains("unknown field `args`"), "{err}");
    let err = parse("argv = [\"/bin/true\"]\n[rlimits]\ncore = 0\n").unwrap_err();
    assert!(err.contains("unknown field `core`"), "{err}");
}

#[test]
fn a_bad_value_is_refused_with_its_key() {
    let base = "argv = [\"/bin/x\"]\n";
    for (body, key) in [
        ("caps = [\"nope\"]", "caps"),
        ("namespaces = [\"nope\"]", "namespaces"),
        ("securebits = \"nope\"", "securebits"),
        ("user_map = \"nope\"", "user_map"),
        ("seccomp = \"nope\"", "seccomp"),
        ("seccomp = \"deny\"", "syscalls"),
        ("seccomp = \"deny\"\nsyscalls = [\"nope\"]", "syscalls"),
        ("syscalls = [\"read\"]", "syscalls"),
        ("stdout = \"fd:x\"", "stdout"),
        ("stdin = \"same\"", "stdin"),
        ("[rlimits]\nnofile = 0", "rlimits.nofile"),
    ] {
        let err = parse(&format!("{base}{body}\n")).unwrap_err();
        assert!(err.starts_with(key), "{body}: {err}");
    }
    assert!(parse("cwd = \"/\"\n").unwrap_err().contains("argv"));
}

#[test]
fn a_value_the_overseer_would_refuse_is_refused_before_sending() {
    let base = "argv = [\"/bin/x\"]\n";
    for (body, key) in [
        ("cwd = \"work\"", "cwd"),
        ("cwd = \"\"", "cwd"),
        ("deadline_ms = 0", "deadline_ms"),
        ("umask = 0o1000", "umask"),
    ] {
        let err = parse(&format!("{base}{body}\n")).unwrap_err();
        assert!(err.starts_with(key), "{body}: {err}");
    }
    for body in ["cwd = \"/work\"", "deadline_ms = 1", "umask = 0o777"] {
        assert!(parse(&format!("{base}{body}\n")).is_ok(), "{body}");
    }
    // Over 64 KiB once laid out.
    let big = format!("{base}env = [\"K={}\"]\n", "v".repeat(70_000));
    assert!(parse(&big).unwrap_err().contains("64 KiB"));
}

#[test]
fn qctl_run_names_the_file_and_sends_nothing_for_a_bad_value() {
    let dir = TempDir::new("request-bad");
    let file = dir.join("r.toml");
    std::fs::write(&file, "argv = [\"/bin/x\"]\ndeadline_ms = 0\n").unwrap();
    let args: Vec<String> = [
        "--socket",
        "/nonexistent/qctl-sock",
        "run",
        file.to_str().unwrap(),
        "--name",
        "n",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = qctl::run(&args, &mut out, &mut err);
    let err = String::from_utf8(err).unwrap();
    assert_eq!(code, 1, "{err}");
    // The file's error, not the connection's: the socket is never tried.
    assert!(
        err.starts_with(&format!("qctl: {}: deadline_ms", file.display())),
        "{err}"
    );
}
