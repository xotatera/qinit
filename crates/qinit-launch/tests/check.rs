// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! `RequestSpec::check`: the checks a client makes before it sends a request, shared by `qctl`
//! and the C builder.
use qinit_launch::{CheckError, RequestSpec, Seccomp, Stream};

fn base() -> RequestSpec {
    RequestSpec {
        argv: vec!["/x".into()],
        user: "svc".into(),
        ..RequestSpec::default()
    }
}

#[test]
fn check_gives_qctls_texts() {
    let cases = [
        (
            RequestSpec {
                cwd: "work".into(),
                ..base()
            },
            CheckError::Cwd("work".into()),
            "cwd: `work` is not an absolute path",
        ),
        (
            RequestSpec {
                deadline_ms: 0,
                ..base()
            },
            CheckError::Deadline,
            "deadline_ms: must be at least 1",
        ),
        (
            RequestSpec {
                umask: 0o1000,
                ..base()
            },
            CheckError::Umask(0o1000),
            "umask: 0o1000 is over 0o777",
        ),
        (
            RequestSpec {
                env: vec![format!("K={}", "v".repeat(70_000))],
                ..base()
            },
            CheckError::TooLarge,
            "the request is over 64 KiB once laid out",
        ),
        (
            RequestSpec {
                seccomp: Seccomp::Deny(Vec::new()),
                ..base()
            },
            CheckError::NoSyscalls,
            "syscalls: a deny or allow filter needs at least one syscall",
        ),
        (
            RequestSpec {
                seccomp: Seccomp::Allow(Vec::new()),
                ..base()
            },
            CheckError::NoSyscalls,
            "syscalls: a deny or allow filter needs at least one syscall",
        ),
        (
            RequestSpec {
                stdin: Stream::Same,
                ..base()
            },
            CheckError::BadStream,
            "stdin and stdout cannot be \"same\"",
        ),
    ];
    for (spec, error, text) in cases {
        let got = spec.check().unwrap_err();
        assert_eq!(got, error);
        assert_eq!(got.to_string(), text);
    }
}

#[test]
fn an_empty_cwd_is_not_absolute() {
    let spec = RequestSpec {
        cwd: String::new(),
        ..base()
    };
    assert_eq!(spec.check(), Err(CheckError::Cwd(String::new())));
}

#[test]
fn the_checks_go_in_qctls_order() {
    // Every check fails: the first one, `cwd`, is the one reported, and the layout comes last.
    let spec = RequestSpec {
        cwd: "work".into(),
        deadline_ms: 0,
        umask: 0o1000,
        stdout: Stream::Same,
        ..base()
    };
    assert_eq!(spec.check(), Err(CheckError::Cwd("work".into())));
    let spec = RequestSpec {
        deadline_ms: 0,
        umask: 0o1000,
        ..base()
    };
    assert_eq!(spec.check(), Err(CheckError::Deadline));
    let spec = RequestSpec {
        umask: 0o1000,
        seccomp: Seccomp::Deny(Vec::new()),
        ..base()
    };
    assert_eq!(spec.check(), Err(CheckError::Umask(0o1000)));
    let spec = RequestSpec {
        seccomp: Seccomp::Deny(Vec::new()),
        stdout: Stream::Same,
        ..base()
    };
    assert_eq!(spec.check(), Err(CheckError::NoSyscalls));
}

#[test]
fn a_request_that_passes_gives_the_bytes() {
    for spec in [
        base(),
        RequestSpec {
            cwd: "/work".into(),
            deadline_ms: 1,
            umask: 0o777,
            ..base()
        },
        RequestSpec {
            seccomp: Seccomp::Allow(vec![0]),
            ..base()
        },
    ] {
        assert_eq!(spec.check(), Ok(spec.bytes().unwrap()));
    }
}
