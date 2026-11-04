// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The request builder, the environment of the service and the status record.
use qinit_db::Model;
use qinit_overseer::identity::Identity;
use qinit_overseer::request::{
    BuildError, EncodeError, RequestSpec, Routed, Seccomp, Securebits, Stream, from_instance,
    from_model,
};
use qinit_overseer::run::envp;
use qinit_overseer::status::{STEP_DECODE, Status, step_name};
use qinit_overseer_core::*;
use qinit_sys::fd::pipe;
use std::ffi::CString;
use std::os::fd::AsFd;

fn full() -> RequestSpec {
    RequestSpec {
        argv: vec!["/usr/bin/daemon".into(), "--flag".into()],
        env: vec!["A=1".into(), "EMPTY=".into()],
        cwd: "/srv".into(),
        umask: 0o077,
        rlimits: {
            let mut l = [None; 16];
            l[7] = Some(1024);
            l
        },
        user: "svc".into(),
        caps: (1 << 10) | (1 << 40),
        securebits: Securebits::NorootLocked,
        nnp: true,
        ns: 0b10011,
        seccomp: Seccomp::Deny(vec![101, 110]),
        paths: vec!["ro:/etc".into(), "rw:/var/log".into()],
        stdin: Stream::Fd(8),
        stdout: Stream::Path("/var/log/out".into()),
        stderr: Stream::Fd(7),
        ready_fd: Some(6),
        die_with_parent: true,
        deadline_ms: 2500,
    }
}

fn text(b: &[u8], off_word: usize, len_word: usize) -> String {
    String::from_utf8(pool(b, req(b, off_word), req(b, len_word)).to_vec()).unwrap()
}

#[test]
fn a_request_spec_round_trips_through_decode() {
    let spec = full();
    let b = spec.bytes().unwrap();
    assert_eq!(decode(&b), Ok(()));
    assert_eq!(text(&b, Q_ARGV_OFF, Q_ARGV_LEN), "/usr/bin/daemon\0--flag");
    assert_eq!(text(&b, Q_ENV_OFF, Q_ENV_LEN), "A=1\0EMPTY=");
    assert_eq!(text(&b, Q_CWD_OFF, Q_CWD_LEN), "/srv");
    assert_eq!(text(&b, Q_USER_OFF, Q_USER_LEN), "svc");
    assert_eq!(text(&b, Q_SECCOMP_OFF, Q_SECCOMP_LEN), "101\x00110");
    assert_eq!(text(&b, Q_PATHS_OFF, Q_PATHS_LEN), "ro:/etc\0rw:/var/log");
    assert_eq!(text(&b, Q_STDOUT_A, Q_STDOUT_B), "/var/log/out");
    assert_eq!(req(&b, Q_UMASK), 0o077);
    assert_eq!(req(&b, Q_RLIMIT_MASK), 1 << 7);
    assert_eq!(req(&b, Q_RLIMIT_BASE + 2 * 7), 1024);
    assert_eq!((req(&b, Q_CAPS_LO), req(&b, Q_CAPS_HI)), (1 << 10, 1 << 8));
    assert_eq!(req(&b, Q_SECUREBITS), 2);
    assert_eq!(req(&b, Q_NNP), 1);
    assert_eq!(req(&b, Q_NS), 0b10011);
    assert_eq!(req(&b, Q_SECCOMP), 2);
    assert_eq!(req(&b, Q_STDOUT_KIND), STREAM_PATH);
    assert_eq!(
        (req(&b, Q_STDERR_KIND), req(&b, Q_STDERR_A)),
        (STREAM_FD, 7)
    );
    assert_eq!(
        (req(&b, Q_READY_KIND), req(&b, Q_READY_FD)),
        (READY_PIPE, 6)
    );
    assert_eq!(req(&b, Q_FLAGS), FLAG_DIE_WITH_PARENT);
    assert_eq!(req(&b, Q_DEADLINE_MS), 2500);
}

#[test]
fn the_default_spec_with_a_command_and_user_decodes() {
    let spec = RequestSpec {
        argv: vec!["/bin/true".into()],
        user: "svc".into(),
        ..RequestSpec::default()
    };
    let b = spec.bytes().unwrap();
    assert_eq!(decode(&b), Ok(()));
    assert_eq!(req(&b, Q_STDERR_KIND), STREAM_SAME);
    assert_eq!(req(&b, Q_READY_KIND), READY_NONE);
    assert_eq!(req(&b, Q_DEADLINE_MS), 30_000);
}

#[test]
fn a_request_over_the_size_limit_is_a_build_error() {
    let spec = RequestSpec {
        argv: vec!["x".repeat(MAX_REQUEST)],
        user: "svc".into(),
        ..RequestSpec::default()
    };
    assert_eq!(spec.bytes().unwrap_err(), EncodeError::TooLarge);
}

fn golden() -> Model {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../qinit-frames/tests/golden/expected.db"
    );
    let bytes = std::fs::read(path).unwrap();
    qinit_db::open(&bytes).unwrap().decode()
}

#[test]
fn from_model_on_the_golden_tree_decodes() {
    let m = golden();
    let routed = Routed {
        stdin: None,
        stdout: Some(5),
        stderr: None,
        ready: Some(6),
    };
    let mut seen = 0;
    for node in m.nodes.iter().filter(|n| n.cred.is_some()) {
        let spec = from_model(node, &m, &routed, 30_000).unwrap();
        assert_eq!(decode(&spec.bytes().unwrap()), Ok(()), "{}", node.name);
        seen += 1;
    }
    assert!(seen >= 4, "{seen}");
    let logd = m.nodes.iter().find(|n| n.name == "logd").unwrap();
    let spec = from_model(logd, &m, &routed, 30_000).unwrap();
    assert_eq!(spec.env, ["LOGD_DIR=/var/log/qinit", "LOGD_LEVEL=debug"]);
    assert_eq!((spec.umask, spec.rlimits[7]), (0o077, Some(1024)));
    assert_eq!(spec.cwd, "/var/log/qinit");
    assert_eq!(spec.user, "logd");
    assert_eq!(spec.ns, 0b01100);
    assert_eq!(spec.seccomp, Seccomp::Default);
    assert_eq!(spec.paths, ["ro:/etc/logd", "rw:/var/log/qinit"]);
    assert_eq!(spec.ready_fd, Some(6));
    let piped = m
        .nodes
        .iter()
        .find(|n| {
            matches!(
                n.output.map(|r| &m.routes[r as usize]),
                Some(qinit_db::Route::Pipe(_))
            )
        })
        .unwrap();
    let spec = from_model(piped, &m, &routed, 30_000).unwrap();
    assert_eq!(spec.stdout, Stream::Fd(5));
    assert_eq!(spec.stderr, Stream::Same);
}

#[test]
fn a_pipe_route_without_its_fd_is_a_build_error() {
    let m = golden();
    let piped = m
        .nodes
        .iter()
        .find(|n| {
            matches!(
                n.output.map(|r| &m.routes[r as usize]),
                Some(qinit_db::Route::Pipe(_))
            )
        })
        .unwrap();
    let none = Routed {
        stdin: None,
        stdout: None,
        stderr: None,
        ready: Some(6),
    };
    assert_eq!(
        from_model(piped, &m, &none, 1000).unwrap_err(),
        BuildError::MissingFd
    );
    let logd = m.nodes.iter().find(|n| n.name == "logd").unwrap();
    let no_ready = Routed {
        stdin: None,
        stdout: Some(5),
        stderr: None,
        ready: None,
    };
    assert_eq!(
        from_model(logd, &m, &no_ready, 1000).unwrap_err(),
        BuildError::MissingFd
    );
}

#[test]
fn a_brood_has_no_request() {
    let m = golden();
    let brood = m.nodes.iter().find(|n| n.cred.is_none()).unwrap();
    let routed = Routed {
        stdin: None,
        stdout: None,
        stderr: None,
        ready: None,
    };
    assert_eq!(
        from_model(brood, &m, &routed, 1000).unwrap_err(),
        BuildError::NoCredentials
    );
}

fn id() -> Identity {
    Identity {
        uid: 1000,
        gid: 1000,
        groups: vec![],
        home: "/home/svc".into(),
    }
}

fn strings(v: &[CString]) -> Vec<String> {
    v.iter().map(|c| c.to_str().unwrap().to_owned()).collect()
}

#[test]
fn frame_env_overrides_the_base_path() {
    let spec = RequestSpec {
        env: vec!["PATH=/frame".into(), "EMPTY=".into()],
        user: "svc".into(),
        ..RequestSpec::default()
    };
    let env = strings(&envp(&spec, &id()));
    assert_eq!(env.iter().filter(|e| e.starts_with("PATH=")).count(), 1);
    assert!(env.contains(&"PATH=/frame".to_owned()), "{env:?}");
    assert!(env.contains(&"EMPTY=".to_owned()));
    for want in ["HOME=/home/svc", "USER=svc", "LOGNAME=svc"] {
        assert!(env.contains(&want.to_owned()), "{want}");
    }
    assert!(!env.iter().any(|e| e.starts_with("QINIT_READY_FD=")));
}

#[test]
fn the_base_environment_has_the_standard_path_and_the_ready_fd() {
    let spec = RequestSpec {
        user: "svc".into(),
        ready_fd: Some(6),
        ..RequestSpec::default()
    };
    let env = strings(&envp(&spec, &id()));
    assert!(
        env.contains(
            &"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned()
        )
    );
    assert!(env.contains(&"QINIT_READY_FD=3".to_owned()));
}

#[test]
fn a_status_record_round_trips_and_eof_is_none() {
    let (r, w) = pipe(libc::O_CLOEXEC).unwrap();
    let st = Status {
        step: 7,
        errno: libc::EACCES,
    };
    st.write(w.as_fd());
    assert_eq!(Status::read(r.as_fd()), Some(st));
    drop(w);
    assert_eq!(Status::read(r.as_fd()), None);
}

#[test]
fn step_names_cover_the_pseudo_steps_and_the_plan() {
    let spec = RequestSpec {
        argv: vec!["/bin/true".into()],
        user: "svc".into(),
        ..RequestSpec::default()
    };
    let b = spec.bytes().unwrap();
    assert_eq!(step_name(&b, STEP_DECODE), "decode");
    assert_eq!(step_name(&b, STEP_DECODE - 1), "identity");
    assert_eq!(step_name(&b, 0), "setsid");
    assert_eq!(step_name(&b, 1_000_000), "?");
}

#[test]
fn a_routed_stdin_is_laid_out_like_stdout() {
    let b = full().bytes().unwrap();
    assert_eq!(decode(&b), Ok(()));
    assert_eq!(req(&b, Q_STDIN_KIND), STREAM_FD);
    assert_eq!(req(&b, Q_STDIN_A), 8);
    let default = RequestSpec {
        argv: vec!["/bin/true".into()],
        user: "svc".into(),
        ..RequestSpec::default()
    };
    let b = default.bytes().unwrap();
    assert_eq!(decode(&b), Ok(()));
    assert_eq!(req(&b, Q_STDIN_KIND), STREAM_PATH);
    assert_eq!(text(&b, Q_STDIN_A, Q_STDIN_B), "/dev/null");
}

#[test]
fn stdin_same_is_bad_stream() {
    let spec = RequestSpec {
        stdin: Stream::Same,
        ..full()
    };
    assert_eq!(spec.bytes().unwrap_err(), EncodeError::BadStream);
}

#[test]
fn from_model_routes_a_supplied_stdin() {
    let m = golden();
    let logd = m.nodes.iter().find(|n| n.name == "logd").unwrap();
    let routed = Routed {
        stdin: Some(9),
        stdout: Some(5),
        stderr: None,
        ready: Some(6),
    };
    let spec = from_model(logd, &m, &routed, 1000).unwrap();
    assert_eq!(spec.stdin, Stream::Fd(9));
    let routed = Routed {
        stdin: None,
        ..routed
    };
    let spec = from_model(logd, &m, &routed, 1000).unwrap();
    assert_eq!(spec.stdin, Stream::Path("/dev/null".into()));
}

#[test]
fn from_instance_appends_the_tail_and_env_and_routes_the_fds() {
    let m = golden();
    let job = m.nodes.iter().find(|n| n.name == "mount-var").unwrap();
    let routed = Routed {
        stdin: Some(8),
        stdout: Some(9),
        stderr: None,
        ready: None,
    };
    let tail = ["--ro".to_owned()];
    let env = [("TARGET".to_owned(), "/data".to_owned())];
    let spec = from_instance(job, &m, &routed, &tail, &env, 5000).unwrap();
    assert_eq!(decode(&spec.bytes().unwrap()), Ok(()));
    assert_eq!(spec.argv, ["/usr/bin/mount", "/var", "--ro"]);
    assert_eq!(spec.env, ["TARGET=/data"]);
    assert_eq!(
        (&spec.stdin, &spec.stdout, &spec.stderr),
        (&Stream::Fd(8), &Stream::Fd(9), &Stream::Same)
    );
    assert_eq!(spec.deadline_ms, 5000);
}

#[test]
fn from_instance_env_overrides_the_frames_key_and_stays_sorted() {
    let m = golden();
    let logd = m.nodes.iter().find(|n| n.name == "logd").unwrap();
    let routed = Routed {
        stdin: None,
        stdout: None,
        stderr: None,
        ready: Some(6),
    };
    let env = [
        ("LOGD_LEVEL".to_owned(), "trace".to_owned()),
        ("AAA".to_owned(), "1".to_owned()),
    ];
    let spec = from_instance(logd, &m, &routed, &[], &env, 1000).unwrap();
    assert_eq!(
        spec.env,
        ["AAA=1", "LOGD_DIR=/var/log/qinit", "LOGD_LEVEL=trace"]
    );
    assert_eq!(spec.stdin, Stream::Path("/dev/null".into()));
}

#[test]
fn a_caller_stdout_replaces_the_frames_pipe_route() {
    let m = golden();
    let piped = m
        .nodes
        .iter()
        .find(|n| {
            matches!(
                n.output.map(|r| &m.routes[r as usize]),
                Some(qinit_db::Route::Pipe(_))
            )
        })
        .unwrap();
    let routed = Routed {
        stdin: None,
        stdout: Some(11),
        stderr: None,
        ready: Some(6),
    };
    let spec = from_instance(piped, &m, &routed, &[], &[], 1000).unwrap();
    assert_eq!(spec.stdout, Stream::Fd(11));
    let missing = Routed {
        stdout: None,
        ..routed
    };
    assert_eq!(
        from_instance(piped, &m, &missing, &[], &[], 1000).unwrap_err(),
        BuildError::MissingFd
    );
}

#[test]
#[allow(clippy::cast_possible_truncation)] // a limit's low and high words
fn from_model_carries_every_limit_into_the_record() {
    let mut m = golden();
    let at = m.nodes.iter().position(|n| n.name == "logd").unwrap();
    let want: [Option<u64>; 16] = std::array::from_fn(|r| {
        (r != 4).then_some(match r {
            7 => 4096,
            13 | 14 => 9,
            6 => u64::MAX,
            _ => (7u64 << 32) | (r as u64 + 1),
        })
    });
    m.nodes[at].rlimits = want;
    let routed = Routed {
        stdin: None,
        stdout: Some(5),
        stderr: None,
        ready: Some(6),
    };
    let spec = from_model(&m.nodes[at], &m, &routed, 30_000).unwrap();
    let b = spec.bytes().unwrap();
    assert_eq!(decode(&b), Ok(()));
    let mask = (0..16)
        .filter(|r| want[*r].is_some())
        .fold(0, |m, r| m | (1u32 << r));
    assert_eq!(req(&b, Q_RLIMIT_MASK), mask);
    for (r, v) in want.iter().enumerate() {
        let v = v.unwrap_or(0);
        assert_eq!(req(&b, Q_RLIMIT_BASE + 2 * r), v as u32, "low {r}");
        assert_eq!(
            req(&b, Q_RLIMIT_BASE + 2 * r + 1),
            (v >> 32) as u32,
            "high {r}"
        );
    }
}

#[test]
fn a_limit_step_is_named_after_its_resource() {
    assert_eq!(
        qinit_overseer::status::name(Step::Rlimit(7, 1)),
        "rlimit-nofile"
    );
    assert_eq!(
        qinit_overseer::status::name(Step::Rlimit(8, 1)),
        "rlimit-memlock"
    );
    assert_eq!(
        qinit_overseer::status::name(Step::RlimitCore0),
        "rlimit-core"
    );
}
