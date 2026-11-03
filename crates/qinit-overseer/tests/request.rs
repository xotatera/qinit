// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The request builder, the environment of the service and the status record.
use qinit_db::{Model, Seccomp, Securebits};
use qinit_overseer::identity::Identity;
use qinit_overseer::request::{BuildError, RequestSpec, Routed, Stream, from_model};
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
        nofile: 1024,
        user: "svc".into(),
        caps: (1 << 10) | (1 << 40),
        securebits: Securebits::NorootLocked,
        nnp: true,
        ns: 0b10011,
        seccomp: Seccomp::Deny(vec![101, 110]),
        landlock: vec!["ro:/etc".into(), "rw:/var/log".into()],
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
    assert_eq!(
        text(&b, Q_LANDLOCK_OFF, Q_LANDLOCK_LEN),
        "ro:/etc\0rw:/var/log"
    );
    assert_eq!(text(&b, Q_STDOUT_A, Q_STDOUT_B), "/var/log/out");
    assert_eq!(req(&b, Q_UMASK), 0o077);
    assert_eq!(req(&b, Q_NOFILE), 1024);
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
    assert_eq!(spec.bytes().unwrap_err(), BuildError::TooLarge);
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
    assert_eq!((spec.umask, spec.nofile), (0o077, 1024));
    assert_eq!(spec.cwd, "/var/log/qinit");
    assert_eq!(spec.user, "logd");
    assert_eq!(spec.ns, 0b01100);
    assert_eq!(spec.seccomp, Seccomp::Default);
    assert_eq!(spec.landlock, ["ro:/etc/logd", "rw:/var/log/qinit"]);
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
