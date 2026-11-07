// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! The request builder (`qinit_request_*`), called from Rust through the rlib: it makes the
//! bytes the Rust encoder makes, refuses what `RequestSpec::check` refuses with its words, and
//! takes NULL anywhere without harm.
use qinit_client_c::*;
use qinit_launch::{RequestSpec, Seccomp, Securebits, Stream, UserMap};
use std::ffi::{CStr, c_char, c_int};
use std::ptr;

/// Calls a builder function: the tests pass only NULL or a live builder, NULL or a
/// NUL-terminated string that outlives the call, and NULL or writable out pointers.
macro_rules! c {
    ($call:expr) => {{
        // SAFETY: by this macro's rule, every argument is valid for the call.
        unsafe { $call }
    }};
}

/// A builder, freed when dropped.
struct Builder(*mut qinit_request);

impl Builder {
    fn new() -> Builder {
        let r = c!(qinit_request_new());
        assert!(!r.is_null());
        Builder(r)
    }

    /// The bytes, or the kind of the failure with the reason.
    fn bytes(&self) -> Result<Vec<u8>, (c_int, String)> {
        let (mut p, mut len): (*const u8, usize) = (ptr::null(), usize::MAX);
        let rc = c!(qinit_request_bytes(self.0, &raw mut p, &raw mut len));
        if rc != 0 {
            assert!(p.is_null() && len == 0, "a failure gives no bytes");
            return Err((rc, self.error()));
        }
        assert_eq!(self.error(), "", "a success clears the reason");
        // SAFETY: on success `p` points to `len` bytes owned by the builder until its next call.
        Ok(unsafe { std::slice::from_raw_parts(p, len) }.to_vec())
    }

    fn error(&self) -> String {
        let text = c!(qinit_request_error(self.0));
        // SAFETY: the text is NUL-terminated and the builder's until its next call.
        unsafe { CStr::from_ptr(text) }.to_str().unwrap().to_owned()
    }
}

impl Drop for Builder {
    fn drop(&mut self) {
        c!(qinit_request_free(self.0));
    }
}

/// `rc` is 0.
#[track_caller]
fn ok(rc: c_int) {
    assert_eq!(rc, 0);
}

#[test]
fn a_new_builder_gives_the_default_request() {
    let b = Builder::new();
    ok(c!(qinit_request_add_arg(b.0, c"/bin/x".as_ptr())));
    ok(c!(qinit_request_set_user(b.0, c"svc".as_ptr())));
    let want = RequestSpec {
        argv: vec!["/bin/x".into()],
        user: "svc".into(),
        ..RequestSpec::default()
    };
    assert_eq!(b.bytes().unwrap(), want.bytes().unwrap());
}

#[test]
#[allow(clippy::too_many_lines)] // one setter call per field, then the same request in Rust
fn the_builder_makes_the_bytes_rust_makes() {
    let b = Builder::new();
    let r = b.0;
    ok(c!(qinit_request_add_arg(r, c"/usr/bin/job".as_ptr())));
    ok(c!(qinit_request_add_arg(r, c"--once".as_ptr())));
    ok(c!(qinit_request_add_env(r, c"LANG=C".as_ptr())));
    ok(c!(qinit_request_add_env(r, c"TZ=UTC".as_ptr())));
    ok(c!(qinit_request_set_cwd(r, c"/work".as_ptr())));
    ok(c!(qinit_request_set_umask(r, 0o022)));
    ok(c!(qinit_request_set_rlimit(r, 7, 1024)));
    ok(c!(qinit_request_set_rlimit(r, 3, u64::MAX)));
    ok(c!(qinit_request_set_user(r, c"svc".as_ptr())));
    ok(c!(qinit_request_set_caps(r, (1 << 10) | (1 << 21))));
    ok(c!(qinit_request_set_securebits(
        r,
        QINIT_SECUREBITS_NOROOT_LOCKED,
    )));
    ok(c!(qinit_request_set_nnp(r, 0)));
    ok(c!(qinit_request_set_namespaces(
        r,
        QINIT_NS_MOUNT | QINIT_NS_PID | QINIT_NS_USER,
    )));
    ok(c!(qinit_request_set_user_map(r, QINIT_USER_MAP_RANGE)));
    ok(c!(qinit_request_set_inside_ids(r, 1000, 1001)));
    ok(c!(qinit_request_set_seccomp(r, QINIT_SECCOMP_DENY)));
    ok(c!(qinit_request_add_syscall(r, 101)));
    ok(c!(qinit_request_add_syscall(r, 165)));
    ok(c!(qinit_request_add_path(r, c"ro:/usr".as_ptr())));
    ok(c!(qinit_request_add_path(r, c"rw:/var/lib/job".as_ptr())));
    ok(c!(qinit_request_set_stdin_fd(r, 5)));
    ok(c!(qinit_request_set_stdout_path(
        r,
        c"/var/log/job.log".as_ptr(),
    )));
    ok(c!(qinit_request_set_stderr_fd(r, 7)));
    ok(c!(qinit_request_set_ready_fd(r, 8)));
    ok(c!(qinit_request_set_die_with_parent(r, 1)));
    ok(c!(qinit_request_set_deadline_ms(r, 5000)));
    let mut rlimits = [None; 16];
    rlimits[7] = Some(1024);
    rlimits[3] = Some(u64::MAX);
    let want = RequestSpec {
        argv: vec!["/usr/bin/job".into(), "--once".into()],
        env: vec!["LANG=C".into(), "TZ=UTC".into()],
        cwd: "/work".into(),
        umask: 0o022,
        rlimits,
        user: "svc".into(),
        caps: (1 << 10) | (1 << 21),
        securebits: Securebits::NorootLocked,
        nnp: false,
        ns: 1 | 2 | 32,
        user_map: UserMap::Range,
        inside_uid: 1000,
        inside_gid: 1001,
        seccomp: Seccomp::Deny(vec![101, 165]),
        paths: vec!["ro:/usr".into(), "rw:/var/lib/job".into()],
        stdin: Stream::Fd(5),
        stdout: Stream::Path("/var/log/job.log".into()),
        stderr: Stream::Fd(7),
        ready_fd: Some(8),
        die_with_parent: true,
        deadline_ms: 5000,
    };
    assert_eq!(b.bytes().unwrap(), want.bytes().unwrap());

    // The other values of each field: the last setter call wins.
    ok(c!(qinit_request_set_securebits(r, QINIT_SECUREBITS_NOROOT)));
    ok(c!(qinit_request_set_user_map(r, QINIT_USER_MAP_OWN)));
    ok(c!(qinit_request_set_seccomp(r, QINIT_SECCOMP_ALLOW)));
    ok(c!(qinit_request_set_stdin_path(r, c"/dev/zero".as_ptr())));
    ok(c!(qinit_request_set_stdout_fd(r, 6)));
    ok(c!(qinit_request_set_stderr_same(r)));
    ok(c!(qinit_request_set_ready_fd(r, -1)));
    ok(c!(qinit_request_set_die_with_parent(r, 0)));
    ok(c!(qinit_request_set_nnp(r, 1)));
    let want = RequestSpec {
        securebits: Securebits::Noroot,
        user_map: UserMap::Own,
        seccomp: Seccomp::Allow(vec![101, 165]),
        stdin: Stream::Path("/dev/zero".into()),
        stdout: Stream::Fd(6),
        stderr: Stream::Same,
        ready_fd: None,
        die_with_parent: false,
        nnp: true,
        ..want
    };
    assert_eq!(b.bytes().unwrap(), want.bytes().unwrap());
    ok(c!(qinit_request_set_stderr_path(r, c"/dev/null".as_ptr())));
    ok(c!(qinit_request_set_securebits(r, QINIT_SECUREBITS_NONE)));
    let want = RequestSpec {
        stderr: Stream::Path("/dev/null".into()),
        securebits: Securebits::None,
        ..want
    };
    assert_eq!(b.bytes().unwrap(), want.bytes().unwrap());
}

#[test]
fn the_seccomp_modes_without_a_list() {
    for (mode, want) in [
        (QINIT_SECCOMP_NONE, Seccomp::None),
        (QINIT_SECCOMP_DEFAULT, Seccomp::Default),
    ] {
        let b = Builder::new();
        ok(c!(qinit_request_add_arg(b.0, c"/x".as_ptr())));
        ok(c!(qinit_request_set_seccomp(b.0, mode)));
        let want = RequestSpec {
            argv: vec!["/x".into()],
            seccomp: want,
            ..RequestSpec::default()
        };
        assert_eq!(b.bytes().unwrap(), want.bytes().unwrap());
    }
}

#[test]
fn a_request_check_refuses_is_refused_with_its_words() {
    let big = std::ffi::CString::new(format!("K={}", "v".repeat(70_000))).unwrap();
    // Each setter call, and the same value in Rust. A "same" standard input or output
    // (`BadStream`) has no setter, so the C builder cannot make one.
    let cases: [(&dyn Fn(*mut qinit_request) -> c_int, RequestSpec); 4] = [
        (
            &|r| c!(qinit_request_set_cwd(r, c"work".as_ptr())),
            RequestSpec {
                cwd: "work".into(),
                ..RequestSpec::default()
            },
        ),
        (
            &|r| c!(qinit_request_set_deadline_ms(r, 0)),
            RequestSpec {
                deadline_ms: 0,
                ..RequestSpec::default()
            },
        ),
        (
            &|r| c!(qinit_request_set_umask(r, 0o1000)),
            RequestSpec {
                umask: 0o1000,
                ..RequestSpec::default()
            },
        ),
        (
            &|r| c!(qinit_request_add_env(r, big.as_ptr())),
            RequestSpec {
                env: vec![format!("K={}", "v".repeat(70_000))],
                ..RequestSpec::default()
            },
        ),
    ];
    for (set, spec) in cases {
        let b = Builder::new();
        ok(set(b.0));
        let want = spec.check().unwrap_err().to_string();
        assert_eq!(b.bytes(), Err((QINIT_E_ARGUMENT, want)));
    }
}

#[test]
fn a_list_with_no_filter_to_hold_it_is_refused() {
    for mode in [QINIT_SECCOMP_NONE, QINIT_SECCOMP_DEFAULT] {
        let b = Builder::new();
        ok(c!(qinit_request_set_seccomp(b.0, mode)));
        ok(c!(qinit_request_add_syscall(b.0, 101)));
        assert_eq!(
            b.bytes(),
            Err((
                QINIT_E_ARGUMENT,
                "syscalls: only a deny or allow seccomp filter takes a list".into()
            ))
        );
    }
}

#[test]
fn a_failure_is_cleared_by_the_next_call() {
    let b = Builder::new();
    ok(c!(qinit_request_set_deadline_ms(b.0, 0)));
    assert!(b.bytes().is_err());
    assert_ne!(b.error(), "");
    ok(c!(qinit_request_set_deadline_ms(b.0, 1)));
    assert_eq!(b.error(), "");
    assert!(b.bytes().is_ok());
}

#[test]
fn words_out_of_range_are_refused_and_change_nothing() {
    let b = Builder::new();
    let before = b.bytes().unwrap();
    let calls: [(&str, c_int); 9] = [
        ("rlimit 16", c!(qinit_request_set_rlimit(b.0, 16, 1))),
        ("securebits 3", c!(qinit_request_set_securebits(b.0, 3))),
        ("nnp 2", c!(qinit_request_set_nnp(b.0, 2))),
        ("user_map 2", c!(qinit_request_set_user_map(b.0, 2))),
        ("seccomp 4", c!(qinit_request_set_seccomp(b.0, 4))),
        ("ready_fd -2", c!(qinit_request_set_ready_fd(b.0, -2))),
        (
            "die_with_parent -1",
            c!(qinit_request_set_die_with_parent(b.0, -1)),
        ),
        ("cwd empty", c!(qinit_request_set_cwd(b.0, c"".as_ptr()))),
        (
            "user not UTF-8",
            c!(qinit_request_set_user(b.0, c"\xff".as_ptr())),
        ),
    ];
    for (what, rc) in calls {
        assert_eq!(rc, QINIT_E_ARGUMENT, "{what}");
    }
    assert_eq!(b.bytes().unwrap(), before);
}

#[test]
fn each_setter_takes_null_safely() {
    let none: *mut qinit_request = ptr::null_mut();
    let text: *const c_char = c"/x".as_ptr();
    let (mut p, mut len): (*const u8, usize) = (ptr::null(), 0);
    // A NULL builder: every function refuses it and touches nothing.
    let calls: [c_int; 27] = [
        c!(qinit_request_add_arg(none, text)),
        c!(qinit_request_add_env(none, text)),
        c!(qinit_request_add_path(none, text)),
        c!(qinit_request_add_syscall(none, 1)),
        c!(qinit_request_set_cwd(none, text)),
        c!(qinit_request_set_umask(none, 0)),
        c!(qinit_request_set_rlimit(none, 0, 0)),
        c!(qinit_request_set_user(none, text)),
        c!(qinit_request_set_caps(none, 0)),
        c!(qinit_request_set_securebits(none, 0)),
        c!(qinit_request_set_nnp(none, 1)),
        c!(qinit_request_set_namespaces(none, 0)),
        c!(qinit_request_set_user_map(none, 0)),
        c!(qinit_request_set_inside_ids(none, 0, 0)),
        c!(qinit_request_set_seccomp(none, 0)),
        c!(qinit_request_set_stdin_path(none, text)),
        c!(qinit_request_set_stdin_fd(none, 5)),
        c!(qinit_request_set_stdout_path(none, text)),
        c!(qinit_request_set_stdout_fd(none, 6)),
        c!(qinit_request_set_stderr_path(none, text)),
        c!(qinit_request_set_stderr_fd(none, 7)),
        c!(qinit_request_set_stderr_same(none)),
        c!(qinit_request_set_ready_fd(none, 8)),
        c!(qinit_request_set_die_with_parent(none, 1)),
        c!(qinit_request_set_deadline_ms(none, 1)),
        c!(qinit_request_bytes(none, &raw mut p, &raw mut len)),
        c!(qinit_request_bytes(none, ptr::null_mut(), ptr::null_mut())),
    ];
    for (i, rc) in calls.iter().enumerate() {
        assert_eq!(*rc, QINIT_E_ARGUMENT, "call {i}");
    }
    assert!(p.is_null() && len == 0);
    c!(qinit_request_free(none));
    let empty = c!(qinit_request_error(none));
    // SAFETY: the text for a NULL builder is a static empty string.
    assert_eq!(unsafe { CStr::from_ptr(empty) }, c"");

    // A live builder: a NULL string or out pointer is refused, named in the reason, and the
    // request is as it was.
    let b = Builder::new();
    let before = b.bytes().unwrap();
    let null: *const c_char = ptr::null();
    let calls: [(&str, &dyn Fn() -> c_int); 9] = [
        ("arg", &|| c!(qinit_request_add_arg(b.0, null))),
        ("env", &|| c!(qinit_request_add_env(b.0, null))),
        ("path", &|| c!(qinit_request_add_path(b.0, null))),
        ("cwd", &|| c!(qinit_request_set_cwd(b.0, null))),
        ("user", &|| c!(qinit_request_set_user(b.0, null))),
        ("stdin", &|| c!(qinit_request_set_stdin_path(b.0, null))),
        ("stdout", &|| c!(qinit_request_set_stdout_path(b.0, null))),
        ("stderr", &|| c!(qinit_request_set_stderr_path(b.0, null))),
        ("ptr", &|| {
            let mut len = 0;
            c!(qinit_request_bytes(b.0, ptr::null_mut(), &raw mut len))
        }),
    ];
    for (what, call) in calls {
        assert_eq!(call(), QINIT_E_ARGUMENT, "{what}");
        assert!(b.error().starts_with(what), "{what}: {}", b.error());
    }
    let rc = c!(qinit_request_bytes(b.0, &raw mut p, ptr::null_mut()));
    assert_eq!(rc, QINIT_E_ARGUMENT);
    assert!(b.error().starts_with("len"), "{}", b.error());
    assert_eq!(b.bytes().unwrap(), before);
}
