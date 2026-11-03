// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The `overseer` binary's refusals, which need no privilege: a request that does not decode
//! and a user that does not resolve each leave a status record and exit 127. The launches
//! that do change credentials run in the VM suites.
use qinit_overseer::request::RequestSpec;
use qinit_overseer::status::{STEP_DECODE, STEP_IDENTITY, Status};
use qinit_sys::{fd, memfd, proc, spawn};
use std::ffi::OsStr;
use std::os::fd::AsFd;
use std::path::Path;

/// Runs the binary with `request` on fd 3 and a status pipe on fd 4: the record it left (if
/// any) and its exit code.
fn run(request: &[u8]) -> (Option<Status>, i32) {
    let req = memfd::sealed(c"req", request).unwrap();
    let (status_r, status_w) = fd::pipe(libc::O_CLOEXEC).unwrap();
    let (err_r, err_w) = fd::pipe(libc::O_CLOEXEC).unwrap();
    let exe = Path::new(env!("CARGO_BIN_EXE_overseer"));
    let p = spawn::Prepared::new(
        exe,
        &[OsStr::new("overseer")],
        &[],
        &[(req.as_fd(), 3), (status_w.as_fd(), 4)],
    )
    .unwrap();
    let (_pid, pidfd) = spawn::spawn(&p, None, err_w.as_fd()).unwrap();
    drop((err_w, status_w, req));
    assert_eq!(
        Status::read(err_r.as_fd()),
        None,
        "the binary was not started"
    );
    let record = Status::read(status_r.as_fd());
    let code = libc::WEXITSTATUS(proc::wait_pidfd(&pidfd).unwrap());
    (record, code)
}

fn spec(user: &str) -> RequestSpec {
    RequestSpec {
        argv: vec!["/bin/true".into()],
        user: user.into(),
        ..RequestSpec::default()
    }
}

#[test]
fn a_request_that_does_not_decode_is_a_decode_record() {
    let (record, code) = run(b"not a request");
    assert_eq!(
        record,
        Some(Status {
            step: STEP_DECODE,
            errno: libc::EINVAL
        })
    );
    assert_eq!(code, 127);
}

#[test]
fn an_unknown_user_is_an_identity_record() {
    let (record, code) = run(&spec("no-such-account-qinit").bytes().unwrap());
    assert_eq!(
        record,
        Some(Status {
            step: STEP_IDENTITY,
            errno: libc::ENOENT
        })
    );
    assert_eq!(code, 127);
}

#[test]
fn a_user_with_a_bad_name_is_an_identity_record_before_any_lookup() {
    let (record, code) = run(&spec("0day").bytes().unwrap());
    assert_eq!(
        record,
        Some(Status {
            step: STEP_IDENTITY,
            errno: libc::EINVAL
        })
    );
    assert_eq!(code, 127);
}
