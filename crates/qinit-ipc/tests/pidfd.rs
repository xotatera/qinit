// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0

//! The pure rule that tells a missing kernel feature from a status that is not there yet.
use qinit_ipc::Errno;
use qinit_ipc::pidfd::{PidfdExit, decide_exit};

#[test]
fn a_kernel_without_the_flag_is_unsupported() {
    // An answer with no exit information from a kernel that cannot give it.
    assert_eq!(
        decide_exit(false, Ok(None)).unwrap(),
        PidfdExit::Unsupported
    );
    // So is a kernel that refuses the ioctl itself, or (before 6.15) cannot find a reaped task.
    for errno in [libc::EINVAL, libc::ENOTTY, libc::ESRCH] {
        assert_eq!(
            decide_exit(false, Err(Errno(errno))).unwrap(),
            PidfdExit::Unsupported
        );
    }
}

#[test]
fn a_kernel_with_the_flag_that_has_no_status_says_running() {
    assert_eq!(decide_exit(true, Ok(None)).unwrap(), PidfdExit::Running);
    assert_eq!(
        decide_exit(true, Ok(Some(0x0700))).unwrap(),
        PidfdExit::Exited(0x0700)
    );
}

#[test]
fn esrch_on_a_kernel_that_reports_is_an_error() {
    assert_eq!(
        decide_exit(true, Err(Errno(libc::ESRCH))).unwrap_err(),
        Errno(libc::ESRCH)
    );
}

#[test]
fn any_other_failure_is_an_error() {
    assert_eq!(
        decide_exit(true, Err(Errno(libc::EBADF))).unwrap_err(),
        Errno(libc::EBADF)
    );
}
