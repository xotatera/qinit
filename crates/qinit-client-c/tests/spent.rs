// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! A refused watch spends the client: every call but `qinit_fd`, `qinit_last_error` and
//! `qinit_close` is then `QINIT_E_ARGUMENT` (negated for `qinit_watch_next`), and nothing is sent.
#[path = "../../qinit-client/tests/common/served.rs"]
mod served;

use qinit_client_c::*;
use std::ffi::CString;
use std::ptr;

#[test]
fn a_refused_watch_leaves_a_spent_client_that_refuses_every_call_alike() {
    let s = served::Served::start(&["db"], true, served::instant(None));
    let path = CString::new(s.path.to_str().unwrap()).unwrap();
    let mut c = ptr::null_mut();
    // SAFETY: `path` is NUL-terminated and `c` a valid out pointer.
    assert_eq!(unsafe { qinit_connect(path.as_ptr(), &raw mut c) }, 0);
    // SAFETY: the client is open and the target NUL-terminated.
    let rc = unsafe { qinit_watch(c, 0, c"nope".as_ptr()) };
    assert_eq!(rc, QINIT_E_SERVER, "an unknown target is refused by colony");
    // SAFETY: the client is open.
    assert_eq!(unsafe { qinit_fd(c) }, -1, "the connection is gone");
    let last = || {
        let mut e = qinit_error {
            kind: -1,
            code: -1,
            detail: 0,
        };
        // SAFETY: the client is open and `e` a valid out pointer.
        unsafe { qinit_last_error(c, &raw mut e) };
        e.kind
    };

    let mut status = std::mem::MaybeUninit::<qinit_status>::uninit();
    // SAFETY: every pointer is valid.
    let rc = unsafe { qinit_status(c, c"db".as_ptr(), status.as_mut_ptr()) };
    assert_eq!((rc, last()), (QINIT_E_ARGUMENT, QINIT_E_ARGUMENT), "status");
    let mut waited = std::mem::MaybeUninit::<qinit_wait_result>::uninit();
    // SAFETY: every pointer is valid.
    let rc = unsafe { qinit_change(c, c"db".as_ptr(), QINIT_ACTION_STOP, 0, waited.as_mut_ptr()) };
    assert_eq!((rc, last()), (QINIT_E_ARGUMENT, QINIT_E_ARGUMENT), "change");
    // SAFETY: the client is open and the target NUL-terminated.
    let rc = unsafe { qinit_watch(c, 0, c"db".as_ptr()) };
    assert_eq!((rc, last()), (QINIT_E_ARGUMENT, QINIT_E_ARGUMENT), "watch");
    let mut event = std::mem::MaybeUninit::<qinit_event>::uninit();
    // SAFETY: every pointer is valid.
    let rc = unsafe { qinit_watch_next(c, 0, event.as_mut_ptr()) };
    assert_eq!(
        (rc, last()),
        (-QINIT_E_ARGUMENT, QINIT_E_ARGUMENT),
        "watch_next"
    );
    let mut finish = std::mem::MaybeUninit::<qinit_finish>::uninit();
    // SAFETY: every pointer is valid.
    let rc = unsafe { qinit_launch_finish(c, finish.as_mut_ptr()) };
    assert_eq!((rc, last()), (QINIT_E_ARGUMENT, QINIT_E_ARGUMENT), "finish");
    // SAFETY: the client came from `qinit_connect` and is closed once.
    unsafe { qinit_close(c) };
}
