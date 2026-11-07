// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! A refused watch (colony said no) keeps the client usable.
#[path = "../../qinit-client/tests/common/served.rs"]
mod served;

use qinit_client_c::*;
use std::ffi::CString;
use std::ptr;

#[test]
fn a_refused_watch_keeps_the_client_usable() {
    let s = served::Served::start(&["db"], true, served::instant(None));
    let path = CString::new(s.path.to_str().unwrap()).unwrap();
    let mut c = ptr::null_mut();
    // SAFETY: `path` is NUL-terminated and `c` a valid out pointer.
    assert_eq!(unsafe { qinit_connect(path.as_ptr(), &raw mut c) }, 0);
    // SAFETY: the client is open and the target NUL-terminated.
    let rc = unsafe { qinit_watch(c, 0, c"nope".as_ptr()) };
    assert_eq!(rc, QINIT_E_SERVER, "an unknown target is refused by colony");
    // SAFETY: the client is open.
    assert!(unsafe { qinit_fd(c) } >= 0, "the connection is kept");
    let mut status = std::mem::MaybeUninit::<qinit_status>::uninit();
    // SAFETY: every pointer is valid.
    let rc = unsafe { qinit_status(c, c"db".as_ptr(), status.as_mut_ptr()) };
    assert_eq!(rc, 0, "the same client still asks");
    // SAFETY: the client is open and the target NUL-terminated.
    let rc = unsafe { qinit_watch(c, 0, c"db".as_ptr()) };
    assert_eq!(rc, 0, "and watches");
    // SAFETY: the client came from `qinit_connect` and is closed once.
    unsafe { qinit_close(c) };
}
