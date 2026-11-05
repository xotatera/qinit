// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! The C smoke program (`tests/c/smoke.c`, compiled and linked by `build.rs`) drives a served
//! colony through the C interface.
#[path = "../../qinit-client/tests/common/served.rs"]
mod served;

use std::ffi::{CString, c_char};

unsafe extern "C" {
    fn qinit_smoke(socket: *const c_char) -> i32;
}

/// Addresses of every exported function.
struct Keep(#[expect(dead_code, reason = "the addresses are kept, never read")] [*const (); 16]);

// SAFETY: the addresses are never dereferenced or called through the table; they only exist.
unsafe impl Sync for Keep {}

/// The smoke object is linked after the rlibs, and an archive member is pulled in only by a
/// reference that precedes it: this table makes every `qinit_*` member present first.
#[used]
static KEEP: Keep = Keep([
    qinit_client_c::qinit_abi_version as *const (),
    qinit_client_c::qinit_connect as *const (),
    qinit_client_c::qinit_close as *const (),
    qinit_client_c::qinit_fd as *const (),
    qinit_client_c::qinit_last_error as *const (),
    qinit_client_c::qinit_status as *const (),
    qinit_client_c::qinit_list as *const (),
    qinit_client_c::qinit_change as *const (),
    qinit_client_c::qinit_refresh as *const (),
    qinit_client_c::qinit_shutdown as *const (),
    qinit_client_c::qinit_launch_begin as *const (),
    qinit_client_c::qinit_run_begin as *const (),
    qinit_client_c::qinit_launch_finish as *const (),
    qinit_client_c::qinit_pidfd_exit as *const (),
    qinit_client_c::qinit_watch as *const (),
    qinit_client_c::qinit_watch_next as *const (),
]);

#[test]
fn c_smoke_program_drives_a_server() {
    let s = served::Served::start(&["db"], true, served::instant(None));
    let path = CString::new(s.path.to_str().unwrap()).unwrap();
    // SAFETY: `path` is NUL-terminated and outlives the call; the program closes what it opens.
    assert_eq!(unsafe { qinit_smoke(path.as_ptr()) }, 0);
}
