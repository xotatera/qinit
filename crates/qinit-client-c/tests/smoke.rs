// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! The C programs (`tests/c/smoke.c` and `tests/c/builder.c`, compiled and linked by `build.rs`)
//! drive a served colony through the C interface, and compile without a warning under the
//! strictest flags.
#[cfg(not(smoke_c_unavailable))]
#[path = "../../qinit-client/tests/common/served.rs"]
mod served;

#[cfg(not(smoke_c_unavailable))]
use std::ffi::{CString, c_char};

#[cfg(not(smoke_c_unavailable))]
unsafe extern "C" {
    fn qinit_smoke(socket: *const c_char) -> i32;
    fn qinit_builder(socket: *const c_char) -> i32;
}

/// Addresses of every exported function.
#[cfg(not(smoke_c_unavailable))]
struct Keep(#[expect(dead_code, reason = "the addresses are kept, never read")] [*const (); 45]);

// SAFETY: the addresses are never dereferenced or called through the table; they only exist.
#[cfg(not(smoke_c_unavailable))]
unsafe impl Sync for Keep {}

/// The smoke object is linked after the rlibs, and an archive member is pulled in only by a
/// reference that precedes it: this table makes every `qinit_*` member present first.
#[cfg(not(smoke_c_unavailable))]
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
    qinit_client_c::qinit_request_new as *const (),
    qinit_client_c::qinit_request_free as *const (),
    qinit_client_c::qinit_request_error as *const (),
    qinit_client_c::qinit_request_bytes as *const (),
    qinit_client_c::qinit_request_add_arg as *const (),
    qinit_client_c::qinit_request_add_env as *const (),
    qinit_client_c::qinit_request_add_path as *const (),
    qinit_client_c::qinit_request_add_syscall as *const (),
    qinit_client_c::qinit_request_set_cwd as *const (),
    qinit_client_c::qinit_request_set_umask as *const (),
    qinit_client_c::qinit_request_set_rlimit as *const (),
    qinit_client_c::qinit_request_set_user as *const (),
    qinit_client_c::qinit_request_set_caps as *const (),
    qinit_client_c::qinit_request_set_securebits as *const (),
    qinit_client_c::qinit_request_set_nnp as *const (),
    qinit_client_c::qinit_request_set_namespaces as *const (),
    qinit_client_c::qinit_request_set_user_map as *const (),
    qinit_client_c::qinit_request_set_inside_ids as *const (),
    qinit_client_c::qinit_request_set_seccomp as *const (),
    qinit_client_c::qinit_request_set_stdin_path as *const (),
    qinit_client_c::qinit_request_set_stdin_fd as *const (),
    qinit_client_c::qinit_request_set_stdout_path as *const (),
    qinit_client_c::qinit_request_set_stdout_fd as *const (),
    qinit_client_c::qinit_request_set_stderr_path as *const (),
    qinit_client_c::qinit_request_set_stderr_fd as *const (),
    qinit_client_c::qinit_request_set_stderr_same as *const (),
    qinit_client_c::qinit_request_set_ready_fd as *const (),
    qinit_client_c::qinit_request_set_die_with_parent as *const (),
    qinit_client_c::qinit_request_set_deadline_ms as *const (),
]);

#[cfg(not(smoke_c_unavailable))]
#[test]
fn c_smoke_program_drives_a_server() {
    let s = served::Served::start(&["db"], true, served::instant(None));
    let path = CString::new(s.path.to_str().unwrap()).unwrap();
    // SAFETY: `path` is NUL-terminated and outlives the call; the program closes what it opens.
    assert_eq!(unsafe { qinit_smoke(path.as_ptr()) }, 0);
}

/// A request built through `qinit_request_*` runs to its exit through `qinit_run_begin`.
#[cfg(not(smoke_c_unavailable))]
#[test]
fn c_builder_program_runs_a_request() {
    let s = served::Served::start_policy(
        &[],
        true,
        served::instant(Some(0)),
        Vec::new(),
        Some("default = \"allow\"\n"),
    );
    let path = CString::new(s.path.to_str().unwrap()).unwrap();
    // SAFETY: `path` is NUL-terminated and outlives the call; the program frees what it makes.
    assert_eq!(unsafe { qinit_builder(path.as_ptr()) }, 0);
}

#[cfg(smoke_c_unavailable)]
#[test]
fn c_smoke_program_drives_a_server() {
    panic!("build.rs could not compile the C programs in tests/c; its cargo warning says why");
}

#[cfg(smoke_c_unavailable)]
#[test]
fn c_builder_program_runs_a_request() {
    panic!("build.rs could not compile the C programs in tests/c; its cargo warning says why");
}

#[test]
fn the_c_programs_compile_without_a_warning() {
    let dir = env!("CARGO_MANIFEST_DIR");
    for program in ["smoke", "builder"] {
        let r = std::process::Command::new("cc")
            .args([
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-fsyntax-only",
                "-I",
                &format!("{dir}/include"),
                &format!("{dir}/tests/c/{program}.c"),
            ])
            .output()
            .expect("cc runs");
        assert!(
            r.status.success(),
            "cc -Werror on tests/c/{program}.c ({}):\n{}{}",
            r.status,
            String::from_utf8_lossy(&r.stdout),
            String::from_utf8_lossy(&r.stderr)
        );
    }
}
