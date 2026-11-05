// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! The C functions refuse bad arguments before they touch the connection, called from Rust
//! through the rlib against a listening socket that never answers.
use qinit_client_c::*;
use std::ffi::{CString, c_char};
use std::os::fd::{AsFd, OwnedFd};
use std::path::PathBuf;
use std::ptr;

/// A listening socket and the server side of one accepted connection.
struct Silent {
    listener: OwnedFd,
    /// None once the test hung up.
    conn: Option<OwnedFd>,
    client: *mut qinit_client,
    dir: PathBuf,
}

impl Silent {
    fn start(tag: &str) -> Silent {
        let dir = std::env::temp_dir().join(format!("qinit-client-c-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = CString::new(dir.join("colony").to_str().unwrap()).unwrap();
        let listener = qinit_ipc::listen_seqpacket(&path, 4).unwrap();
        let mut client = ptr::null_mut();
        // SAFETY: `path` is NUL-terminated and `client` is a valid out pointer.
        assert_eq!(unsafe { qinit_connect(path.as_ptr(), &raw mut client) }, 0);
        assert!(!client.is_null());
        let conn = qinit_ipc::accept(listener.as_fd()).unwrap();
        Silent {
            listener,
            conn: Some(conn),
            client,
            dir,
        }
    }

    fn last(&self) -> qinit_error {
        let mut e = qinit_error {
            kind: -1,
            code: -1,
            detail: u32::MAX,
        };
        // SAFETY: the client is open and `e` is a valid out pointer.
        unsafe { qinit_last_error(self.client, &raw mut e) };
        e
    }

    /// Whether the server side has anything to read now.
    fn sent_anything(&self) -> bool {
        self.sent_within(0)
    }

    /// Whether the server side has anything to read within `ms`.
    fn sent_within(&self, ms: i32) -> bool {
        let conn = self.conn.as_ref().expect("connected");
        qinit_ipc::poll_readable(conn.as_fd(), ms).unwrap()
    }

    /// Closes the server side: the client's next read sees the end.
    fn hang_up(&mut self) {
        self.conn = None;
    }
}

impl Drop for Silent {
    fn drop(&mut self) {
        // SAFETY: the client came from `qinit_connect` and is closed once.
        unsafe { qinit_close(self.client) };
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn assert_argument(s: &Silent, rc: i32, what: &str) {
    assert_eq!(rc, QINIT_E_ARGUMENT, "{what}: return");
    let e = s.last();
    assert_eq!(e.kind, QINIT_E_ARGUMENT, "{what}: last error kind");
    assert!(!s.sent_anything(), "{what}: something was sent");
}

#[test]
fn arguments_are_checked_before_anything_is_sent() {
    let s = Silent::start("arguments");
    let c = s.client;
    let db = c"db";

    // A null out pointer.
    // SAFETY: the client is open; the target is NUL-terminated; a null `out` is what is tested.
    let rc = unsafe { qinit_status(c, db.as_ptr(), ptr::null_mut()) };
    assert_argument(&s, rc, "status, null out");

    // A null target.
    let mut status = std::mem::MaybeUninit::<qinit_status>::uninit();
    // SAFETY: the client is open and `status` is writable; a null target is what is tested.
    let rc = unsafe { qinit_status(c, ptr::null(), status.as_mut_ptr()) };
    assert_argument(&s, rc, "status, null target");

    // A 97-byte name (one over QINIT_NAME_MAX) for a launch.
    let long = CString::new("a".repeat(QINIT_NAME_MAX as usize + 1)).unwrap();
    let args = qinit_launch_args {
        argv_tail: ptr::null(),
        argv_tail_len: 0,
        env: ptr::null(),
        env_len: 0,
        stdin_fd: -1,
        stdout_fd: -1,
        stderr_fd: -1,
        want_pidfd: 0,
    };
    let mut begun = std::mem::MaybeUninit::<qinit_begun>::uninit();
    // SAFETY: every pointer is valid; the over-long frame name is what is tested.
    let rc =
        unsafe { qinit_launch_begin(c, long.as_ptr(), &raw const args, 1000, begun.as_mut_ptr()) };
    assert_argument(&s, rc, "launch, 97-byte frame");

    // A 108-byte target (one over the 107 a target may have).
    let target = CString::new(format!("{}#1", "a".repeat(106))).unwrap();
    assert_eq!(target.as_bytes().len(), 108);
    // SAFETY: every pointer is valid; the over-long target is what is tested.
    let rc = unsafe { qinit_status(c, target.as_ptr(), status.as_mut_ptr()) };
    assert_argument(&s, rc, "status, 108-byte target");

    // A name that is not UTF-8.
    let bad: [u8; 3] = [b'd', 0xff, 0];
    // SAFETY: `bad` is NUL-terminated; its non-UTF-8 byte is what is tested.
    let rc = unsafe { qinit_status(c, bad.as_ptr().cast::<c_char>(), status.as_mut_ptr()) };
    assert_argument(&s, rc, "status, non-UTF-8 target");

    // A 108-byte watch target (one over the 107 a target may have).
    // SAFETY: the client is open and the target NUL-terminated; its length is what is tested.
    let rc = unsafe { qinit_watch(c, 0, target.as_ptr()) };
    assert_argument(&s, rc, "watch, 108-byte target");

    // A 96-byte run name (one over QINIT_RUN_NAME_MAX, which leaves room for the `~`).
    let run_name = CString::new("r".repeat(QINIT_RUN_NAME_MAX as usize + 1)).unwrap();
    let request = [0u8; 8];
    let run_args = run_args(&request);
    // SAFETY: every pointer is valid; the over-long name is what is tested.
    let rc = unsafe {
        qinit_run_begin(
            c,
            run_name.as_ptr(),
            &raw const run_args,
            1000,
            begun.as_mut_ptr(),
        )
    };
    assert_argument(&s, rc, "run, 96-byte name");

    // A scope other than 0 (one target) or 1 (everything).
    // SAFETY: the client is open and the target NUL-terminated; the scope 2 is what is tested.
    let rc = unsafe { qinit_watch(c, 2, db.as_ptr()) };
    assert_argument(&s, rc, "watch, scope 2");

    // An action out of range.
    let mut waited = std::mem::MaybeUninit::<qinit_wait_result>::uninit();
    // SAFETY: every pointer is valid; the action 6 is what is tested.
    let rc = unsafe { qinit_change(c, db.as_ptr(), 6, 0, waited.as_mut_ptr()) };
    assert_argument(&s, rc, "change, action 6");

    // A finish with no launch begun.
    let mut finish = std::mem::MaybeUninit::<qinit_finish>::uninit();
    // SAFETY: the client is open and `finish` is writable.
    let rc = unsafe { qinit_launch_finish(c, finish.as_mut_ptr()) };
    assert_argument(&s, rc, "finish, nothing begun");

    // The client is still a client: the bad watch did not spend it.
    // SAFETY: the client is open.
    let fd = unsafe { qinit_fd(c) };
    assert!(fd >= 0);
    // The probe sees a message the client socket does send (a positive control).
    // SAFETY: `fd` is the client's socket, open while the client is.
    let sock = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    qinit_ipc::send(sock, b"x", &[]).unwrap();
    assert!(s.sent_anything());
}

/// Run arguments over `request`, with no descriptors and the smallest grace.
fn run_args(request: &[u8]) -> qinit_run_args {
    qinit_run_args {
        request: request.as_ptr(),
        request_len: request.len(),
        stdin_fd: -1,
        stdout_fd: -1,
        stderr_fd: -1,
        want_pidfd: 0,
        wait_ready: 0,
        memory_max_kib: 0,
        pids_max: 0,
        stop_mode: QINIT_STOP_MAIN,
        stop_grace_ms: 100,
    }
}

/// A raw client pointer moved to the thread that alone uses it until it is joined.
struct Owned(*mut qinit_client);
// SAFETY: the pointer is used by one thread at a time: the spawned one, until it is joined.
unsafe impl Send for Owned {}

#[test]
fn a_95_byte_run_name_is_sent() {
    let mut s = Silent::start("run95");
    let client = Owned(s.client);
    let call = std::thread::spawn(move || {
        let client = client;
        let name = CString::new("r".repeat(QINIT_RUN_NAME_MAX as usize)).unwrap();
        let request = [0u8; 8];
        let a = run_args(&request);
        let mut begun = std::mem::MaybeUninit::<qinit_begun>::uninit();
        // SAFETY: every pointer is valid for the call, and only this thread uses the client.
        unsafe {
            qinit_run_begin(
                client.0,
                name.as_ptr(),
                &raw const a,
                1000,
                begun.as_mut_ptr(),
            )
        }
    });
    assert!(s.sent_within(5000), "the 95-byte name passed the check");
    s.hang_up();
    let rc = call.join().unwrap();
    assert_ne!(rc, QINIT_E_ARGUMENT);
    assert_ne!(rc, 0);
}

/// The kind `qinit_last_error(NULL, …)` gives: this thread's last connect failure.
fn connect_error() -> i32 {
    let mut e = qinit_error {
        kind: -1,
        code: -1,
        detail: 0,
    };
    // SAFETY: a null client asks for the connect failure; `e` is a valid out pointer.
    unsafe { qinit_last_error(ptr::null(), &raw mut e) };
    e.kind
}

/// Records a connect failure (an errno) for this thread.
fn fail_a_connect() {
    let mut client = ptr::null_mut();
    // SAFETY: the path is NUL-terminated and `client` a valid out pointer.
    let rc = unsafe { qinit_connect(c"/nonexistent/qinit-client-c".as_ptr(), &raw mut client) };
    assert_eq!(rc, QINIT_E_ERRNO);
    assert!(client.is_null());
    assert_eq!(connect_error(), QINIT_E_ERRNO);
}

#[test]
fn a_connect_with_a_null_out_connects_nothing_and_is_the_last_connect_failure() {
    let s = Silent::start("nullout");
    fail_a_connect();
    let path = CString::new(s.dir.join("colony").to_str().unwrap()).unwrap();
    // SAFETY: `path` is NUL-terminated; the null `out` is what is tested.
    let rc = unsafe { qinit_connect(path.as_ptr(), ptr::null_mut()) };
    assert_eq!(rc, QINIT_E_ARGUMENT);
    assert_eq!(connect_error(), QINIT_E_ARGUMENT, "not the stale errno");
    assert!(
        !qinit_ipc::poll_readable(s.listener.as_fd(), 0).unwrap(),
        "no connection was made"
    );
}

#[test]
fn a_null_client_is_an_argument_error() {
    fail_a_connect();
    let mut status = std::mem::MaybeUninit::<qinit_status>::uninit();
    // SAFETY: a null client is what is tested; the other pointers are valid.
    let rc = unsafe { qinit_status(ptr::null_mut(), c"db".as_ptr(), status.as_mut_ptr()) };
    assert_eq!(rc, QINIT_E_ARGUMENT);
    // A call with no client records nothing: the connect failure is still the last one.
    assert_eq!(connect_error(), QINIT_E_ERRNO);
    // SAFETY: a null client is accepted by `qinit_fd` and `qinit_close`.
    assert_eq!(unsafe { qinit_fd(ptr::null()) }, -1);
    // SAFETY: as above.
    unsafe { qinit_close(ptr::null_mut()) };
}

#[test]
fn abi_version_is_one() {
    // SAFETY: no arguments.
    assert_eq!(unsafe { qinit_abi_version() }, 1);
    assert_eq!(QINIT_ABI_VERSION, 1);
}
