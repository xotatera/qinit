// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! `qinit-client-c`: the C interface over `qinit-client` (`include/qinit_client.h`, generated
//! by cbindgen from this crate). Every exported function checks its pointers and words, converts
//! them inside documented `unsafe` blocks, then calls the safe client; no logic lives here. A
//! panic never crosses the boundary: each body runs under `catch_unwind` and a caught panic is
//! `QINIT_E_UNEXPECTED`.
//!
//! Conventions: a function that can fail returns 0 or the `QINIT_E_*` kind of its failure, and
//! `qinit_last_error` gives the kind, code and detail of the last call on that client (a call
//! with a NULL client is `QINIT_E_ARGUMENT` and records nothing).
//! `qinit_watch_next` and `qinit_pidfd_exit`, whose successes are 0, 1 and 2, fail with the
//! negated kind. Strings in are NUL-terminated UTF-8; names out are copied into
//! `QINIT_NAME_MAX + 1` bytes, NUL-terminated. Descriptors in are borrowed for the call; a pidfd
//! out is the caller's to close. A client is used from one thread at a time.

mod error;
mod types;
mod watch;

pub use error::*;
pub use types::*;
pub use watch::*;

use ::qinit_client::{
    Action, Begun, Client, LaunchArgs, LaunchOutcome, Mode, Outcome, PidfdExit, RunArgs, SOCKET,
    Started, Status, StopMode, Wait, Watcher,
};
use std::cell::Cell;
use std::ffi::{CStr, OsStr, c_char, c_int};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::time::Duration;

/// A connection to colony, opaque to C: a client until `qinit_watch` turns it into a watcher.
#[allow(non_camel_case_types)] // the C name
pub struct qinit_client {
    inner: Inner,
    last: qinit_error,
    /// The id of the launch or run begun and not yet finished.
    began: Option<u32>,
}

enum Inner {
    Client(Client),
    Watching(Watcher),
    /// A failed `qinit_watch` consumed the connection.
    Spent,
}

impl qinit_client {
    /// The client, for a request.
    fn client(&mut self) -> Result<&mut Client, Fail> {
        match &mut self.inner {
            Inner::Client(c) => Ok(c),
            // Not a call this client can make now, whether it watches or its watch was refused.
            Inner::Watching(_) | Inner::Spent => Err(Fail::ARGUMENT),
        }
    }
}

thread_local! {
    /// The failure of this thread's last `qinit_connect`, which has no client to keep it.
    static CONNECT_ERROR: Cell<qinit_error> = const { Cell::new(qinit_error::NONE) };
}

/// Runs `f` on the client behind `c` with panics caught, records its failure (or none) as the
/// client's last error, and returns `f`'s value or the failure's kind.
///
/// # Safety
/// `c` is null or a live client from `qinit_connect` that no other thread uses during the call.
unsafe fn enter(
    c: *mut qinit_client,
    f: impl FnOnce(&mut qinit_client) -> Result<c_int, Fail>,
) -> Result<c_int, c_int> {
    // SAFETY: by the contract, `c` is null or a live, exclusively used client.
    let Some(client) = (unsafe { c.as_mut() }) else {
        return Err(QINIT_E_ARGUMENT);
    };
    let r = catch_unwind(AssertUnwindSafe(|| f(&mut *client))).unwrap_or(Err(Fail::UNEXPECTED));
    match r {
        Ok(v) => {
            client.last = qinit_error::NONE;
            Ok(v)
        }
        Err(Fail(e)) => {
            client.last = e;
            Err(e.kind)
        }
    }
}

/// [`enter`] for a function that returns 0 or the kind of its failure.
///
/// # Safety
/// As [`enter`].
unsafe fn run(
    c: *mut qinit_client,
    f: impl FnOnce(&mut qinit_client) -> Result<(), Fail>,
) -> c_int {
    // SAFETY: the caller's contract is `enter`'s.
    unsafe { enter(c, |cl| f(cl).map(|()| 0)) }.unwrap_or_else(|kind| kind)
}

/// `p`, unless it is null.
fn out<T>(p: *mut T) -> Result<*mut T, Fail> {
    if p.is_null() {
        Err(Fail::ARGUMENT)
    } else {
        Ok(p)
    }
}

/// Writes `v` to `p`.
///
/// # Safety
/// `p` is non-null, aligned and writable for a `T`.
unsafe fn put<T>(p: *mut T, v: T) {
    // SAFETY: by the contract, `p` is valid for a write of a `T`.
    unsafe { p.write(v) };
}

/// The string at `p`: 1 to `max` bytes of UTF-8.
///
/// # Safety
/// `p` is null or a NUL-terminated string that stays valid and unchanged for `'a`.
unsafe fn text<'a>(p: *const c_char, max: u32) -> Result<&'a str, Fail> {
    if p.is_null() {
        return Err(Fail::ARGUMENT);
    }
    // SAFETY: by the contract, `p` is a valid NUL-terminated string for `'a`.
    let bytes = unsafe { CStr::from_ptr(p) }.to_bytes();
    if bytes.is_empty() || bytes.len() > max as usize {
        return Err(Fail::ARGUMENT);
    }
    std::str::from_utf8(bytes).map_err(|_| Fail::ARGUMENT)
}

/// The most strings a list in may have (a message is at most 64 KiB, one byte per string at
/// least).
const MAX_LIST: usize = 65536;

/// The `len` strings at `p`, each non-empty UTF-8.
///
/// # Safety
/// When `len` is not 0, `p` is null or points to `len` pointers, each null or a NUL-terminated
/// string, all valid and unchanged for `'a`.
unsafe fn texts<'a>(p: *const *const c_char, len: usize) -> Result<Vec<&'a str>, Fail> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if p.is_null() || len > MAX_LIST {
        return Err(Fail::ARGUMENT);
    }
    // SAFETY: by the contract, `p` points to `len` initialised pointers valid for `'a`; `len` is
    // at most `MAX_LIST`, so the slice is far below `isize::MAX` bytes.
    let ptrs = unsafe { std::slice::from_raw_parts(p, len) };
    ptrs.iter()
        // SAFETY: each element is null or a valid NUL-terminated string for `'a`.
        .map(|&s| unsafe { text(s, u32::MAX) })
        .collect()
}

/// The descriptor `fd`, -1 for none.
///
/// # Safety
/// `fd` is -1 or an open descriptor that stays open for `'a`.
unsafe fn borrowed<'a>(fd: c_int) -> Result<Option<BorrowedFd<'a>>, Fail> {
    match fd {
        -1 => Ok(None),
        n if n < 0 => Err(Fail::ARGUMENT),
        // SAFETY: by the contract, a non-negative `fd` is open for `'a`.
        n => Ok(Some(unsafe { BorrowedFd::borrow_raw(n) })),
    }
}

/// A C boolean that must be 0 or 1.
fn flag(v: c_int) -> Result<bool, Fail> {
    match v {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Fail::ARGUMENT),
    }
}

/// `wait_ms` as a wait: 0 replies on acceptance.
fn wait(wait_ms: u32) -> Wait {
    if wait_ms == 0 {
        Wait::Now
    } else {
        Wait::Settled(Duration::from_millis(u64::from(wait_ms)))
    }
}

fn wait_result(o: Outcome) -> qinit_wait_result {
    let (outcome, s) = match o {
        Outcome::Accepted => (QINIT_OUTCOME_ACCEPTED, None),
        Outcome::Settled(s) => (QINIT_OUTCOME_SETTLED, Some(s)),
        Outcome::Pending(s) => (QINIT_OUTCOME_PENDING, Some(s)),
        Outcome::Superseded(s) => (QINIT_OUTCOME_SUPERSEDED, Some(s)),
    };
    qinit_wait_result {
        outcome,
        state: s.map_or(0, |s| s.state),
        detail: s.map_or(0, |s| s.detail),
    }
}

/// The version of this interface, `QINIT_ABI_VERSION`.
///
/// # Safety
/// None: it reads nothing. It is `unsafe` as every exported function is.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_abi_version() -> u32 {
    QINIT_ABI_VERSION
}

/// Connects to colony at `path` (NULL: `/run/qinit/colony`) and stores the client in `*out`
/// (NULL on failure; `qinit_last_error(NULL, …)` then gives this thread's connect failure). A
/// NULL `out` is `QINIT_E_ARGUMENT` before anything is connected, and is that failure too.
///
/// # Safety
/// `path` is NULL or a NUL-terminated string; `out` is NULL or writable for a pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_connect(path: *const c_char, out: *mut *mut qinit_client) -> c_int {
    if out.is_null() {
        CONNECT_ERROR.with(|c| c.set(Fail::ARGUMENT.0));
        return QINIT_E_ARGUMENT;
    }
    let r = catch_unwind(AssertUnwindSafe(|| -> Result<*mut qinit_client, Fail> {
        let path = if path.is_null() {
            Path::new(SOCKET)
        } else {
            // SAFETY: by the contract, a non-null `path` is a NUL-terminated string.
            let bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
            // A socket path fits `sun_path` (108 bytes with its NUL).
            if bytes.is_empty() || bytes.len() > 107 {
                return Err(Fail::ARGUMENT);
            }
            Path::new(OsStr::from_bytes(bytes))
        };
        let client = Client::connect(path)?;
        Ok(Box::into_raw(Box::new(qinit_client {
            inner: Inner::Client(client),
            last: qinit_error::NONE,
            began: None,
        })))
    }))
    .unwrap_or(Err(Fail::UNEXPECTED));
    let (ptr, e) = match r {
        Ok(c) => (c, qinit_error::NONE),
        Err(Fail(e)) => (std::ptr::null_mut(), e),
    };
    CONNECT_ERROR.with(|c| c.set(e));
    // SAFETY: `out` is non-null and, by the contract, writable for a pointer.
    unsafe { put(out, ptr) };
    e.kind
}

/// Closes the connection and frees the client; NULL is ignored.
///
/// # Safety
/// `c` is NULL or a client from `qinit_connect` not yet closed and not in use.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_close(c: *mut qinit_client) {
    if !c.is_null() {
        // SAFETY: by the contract, `c` came from `Box::into_raw` in `qinit_connect` and is closed
        // once; dropping closes the socket and cannot panic.
        drop(unsafe { Box::from_raw(c) });
    }
}

/// The client's socket, for the caller's poll; -1 for NULL or a client whose connection is gone.
///
/// # Safety
/// `c` is NULL or a live client not in use by another thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_fd(c: *const qinit_client) -> c_int {
    // SAFETY: by the contract, `c` is null or a live client.
    match unsafe { c.as_ref() }.map(|c| &c.inner) {
        Some(Inner::Client(cl)) => cl.as_fd().as_raw_fd(),
        Some(Inner::Watching(w)) => w.as_fd().as_raw_fd(),
        Some(Inner::Spent) | None => -1,
    }
}

/// Fills `*out` with the failure of the last call on `c` (kind 0 when it succeeded); with a NULL
/// `c`, the failure of this thread's last `qinit_connect`. A NULL `out` is ignored. A call made
/// with a NULL client fails with `QINIT_E_ARGUMENT` and records nothing: it changes neither.
///
/// # Safety
/// `c` is NULL or a live client; `out` is NULL or writable for a `qinit_error`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_last_error(c: *const qinit_client, out: *mut qinit_error) {
    if out.is_null() {
        return;
    }
    // SAFETY: by the contract, `c` is null or a live client.
    let e = match unsafe { c.as_ref() } {
        Some(c) => c.last,
        None => CONNECT_ERROR.with(Cell::get),
    };
    // SAFETY: `out` is non-null and, by the contract, writable for a `qinit_error`.
    unsafe { put(out, e) };
}

/// The status of a node, or of an instance (`<frame>#<id>`).
///
/// # Safety
/// `c` is NULL or a live client; `target` NULL or a NUL-terminated string; `out` NULL or writable
/// for a `qinit_status`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_status(
    c: *mut qinit_client,
    target: *const c_char,
    out: *mut qinit_status,
) -> c_int {
    let body = |cl: &mut qinit_client| -> Result<(), Fail> {
        let out = self::out(out)?;
        // SAFETY: by the contract, `target` is null or a NUL-terminated string.
        let target = unsafe { text(target, QINIT_TARGET_MAX) }?;
        let v = match cl.client()?.status(target)? {
            Status::Node(n) => qinit_status {
                is_instance: 0,
                node: qinit_node_info {
                    name: name(&n.name),
                    kind: n.kind,
                    state: n.state.state,
                    detail: n.state.detail,
                    group: n.blocking.as_ref().map_or(u32::MAX, |b| b.0),
                    blocking: name(n.blocking.as_ref().map_or("", |b| b.1.as_str())),
                    backoff_ms: n.backoff_ms,
                    since_ms: n.since_ms,
                    restarts: n.restarts,
                    pid: n.pid.unwrap_or(0),
                },
                instance: qinit_instance_info::ZERO,
            },
            Status::Instance(i) => qinit_status {
                is_instance: 1,
                node: qinit_node_info::ZERO,
                instance: qinit_instance_info {
                    frame: name(&i.frame),
                    id: i.id,
                    state: i.state,
                    has_status: i32::from(i.status.is_some()),
                    status: i.status.unwrap_or(0),
                    pid: i.pid.unwrap_or(0),
                },
            },
        };
        // SAFETY: `out` is non-null and, by the contract, writable for a `qinit_status`.
        unsafe { put(out, v) };
        Ok(())
    };
    // SAFETY: the contract of `run` is this function's.
    unsafe { run(c, body) }
}

/// Every node of `kind` (`QINIT_LIST_*`): up to `cap` entries into `entries` (NULL when `cap` is
/// 0), and the whole count into `*total`.
///
/// # Safety
/// `c` is NULL or a live client; `entries` NULL or writable for `cap` entries; `total` NULL or
/// writable for a `size_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_list(
    c: *mut qinit_client,
    kind: u32,
    entries: *mut qinit_entry,
    cap: usize,
    total: *mut usize,
) -> c_int {
    let body = |cl: &mut qinit_client| -> Result<(), Fail> {
        let total = out(total)?;
        if (cap > 0 && entries.is_null()) || kind > QINIT_LIST_BROODS {
            return Err(Fail::ARGUMENT);
        }
        let all = cl.client()?.list(kind)?;
        for (i, e) in all.iter().take(cap).enumerate() {
            let v = qinit_entry {
                name: name(&e.name),
                kind: e.kind,
                state: e.state.state,
                detail: e.state.detail,
            };
            // SAFETY: `i < cap` and, by the contract, `entries` is writable for `cap`
            // entries, so the element is in the caller's array.
            let slot = unsafe { entries.add(i) };
            // SAFETY: `slot` is an element of the caller's writable array.
            unsafe { put(slot, v) };
        }
        // SAFETY: `total` is non-null and, by the contract, writable.
        unsafe { put(total, all.len()) };
        Ok(())
    };
    // SAFETY: the contract of `run` is this function's.
    unsafe { run(c, body) }
}

/// Does `action` (`QINIT_ACTION_*`) to a node or an instance (root only), waiting up to `wait_ms`
/// for the target state (0: reply on acceptance).
///
/// # Safety
/// `c` is NULL or a live client; `target` NULL or a NUL-terminated string; `out` NULL or writable
/// for a `qinit_wait_result`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_change(
    c: *mut qinit_client,
    target: *const c_char,
    action: u32,
    wait_ms: u32,
    out: *mut qinit_wait_result,
) -> c_int {
    let body = |cl: &mut qinit_client| -> Result<(), Fail> {
        let out = self::out(out)?;
        // SAFETY: by the contract, `target` is null or a NUL-terminated string.
        let target = unsafe { text(target, QINIT_TARGET_MAX) }?;
        let action = Action::from_word(action).ok_or(Fail::ARGUMENT)?;
        let o = cl.client()?.change(target, action, wait(wait_ms))?;
        // SAFETY: `out` is non-null and, by the contract, writable.
        unsafe { put(out, wait_result(o)) };
        Ok(())
    };
    // SAFETY: the contract of `run` is this function's.
    unsafe { run(c, body) }
}

/// Swaps in the compiled database in `db_fd` (borrowed; root only), waiting up to `wait_ms`.
///
/// # Safety
/// `c` is NULL or a live client; `db_fd` an open descriptor; `out` NULL or writable for a
/// `qinit_wait_result`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_refresh(
    c: *mut qinit_client,
    db_fd: c_int,
    wait_ms: u32,
    out: *mut qinit_wait_result,
) -> c_int {
    let body = |cl: &mut qinit_client| -> Result<(), Fail> {
        let out = self::out(out)?;
        // SAFETY: by the contract, a non-negative `db_fd` is open for the call.
        let db = unsafe { borrowed(db_fd) }?.ok_or(Fail::ARGUMENT)?;
        let o = cl.client()?.refresh(db, wait(wait_ms))?;
        // SAFETY: `out` is non-null and, by the contract, writable.
        unsafe { put(out, wait_result(o)) };
        Ok(())
    };
    // SAFETY: the contract of `run` is this function's.
    unsafe { run(c, body) }
}

/// Shuts the system down in `mode` (`QINIT_MODE_*`; root only), waiting up to `wait_ms`.
///
/// # Safety
/// `c` is NULL or a live client; `out` NULL or writable for a `qinit_wait_result`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_shutdown(
    c: *mut qinit_client,
    mode: u32,
    wait_ms: u32,
    out: *mut qinit_wait_result,
) -> c_int {
    let body = |cl: &mut qinit_client| -> Result<(), Fail> {
        let out = self::out(out)?;
        let mode = Mode::from_word(mode).ok_or(Fail::ARGUMENT)?;
        let o = cl.client()?.shutdown(mode, wait(wait_ms))?;
        // SAFETY: `out` is non-null and, by the contract, writable.
        unsafe { put(out, wait_result(o)) };
        Ok(())
    };
    // SAFETY: the contract of `run` is this function's.
    unsafe { run(c, body) }
}

/// Records a begun launch or run and fills `*out`.
///
/// # Safety
/// `out` is non-null and writable for a `qinit_begun`.
unsafe fn begun(cl: &mut qinit_client, b: Begun, out: *mut qinit_begun) {
    let v = match b {
        Begun::Started(Started { id, pidfd }) => {
            cl.began = Some(id);
            qinit_begun {
                kind: QINIT_BEGUN_STARTED,
                id,
                pidfd: pidfd.map_or(-1, IntoRawFd::into_raw_fd),
                step: 0,
                error_number: 0,
            }
        }
        Begun::Failed { step, errno } => {
            cl.began = None;
            qinit_begun {
                kind: QINIT_BEGUN_FAILED,
                id: 0,
                pidfd: -1,
                step,
                error_number: errno,
            }
        }
    };
    // SAFETY: by the contract, `out` is writable.
    unsafe { put(out, v) };
}

/// Launches an instance of the forager `frame` (root only) and reads its first reply into
/// `*out`; `qinit_launch_finish` reads how it ends, within `wait_ms`.
///
/// # Safety
/// `c` is NULL or a live client; `frame` NULL or a NUL-terminated string; `a` NULL or a valid
/// `qinit_launch_args` whose arrays, strings and descriptors are valid for the call; `out` NULL
/// or writable for a `qinit_begun`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_launch_begin(
    c: *mut qinit_client,
    frame: *const c_char,
    a: *const qinit_launch_args,
    wait_ms: u32,
    out: *mut qinit_begun,
) -> c_int {
    let body = |cl: &mut qinit_client| -> Result<(), Fail> {
        let out = self::out(out)?;
        // SAFETY: by the contract, `frame` is null or a NUL-terminated string.
        let frame = unsafe { text(frame, QINIT_NAME_MAX) }?;
        // SAFETY: by the contract, `a` is null or a valid, aligned `qinit_launch_args`.
        let a = unsafe { a.as_ref() }.ok_or(Fail::ARGUMENT)?;
        // SAFETY: by the contract, the array holds `argv_tail_len` valid strings.
        let tail = unsafe { texts(a.argv_tail, a.argv_tail_len) }?;
        // SAFETY: by the contract, the array holds `env_len` valid strings.
        let env = unsafe { texts(a.env, a.env_len) }?;
        let env = env
            .iter()
            .map(|kv| kv.split_once('=').filter(|(k, _)| !k.is_empty()))
            .collect::<Option<Vec<(&str, &str)>>>()
            .ok_or(Fail::ARGUMENT)?;
        let pidfd = flag(a.want_pidfd)?;
        let args = LaunchArgs {
            argv_tail: &tail,
            env: &env,
            // SAFETY: by the contract, each descriptor is -1 or open for the call.
            stdin: unsafe { borrowed(a.stdin_fd) }?,
            // SAFETY: as above.
            stdout: unsafe { borrowed(a.stdout_fd) }?,
            // SAFETY: as above.
            stderr: unsafe { borrowed(a.stderr_fd) }?,
        };
        let wait = Duration::from_millis(u64::from(wait_ms));
        let b = cl.client()?.begin_launch(frame, &args, pidfd, wait)?;
        // SAFETY: `out` is non-null and, by the contract, writable.
        unsafe { begun(cl, b, out) };
        Ok(())
    };
    // SAFETY: the contract of `run` is this function's.
    unsafe { run(c, body) }
}

/// Runs the launch request in `a` (QLR1 bytes) as the instance `~<name>#<id>` (root only) and
/// reads its first reply into `*out`; `qinit_launch_finish` reads how it ends, within `wait_ms`.
///
/// # Safety
/// `c` is NULL or a live client; `name` NULL or a NUL-terminated string; `a` NULL or a valid
/// `qinit_run_args` whose request bytes and descriptors are valid for the call; `out` NULL or
/// writable for a `qinit_begun`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_run_begin(
    c: *mut qinit_client,
    name: *const c_char,
    a: *const qinit_run_args,
    wait_ms: u32,
    out: *mut qinit_begun,
) -> c_int {
    let body = |cl: &mut qinit_client| -> Result<(), Fail> {
        let out = self::out(out)?;
        // SAFETY: by the contract, `name` is null or a NUL-terminated string.
        let name = unsafe { text(name, QINIT_RUN_NAME_MAX) }?;
        // SAFETY: by the contract, `a` is null or a valid, aligned `qinit_run_args`.
        let a = unsafe { a.as_ref() }.ok_or(Fail::ARGUMENT)?;
        if a.request.is_null() || a.request_len == 0 || a.request_len > QINIT_REQUEST_MAX as usize {
            return Err(Fail::ARGUMENT);
        }
        // SAFETY: by the contract, `request` points to `request_len` readable bytes, at most
        // 64 KiB.
        let request = unsafe { std::slice::from_raw_parts(a.request, a.request_len) };
        let stop_mode = match a.stop_mode {
            QINIT_STOP_MAIN => StopMode::Main,
            QINIT_STOP_CELL => StopMode::Cell,
            _ => return Err(Fail::ARGUMENT),
        };
        let pidfd = flag(a.want_pidfd)?;
        let args = RunArgs {
            // SAFETY: by the contract, each descriptor is -1 or open for the call.
            stdin: unsafe { borrowed(a.stdin_fd) }?,
            // SAFETY: as above.
            stdout: unsafe { borrowed(a.stdout_fd) }?,
            // SAFETY: as above.
            stderr: unsafe { borrowed(a.stderr_fd) }?,
            memory_max_kib: a.memory_max_kib,
            pids_max: a.pids_max,
            stop_mode,
            stop_grace_ms: a.stop_grace_ms,
            wait_ready: flag(a.wait_ready)?,
        };
        let wait = Duration::from_millis(u64::from(wait_ms));
        let b = cl
            .client()?
            .begin_run_bytes(name, request, &args, pidfd, wait)?;
        // SAFETY: `out` is non-null and, by the contract, writable.
        unsafe { begun(cl, b, out) };
        Ok(())
    };
    // SAFETY: the contract of `run` is this function's.
    unsafe { run(c, body) }
}

/// Reads how the launch or run this client began ends. The call uses up the begun id whether it
/// succeeds or fails: a second call is `QINIT_E_ARGUMENT`, as is a call when none was begun.
///
/// # Safety
/// `c` is NULL or a live client; `out` NULL or writable for a `qinit_finish`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_launch_finish(
    c: *mut qinit_client,
    out: *mut qinit_finish,
) -> c_int {
    let body = |cl: &mut qinit_client| -> Result<(), Fail> {
        let out = self::out(out)?;
        cl.client()?;
        let id = cl.began.take().ok_or(Fail::ARGUMENT)?;
        let v = match cl.client()?.finish(id)? {
            LaunchOutcome::Exited { status, .. } => qinit_finish {
                kind: QINIT_FINISH_EXITED,
                status,
                state: 0,
                detail: 0,
            },
            LaunchOutcome::Pending { state, .. } => qinit_finish {
                kind: QINIT_FINISH_PENDING,
                status: 0,
                state: state.state,
                detail: state.detail,
            },
            LaunchOutcome::Ready { .. } => qinit_finish {
                kind: QINIT_FINISH_READY,
                status: 0,
                state: 0,
                detail: 0,
            },
            // `finish` reads the second reply, which is never a failure to start.
            LaunchOutcome::Failed { .. } => return Err(Fail::UNEXPECTED),
        };
        // SAFETY: `out` is non-null and, by the contract, writable.
        unsafe { put(out, v) };
        Ok(())
    };
    // SAFETY: the contract of `run` is this function's.
    unsafe { run(c, body) }
}

/// The exit status of the process behind `pidfd` (borrowed) once its parent reaped it:
/// `QINIT_PIDFD_EXITED` with `*status`, `QINIT_PIDFD_RUNNING`, or `QINIT_PIDFD_UNSUPPORTED`
/// (before Linux 6.15). It fails with `-QINIT_E_ARGUMENT` for a NULL `status` or a negative
/// `pidfd`, and with `-QINIT_E_ERRNO`, the errno in `*status`.
///
/// # Safety
/// `pidfd` is an open descriptor; `status` NULL or writable for an `int32_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_pidfd_exit(pidfd: c_int, status: *mut i32) -> c_int {
    if status.is_null() || pidfd < 0 {
        return -QINIT_E_ARGUMENT;
    }
    // SAFETY: by the contract, a non-negative `pidfd` is open for the call.
    let fd = unsafe { BorrowedFd::borrow_raw(pidfd) };
    let r =
        catch_unwind(|| ::qinit_client::pidfd_exit(fd)).unwrap_or(Err(std::io::Error::other("")));
    let (rc, v) = match r {
        Ok(PidfdExit::Exited(s)) => (QINIT_PIDFD_EXITED, s),
        Ok(PidfdExit::Running) => (QINIT_PIDFD_RUNNING, 0),
        Ok(PidfdExit::Unsupported) => (QINIT_PIDFD_UNSUPPORTED, 0),
        Err(e) => match e.raw_os_error() {
            Some(errno) => (-QINIT_E_ERRNO, errno),
            None => (-QINIT_E_UNEXPECTED, 0),
        },
    };
    // SAFETY: `status` is non-null and, by the contract, writable.
    unsafe { put(status, v) };
    rc
}
