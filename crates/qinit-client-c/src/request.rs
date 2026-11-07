// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! The request builder: a `qinit_request` holds a launch request (`RequestSpec`) that the
//! setters fill field by field, and `qinit_request_bytes` checks and lays out for
//! `qinit_run_begin`. The check is `RequestSpec::check`, the one `qctl` makes; the fields and
//! words are those of `docs/launch-request.md`.
use crate::{QINIT_E_ARGUMENT, QINIT_E_UNEXPECTED, flag, put, text};
use ::qinit_launch::{RequestSpec, Seccomp, Securebits, Stream, UserMap};
use std::ffi::{CString, c_char, c_int};
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Seccomp modes of `qinit_request_set_seccomp`: none, the default filter, or a filter that
/// denies or allows only the syscalls `qinit_request_add_syscall` lists.
pub const QINIT_SECCOMP_NONE: u32 = 0;
pub const QINIT_SECCOMP_DEFAULT: u32 = 1;
pub const QINIT_SECCOMP_DENY: u32 = 2;
pub const QINIT_SECCOMP_ALLOW: u32 = 3;

/// Securebits of `qinit_request_set_securebits`.
pub const QINIT_SECUREBITS_NONE: u32 = 0;
pub const QINIT_SECUREBITS_NOROOT: u32 = 1;
pub const QINIT_SECUREBITS_NOROOT_LOCKED: u32 = 2;

/// User maps of `qinit_request_set_user_map`: the service's own ids, or its subordinate range
/// too (only with `QINIT_NS_USER`).
pub const QINIT_USER_MAP_OWN: u32 = 0;
pub const QINIT_USER_MAP_RANGE: u32 = 1;

/// Namespace bits of `qinit_request_set_namespaces`.
pub const QINIT_NS_MOUNT: u32 = 1;
pub const QINIT_NS_PID: u32 = 2;
pub const QINIT_NS_IPC: u32 = 4;
pub const QINIT_NS_UTS: u32 = 8;
pub const QINIT_NS_NET: u32 = 16;
pub const QINIT_NS_USER: u32 = 32;

/// A launch request under construction, opaque to C. `qinit_request_new` makes one and
/// `qinit_request_free` frees it; the strings a setter takes are copied, and the bytes and the
/// reason it hands out are its own.
#[allow(non_camel_case_types)] // the C name
pub struct qinit_request {
    /// What the setters set.
    fields: Fields,
    /// The bytes of the last `qinit_request_bytes`, until the next call.
    bytes: Vec<u8>,
    /// Why the last call failed; empty when it succeeded.
    error: CString,
}

/// The fields of a request as the setters leave them.
#[derive(Clone)]
struct Fields {
    /// Every field but `seccomp`, which `qinit_request_bytes` makes from the next two.
    spec: RequestSpec,
    /// `QINIT_SECCOMP_*`.
    seccomp: u32,
    syscalls: Vec<u32>,
}

/// A refused call: the kind it returns and the reason `qinit_request_error` gives.
struct Refused(c_int, String);

/// A bad argument, with its reason.
fn refused(why: impl Into<String>) -> Refused {
    Refused(QINIT_E_ARGUMENT, why.into())
}

/// Runs the setter `f` on a copy of the fields of the request behind `r`, through [`call`], and
/// keeps the copy only when `f` succeeds: a refusal or a panic part way leaves the fields as
/// they were.
///
/// # Safety
/// As [`call`].
unsafe fn on(r: *mut qinit_request, f: impl FnOnce(&mut Fields) -> Result<(), Refused>) -> c_int {
    let step = |req: &mut qinit_request| {
        let mut draft = req.fields.clone();
        f(&mut draft)?;
        req.fields = draft;
        Ok(())
    };
    // SAFETY: the contract of `call` is this function's.
    unsafe { call(r, step) }
}

/// Runs `f` on the request behind `r` with panics caught, after dropping the bytes of the last
/// `qinit_request_bytes`, and keeps its reason (or none). Returns 0 or the failure's kind; a NULL
/// `r` is `QINIT_E_ARGUMENT`.
///
/// # Safety
/// `r` is null or a live request from `qinit_request_new` that no other thread uses during the
/// call.
unsafe fn call(
    r: *mut qinit_request,
    f: impl FnOnce(&mut qinit_request) -> Result<(), Refused>,
) -> c_int {
    // SAFETY: by the contract, `r` is null or a live, exclusively used request.
    let Some(req) = (unsafe { r.as_mut() }) else {
        return QINIT_E_ARGUMENT;
    };
    req.bytes = Vec::new();
    let result = catch_unwind(AssertUnwindSafe(|| f(&mut *req)))
        .unwrap_or_else(|_| Err(Refused(QINIT_E_UNEXPECTED, "a panic in the builder".into())));
    let (rc, why) = match result {
        Ok(()) => (0, String::new()),
        Err(Refused(kind, why)) => (kind, why),
    };
    // The reasons come from C strings and fixed words, so they hold no NUL.
    req.error = CString::new(why).unwrap_or_default();
    rc
}

/// The string at `p` for the field `what`: 1 byte or more of UTF-8.
///
/// # Safety
/// `p` is null or a NUL-terminated string valid for the call.
unsafe fn owned(p: *const c_char, what: &str) -> Result<String, Refused> {
    // SAFETY: by the contract, `p` is null or a NUL-terminated string.
    unsafe { text(p, u32::MAX) }
        .map(str::to_owned)
        .map_err(|_| refused(format!("{what}: NULL, empty or not UTF-8")))
}

/// A C boolean for the field `what`.
fn boolean(v: c_int, what: &str) -> Result<bool, Refused> {
    flag(v).map_err(|_| refused(format!("{what}: {v} is not 0 or 1")))
}

/// `v` is not one of the `words` of the field `what`.
fn word(what: &str, v: u32, words: &str) -> Refused {
    refused(format!("{what}: {v} is not a {words} word"))
}

/// The seccomp policy from its mode and list.
fn seccomp(mode: u32, list: &[u32]) -> Result<Seccomp, Refused> {
    match mode {
        QINIT_SECCOMP_NONE | QINIT_SECCOMP_DEFAULT if !list.is_empty() => Err(refused(
            "syscalls: only a deny or allow seccomp filter takes a list",
        )),
        QINIT_SECCOMP_NONE => Ok(Seccomp::None),
        QINIT_SECCOMP_DEFAULT => Ok(Seccomp::Default),
        QINIT_SECCOMP_DENY => Ok(Seccomp::Deny(list.to_vec())),
        _ => Ok(Seccomp::Allow(list.to_vec())),
    }
}

/// A new request with the defaults of `docs/launch-request.md`: no argv, environment or paths,
/// `cwd` `/`, `umask` 0o027, no resource limits, no user, no capabilities, securebits none,
/// `no_new_privs` on, no namespaces, the own user map, inside ids 0, seccomp none, standard
/// input and output `/dev/null`, standard error the same as standard output, no readiness
/// pipe, `die_with_parent` off, and a deadline of 30000 ms. A request needs at least one argv
/// element and a user. The caller frees it with `qinit_request_free`; NULL only when it could
/// not be made.
///
/// # Safety
/// None: it reads nothing. It is `unsafe` as every exported function is.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_new() -> *mut qinit_request {
    catch_unwind(|| {
        Box::into_raw(Box::new(qinit_request {
            fields: Fields {
                spec: RequestSpec::default(),
                seccomp: QINIT_SECCOMP_NONE,
                syscalls: Vec::new(),
            },
            bytes: Vec::new(),
            error: CString::default(),
        }))
    })
    .unwrap_or(std::ptr::null_mut())
}

/// Frees the request, with its bytes and its reason; NULL is ignored.
///
/// # Safety
/// `r` is NULL or a request from `qinit_request_new` not yet freed and not in use.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_free(r: *mut qinit_request) {
    // No `catch_unwind` here: nothing below can panic. The request holds only strings,
    // vectors and a `CString`, whose drops free memory and do nothing else.
    if !r.is_null() {
        // SAFETY: by the contract, `r` came from `Box::into_raw` in `qinit_request_new` and is
        // freed once.
        drop(unsafe { Box::from_raw(r) });
    }
}

/// Why the last call on `r` failed, NUL-terminated: the field and what is wrong with it (for
/// `qinit_request_bytes`, the words `qctl` uses). Empty when it succeeded, and for a NULL `r`.
/// The text is the request's, valid until the next call on it other than this one.
///
/// # Safety
/// `r` is NULL or a live request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_error(r: *const qinit_request) -> *const c_char {
    // No `catch_unwind` here: a null check and a pointer read cannot panic.
    // SAFETY: by the contract, `r` is null or a live request.
    match unsafe { r.as_ref() } {
        Some(req) => req.error.as_ptr(),
        None => c"".as_ptr(),
    }
}

/// Checks the request and lays it out: on success `*ptr` and `*len` give its bytes (QLR1) for
/// `qinit_run_args.request`. The bytes are the request's, valid until the next call on it
/// other than `qinit_request_error`, or until it is freed. The check is the one `qctl` makes
/// (`cwd` absolute, `deadline_ms` at least 1, `umask` at most 0o777, a deny or allow filter
/// with at least one syscall, at most `QINIT_REQUEST_MAX` bytes), and also refuses syscalls
/// listed with seccomp none or default. A request that fails it is `QINIT_E_ARGUMENT`, with
/// `*ptr` NULL, `*len` 0 and the reason in `qinit_request_error`; nothing else is checked here,
/// so colony may still refuse the request (`QINIT_E_SERVER` from `qinit_run_begin`).
///
/// `ptr` and `len` must both be non-NULL: a NULL one is `QINIT_E_ARGUMENT` (reason `ptr: NULL`
/// or `len: NULL`), and then nothing is written through the other.
///
/// # Safety
/// `r` is NULL or a live request; `ptr` NULL or writable for a pointer; `len` NULL or writable
/// for a `size_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_bytes(
    r: *mut qinit_request,
    ptr: *mut *const u8,
    len: *mut usize,
) -> c_int {
    let body = |req: &mut qinit_request| -> Result<(), Refused> {
        if ptr.is_null() {
            return Err(refused("ptr: NULL"));
        }
        if len.is_null() {
            return Err(refused("len: NULL"));
        }
        let fields = &req.fields;
        let checked = seccomp(fields.seccomp, &fields.syscalls).and_then(|s| {
            let spec = RequestSpec {
                seccomp: s,
                ..fields.spec.clone()
            };
            spec.check().map_err(|e| refused(e.to_string()))
        });
        let (p, n, result) = match checked {
            Ok(bytes) => {
                req.bytes = bytes;
                (req.bytes.as_ptr(), req.bytes.len(), Ok(()))
            }
            Err(e) => (std::ptr::null(), 0, Err(e)),
        };
        // SAFETY: `ptr` is non-null and, by the contract, writable for a pointer.
        unsafe { put(ptr, p) };
        // SAFETY: `len` is non-null and, by the contract, writable for a `size_t`.
        unsafe { put(len, n) };
        result
    };
    // SAFETY: the contract of `call` is this function's.
    unsafe { call(r, body) }
}

/// Runs `set` with the string at `s` for the field `what`, through [`on`].
///
/// # Safety
/// As [`on`], and `s` is null or a NUL-terminated string valid for the call.
unsafe fn set_string(
    r: *mut qinit_request,
    s: *const c_char,
    what: &str,
    set: impl FnOnce(&mut Fields, String),
) -> c_int {
    let body = |req: &mut Fields| -> Result<(), Refused> {
        // SAFETY: by the contract, `s` is null or a NUL-terminated string.
        let v = unsafe { owned(s, what) }?;
        set(req, v);
        Ok(())
    };
    // SAFETY: the contract of `on` is this function's.
    unsafe { on(r, body) }
}

/// Appends an argv element; the first is the program.
///
/// # Safety
/// `r` is NULL or a live request; `arg` NULL or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_add_arg(r: *mut qinit_request, arg: *const c_char) -> c_int {
    // SAFETY: the contract of `set_string` is this function's.
    unsafe { set_string(r, arg, "arg", |req, v| req.spec.argv.push(v)) }
}

/// Appends an environment entry, `KEY=value`.
///
/// # Safety
/// `r` is NULL or a live request; `entry` NULL or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_add_env(
    r: *mut qinit_request,
    entry: *const c_char,
) -> c_int {
    // SAFETY: the contract of `set_string` is this function's.
    unsafe { set_string(r, entry, "env", |req, v| req.spec.env.push(v)) }
}

/// Appends an entry of the service's view (`ro:/usr`, `rw:/var/lib/x`, ...).
///
/// # Safety
/// `r` is NULL or a live request; `entry` NULL or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_add_path(
    r: *mut qinit_request,
    entry: *const c_char,
) -> c_int {
    // SAFETY: the contract of `set_string` is this function's.
    unsafe { set_string(r, entry, "path", |req, v| req.spec.paths.push(v)) }
}

/// Appends a syscall, by number, to the list of a `QINIT_SECCOMP_DENY` or
/// `QINIT_SECCOMP_ALLOW` filter.
///
/// # Safety
/// `r` is NULL or a live request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_add_syscall(r: *mut qinit_request, nr: u32) -> c_int {
    // SAFETY: the contract of `on` is this function's.
    unsafe {
        on(r, |req| {
            req.syscalls.push(nr);
            Ok(())
        })
    }
}

/// Sets the working directory, an absolute path.
///
/// # Safety
/// `r` is NULL or a live request; `path` NULL or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_set_cwd(
    r: *mut qinit_request,
    path: *const c_char,
) -> c_int {
    // SAFETY: the contract of `set_string` is this function's.
    unsafe { set_string(r, path, "cwd", |req, v| req.spec.cwd = v) }
}

/// Sets the umask, at most 0o777.
///
/// # Safety
/// `r` is NULL or a live request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_set_umask(r: *mut qinit_request, umask: u32) -> c_int {
    // SAFETY: the contract of `on` is this function's.
    unsafe {
        on(r, |req| {
            req.spec.umask = umask;
            Ok(())
        })
    }
}

/// Sets resource limit `resource` (the kernel's number, 0 to 15: `RLIMIT_*`) to `value`, soft
/// and hard; `UINT64_MAX` is infinity.
///
/// # Safety
/// `r` is NULL or a live request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_set_rlimit(
    r: *mut qinit_request,
    resource: u32,
    value: u64,
) -> c_int {
    let body = |req: &mut Fields| -> Result<(), Refused> {
        let slot = usize::try_from(resource)
            .ok()
            .and_then(|i| req.spec.rlimits.get_mut(i))
            .ok_or_else(|| refused(format!("rlimit: resource {resource} is not 0 to 15")))?;
        *slot = Some(value);
        Ok(())
    };
    // SAFETY: the contract of `on` is this function's.
    unsafe { on(r, body) }
}

/// Sets the user the service runs as, a name or a number.
///
/// # Safety
/// `r` is NULL or a live request; `user` NULL or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_set_user(
    r: *mut qinit_request,
    user: *const c_char,
) -> c_int {
    // SAFETY: the contract of `set_string` is this function's.
    unsafe { set_string(r, user, "user", |req, v| req.spec.user = v) }
}

/// Sets the capabilities to keep, bit `n` for capability number `n`.
///
/// # Safety
/// `r` is NULL or a live request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_set_caps(r: *mut qinit_request, caps: u64) -> c_int {
    // SAFETY: the contract of `on` is this function's.
    unsafe {
        on(r, |req| {
            req.spec.caps = caps;
            Ok(())
        })
    }
}

/// Sets the securebits, a `QINIT_SECUREBITS_*`.
///
/// # Safety
/// `r` is NULL or a live request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_set_securebits(r: *mut qinit_request, bits: u32) -> c_int {
    // SAFETY: the contract of `on` is this function's.
    unsafe {
        on(r, |req| {
            req.spec.securebits = match bits {
                QINIT_SECUREBITS_NONE => Securebits::None,
                QINIT_SECUREBITS_NOROOT => Securebits::Noroot,
                QINIT_SECUREBITS_NOROOT_LOCKED => Securebits::NorootLocked,
                _ => return Err(word("securebits", bits, "QINIT_SECUREBITS_*")),
            };
            Ok(())
        })
    }
}

/// Sets `no_new_privs`, 0 or 1.
///
/// # Safety
/// `r` is NULL or a live request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_set_nnp(r: *mut qinit_request, enabled: c_int) -> c_int {
    // SAFETY: the contract of `on` is this function's.
    unsafe {
        on(r, |req| {
            req.spec.nnp = boolean(enabled, "nnp")?;
            Ok(())
        })
    }
}

/// Sets the namespaces, an or of `QINIT_NS_*`.
///
/// # Safety
/// `r` is NULL or a live request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_set_namespaces(r: *mut qinit_request, ns: u32) -> c_int {
    // SAFETY: the contract of `on` is this function's.
    unsafe {
        on(r, |req| {
            req.spec.ns = ns;
            Ok(())
        })
    }
}

/// Sets the user map, a `QINIT_USER_MAP_*`.
///
/// # Safety
/// `r` is NULL or a live request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_set_user_map(r: *mut qinit_request, map: u32) -> c_int {
    // SAFETY: the contract of `on` is this function's.
    unsafe {
        on(r, |req| {
            req.spec.user_map = match map {
                QINIT_USER_MAP_OWN => UserMap::Own,
                QINIT_USER_MAP_RANGE => UserMap::Range,
                _ => return Err(word("user_map", map, "QINIT_USER_MAP_*")),
            };
            Ok(())
        })
    }
}

/// Sets the ids the service runs as inside its user namespace (non-zero only with
/// `QINIT_NS_USER`, at most 4294967294).
///
/// # Safety
/// `r` is NULL or a live request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_set_inside_ids(
    r: *mut qinit_request,
    uid: u32,
    gid: u32,
) -> c_int {
    // SAFETY: the contract of `on` is this function's.
    unsafe {
        on(r, |req| {
            (req.spec.inside_uid, req.spec.inside_gid) = (uid, gid);
            Ok(())
        })
    }
}

/// Sets the seccomp mode, a `QINIT_SECCOMP_*`; the list is `qinit_request_add_syscall`'s.
///
/// # Safety
/// `r` is NULL or a live request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_set_seccomp(r: *mut qinit_request, mode: u32) -> c_int {
    // SAFETY: the contract of `on` is this function's.
    unsafe {
        on(r, |req| {
            if mode > QINIT_SECCOMP_ALLOW {
                return Err(word("seccomp", mode, "QINIT_SECCOMP_*"));
            }
            req.seccomp = mode;
            Ok(())
        })
    }
}

/// Standard input from a path, opened by its file type.
///
/// # Safety
/// `r` is NULL or a live request; `path` NULL or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_set_stdin_path(
    r: *mut qinit_request,
    path: *const c_char,
) -> c_int {
    // SAFETY: the contract of `set_string` is this function's.
    unsafe { set_string(r, path, "stdin", |req, v| req.spec.stdin = Stream::Path(v)) }
}

/// Standard input from routed descriptor `n`. Under `qinit_run_begin` a stream sent as a
/// descriptor arrives by its role, standard input as 5 (`docs/control-protocol.md`, `Run`).
///
/// # Safety
/// `r` is NULL or a live request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_set_stdin_fd(r: *mut qinit_request, n: u32) -> c_int {
    // SAFETY: the contract of `on` is this function's.
    unsafe {
        on(r, |req| {
            req.spec.stdin = Stream::Fd(n);
            Ok(())
        })
    }
}

/// Standard output to a path, opened by its file type.
///
/// # Safety
/// `r` is NULL or a live request; `path` NULL or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_set_stdout_path(
    r: *mut qinit_request,
    path: *const c_char,
) -> c_int {
    // SAFETY: the contract of `set_string` is this function's.
    unsafe {
        set_string(r, path, "stdout", |req, v| {
            req.spec.stdout = Stream::Path(v);
        })
    }
}

/// Standard output to routed descriptor `n`; under `qinit_run_begin`, 6.
///
/// # Safety
/// `r` is NULL or a live request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_set_stdout_fd(r: *mut qinit_request, n: u32) -> c_int {
    // SAFETY: the contract of `on` is this function's.
    unsafe {
        on(r, |req| {
            req.spec.stdout = Stream::Fd(n);
            Ok(())
        })
    }
}

/// Standard error to a path, opened by its file type.
///
/// # Safety
/// `r` is NULL or a live request; `path` NULL or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_set_stderr_path(
    r: *mut qinit_request,
    path: *const c_char,
) -> c_int {
    // SAFETY: the contract of `set_string` is this function's.
    unsafe {
        set_string(r, path, "stderr", |req, v| {
            req.spec.stderr = Stream::Path(v);
        })
    }
}

/// Standard error to routed descriptor `n`; under `qinit_run_begin`, 7.
///
/// # Safety
/// `r` is NULL or a live request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_set_stderr_fd(r: *mut qinit_request, n: u32) -> c_int {
    // SAFETY: the contract of `on` is this function's.
    unsafe {
        on(r, |req| {
            req.spec.stderr = Stream::Fd(n);
            Ok(())
        })
    }
}

/// Standard error to wherever standard output goes (the default).
///
/// # Safety
/// `r` is NULL or a live request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_set_stderr_same(r: *mut qinit_request) -> c_int {
    // SAFETY: the contract of `on` is this function's.
    unsafe {
        on(r, |req| {
            req.spec.stderr = Stream::Same;
            Ok(())
        })
    }
}

/// Routes a readiness pipe to descriptor `fd`, or none with -1 (the default). It is a routed
/// number from 5 to 37 that no stream uses; under `qinit_run_begin`, whose streams take 5 to 7,
/// 8 is free, and the pipe needs `wait_ready` (`docs/control-protocol.md`, `Run`).
///
/// # Safety
/// `r` is NULL or a live request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_set_ready_fd(r: *mut qinit_request, fd: c_int) -> c_int {
    let body = |req: &mut Fields| -> Result<(), Refused> {
        req.spec.ready_fd = match fd {
            -1 => None,
            n => Some(
                u32::try_from(n)
                    .map_err(|_| refused(format!("ready_fd: {n} is not -1 or a descriptor")))?,
            ),
        };
        Ok(())
    };
    // SAFETY: the contract of `on` is this function's.
    unsafe { on(r, body) }
}

/// Sets `die_with_parent`, 0 or 1: the service gets `SIGKILL` when its parent thread exits.
///
/// # Safety
/// `r` is NULL or a live request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_set_die_with_parent(
    r: *mut qinit_request,
    enabled: c_int,
) -> c_int {
    // SAFETY: the contract of `on` is this function's.
    unsafe {
        on(r, |req| {
            req.spec.die_with_parent = boolean(enabled, "die_with_parent")?;
            Ok(())
        })
    }
}

/// Sets the deadline of the launch in milliseconds, at least 1.
///
/// # Safety
/// `r` is NULL or a live request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_request_set_deadline_ms(r: *mut qinit_request, ms: u32) -> c_int {
    // SAFETY: the contract of `on` is this function's.
    unsafe {
        on(r, |req| {
            req.spec.deadline_ms = ms;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The working directory of the live request `r`.
    fn cwd(r: *mut qinit_request) -> String {
        // SAFETY: the tests pass only a live request used by this thread.
        unsafe { &*r }.fields.spec.cwd.clone()
    }

    #[test]
    fn a_setter_that_fails_part_way_changes_nothing() {
        // SAFETY: it reads nothing.
        let r = unsafe { qinit_request_new() };
        // SAFETY: `r` is a live request used by this thread only.
        let rc = unsafe {
            on(r, |req| {
                req.spec.cwd = "/half".into();
                panic!("part way")
            })
        };
        assert_eq!(rc, QINIT_E_UNEXPECTED);
        assert_eq!(cwd(r), "/", "a panic part way left the request changed");
        // SAFETY: as above.
        let rc = unsafe {
            on(r, |req| {
                req.spec.cwd = "/half".into();
                Err(refused("refused after a change"))
            })
        };
        assert_eq!(rc, QINIT_E_ARGUMENT);
        assert_eq!(cwd(r), "/", "a refusal part way left the request changed");
        // SAFETY: `r` came from `qinit_request_new` and is freed once.
        unsafe { qinit_request_free(r) };
    }
}
