// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Spawning with `clone3`, optionally straight into a cgroup (`CLONE_INTO_CGROUP`), with a
//! pidfd back (`CLONE_PIDFD`). Between the clone and `execve` the child runs only raw system
//! calls on memory prepared before the clone: it resets its signal mask and dispositions,
//! routes the given descriptors to their target numbers, closes every other number up to the
//! highest target, marks everything above close-on-exec, and execs. An exec failure writes the
//! errno (four native-endian bytes) to the caller's close-on-exec error pipe; a successful exec
//! closes it (plan P8). No allocation and no libc locking happens in the child, so a caller
//! with threads is safe.
use crate::fd::dup_above;
use crate::{Errno, Result, check_long, cpath};
use std::ffi::{CString, OsStr};
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// `clone3` flag: a pidfd for the child in `CloneArgs::pidfd`.
pub const CLONE_PIDFD: u64 = 0x1000;
/// `clone3` flag: the child starts in the cgroup `CloneArgs::cgroup` names (a dirfd).
pub const CLONE_INTO_CGROUP: u64 = 1 << 33;
/// `close_range` flag: mark the range close-on-exec instead of closing it.
const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
/// Most routes one spawn takes.
pub const MAX_ROUTES: usize = 32;
/// Highest target number a route may name.
pub const MAX_TARGET: RawFd = 1023;

/// `struct clone_args`, `CLONE_ARGS_SIZE_VER2` (88 bytes).
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

const _: () = assert!(core::mem::size_of::<CloneArgs>() == 88);

/// The kernel's `struct sigaction` on `x86_64` for `rt_sigaction`.
#[repr(C)]
struct KernelSigaction {
    handler: usize,
    flags: u64,
    restorer: usize,
    mask: u64,
}

/// A program, its arguments, environment and descriptor routes, laid out before the clone.
/// Borrows the route sources for `'a`: they stay open until `spawn` returns.
pub struct Prepared<'a> {
    path: CString,
    _argv: Vec<CString>,
    argv_ptrs: Vec<*const libc::c_char>,
    _env: Vec<CString>,
    env_ptrs: Vec<*const libc::c_char>,
    routes: Vec<(RawFd, RawFd)>,
    /// Lowest number above every source and target, where the child parks its copies.
    park: RawFd,
    /// Highest target number, or -1 with no routes.
    top: RawFd,
    _sources: PhantomData<BorrowedFd<'a>>,
}

fn cstrings(items: &[&OsStr]) -> Result<(Vec<CString>, Vec<*const libc::c_char>)> {
    let owned: Vec<CString> = items
        .iter()
        .map(|s| CString::new(s.as_bytes()).map_err(|_| Errno(libc::EINVAL)))
        .collect::<Result<_>>()?;
    let mut ptrs: Vec<*const libc::c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    Ok((owned, ptrs))
}

impl<'a> Prepared<'a> {
    /// `EINVAL` for a NUL in any string, more than [`MAX_ROUTES`] routes, or a target that is
    /// negative, above [`MAX_TARGET`] or named twice.
    pub fn new(
        path: &Path,
        argv: &[&OsStr],
        env: &[&OsStr],
        routes: &[(BorrowedFd<'a>, RawFd)],
    ) -> Result<Prepared<'a>> {
        if routes.len() > MAX_ROUTES {
            return Err(Errno(libc::EINVAL));
        }
        let routes: Vec<(RawFd, RawFd)> = routes.iter().map(|(s, d)| (s.as_raw_fd(), *d)).collect();
        for (i, &(_, d)) in routes.iter().enumerate() {
            if !(0..=MAX_TARGET).contains(&d) || routes[..i].iter().any(|&(_, e)| e == d) {
                return Err(Errno(libc::EINVAL));
            }
        }
        let top = routes.iter().map(|&(_, d)| d).max().unwrap_or(-1);
        let park = routes
            .iter()
            .flat_map(|&(s, d)| [s, d])
            .max()
            .unwrap_or(2)
            .max(2)
            + 1;
        let (argv_owned, argv_ptrs) = cstrings(argv)?;
        let (env_owned, env_ptrs) = cstrings(env)?;
        Ok(Prepared {
            path: cpath(path)?,
            _argv: argv_owned,
            argv_ptrs,
            _env: env_owned,
            env_ptrs,
            routes,
            park,
            top,
            _sources: PhantomData,
        })
    }
}

/// Starts `p` in a new process, in cgroup `cgroup` (a cgroup2 directory fd) when given.
/// `exec_err` is the write end of a close-on-exec pipe: the caller drops its own copy after
/// this returns and reads the read end (EOF: exec succeeded; four bytes: the errno). Returns
/// the child's pid and pidfd.
pub fn spawn(
    p: &Prepared<'_>,
    cgroup: Option<BorrowedFd<'_>>,
    exec_err: BorrowedFd<'_>,
) -> Result<(libc::pid_t, OwnedFd)> {
    // The child keeps the error pipe above every target and parking floor (`park` is above
    // every target), so routing cannot overwrite it.
    let err = dup_above(exec_err, p.park + 1)?;
    let mut pidfd: libc::c_int = -1;
    let mut args = CloneArgs {
        flags: CLONE_PIDFD,
        pidfd: (&raw mut pidfd) as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default()
    };
    if let Some(cg) = cgroup {
        args.flags |= CLONE_INTO_CGROUP;
        #[allow(clippy::cast_sign_loss)] // a descriptor number is non-negative
        let n = cg.as_raw_fd() as u64;
        args.cgroup = n;
    }
    // Every signal stays blocked from before the clone until the child has reset its
    // dispositions, so no handler of this process ever runs in the child.
    let mut old: u64 = 0;
    check_long(sigprocmask(libc::SIG_SETMASK, &ALL_SIGNALS, Some(&mut old)))?;
    // SAFETY: clone3 with a valid clone_args of its size and no CLONE_VM: the child gets a copy
    // of this address space and runs `child`, which never returns.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &raw const args,
            core::mem::size_of::<CloneArgs>(),
        )
    };
    if raw == 0 {
        child(p, err.as_raw_fd());
    }
    // Read clone3's errno before the mask restore can overwrite it.
    let r = check_long(raw);
    // A restore of a mask this thread had a moment ago cannot fail.
    sigprocmask(libc::SIG_SETMASK, &old, None);
    let r = r?;
    drop(err);
    let pid = libc::pid_t::try_from(r).map_err(|_| Errno(libc::EOVERFLOW))?;
    // SAFETY: CLONE_PIDFD stored a descriptor the kernel just created for the child.
    Ok((pid, unsafe { OwnedFd::from_raw_fd(pidfd) }))
}

/// The child between clone and exec: raw system calls only.
fn child(p: &Prepared<'_>, err: RawFd) -> ! {
    default_dispositions();
    // Unblocked only now that no handler is installed (an ignored signal survives exec).
    if sigprocmask(libc::SIG_SETMASK, &0, None) < 0 {
        fail(err);
    }
    let mut parked: [RawFd; MAX_ROUTES] = [0; MAX_ROUTES];
    for (i, &(src, _)) in p.routes.iter().enumerate() {
        // SAFETY: F_DUPFD_CLOEXEC on an inherited descriptor; no memory is passed.
        let t = unsafe { libc::syscall(libc::SYS_fcntl, src, libc::F_DUPFD_CLOEXEC, p.park) };
        if t < 0 {
            fail(err);
        }
        #[allow(clippy::cast_possible_truncation)] // fcntl returned a valid RawFd
        let t = t as RawFd;
        parked[i] = t;
    }
    for (i, &(_, dst)) in p.routes.iter().enumerate() {
        // SAFETY: dup3 of a parked copy onto its target, without close-on-exec.
        if unsafe { libc::syscall(libc::SYS_dup3, parked[i], dst, 0) } < 0 {
            fail(err);
        }
    }
    for n in 0..=p.top {
        if !p.routes.iter().any(|&(_, d)| d == n) {
            // SAFETY: closing an unrouted number below the highest target; EBADF is harmless.
            unsafe { libc::syscall(libc::SYS_close, n) };
        }
    }
    #[allow(clippy::cast_sign_loss)] // top + 1 is at least 0
    let first = (p.top + 1) as libc::c_uint;
    // SAFETY: close_range takes integers; everything from `first` up becomes close-on-exec.
    if unsafe {
        libc::syscall(
            libc::SYS_close_range,
            first,
            libc::c_uint::MAX,
            CLOSE_RANGE_CLOEXEC,
        )
    } < 0
    {
        fail(err);
    }
    // SAFETY: path, argv and envp are NUL-terminated and outlive the call (prepared before the
    // clone, copied with the address space).
    unsafe {
        libc::syscall(
            libc::SYS_execve,
            p.path.as_ptr(),
            p.argv_ptrs.as_ptr(),
            p.env_ptrs.as_ptr(),
        )
    };
    fail(err)
}

/// The kernel's 64-signal set with every bit set (it never blocks SIGKILL or SIGSTOP).
const ALL_SIGNALS: u64 = u64::MAX;

/// Raw `rt_sigprocmask(how, set, old)` on the calling thread, usable in the child: the
/// syscall's return (negative with errno set on failure).
fn sigprocmask(how: libc::c_int, set: &u64, old: Option<&mut u64>) -> libc::c_long {
    let old = old.map_or(std::ptr::null_mut(), std::ptr::from_mut);
    // SAFETY: an 8-byte kernel signal set read for the call; `old` is null or a borrowed
    // 8-byte set the kernel writes.
    unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            how,
            std::ptr::from_ref(set),
            old,
            8usize,
        )
    }
}

/// Every signal at its default disposition; the caller blocks them all meanwhile.
fn default_dispositions() {
    let default = KernelSigaction {
        handler: 0,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    for sig in 1..=64 {
        if sig == libc::SIGKILL || sig == libc::SIGSTOP {
            continue;
        }
        // SAFETY: rt_sigaction with a valid kernel sigaction (SIG_DFL) and no old-action pointer.
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigaction,
                sig,
                &raw const default,
                std::ptr::null_mut::<KernelSigaction>(),
                8usize,
            )
        };
    }
}

/// Reports the current errno on the error pipe and exits 127.
fn fail(err: RawFd) -> ! {
    let bytes = Errno::last().0.to_ne_bytes();
    // SAFETY: four readable bytes; a failed write leaves only the exit status to tell.
    unsafe { libc::syscall(libc::SYS_write, err, bytes.as_ptr(), bytes.len()) };
    // SAFETY: SYS_exit terminates this single-threaded child, with no memory arguments.
    unsafe { libc::syscall(libc::SYS_exit, 127) };
    // SYS_exit never returns; do not run a destructor or panic in the child.
    loop {
        core::hint::spin_loop();
    }
}
