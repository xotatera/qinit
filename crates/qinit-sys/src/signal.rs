// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Signal masks of the calling thread.
use crate::{Errno, Result, check};
use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::atomic::{AtomicI32, Ordering};

fn empty_set() -> libc::sigset_t {
    let mut s = MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: sigemptyset initialises the set it is given.
    unsafe { libc::sigemptyset(s.as_mut_ptr()) };
    // SAFETY: initialised by sigemptyset above.
    unsafe { s.assume_init() }
}

pub(crate) fn set_of(sigs: &[libc::c_int]) -> Result<libc::sigset_t> {
    let mut s = empty_set();
    for &sig in sigs {
        // SAFETY: `s` is an initialised set.
        check(unsafe { libc::sigaddset(&raw mut s, sig) })?;
    }
    Ok(s)
}

/// Blocks `sigs` in the calling thread.
pub fn block_in_thread(sigs: &[libc::c_int]) -> Result<()> {
    let set = set_of(sigs)?;
    // SAFETY: `set` is initialised; the old mask is not requested.
    match unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut()) } {
        0 => Ok(()),
        e => Err(Errno(e)),
    }
}

/// Unblocks every signal in the calling thread.
pub fn unblock_all() -> Result<()> {
    let empty = empty_set();
    // SAFETY: `empty` is initialised; the old mask is not requested.
    match unsafe {
        libc::pthread_sigmask(libc::SIG_SETMASK, &raw const empty, std::ptr::null_mut())
    } {
        0 => Ok(()),
        e => Err(Errno(e)),
    }
}

/// The signals a fault raises. They stay unblocked, so a synchronous fault is delivered to the
/// parking handler and never kills the process by default.
pub const FATAL: [libc::c_int; 5] = [
    libc::SIGSEGV,
    libc::SIGBUS,
    libc::SIGILL,
    libc::SIGFPE,
    libc::SIGABRT,
];

/// Blocks every signal except [`FATAL`] in the calling thread.
pub fn block_all_but_fatal() -> Result<()> {
    let mut set = MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: sigfillset initialises the set it is given.
    unsafe { libc::sigfillset(set.as_mut_ptr()) };
    // SAFETY: initialised by sigfillset above.
    let mut set = unsafe { set.assume_init() };
    for sig in FATAL {
        // SAFETY: `set` is an initialised set.
        check(unsafe { libc::sigdelset(&raw mut set, sig) })?;
    }
    // SAFETY: `set` is initialised; the old mask is not requested.
    match unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &raw const set, std::ptr::null_mut()) }
    {
        0 => Ok(()),
        e => Err(Errno(e)),
    }
}

/// The descriptor the parking handler writes its line to (-1: none).
static PARK_FD: AtomicI32 = AtomicI32::new(-1);

/// Names the descriptor [`park`] and the fault handler write to. The caller keeps it open
/// for the life of the process.
pub fn set_park_fd(fd: BorrowedFd<'_>) {
    PARK_FD.store(fd.as_raw_fd(), Ordering::Relaxed);
}

const ALT_STACK_LEN: usize = 64 * 1024;

/// The stack the fault handler runs on, so a stack overflow can be handled.
struct AltStack(UnsafeCell<[u8; ALT_STACK_LEN]>);

// SAFETY: the kernel is the only user of the buffer, and only for the thread that installed it.
unsafe impl Sync for AltStack {}

static ALT_STACK: AltStack = AltStack(UnsafeCell::new([0; ALT_STACK_LEN]));

const FATAL_LINE: &[u8] = b"<2>queen: fatal signal\n";

fn write_line(line: &[u8]) {
    let fd = PARK_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        // SAFETY: a readable buffer of `line.len()` bytes; a failed write is all there is to tell.
        unsafe { libc::write(fd, line.as_ptr().cast(), line.len()) };
    }
}

extern "C" fn on_fatal(_sig: libc::c_int) {
    write_line(FATAL_LINE);
    loop {
        // SAFETY: pause takes no arguments; every other signal is blocked by `sa_mask`.
        unsafe { libc::pause() };
    }
}

/// Installs the parking handler for [`FATAL`] on an alternate stack of the calling thread: it
/// writes one line to the park descriptor and then sleeps for good. A fault inside the
/// handler repeats it (`SA_NODEFER`), which parks again.
pub fn install_fault_park() -> Result<()> {
    let stack = libc::stack_t {
        ss_sp: ALT_STACK.0.get().cast(),
        ss_flags: 0,
        ss_size: ALT_STACK_LEN,
    };
    // SAFETY: a valid alternate stack that lives for the whole process; no old stack requested.
    check(unsafe { libc::sigaltstack(&raw const stack, std::ptr::null_mut()) })?;
    // SAFETY: an all-zero sigaction is a valid starting value.
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = on_fatal as extern "C" fn(libc::c_int) as usize;
    act.sa_flags = libc::SA_ONSTACK | libc::SA_NODEFER;
    // SAFETY: `act.sa_mask` is a valid set to fill.
    unsafe { libc::sigfillset(&raw mut act.sa_mask) };
    for sig in FATAL {
        // SAFETY: a valid sigaction with a handler that only calls write and pause.
        check(unsafe { libc::sigaction(sig, &raw const act, std::ptr::null_mut()) })?;
    }
    Ok(())
}

/// Blocks every signal, writes `line` to the park descriptor and sleeps for good.
pub fn park(line: &[u8]) -> ! {
    let mut set = MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: sigfillset initialises the set it is given.
    unsafe { libc::sigfillset(set.as_mut_ptr()) };
    // SAFETY: initialised by sigfillset above.
    let set = unsafe { set.assume_init() };
    // SAFETY: `set` is initialised; the old mask is not requested.
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &raw const set, std::ptr::null_mut()) };
    write_line(line);
    loop {
        // SAFETY: pause takes no arguments.
        unsafe { libc::pause() };
    }
}
