// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0

//! The exit status of a launched process from its pidfd (`PIDFD_INFO_EXIT`, Linux 6.15). It lives
//! here, not in `qinit-sys`, because the MPL client library hands the pidfd out and cannot depend
//! on the GPL crate; `qinit-sys::proc` re-exports it.
use crate::{Errno, Result, check};
use std::os::fd::{AsFd, AsRawFd};

/// What a pidfd says about its process's exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidfdExit {
    /// No status yet: the process runs, or it has exited and its parent has not reaped it (the
    /// kernel records the status at the reap).
    Running,
    /// It exited and was reaped, with this wait status (`WIFEXITED`/`WIFSIGNALED` decode it).
    Exited(i32),
    /// The kernel does not report an exit status through a pidfd (before Linux 6.15).
    Unsupported,
}

/// `struct pidfd_info`, `PIDFD_INFO_SIZE_VER3` (88 bytes): a kernel that knows less copies out
/// less, and the mask it returns says which fields are valid.
#[allow(dead_code)] // the kernel's layout: every field is part of the ABI
#[repr(C)]
#[derive(Default)]
struct PidfdInfo {
    mask: u64,
    cgroupid: u64,
    pid: u32,
    tgid: u32,
    ppid: u32,
    ruid: u32,
    rgid: u32,
    euid: u32,
    egid: u32,
    suid: u32,
    sgid: u32,
    fsuid: u32,
    fsgid: u32,
    exit_code: i32,
    coredump_mask: u32,
    coredump_signal: u32,
    coredump_code: u32,
    coredump_pad: u32,
    supported_mask: u64,
}

const _: () = assert!(core::mem::size_of::<PidfdInfo>() == 88);

const PIDFD_INFO_EXIT: u64 = 1 << 3;
const PIDFD_INFO_SUPPORTED_MASK: u64 = 1 << 5;
/// `_IOWR(PIDFS_IOCTL_MAGIC = 0xFF, 11, struct pidfd_info)` with the 88-byte struct.
const PIDFD_GET_INFO: u32 = 0xC058_FF0B;

/// `ioctl`'s request argument: `unsigned long` in glibc, `int` in musl.
#[cfg(target_env = "musl")]
type Request = libc::c_int;
#[cfg(not(target_env = "musl"))]
type Request = libc::c_ulong;

/// The pure part of [`pidfd_exit`]. `supported`: the kernel can report exit statuses. `outcome`:
/// the `PIDFD_GET_INFO` result, the exit code when the kernel returned `PIDFD_INFO_EXIT`. A
/// kernel that refuses the ioctl is `Unsupported` too; every other failure is an error.
pub fn decide_exit(supported: bool, outcome: Result<Option<i32>>) -> Result<PidfdExit> {
    match (supported, outcome) {
        (_, Ok(Some(status))) => Ok(PidfdExit::Exited(status)),
        (true, Ok(None)) => Ok(PidfdExit::Running),
        (false, Ok(None)) => Ok(PidfdExit::Unsupported),
        // An unknown request, or (before 6.15, when the ioctl only knew live tasks) a reaped
        // process: not a failure of the caller.
        (_, Err(Errno(libc::EINVAL | libc::ENOTTY))) | (false, Err(Errno(libc::ESRCH))) => {
            Ok(PidfdExit::Unsupported)
        }
        (_, Err(e)) => Err(e),
    }
}

/// Whether the running kernel is at least `major.minor`.
fn kernel_at_least(major: u32, minor: u32) -> bool {
    // SAFETY: utsname is a plain C struct; zeroed is a valid starting value.
    let mut u: libc::utsname = unsafe { core::mem::zeroed() };
    // SAFETY: a writable utsname.
    if unsafe { libc::uname(&raw mut u) } < 0 {
        return false;
    }
    #[allow(clippy::cast_sign_loss)] // c_char to byte
    let release: Vec<u8> = u
        .release
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    let mut nums = release
        .split(|c| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).parse::<u32>().unwrap_or(0));
    (nums.next().unwrap_or(0), nums.next().unwrap_or(0)) >= (major, minor)
}

/// The exit status of the process behind `pidfd` (`PIDFD_GET_INFO` with `PIDFD_INFO_EXIT`,
/// Linux 6.15). The kernel records it when the parent reaps the process and keeps it as long as
/// the pidfd is open. `Unsupported` on a kernel without it, never an error.
pub fn pidfd_exit(pidfd: impl AsFd) -> Result<PidfdExit> {
    let mut info = PidfdInfo {
        mask: PIDFD_INFO_EXIT | PIDFD_INFO_SUPPORTED_MASK,
        ..PidfdInfo::default()
    };
    #[allow(clippy::cast_possible_wrap, clippy::cast_lossless)] // same bits, each libc's type
    let request = PIDFD_GET_INFO as Request;
    // SAFETY: the ioctl fills a pidfd_info of the size its request number encodes.
    let got = check(unsafe { libc::ioctl(pidfd.as_fd().as_raw_fd(), request, &raw mut info) })
        .map(|_| (info.mask & PIDFD_INFO_EXIT != 0).then_some(info.exit_code));
    // Newer kernels say what they support; the others are told apart by their version.
    let supported = if info.mask & PIDFD_INFO_SUPPORTED_MASK != 0 {
        info.supported_mask & PIDFD_INFO_EXIT != 0
    } else {
        kernel_at_least(6, 15)
    };
    decide_exit(supported, got)
}
