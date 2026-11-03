// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Installing a classic-BPF seccomp filter.
use crate::{Errno, Result, check_long};

/// `struct sock_filter`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// `struct sock_fprog`.
#[repr(C)]
struct Fprog {
    len: libc::c_ushort,
    filter: *const Insn,
}

/// `seccomp(SECCOMP_SET_MODE_FILTER, 0, prog)` (`linux/seccomp.h`).
const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
/// Most instructions one filter may hold (`BPF_MAXINSNS`).
const BPF_MAXINSNS: usize = 4096;

/// Installs `program` as this thread's seccomp filter; needs `no_new_privs` or `CAP_SYS_ADMIN`.
pub fn install(program: &[Insn]) -> Result<()> {
    if program.is_empty() || program.len() > BPF_MAXINSNS {
        return Err(Errno(libc::EINVAL));
    }
    let prog = Fprog {
        #[allow(clippy::cast_possible_truncation)] // bounded by BPF_MAXINSNS above
        len: program.len() as libc::c_ushort,
        filter: program.as_ptr(),
    };
    // SAFETY: a readable fprog pointing at `program`, which outlives the call.
    check_long(unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0u32,
            &raw const prog,
        )
    })?;
    Ok(())
}
