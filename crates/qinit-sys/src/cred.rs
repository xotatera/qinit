// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Identity and privilege: groups, ids, securebits, capabilities, `prctl` flags.
use crate::{Result, check, check_long};

/// `SECBIT_NOROOT`: root gets no capabilities from being root.
pub const SECBIT_NOROOT: u32 = 1;
/// `SECBIT_NOROOT_LOCKED`.
pub const SECBIT_NOROOT_LOCKED: u32 = 2;
/// `SECBIT_KEEP_CAPS`: keep permitted capabilities across a uid change.
pub const SECBIT_KEEP_CAPS: u32 = 16;
/// The highest capability number (`CAP_CHECKPOINT_RESTORE`).
pub const CAP_LAST: u32 = 40;

/// `prctl` option `PR_SET_PDEATHSIG` (`linux/prctl.h`).
const PR_SET_PDEATHSIG: libc::c_int = 1;
/// `PR_SET_DUMPABLE`.
const PR_SET_DUMPABLE: libc::c_int = 4;
/// `PR_CAPBSET_DROP`.
const PR_CAPBSET_DROP: libc::c_int = 24;
/// `PR_GET_SECUREBITS`.
const PR_GET_SECUREBITS: libc::c_int = 27;
/// `PR_SET_SECUREBITS`.
const PR_SET_SECUREBITS: libc::c_int = 28;
/// `PR_SET_NO_NEW_PRIVS`.
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
/// `PR_GET_NO_NEW_PRIVS`.
const PR_GET_NO_NEW_PRIVS: libc::c_int = 39;
/// `PR_CAP_AMBIENT`.
const PR_CAP_AMBIENT: libc::c_int = 47;
/// `PR_CAP_AMBIENT_RAISE`.
const PR_CAP_AMBIENT_RAISE: libc::c_ulong = 2;
/// `_LINUX_CAPABILITY_VERSION_3` (`linux/capability.h`).
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// `struct __user_cap_header_struct`.
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

/// One of the two `struct __user_cap_data_struct` of version 3.
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn prctl(option: libc::c_int, a: libc::c_ulong, b: libc::c_ulong) -> Result<libc::c_int> {
    // SAFETY: prctl with integer arguments only; the remaining two are zero as the options
    // used here require.
    check(unsafe { libc::prctl(option, a, b, 0, 0) })
}

/// `setgroups(gids)`: the supplementary groups.
pub fn setgroups(gids: &[u32]) -> Result<()> {
    // SAFETY: the slice is readable for its length for the call.
    check(unsafe { libc::setgroups(gids.len(), gids.as_ptr()) })?;
    Ok(())
}

/// `setresgid(gid, gid, gid)`.
pub fn setresgid(gid: u32) -> Result<()> {
    // SAFETY: integers only.
    check(unsafe { libc::setresgid(gid, gid, gid) })?;
    Ok(())
}

/// `setresuid(uid, uid, uid)`.
pub fn setresuid(uid: u32) -> Result<()> {
    // SAFETY: integers only.
    check(unsafe { libc::setresuid(uid, uid, uid) })?;
    Ok(())
}

/// `prctl(PR_SET_SECUREBITS, bits)`.
pub fn set_securebits(bits: u32) -> Result<()> {
    prctl(PR_SET_SECUREBITS, libc::c_ulong::from(bits), 0)?;
    Ok(())
}

/// `prctl(PR_GET_SECUREBITS)`.
pub fn get_securebits() -> Result<u32> {
    let r = prctl(PR_GET_SECUREBITS, 0, 0)?;
    #[allow(clippy::cast_sign_loss)] // a non-negative bit set
    Ok(r as u32)
}

/// `prctl(PR_CAPBSET_DROP, cap)`: removes `cap` from the bounding set.
pub fn capbset_drop(cap: u32) -> Result<()> {
    prctl(PR_CAPBSET_DROP, libc::c_ulong::from(cap), 0)?;
    Ok(())
}

/// `capset` with a version 3 header: the three sets as 64-bit masks, each split into its two
/// 32-bit halves.
pub fn capset(effective: u64, permitted: u64, inheritable: u64) -> Result<()> {
    let header = CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    #[allow(clippy::cast_possible_truncation)] // the low and high halves are taken on purpose
    let half = |v: u64, hi: bool| if hi { (v >> 32) as u32 } else { v as u32 };
    let data = [
        CapData {
            effective: half(effective, false),
            permitted: half(permitted, false),
            inheritable: half(inheritable, false),
        },
        CapData {
            effective: half(effective, true),
            permitted: half(permitted, true),
            inheritable: half(inheritable, true),
        },
    ];
    // SAFETY: a version 3 header and its two data structs, readable for the call.
    check_long(unsafe { libc::syscall(libc::SYS_capset, &raw const header, data.as_ptr()) })?;
    Ok(())
}

/// `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap)`.
pub fn ambient_raise(cap: u32) -> Result<()> {
    prctl(
        PR_CAP_AMBIENT,
        PR_CAP_AMBIENT_RAISE,
        libc::c_ulong::from(cap),
    )?;
    Ok(())
}

/// `prctl(PR_SET_PDEATHSIG, sig)`: `sig` arrives when the parent thread exits.
pub fn set_pdeathsig(sig: libc::c_int) -> Result<()> {
    #[allow(clippy::cast_sign_loss)] // a signal number is positive
    prctl(PR_SET_PDEATHSIG, sig as libc::c_ulong, 0)?;
    Ok(())
}

/// `prctl(PR_SET_NO_NEW_PRIVS, 1)`.
pub fn set_no_new_privs() -> Result<()> {
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0)?;
    Ok(())
}

/// `prctl(PR_GET_NO_NEW_PRIVS)`.
pub fn no_new_privs() -> Result<bool> {
    Ok(prctl(PR_GET_NO_NEW_PRIVS, 0, 0)? != 0)
}

/// `prctl(PR_SET_DUMPABLE, on)`.
pub fn set_dumpable(on: bool) -> Result<()> {
    prctl(PR_SET_DUMPABLE, libc::c_ulong::from(on), 0)?;
    Ok(())
}
