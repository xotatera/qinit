// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The total decoder: `Ok` only for an [`accepted`] request, and the in-place accessors that
//! are in bounds for any accepted request.
#[allow(clippy::wildcard_imports)] // the layout constants, used throughout
use crate::layout::*;
// Explicit, so these shadow the same names of the database header.
use crate::layout::{H_MAGIC, H_TOTAL_LEN, H_VERSION, HEADER_WORDS};
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use crate::spec::*;
use qinit_db_core::word as raw_word;
#[allow(unused_imports, clippy::wildcard_imports)]
// the db-core helpers and spec items; Verus erases the latter
use qinit_db_core::*;
use vstd::prelude::*;

verus! {

/// Why a request is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchError {
    /// Too short, a bad magic or version, or a length or pool offset that disagrees with the
    /// buffer or exceeds `MAX_REQUEST`.
    Header,
    /// A string reference leaves the pool, is not UTF-8, or a list has an empty element.
    Pool,
    /// An enum is out of range, a reserved word is set, or the seccomp list disagrees with
    /// its mode.
    Enum,
    /// Fields contradict each other or a content rule: an empty argv or user, a relative
    /// cwd, a bad list entry or too many of them, a routed descriptor out of range or named
    /// twice, a zero deadline, or `nnp` off with a sandbox and no `CAP_SYS_ADMIN`.
    Consistency,
}

/// Header or record word `i` of a buffer holding at least the fixed part.
fn hword(b: &[u8], i: usize) -> (v: u32)
    requires
        b@.len() >= FIXED_BYTES,
        i < HEADER_WORDS + REQ_WORDS,
    ensures
        v == spec_word(b@, i as int),
{
    raw_word(b, i)
}

/// Record word `w`.
fn rword(b: &[u8], w: usize) -> (v: u32)
    requires
        b@.len() >= FIXED_BYTES,
        w < REQ_WORDS,
    ensures
        v as int == qw(b@, w),
{
    raw_word(b, HEADER_WORDS + w)
}

fn check_header(b: &[u8]) -> (r: Result<(), LaunchError>)
    ensures
        r is Ok ==> req_header_ok(b@),
{
    if b.len() < FIXED_BYTES || b.len() > MAX_REQUEST {
        return Err(LaunchError::Header);
    }
    if hword(b, H_MAGIC) != LAUNCH_MAGIC || hword(b, H_VERSION) != LAUNCH_VERSION {
        return Err(LaunchError::Header);
    }
    if hword(b, H_TOTAL_LEN) as usize != b.len() {
        return Err(LaunchError::Header);
    }
    let off = hword(b, H_POOL_OFF) as usize;
    let len = hword(b, H_POOL_LEN) as usize;
    if off < FIXED_BYTES || off > b.len() || len != b.len() - off {
        return Err(LaunchError::Header);
    }
    Ok(())
}

/// Checks one pool reference.
fn pool_ref_ok(b: &[u8], off: u32, len: u32) -> (r: Result<(), LaunchError>)
    requires
        req_header_ok(b@),
    ensures
        r is Ok ==> req_pool_ref(b@, off as int, len as int),
{
    let pool_off = hword(b, H_POOL_OFF) as usize;
    let pool_len = hword(b, H_POOL_LEN) as usize;
    if len as usize > pool_len || off as usize > pool_len - len as usize {
        return Err(LaunchError::Pool);
    }
    let a = pool_off + off as usize;
    if !utf8_ok(b, a, a + len as usize) {
        return Err(LaunchError::Pool);
    }
    Ok(())
}

/// Checks a list reference: a pool reference whose bytes are NUL-separated non-empty elements.
fn list_ref_ok(b: &[u8], off: u32, len: u32) -> (r: Result<(), LaunchError>)
    requires
        req_header_ok(b@),
    ensures
        r is Ok ==> req_list_ref(b@, off as int, len as int),
{
    pool_ref_ok(b, off, len)?;
    let a = hword(b, H_POOL_OFF) as usize + off as usize;
    if !nul_list_ok(b, a, a + len as usize) {
        return Err(LaunchError::Pool);
    }
    Ok(())
}

/// The pool bytes of a reference.
fn field(b: &[u8], off: u32, len: u32) -> (s: &[u8])
    requires
        req_header_ok(b@),
        req_pool_ref(b@, off as int, len as int),
    ensures
        s@ == req_pool(b@, off as int, len as int),
{
    let a = hword(b, H_POOL_OFF) as usize + off as usize;
    vstd::slice::slice_subrange(b, a, a + len as usize)
}

fn check_refs(b: &[u8]) -> (r: Result<(), LaunchError>)
    requires
        req_header_ok(b@),
    ensures
        r is Ok ==> refs_ok(b@),
{
    list_ref_ok(b, rword(b, Q_ARGV_OFF), rword(b, Q_ARGV_LEN))?;
    list_ref_ok(b, rword(b, Q_ENV_OFF), rword(b, Q_ENV_LEN))?;
    pool_ref_ok(b, rword(b, Q_CWD_OFF), rword(b, Q_CWD_LEN))?;
    pool_ref_ok(b, rword(b, Q_USER_OFF), rword(b, Q_USER_LEN))?;
    list_ref_ok(b, rword(b, Q_SECCOMP_OFF), rword(b, Q_SECCOMP_LEN))?;
    list_ref_ok(b, rword(b, Q_PATHS_OFF), rword(b, Q_PATHS_LEN))?;
    if rword(b, Q_STDIN_KIND) == STREAM_PATH {
        pool_ref_ok(b, rword(b, Q_STDIN_A), rword(b, Q_STDIN_B))?;
    }
    if rword(b, Q_STDOUT_KIND) == STREAM_PATH {
        pool_ref_ok(b, rword(b, Q_STDOUT_A), rword(b, Q_STDOUT_B))?;
    }
    if rword(b, Q_STDERR_KIND) == STREAM_PATH {
        pool_ref_ok(b, rword(b, Q_STDERR_A), rword(b, Q_STDERR_B))?;
    }
    Ok(())
}

fn check_enums(b: &[u8]) -> (r: Result<(), LaunchError>)
    requires
        req_header_ok(b@),
    ensures
        r is Ok ==> enums_ok(b@),
{
    let seccomp = rword(b, Q_SECCOMP);
    if rword(b, Q_UMASK) > MAX_UMASK || rword(b, Q_CAPS_HI) > 0x1ff || rword(b, Q_SECUREBITS) > 2
        || rword(b, Q_NNP) > 1 || rword(b, Q_NS) > 0x1f || seccomp > 3 || ((seccomp <= 1) != (rword(
        b,
        Q_SECCOMP_LEN,
    ) == 0)) {
        return Err(LaunchError::Enum);
    }
    if rword(b, Q_STDIN_KIND) > STREAM_FD || rword(b, Q_STDOUT_KIND) > STREAM_FD || rword(
        b,
        Q_STDERR_KIND,
    ) > STREAM_SAME || rword(b, Q_READY_KIND) > READY_PIPE || rword(b, Q_FLAGS)
        > FLAG_DIE_WITH_PARENT || rword(b, Q_RESERVED_0) != 0 || rword(b, Q_RESERVED_1) != 0
        || rword(b, Q_RLIMIT_MASK) & !RLIMIT_MASK_ALLOWED != 0 {
        return Err(LaunchError::Enum);
    }
    Ok(())
}

/// Every limit of the request is [`req_rlimit_ok`].
#[allow(clippy::cast_possible_truncation)]  // `k < RLIMIT_COUNT`, so the shift count fits
fn check_rlimits(b: &[u8]) -> (r: Result<(), LaunchError>)
    requires
        req_header_ok(b@),
    ensures
        r is Ok ==> req_rlimits_ok(b@),
{
    let mask = rword(b, Q_RLIMIT_MASK);
    let mut k: usize = 0;
    while k < RLIMIT_COUNT
        invariant
            req_header_ok(b@),
            mask as int == qw(b@, Q_RLIMIT_MASK),
            k <= RLIMIT_COUNT,
            forall|j: usize| j < k ==> #[trigger] req_rlimit_ok(b@, j),
        decreases RLIMIT_COUNT - k,
    {
        let lo = rword(b, Q_RLIMIT_BASE + 2 * k);
        let hi = rword(b, Q_RLIMIT_BASE + 2 * k + 1);
        let bad = if (mask >> (k as u32)) & 1 == 0 {
            lo != 0 || hi != 0
        } else {
            (k == RLIMIT_NOFILE as usize && ((lo == 0 && hi == 0) || (lo == u32::MAX && hi
                == u32::MAX))) || (k == RLIMIT_NICE as usize && (hi != 0 || lo > MAX_RLIMIT_NICE))
                || (k == RLIMIT_RTPRIO as usize && (hi != 0 || lo > MAX_RLIMIT_RTPRIO))
        };
        if bad {
            return Err(LaunchError::Consistency);
        }
        k += 1;
    }
    Ok(())
}

#[allow(clippy::manual_range_contains)]  // `RangeInclusive::contains` is not available inside `verus!`
fn fd_ok_exec(v: u32) -> (r: bool)
    ensures
        r == fd_ok(v as int),
{
    MIN_ROUTED_FD <= v && v <= MAX_ROUTED_FD
}

#[allow(clippy::cast_lossless)]  // `i64::from` is not available inside `verus!`
fn check_routes(b: &[u8]) -> (r: Result<(), LaunchError>)
    requires
        req_header_ok(b@),
    ensures
        r is Ok ==> routes_ok(b@),
{
    let in_kind = rword(b, Q_STDIN_KIND);
    let in_a = rword(b, Q_STDIN_A);
    let out_kind = rword(b, Q_STDOUT_KIND);
    let out_a = rword(b, Q_STDOUT_A);
    let err_kind = rword(b, Q_STDERR_KIND);
    let err_a = rword(b, Q_STDERR_A);
    let ready_kind = rword(b, Q_READY_KIND);
    let ready_a = rword(b, Q_READY_FD);
    if in_kind == STREAM_FD && (!fd_ok_exec(in_a) || rword(b, Q_STDIN_B) != 0) {
        return Err(LaunchError::Consistency);
    }
    if out_kind == STREAM_FD && (!fd_ok_exec(out_a) || rword(b, Q_STDOUT_B) != 0) {
        return Err(LaunchError::Consistency);
    }
    if err_kind == STREAM_FD && (!fd_ok_exec(err_a) || rword(b, Q_STDERR_B) != 0) {
        return Err(LaunchError::Consistency);
    }
    if err_kind == STREAM_SAME && (err_a != 0 || rword(b, Q_STDERR_B) != 0) {
        return Err(LaunchError::Consistency);
    }
    if ready_kind == READY_PIPE && !fd_ok_exec(ready_a) {
        return Err(LaunchError::Consistency);
    }
    if ready_kind == READY_NONE && ready_a != 0 {
        return Err(LaunchError::Consistency);
    }
    let inp: i64 = if in_kind == STREAM_FD {
        in_a as i64
    } else {
        -1
    };
    let out: i64 = if out_kind == STREAM_FD {
        out_a as i64
    } else {
        -1
    };
    let err: i64 = if err_kind == STREAM_FD {
        err_a as i64
    } else {
        -1
    };
    let ready: i64 = if ready_kind == READY_PIPE {
        ready_a as i64
    } else {
        -1
    };
    if inp >= 0 && (inp == out || inp == err || inp == ready) {
        return Err(LaunchError::Consistency);
    }
    if out >= 0 && (out == err || out == ready) {
        return Err(LaunchError::Consistency);
    }
    if err >= 0 && err == ready {
        return Err(LaunchError::Consistency);
    }
    Ok(())
}

fn check_content(b: &[u8]) -> (r: Result<(), LaunchError>)
    requires
        req_header_ok(b@),
        refs_ok(b@),
    ensures
        r is Ok ==> content_ok(b@),
{
    if rword(b, Q_ARGV_LEN) == 0 || rword(b, Q_DEADLINE_MS) == 0 {
        return Err(LaunchError::Consistency);
    }
    check_rlimits(b)?;
    let user_len = rword(b, Q_USER_LEN);
    if user_len == 0 || user_len as usize > MAX_NAME_LEN {
        return Err(LaunchError::Consistency);
    }
    let cwd = field(b, rword(b, Q_CWD_OFF), rword(b, Q_CWD_LEN));
    if !canonical_exec(cwd, 0, cwd.len()) {
        return Err(LaunchError::Consistency);
    }
    proof {
        assert(cwd@.subrange(0, cwd@.len() as int) =~= cwd@);
    }
    let env = field(b, rword(b, Q_ENV_OFF), rword(b, Q_ENV_LEN));
    if !elements_ok(env, 0) || count_elements(env) > MAX_ENV_ENTRIES {
        return Err(LaunchError::Consistency);
    }
    let seccomp = field(b, rword(b, Q_SECCOMP_OFF), rword(b, Q_SECCOMP_LEN));
    if !elements_ok(seccomp, 1) || count_elements(seccomp) > MAX_SECCOMP_LIST {
        return Err(LaunchError::Consistency);
    }
    let paths = field(b, rword(b, Q_PATHS_OFF), rword(b, Q_PATHS_LEN));
    if !elements_ok(paths, 2) || count_elements(paths) > MAX_PATH_ENTRIES {
        return Err(LaunchError::Consistency);
    }
    if rword(b, Q_NNP) == 0 && (rword(b, Q_PATHS_LEN) > 0 || rword(b, Q_SECCOMP) != 0) && rword(
        b,
        Q_CAPS_LO,
    ) & CAP_SYS_ADMIN_MASK == 0 {
        assert(!req_has_sys_admin(b@));
        return Err(LaunchError::Consistency);
    }
    Ok(())
}

/// Decodes `b` as a launch request: `Ok` only if it is [`accepted`], after which every
/// accessor below is in bounds.
///
/// # Errors
/// The first rule the request breaks, checked in the order header, pool references, enums,
/// routed descriptors, content.
pub fn decode(b: &[u8]) -> (r: Result<(), LaunchError>)
    ensures
        r is Ok ==> accepted(b@),
{
    check_header(b)?;
    check_refs(b)?;
    check_enums(b)?;
    check_routes(b)?;
    check_content(b)?;
    Ok(())
}

/// Header or record word `w` of an accepted request.
#[must_use]
pub fn word(b: &[u8], w: usize) -> (v: u32)
    requires
        accepted(b@),
        w < HEADER_WORDS + REQ_WORDS,
    ensures
        v == spec_word(b@, w as int),
{
    hword(b, w)
}

/// Record word `w` of an accepted request.
#[must_use]
pub fn req(b: &[u8], w: usize) -> (v: u32)
    requires
        accepted(b@),
        w < REQ_WORDS,
    ensures
        v as int == qw(b@, w),
{
    rword(b, w)
}

/// The pool bytes of a reference of an accepted request (one the record names, so it is in
/// the pool).
#[must_use]
pub fn pool(b: &[u8], off: u32, len: u32) -> (s: &[u8])
    requires
        accepted(b@),
        req_pool_ref(b@, off as int, len as int),
    ensures
        s@ == req_pool(b@, off as int, len as int),
{
    field(b, off, len)
}

} // verus!
