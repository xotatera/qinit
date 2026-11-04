// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! What `decode` accepts: the header, every pool reference, the enums, the routed descriptors
//! and the content rules, as spec functions over the bytes.
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use crate::layout::*;
// Explicit, so these shadow the same names of the database header.
#[allow(unused_imports)] // spec-only use; Verus erases it
use crate::layout::{H_MAGIC, H_TOTAL_LEN, H_VERSION, HEADER_WORDS};
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use qinit_db_core::*;
use vstd::prelude::*;

verus! {

/// Header word `i`.
pub open spec fn qhw(b: Seq<u8>, i: int) -> int {
    spec_word(b, i) as int
}

/// Record word `w`.
pub open spec fn qw(b: Seq<u8>, w: usize) -> int {
    spec_word(b, HEADER_WORDS + w) as int
}

/// The header: magic and version, the total length equal to the buffer within `MAX_REQUEST`,
/// and the pool filling the bytes after the record.
pub open spec fn req_header_ok(b: Seq<u8>) -> bool {
    &&& FIXED_BYTES <= b.len() <= MAX_REQUEST
    &&& qhw(b, H_MAGIC as int) == LAUNCH_MAGIC
    &&& qhw(b, H_VERSION as int) == LAUNCH_VERSION
    &&& qhw(b, H_TOTAL_LEN as int) == b.len()
    &&& qhw(b, H_POOL_OFF as int) >= FIXED_BYTES
    &&& qhw(b, H_POOL_OFF as int) + qhw(b, H_POOL_LEN as int) == b.len()
}

/// The pool bytes `off..off + len`.
pub open spec fn req_pool(b: Seq<u8>, off: int, len: int) -> Seq<u8> {
    b.subrange(qhw(b, H_POOL_OFF as int) + off, qhw(b, H_POOL_OFF as int) + off + len)
}

/// One reference: inside the pool and valid UTF-8.
pub open spec fn req_pool_ref(b: Seq<u8>, off: int, len: int) -> bool {
    &&& 0 <= off
    &&& 0 <= len
    &&& off + len <= qhw(b, H_POOL_LEN as int)
    &&& vstd::utf8::valid_utf8(req_pool(b, off, len))
}

/// A list reference: a pool reference whose bytes are a [`nul_list`].
pub open spec fn req_list_ref(b: Seq<u8>, off: int, len: int) -> bool {
    &&& req_pool_ref(b, off, len)
    &&& nul_list(req_pool(b, off, len))
}

/// The pool slice of the record's `(off, len)` words.
pub open spec fn field_slice(b: Seq<u8>, off: usize, len: usize) -> Seq<u8> {
    req_pool(b, qw(b, off), qw(b, len))
}

/// Every pool reference of the record.
pub open spec fn refs_ok(b: Seq<u8>) -> bool {
    &&& req_list_ref(b, qw(b, Q_ARGV_OFF), qw(b, Q_ARGV_LEN))
    &&& req_list_ref(b, qw(b, Q_ENV_OFF), qw(b, Q_ENV_LEN))
    &&& req_pool_ref(b, qw(b, Q_CWD_OFF), qw(b, Q_CWD_LEN))
    &&& req_pool_ref(b, qw(b, Q_USER_OFF), qw(b, Q_USER_LEN))
    &&& req_list_ref(b, qw(b, Q_SECCOMP_OFF), qw(b, Q_SECCOMP_LEN))
    &&& req_list_ref(b, qw(b, Q_PATHS_OFF), qw(b, Q_PATHS_LEN))
    &&& (qw(b, Q_STDIN_KIND) == STREAM_PATH ==> req_pool_ref(b, qw(b, Q_STDIN_A), qw(b, Q_STDIN_B)))
    &&& (qw(b, Q_STDOUT_KIND) == STREAM_PATH ==> req_pool_ref(
        b,
        qw(b, Q_STDOUT_A),
        qw(b, Q_STDOUT_B),
    ))
    &&& (qw(b, Q_STDERR_KIND) == STREAM_PATH ==> req_pool_ref(
        b,
        qw(b, Q_STDERR_A),
        qw(b, Q_STDERR_B),
    ))
}

/// Every enum in range, every reserved word zero, the seccomp list present exactly for a
/// list mode.
pub open spec fn enums_ok(b: Seq<u8>) -> bool {
    &&& qw(b, Q_UMASK) <= MAX_UMASK
    &&& qw(b, Q_CAPS_HI) <= 0x1ff
    &&& qw(b, Q_SECUREBITS) <= 2
    &&& qw(b, Q_NNP) <= 1
    &&& qw(b, Q_NS) <= 0x3f
    &&& qw(b, Q_SECCOMP) <= 3
    &&& (qw(b, Q_SECCOMP) <= 1) == (qw(b, Q_SECCOMP_LEN) == 0)
    &&& qw(b, Q_STDIN_KIND) <= STREAM_FD
    &&& qw(b, Q_STDOUT_KIND) <= STREAM_FD
    &&& qw(b, Q_STDERR_KIND) <= STREAM_SAME
    &&& qw(b, Q_READY_KIND) <= READY_PIPE
    &&& qw(b, Q_FLAGS) <= FLAG_DIE_WITH_PARENT
    &&& qw(b, Q_USER_MAP) <= 1
    &&& qw(b, Q_RESERVED_1) == 0
    &&& (qw(b, Q_RLIMIT_MASK) as u32) & !RLIMIT_MASK_ALLOWED == 0
}

/// Resource limit `r` of the request: both words 0 when unset; `nofile` at least 1 and finite;
/// `nice` and `rtprio` within their ceilings (the rules of the database's node record).
pub open spec fn req_rlimit_ok(b: Seq<u8>, r: usize) -> bool {
    let lo = qw(b, (Q_RLIMIT_BASE + 2 * r) as usize);
    let hi = qw(b, (Q_RLIMIT_BASE + 2 * r + 1) as usize);
    if ((qw(b, Q_RLIMIT_MASK) as u32) >> (r as u32)) & 1 == 0 {
        lo == 0 && hi == 0
    } else {
        &&& (r == RLIMIT_NOFILE as usize ==> !(lo == 0 && hi == 0) && !(lo == u32::MAX as int && hi
            == u32::MAX as int))
        &&& (r == RLIMIT_NICE as usize ==> hi == 0 && lo <= MAX_RLIMIT_NICE as int)
        &&& (r == RLIMIT_RTPRIO as usize ==> hi == 0 && lo <= MAX_RLIMIT_RTPRIO as int)
    }
}

/// Every limit of the request is [`req_rlimit_ok`].
pub open spec fn req_rlimits_ok(b: Seq<u8>) -> bool {
    forall|r: usize| r < RLIMIT_COUNT ==> #[trigger] req_rlimit_ok(b, r)
}

/// A routed descriptor number.
pub open spec fn fd_ok(v: int) -> bool {
    MIN_ROUTED_FD <= v <= MAX_ROUTED_FD
}

/// The descriptor number a stream word pair names, or -1 for a path or "same".
pub open spec fn stream_fd(b: Seq<u8>, kind: usize, a: usize) -> int {
    if qw(b, kind) == STREAM_FD {
        qw(b, a)
    } else {
        -1
    }
}

/// The descriptor number of the ready pipe, or -1.
pub open spec fn ready_fd(b: Seq<u8>) -> int {
    if qw(b, Q_READY_KIND) == READY_PIPE {
        qw(b, Q_READY_FD)
    } else {
        -1
    }
}

/// Routed descriptors (stdin, stdout, stderr, ready) are in range and distinct; the unused words of a descriptor or "same"
/// stream and of an absent ready pipe are zero.
pub open spec fn routes_ok(b: Seq<u8>) -> bool {
    let inp = stream_fd(b, Q_STDIN_KIND, Q_STDIN_A);
    let out = stream_fd(b, Q_STDOUT_KIND, Q_STDOUT_A);
    let err = stream_fd(b, Q_STDERR_KIND, Q_STDERR_A);
    let ready = ready_fd(b);
    &&& (qw(b, Q_STDIN_KIND) == STREAM_FD ==> fd_ok(inp) && qw(b, Q_STDIN_B) == 0)
    &&& (qw(b, Q_STDOUT_KIND) == STREAM_FD ==> fd_ok(out) && qw(b, Q_STDOUT_B) == 0)
    &&& (qw(b, Q_STDERR_KIND) == STREAM_FD ==> fd_ok(err) && qw(b, Q_STDERR_B) == 0)
    &&& (qw(b, Q_STDERR_KIND) == STREAM_SAME ==> qw(b, Q_STDERR_A) == 0 && qw(b, Q_STDERR_B) == 0)
    &&& (qw(b, Q_READY_KIND) == READY_PIPE ==> fd_ok(ready))
    &&& (qw(b, Q_READY_KIND) == READY_NONE ==> qw(b, Q_READY_FD) == 0)
    &&& (inp >= 0 ==> inp != out && inp != err && inp != ready)
    &&& (out >= 0 ==> out != err && out != ready)
    &&& (err >= 0 ==> err != ready)
}

/// The working directory: a canonical absolute path.
pub open spec fn req_cwd_ok(b: Seq<u8>) -> bool {
    canonical(field_slice(b, Q_CWD_OFF, Q_CWD_LEN))
}

/// The credential holds `CAP_SYS_ADMIN`.
pub open spec fn req_has_sys_admin(b: Seq<u8>) -> bool {
    (qw(b, Q_CAPS_LO) as u32) & CAP_SYS_ADMIN_MASK != 0
}

/// The content rules: a non-empty argv and user, the working directory, the lists' entries
/// and counts, a positive deadline, the limits, and `nnp` off with a Landlock list or seccomp only with
/// `CAP_SYS_ADMIN`.
pub open spec fn content_ok(b: Seq<u8>) -> bool {
    &&& qw(b, Q_ARGV_LEN) >= 1
    &&& 1 <= qw(b, Q_USER_LEN) <= MAX_NAME_LEN
    &&& qw(b, Q_DEADLINE_MS) >= 1
    &&& req_rlimits_ok(b)
    &&& req_cwd_ok(b)
    &&& env_list_ok(field_slice(b, Q_ENV_OFF, Q_ENV_LEN))
    &&& elems(field_slice(b, Q_ENV_OFF, Q_ENV_LEN)) <= MAX_ENV_ENTRIES
    &&& seccomp_list_ok(field_slice(b, Q_SECCOMP_OFF, Q_SECCOMP_LEN))
    &&& elems(field_slice(b, Q_SECCOMP_OFF, Q_SECCOMP_LEN)) <= MAX_SECCOMP_LIST
    &&& paths_list_ok(field_slice(b, Q_PATHS_OFF, Q_PATHS_LEN))
    &&& elems(field_slice(b, Q_PATHS_OFF, Q_PATHS_LEN)) <= MAX_PATH_ENTRIES
    &&& (qw(b, Q_USER_MAP) == 1 ==> (qw(b, Q_NS) as u32) & 32u32 != 0u32)
    &&& qw(b, Q_INSIDE_UID) <= 0xFFFF_FFFE
    &&& qw(b, Q_INSIDE_GID) <= 0xFFFF_FFFE
    &&& ((qw(b, Q_NS) as u32) & 32u32 == 0u32 ==> qw(b, Q_INSIDE_UID) == 0 && qw(b, Q_INSIDE_GID)
        == 0)
    &&& ((qw(b, Q_NS) as u32) & 32u32 != 0u32 ==> !is_root(field_slice(b, Q_USER_OFF, Q_USER_LEN)))
    &&& paths_shape_ok(field_slice(b, Q_PATHS_OFF, Q_PATHS_LEN), qw(b, Q_NS) as u32)
    &&& forall|e: Seq<u8>|
        #![trigger is_first(field_slice(b, Q_ARGV_OFF, Q_ARGV_LEN), e)]
        is_first(field_slice(b, Q_ARGV_OFF, Q_ARGV_LEN), e) ==> paths_cover_ok(
            field_slice(b, Q_PATHS_OFF, Q_PATHS_LEN),
            e,
            field_slice(b, Q_CWD_OFF, Q_CWD_LEN),
        )
    &&& (qw(b, Q_NNP) == 0 && (qw(b, Q_PATHS_LEN) > 0 || qw(b, Q_SECCOMP) != 0)
        ==> req_has_sys_admin(b))
}

/// A request `decode` accepts.
pub open spec fn accepted(b: Seq<u8>) -> bool {
    &&& req_header_ok(b)
    &&& refs_ok(b)
    &&& enums_ok(b)
    &&& routes_ok(b)
    &&& content_ok(b)
}

} // verus!
