// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! V2: pool references, names and NUL-separated lists.

#[allow(unused_imports, clippy::wildcard_imports)] // spec-only use: Verus erases it
use super::tables::*;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use crate::layout::*;
use vstd::prelude::*;

verus! {

/// The pool bytes `off..off + len`.
pub open spec fn pool_slice(b: Seq<u8>, off: int, len: int) -> Seq<u8> {
    b.subrange(toff(b, T_POOL as int) + off, toff(b, T_POOL as int) + off + len)
}

/// V2 for one reference: inside the pool and valid UTF-8.
pub open spec fn pool_ref(b: Seq<u8>, off: int, len: int) -> bool {
    &&& 0 <= off
    &&& 0 <= len
    &&& off + len <= tcnt(b, T_POOL as int)
    &&& vstd::utf8::valid_utf8(pool_slice(b, off, len))
}

/// V2 for a name: a pool reference, non-empty and at most `MAX_NAME_LEN` bytes.
pub open spec fn name_ref(b: Seq<u8>, off: int, len: int) -> bool {
    &&& pool_ref(b, off, len)
    &&& 0 < len <= MAX_NAME_LEN
}

/// A NUL-separated list of non-empty elements: empty, or no NUL first or last and no two NULs
/// in a row.
pub open spec fn nul_list(s: Seq<u8>) -> bool {
    s.len() == 0 || (s[0] != 0 && s[s.len() - 1] != 0 && forall|k: int|
        0 <= k < s.len() - 1 ==> #[trigger] s[k] != 0 || s[k + 1] != 0)
}

/// V2 for a list: a pool reference whose bytes are a [`nul_list`].
pub open spec fn list_ref(b: Seq<u8>, off: int, len: int) -> bool {
    &&& pool_ref(b, off, len)
    &&& nul_list(pool_slice(b, off, len))
}

pub open spec fn node_pool_ok(b: Seq<u8>, i: int) -> bool {
    &&& name_ref(b, nf(b, i, N_NAME_OFF), nf(b, i, N_NAME_LEN))
    &&& list_ref(b, nf(b, i, N_EXEC_OFF), nf(b, i, N_EXEC_LEN))
    &&& pool_ref(b, nf(b, i, N_READY_OFF), nf(b, i, N_READY_LEN))
    &&& pool_ref(b, nf(b, i, N_INSTANCE_OF_OFF), nf(b, i, N_INSTANCE_OF_LEN))
}

pub open spec fn edge_pool_ok(b: Seq<u8>, x: int) -> bool {
    ef(b, x, E_TARGET_KIND) == 1 ==> pool_ref(b, ef(b, x, E_TARGET), ef(b, x, E_TARGET_LEN))
}

pub open spec fn cred_pool_ok(b: Seq<u8>, c: int) -> bool {
    &&& pool_ref(b, cf(b, c, C_USER_OFF), cf(b, c, C_USER_LEN))
    &&& list_ref(b, cf(b, c, C_LANDLOCK_OFF), cf(b, c, C_LANDLOCK_LEN))
}

pub open spec fn route_pool_ok(b: Seq<u8>, r: int) -> bool {
    rf(b, r, R_KIND) == 0 ==> pool_ref(b, rf(b, r, R_A), rf(b, r, R_B))
}

/// V2: every pool reference of every record.
pub open spec fn v2(b: Seq<u8>) -> bool {
    &&& forall|i: int| 0 <= i < nodes(b) ==> #[trigger] node_pool_ok(b, i)
    &&& forall|x: int| 0 <= x < tcnt(b, T_EDGES as int) ==> #[trigger] edge_pool_ok(b, x)
    &&& forall|c: int| 0 <= c < tcnt(b, T_CREDS as int) ==> #[trigger] cred_pool_ok(b, c)
    &&& forall|r: int| 0 <= r < tcnt(b, T_ROUTES as int) ==> #[trigger] route_pool_ok(b, r)
}

} // verus!
