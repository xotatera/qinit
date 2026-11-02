// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! V2: every pool reference is an in-bounds, UTF-8 slice; names are short and non-empty, and
//! lists (argv, Landlock entries) hold no empty element.

use super::DbError;
use super::header::{field, header_word};
#[allow(unused_imports, clippy::wildcard_imports)]
// spec-only items: Verus erases them outside verification
use super::spec::*;
use super::utf8::utf8_ok;
#[allow(clippy::wildcard_imports)] // the layout constants, used throughout
use crate::layout::*;
use vstd::prelude::*;

verus! {

/// Checks one pool reference.
pub(crate) fn pool_ref_ok(b: &[u8], off: u32, len: u32) -> (r: Result<(), DbError>)
    requires
        v1(b@),
    ensures
        r is Ok ==> pool_ref(b@, off as int, len as int),
{
    assert(table_ok(b@, T_POOL as int));
    let start = header_word(b, 4 + 2 * T_POOL) as usize;
    let size = header_word(b, 5 + 2 * T_POOL);
    if len > size || off > size - len {
        return Err(DbError::Pool);
    }
    let a = start + off as usize;
    if !utf8_ok(b, a, a + len as usize) {
        return Err(DbError::Utf8);
    }
    Ok(())
}

/// `b[start..end]` is a NUL-separated list of non-empty elements.
fn nul_list_ok(b: &[u8], start: usize, end: usize) -> (ok: bool)
    requires
        start <= end <= b@.len(),
    ensures
        ok ==> nul_list(b@.subrange(start as int, end as int)),
{
    if start == end {
        return true;
    }
    if b[start] == 0 || b[end - 1] == 0 {
        return false;
    }
    let mut i = start;
    while i + 1 < end
        invariant
            start <= i < end <= b@.len(),
            forall|k: int| start <= k < i ==> #[trigger] b@[k] != 0 || b@[k + 1] != 0,
        decreases end - i,
    {
        if b[i] == 0 && b[i + 1] == 0 {
            return false;
        }
        i += 1;
    }
    let ghost s = b@.subrange(start as int, end as int);
    assert forall|k: int| 0 <= k < s.len() - 1 implies #[trigger] s[k] != 0 || s[k + 1] != 0 by {
        assert(s[k] == b@[start + k]);
        assert(s[k + 1] == b@[start + k + 1]);
    }
    true
}

/// Checks a list: a pool reference whose bytes are NUL-separated non-empty elements.
fn list_ok(b: &[u8], off: u32, len: u32) -> (r: Result<(), DbError>)
    requires
        v1(b@),
    ensures
        r is Ok ==> list_ref(b@, off as int, len as int),
{
    pool_ref_ok(b, off, len)?;
    assert(table_ok(b@, T_POOL as int));
    let a = header_word(b, 4 + 2 * T_POOL) as usize + off as usize;
    if !nul_list_ok(b, a, a + len as usize) {
        return Err(DbError::Pool);
    }
    Ok(())
}

/// Checks a name: a pool reference of 1 to `MAX_NAME_LEN` bytes.
fn name_ok(b: &[u8], off: u32, len: u32) -> (r: Result<(), DbError>)
    requires
        v1(b@),
    ensures
        r is Ok ==> name_ref(b@, off as int, len as int),
{
    if len == 0 || len as usize > MAX_NAME_LEN {
        return Err(DbError::Pool);
    }
    pool_ref_ok(b, off, len)
}

fn check_node_pool(b: &[u8], i: usize) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        i < nodes(b@),
    ensures
        r is Ok ==> node_pool_ok(b@, i as int),
{
    let t = T_NODES;
    name_ok(b, field(b, t, i, N_NAME_OFF), field(b, t, i, N_NAME_LEN))?;
    list_ok(b, field(b, t, i, N_EXEC_OFF), field(b, t, i, N_EXEC_LEN))?;
    pool_ref_ok(b, field(b, t, i, N_READY_OFF), field(b, t, i, N_READY_LEN))?;
    pool_ref_ok(b, field(b, t, i, N_INSTANCE_OF_OFF), field(b, t, i, N_INSTANCE_OF_LEN))
}

fn check_edge_pool(b: &[u8], x: usize) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        x < tcnt(b@, T_EDGES as int),
    ensures
        r is Ok ==> edge_pool_ok(b@, x as int),
{
    let t = T_EDGES;
    if field(b, t, x, E_TARGET_KIND) == 1 {
        pool_ref_ok(b, field(b, t, x, E_TARGET), field(b, t, x, E_TARGET_LEN))
    } else {
        Ok(())
    }
}

fn check_cred_pool(b: &[u8], c: usize) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        c < tcnt(b@, T_CREDS as int),
    ensures
        r is Ok ==> cred_pool_ok(b@, c as int),
{
    let t = T_CREDS;
    pool_ref_ok(b, field(b, t, c, C_USER_OFF), field(b, t, c, C_USER_LEN))?;
    list_ok(b, field(b, t, c, C_LANDLOCK_OFF), field(b, t, c, C_LANDLOCK_LEN))
}

fn check_route_pool(b: &[u8], r: usize) -> (res: Result<(), DbError>)
    requires
        v1(b@),
        r < tcnt(b@, T_ROUTES as int),
    ensures
        res is Ok ==> route_pool_ok(b@, r as int),
{
    let t = T_ROUTES;
    if field(b, t, r, R_KIND) == 0 {
        pool_ref_ok(b, field(b, t, r, R_A), field(b, t, r, R_B))
    } else {
        Ok(())
    }
}

/// Checks every pool reference of every record (V2).
pub(crate) fn check_pool_refs(b: &[u8]) -> (r: Result<(), DbError>)
    requires
        v1(b@),
    ensures
        r is Ok ==> v2(b@),
{
    let n = header_word(b, 5 + 2 * T_NODES) as usize;
    let mut i: usize = 0;
    while i < n
        invariant
            v1(b@),
            n == nodes(b@),
            i <= n,
            forall|j: int| 0 <= j < i ==> #[trigger] node_pool_ok(b@, j),
        decreases n - i,
    {
        check_node_pool(b, i)?;
        i += 1;
    }
    let n = header_word(b, 5 + 2 * T_EDGES) as usize;
    let mut i: usize = 0;
    while i < n
        invariant
            v1(b@),
            n == tcnt(b@, T_EDGES as int),
            i <= n,
            forall|j: int| 0 <= j < i ==> #[trigger] edge_pool_ok(b@, j),
        decreases n - i,
    {
        check_edge_pool(b, i)?;
        i += 1;
    }
    let n = header_word(b, 5 + 2 * T_CREDS) as usize;
    let mut i: usize = 0;
    while i < n
        invariant
            v1(b@),
            n == tcnt(b@, T_CREDS as int),
            i <= n,
            forall|j: int| 0 <= j < i ==> #[trigger] cred_pool_ok(b@, j),
        decreases n - i,
    {
        check_cred_pool(b, i)?;
        i += 1;
    }
    let n = header_word(b, 5 + 2 * T_ROUTES) as usize;
    let mut i: usize = 0;
    while i < n
        invariant
            v1(b@),
            n == tcnt(b@, T_ROUTES as int),
            i <= n,
            forall|j: int| 0 <= j < i ==> #[trigger] route_pool_ok(b@, j),
        decreases n - i,
    {
        check_route_pool(b, i)?;
        i += 1;
    }
    Ok(())
}

} // verus!
