// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! V2: every pool reference is an in-bounds, UTF-8 slice; names are short and non-empty, and
//! lists (argv, Landlock entries) hold no empty element.

use super::DbError;
use super::header::{field, header_word};
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
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
    let of_len = field(b, t, i, N_INSTANCE_OF_LEN);
    if of_len as usize > MAX_NAME_LEN {
        return Err(DbError::Pool);
    }
    pool_ref_ok(b, field(b, t, i, N_INSTANCE_OF_OFF), of_len)?;
    list_ok(b, field(b, t, i, N_ENV_OFF), field(b, t, i, N_ENV_LEN))?;
    pool_ref_ok(b, field(b, t, i, N_CWD_OFF), field(b, t, i, N_CWD_LEN))
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
    list_ok(b, field(b, t, c, C_LANDLOCK_OFF), field(b, t, c, C_LANDLOCK_LEN))?;
    list_ok(b, field(b, t, c, C_SECCOMP_OFF), field(b, t, c, C_SECCOMP_LEN))
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

/// `s[p..q]` is an [`env_entry_ok`] entry: at least two bytes, not starting with `=`, and
/// holding an `=` after the key.
fn env_entry_ok_exec(s: &[u8], p: usize, q: usize) -> (ok: bool)
    requires
        p <= q <= s@.len(),
    ensures
        ok ==> env_entry_ok(s@.subrange(p as int, q as int)),
{
    if q - p < 2 || s[p] == 0x3d {
        return false;
    }
    let ghost entry = s@.subrange(p as int, q as int);
    assert(entry.len() >= 2 && entry[0] == s@[p as int]);
    let mut at = p + 1;
    while at < q
        invariant
            p + 1 <= at <= q <= s@.len(),
            entry == s@.subrange(p as int, q as int),
            entry.len() >= 2,
            entry[0] != 0x3d,
        decreases q - at,
    {
        if s[at] == 0x3d {
            assert(1 <= at - p < entry.len() && entry[at - p] == 0x3d);
            return true;
        }
        at += 1;
    }
    false
}

/// `s[p..q]` is a [`decimal_ok`] syscall number.
#[allow(clippy::cast_lossless)]  // `u32::from` is not available inside `verus!`
fn decimal_ok_exec(s: &[u8], p: usize, q: usize) -> (ok: bool)
    requires
        p <= q <= s@.len(),
    ensures
        ok ==> decimal_ok(s@.subrange(p as int, q as int)),
{
    if q - p < 1 || q - p > 3 {
        return false;
    }
    if q - p > 1 && s[p] == 0x30 {
        return false;
    }
    let ghost entry = s@.subrange(p as int, q as int);
    let mut value: u32 = 0;
    let mut at = p;
    while at < q
        invariant
            p <= at <= q <= s@.len(),
            q - p <= 3,
            entry == s@.subrange(p as int, q as int),
            forall|j: int| 0 <= j < at - p ==> 0x30 <= #[trigger] entry[j] <= 0x39,
            value as int == decimal_value(s@.subrange(p as int, at as int)),
            at - p == 0 ==> value == 0,
            at - p == 1 ==> value < 10,
            at - p == 2 ==> value < 100,
            at - p == 3 ==> value < 1000,
        decreases q - at,
    {
        let digit = s[at];
        #[allow(clippy::manual_range_contains)]  // `RangeInclusive::contains` is not available inside `verus!`
        if digit < 0x30 || digit > 0x39 {
            return false;
        }
        assert(s@.subrange(p as int, at + 1).drop_last() =~= s@.subrange(p as int, at as int));
        assert(s@.subrange(p as int, at + 1).last() == digit);
        value = value * 10 + (digit - 0x30) as u32;
        at += 1;
    }
    value < MAX_SYSCALL
}

/// Every element `[p, q)` of the NUL-separated list `s` with `q <= i` starts where the element
/// before it ends: `es` is the start of the element at `i` when `s[es..i]` has no NUL.
proof fn lemma_elem_start(s: Seq<u8>, es: int, i: int, p: int)
    requires
        0 <= es <= i <= s.len(),
        es == 0 || s[es - 1] == 0,
        forall|k: int| es <= k < i ==> #[trigger] s[k] != 0,
        is_elem(s, p, i),
    ensures
        p == es,
{
    if p < es {
        assert(s[es - 1] != 0);
    }
    if p > es {
        assert(s[p - 1] != 0);
    }
}

/// Every element of the NUL-separated list `s` passes `check`: [`env_entry_ok`] when `kind` is
/// 0, [`decimal_ok`] when it is 1.
fn elements_ok(s: &[u8], kind: u32) -> (ok: bool)
    requires
        nul_list(s@),
        kind <= 1,
    ensures
        ok && kind == 0 ==> env_list_ok(s@),
        ok && kind == 1 ==> seccomp_list_ok(s@),
{
    let n = s.len();
    if n == 0 {
        return true;
    }
    let mut es: usize = 0;
    let mut i: usize = 0;
    while i < n
        invariant
            n == s@.len(),
            0 < n,
            nul_list(s@),
            kind <= 1,
            es <= i <= n,
            es == 0 || s@[es - 1] == 0,
            forall|k: int| es <= k < i ==> #[trigger] s@[k] != 0,
            forall|p: int, q: int| #[trigger]
                is_elem(s@, p, q) && q < i ==> (kind == 0 ==> env_entry_ok(s@.subrange(p, q))) && (
                kind == 1 ==> decimal_ok(s@.subrange(p, q))),
        decreases n - i,
    {
        if s[i] == 0 {
            if kind == 0 && !env_entry_ok_exec(s, es, i) {
                return false;
            }
            if kind == 1 && !decimal_ok_exec(s, es, i) {
                return false;
            }
            assert forall|p: int, q: int| #[trigger] is_elem(s@, p, q) && q < i + 1 implies (kind
                == 0 ==> env_entry_ok(s@.subrange(p, q))) && (kind == 1 ==> decimal_ok(
                s@.subrange(p, q),
            )) by {
                if q == i {
                    lemma_elem_start(s@, es as int, i as int, p);
                }
            }
            es = i + 1;
        }
        i += 1;
    }
    if kind == 0 && !env_entry_ok_exec(s, es, n) {
        return false;
    }
    if kind == 1 && !decimal_ok_exec(s, es, n) {
        return false;
    }
    assert forall|p: int, q: int| #[trigger] is_elem(s@, p, q) implies (kind == 0 ==> env_entry_ok(
        s@.subrange(p, q),
    )) && (kind == 1 ==> decimal_ok(s@.subrange(p, q))) by {
        if q == n {
            lemma_elem_start(s@, es as int, n as int, p);
        }
    }
    true
}

/// Every element of the pool list `off..off + len` is an environment entry (V4).
pub(crate) fn env_list_ok_exec(b: &[u8], off: u32, len: u32) -> (ok: bool)
    requires
        v1(b@),
        list_ref(b@, off as int, len as int),
    ensures
        ok ==> env_list_ok(pool_slice(b@, off as int, len as int)),
{
    assert(table_ok(b@, T_POOL as int));
    let a = header_word(b, 4 + 2 * T_POOL) as usize + off as usize;
    let s = vstd::slice::slice_subrange(b, a, a + len as usize);
    elements_ok(s, 0)
}

/// Every element of the pool list `off..off + len` is a canonical syscall number (V4).
pub(crate) fn seccomp_list_ok_exec(b: &[u8], off: u32, len: u32) -> (ok: bool)
    requires
        v1(b@),
        list_ref(b@, off as int, len as int),
    ensures
        ok ==> seccomp_list_ok(pool_slice(b@, off as int, len as int)),
{
    assert(table_ok(b@, T_POOL as int));
    let a = header_word(b, 4 + 2 * T_POOL) as usize + off as usize;
    let s = vstd::slice::slice_subrange(b, a, a + len as usize);
    elements_ok(s, 1)
}

/// The pool string `off..off + len` is a non-empty absolute path (V4).
pub(crate) fn cwd_ok_exec(b: &[u8], off: u32, len: u32) -> (ok: bool)
    requires
        v1(b@),
        pool_ref(b@, off as int, len as int),
    ensures
        ok ==> cwd_ok(b@, off as int, len as int),
{
    assert(table_ok(b@, T_POOL as int));
    let a = header_word(b, 4 + 2 * T_POOL) as usize + off as usize;
    len >= 1 && b[a] == 0x2f
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
