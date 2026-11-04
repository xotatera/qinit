// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! V2: every pool reference is an in-bounds, UTF-8 slice; names are short and non-empty, and
//! lists (argv, Landlock entries) hold no empty element.
use super::DbError;
use super::header::{field, header_word};
use super::paths::{canonical_exec, path_entry_ok_exec};
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use super::spec::*;
use super::utf8::utf8_check;
use super::{rid, tid};
#[allow(clippy::wildcard_imports)] // the layout constants, used throughout
use crate::layout::*;
use vstd::prelude::*;

verus! {

/// A reference starting or ending at pool offset `x` falls between two characters of the pool.
#[allow(clippy::manual_range_contains)]  // `RangeInclusive::contains` is not available inside `verus!`
fn boundary_ok(b: &[u8], x: u32) -> (ok: bool)
    requires
        v1(b@),
        pool_valid(b@),
        x <= tcnt(b@, T_POOL as int),
    ensures
        ok ==> vstd::utf8::is_char_boundary(pool_seq(b@), x as int),
{
    assert(table_ok(b@, T_POOL as int));
    let start = header_word(b, 4 + 2 * T_POOL) as usize;
    let size = header_word(b, 5 + 2 * T_POOL);
    proof {
        vstd::utf8::is_char_boundary_start_end_of_seq(pool_seq(b@));
    }
    if x == 0 || x == size {
        return true;
    }
    let c = b[start + x as usize];
    proof {
        assert(pool_seq(b@)[x as int] == b@[start + x]);
        vstd::utf8::is_char_boundary_iff_not_is_continuation_byte(pool_seq(b@), x as int);
    }
    c < 0x80 || c > 0xbf
}

/// A valid pool is cut at character boundaries into valid references.
proof fn lemma_ref_utf8(b: Seq<u8>, off: int, len: int)
    requires
        table_ok(b, T_POOL as int),
        pool_valid(b),
        0 <= off,
        0 <= len,
        off + len <= tcnt(b, T_POOL as int),
        vstd::utf8::is_char_boundary(pool_seq(b), off),
        vstd::utf8::is_char_boundary(pool_seq(b), off + len),
    ensures
        vstd::utf8::valid_utf8(pool_slice(b, off, len)),
{
    let p = pool_seq(b);
    let j = off + len;
    vstd::utf8::valid_utf8_split(p, j);
    let q = p.subrange(0, j);
    assert(q =~= p[..j]);
    if len == 0 {
        assert(pool_slice(b, off, len) =~= Seq::<u8>::empty());
    } else {
        if off == 0 {
            assert(pool_slice(b, off, len) =~= q);
        } else {
            vstd::utf8::is_char_boundary_iff_not_is_continuation_byte(p, off);
            vstd::utf8::is_char_boundary_iff_not_is_continuation_byte(q, off);
            assert(q[off] == p[off]);
            vstd::utf8::valid_utf8_split(q, off);
            assert(pool_slice(b, off, len) =~= q[off..]);
        }
    }
}

/// Checks one pool reference of record `record` of table `table`.
pub(crate) fn pool_ref_ok(b: &[u8], off: u32, len: u32, table: u8, record: u32) -> (r: Result<
    (),
    DbError,
>)
    requires
        v1(b@),
        pool_valid(b@),
    ensures
        r is Ok ==> pool_ref(b@, off as int, len as int),
{
    assert(table_ok(b@, T_POOL as int));
    let size = header_word(b, 5 + 2 * T_POOL);
    if len > size || off > size - len {
        return Err(DbError::Pool { table, record });
    }
    if !boundary_ok(b, off) || !boundary_ok(b, off + len) {
        return Err(DbError::Pool { table, record });
    }
    proof {
        lemma_ref_utf8(b@, off as int, len as int);
    }
    Ok(())
}

/// `b[start..end]` is a NUL-separated list of non-empty elements.
#[must_use]
pub fn nul_list_ok(b: &[u8], start: usize, end: usize) -> (ok: bool)
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
fn list_ok(b: &[u8], off: u32, len: u32, table: u8, record: u32) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        pool_valid(b@),
    ensures
        r is Ok ==> list_ref(b@, off as int, len as int),
{
    pool_ref_ok(b, off, len, table, record)?;
    assert(table_ok(b@, T_POOL as int));
    let a = header_word(b, 4 + 2 * T_POOL) as usize + off as usize;
    if !nul_list_ok(b, a, a + len as usize) {
        return Err(DbError::Pool { table, record });
    }
    Ok(())
}

/// Checks a name: a pool reference of 1 to `MAX_NAME_LEN` bytes.
fn name_ok(b: &[u8], off: u32, len: u32, table: u8, record: u32) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        pool_valid(b@),
    ensures
        r is Ok ==> name_ref(b@, off as int, len as int),
{
    if len == 0 || len as usize > MAX_NAME_LEN {
        return Err(DbError::Pool { table, record });
    }
    pool_ref_ok(b, off, len, table, record)
}

fn check_node_pool(b: &[u8], i: usize) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        pool_valid(b@),
        i < nodes(b@),
    ensures
        r is Ok ==> node_pool_ok(b@, i as int),
{
    let t = T_NODES;
    let (tb, rec) = (tid(t), rid(i));
    name_ok(b, field(b, t, i, N_NAME_OFF), field(b, t, i, N_NAME_LEN), tb, rec)?;
    list_ok(b, field(b, t, i, N_EXEC_OFF), field(b, t, i, N_EXEC_LEN), tb, rec)?;
    pool_ref_ok(b, field(b, t, i, N_READY_OFF), field(b, t, i, N_READY_LEN), tb, rec)?;
    let of_len = field(b, t, i, N_INSTANCE_OF_LEN);
    if of_len as usize > MAX_NAME_LEN {
        return Err(DbError::Pool { table: tb, record: rec });
    }
    pool_ref_ok(b, field(b, t, i, N_INSTANCE_OF_OFF), of_len, tb, rec)?;
    list_ok(b, field(b, t, i, N_ENV_OFF), field(b, t, i, N_ENV_LEN), tb, rec)?;
    pool_ref_ok(b, field(b, t, i, N_CWD_OFF), field(b, t, i, N_CWD_LEN), tb, rec)?;
    list_ok(b, field(b, t, i, N_LAUNCH_ENV_OFF), field(b, t, i, N_LAUNCH_ENV_LEN), tb, rec)
}

fn check_edge_pool(b: &[u8], x: usize) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        pool_valid(b@),
        x < tcnt(b@, T_EDGES as int),
    ensures
        r is Ok ==> edge_pool_ok(b@, x as int),
{
    let t = T_EDGES;
    if field(b, t, x, E_TARGET_KIND) == 1 {
        pool_ref_ok(b, field(b, t, x, E_TARGET), field(b, t, x, E_TARGET_LEN), tid(t), rid(x))
    } else {
        Ok(())
    }
}

fn check_cred_pool(b: &[u8], c: usize) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        pool_valid(b@),
        c < tcnt(b@, T_CREDS as int),
    ensures
        r is Ok ==> cred_pool_ok(b@, c as int),
{
    let t = T_CREDS;
    let (tb, rec) = (tid(t), rid(c));
    pool_ref_ok(b, field(b, t, c, C_USER_OFF), field(b, t, c, C_USER_LEN), tb, rec)?;
    list_ok(b, field(b, t, c, C_PATHS_OFF), field(b, t, c, C_PATHS_LEN), tb, rec)?;
    list_ok(b, field(b, t, c, C_SECCOMP_OFF), field(b, t, c, C_SECCOMP_LEN), tb, rec)
}

fn check_route_pool(b: &[u8], r: usize) -> (res: Result<(), DbError>)
    requires
        v1(b@),
        pool_valid(b@),
        r < tcnt(b@, T_ROUTES as int),
    ensures
        res is Ok ==> route_pool_ok(b@, r as int),
{
    let t = T_ROUTES;
    if field(b, t, r, R_KIND) == 0 {
        pool_ref_ok(b, field(b, t, r, R_A), field(b, t, r, R_B), tid(t), rid(r))
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
pub(crate) proof fn lemma_elem_start(s: Seq<u8>, es: int, i: int, p: int)
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

/// The element rule of `kind`: [`env_entry_ok`] for 0, [`decimal_ok`] for 1,
/// [`path_entry_ok`] for 2, [`launch_key_ok`] for 3.
pub open spec fn elem_ok(e: Seq<u8>, kind: u32) -> bool {
    if kind == 0 {
        env_entry_ok(e)
    } else if kind == 1 {
        decimal_ok(e)
    } else if kind == 2 {
        path_entry_ok(e)
    } else {
        launch_key_ok(e)
    }
}

/// `s[p..q]` is a [`launch_key_ok`] key: non-empty, no `=`.
pub(crate) fn launch_key_ok_exec(s: &[u8], p: usize, q: usize) -> (ok: bool)
    requires
        p <= q <= s@.len(),
    ensures
        ok ==> launch_key_ok(s@.subrange(p as int, q as int)),
{
    if q == p {
        return false;
    }
    let ghost key = s@.subrange(p as int, q as int);
    let mut at = p;
    while at < q
        invariant
            p <= at <= q <= s@.len(),
            key == s@.subrange(p as int, q as int),
            forall|k: int| 0 <= k < at - p ==> #[trigger] key[k] != 0x3d,
        decreases q - at,
    {
        if s[at] == 0x3d {
            return false;
        }
        assert(key[(at - p) as int] == s@[at as int]);
        at += 1;
    }
    true
}

/// `s[p..q]` satisfies [`elem_ok`] for `kind`.
fn elem_ok_exec(s: &[u8], p: usize, q: usize, kind: u32) -> (ok: bool)
    requires
        p <= q <= s@.len(),
        kind <= 3,
    ensures
        ok ==> elem_ok(s@.subrange(p as int, q as int), kind),
{
    if kind == 0 {
        env_entry_ok_exec(s, p, q)
    } else if kind == 1 {
        decimal_ok_exec(s, p, q)
    } else if kind == 2 {
        path_entry_ok_exec(s, p, q)
    } else {
        launch_key_ok_exec(s, p, q)
    }
}

/// Every element of the NUL-separated list `s` passes the check of `kind`: [`env_entry_ok`]
/// for 0, [`decimal_ok`] for 1, [`path_entry_ok`] for 2, [`launch_key_ok`] for 3.
#[must_use]
pub fn elements_ok(s: &[u8], kind: u32) -> (ok: bool)
    requires
        nul_list(s@),
        kind <= 3,
    ensures
        ok && kind == 0 ==> env_list_ok(s@),
        ok && kind == 1 ==> seccomp_list_ok(s@),
        ok && kind == 2 ==> paths_list_ok(s@),
        ok && kind == 3 ==> launch_keys_ok(s@),
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
            kind <= 3,
            es <= i <= n,
            es == 0 || s@[es - 1] == 0,
            forall|k: int| es <= k < i ==> #[trigger] s@[k] != 0,
            forall|p: int, q: int| #[trigger]
                is_elem(s@, p, q) && q < i ==> elem_ok(s@.subrange(p, q), kind),
        decreases n - i,
    {
        if s[i] == 0 {
            if !elem_ok_exec(s, es, i, kind) {
                return false;
            }
            assert forall|p: int, q: int| #[trigger] is_elem(s@, p, q) && q < i + 1 implies elem_ok(
                s@.subrange(p, q),
                kind,
            ) by {
                if q == i {
                    lemma_elem_start(s@, es as int, i as int, p);
                }
            }
            es = i + 1;
        }
        i += 1;
    }
    if !elem_ok_exec(s, es, n, kind) {
        return false;
    }
    assert forall|p: int, q: int| #[trigger] is_elem(s@, p, q) implies elem_ok(
        s@.subrange(p, q),
        kind,
    ) by {
        if q == n {
            lemma_elem_start(s@, es as int, n as int, p);
        }
    }
    true
}

/// The elements of the NUL-separated list `s` ([`elems`]): a bounded count of its NULs.
#[must_use]
pub fn count_elements(s: &[u8]) -> (n: usize)
    requires
        s@.len() <= 0x1000_0000,
    ensures
        n as int == elems(s@),
{
    let len = s.len();
    if len == 0 {
        return 0;
    }
    let mut count: usize = 0;
    let mut i: usize = 0;
    while i < len
        invariant
            len == s@.len() <= 0x1000_0000,
            i <= len,
            count <= i,
            count as int == nuls(s@.subrange(0, i as int)),
        decreases len - i,
    {
        assert(s@.subrange(0, i + 1).drop_last() =~= s@.subrange(0, i as int));
        assert(s@.subrange(0, i + 1).last() == s@[i as int]);
        if s[i] == 0 {
            count += 1;
        }
        i += 1;
    }
    assert(s@.subrange(0, len as int) =~= s@);
    count + 1
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

/// The pool string `off..off + len` is a canonical absolute path (V4).
pub(crate) fn cwd_ok_exec(b: &[u8], off: u32, len: u32) -> (ok: bool)
    requires
        v1(b@),
        pool_ref(b@, off as int, len as int),
    ensures
        ok ==> cwd_ok(b@, off as int, len as int),
{
    assert(table_ok(b@, T_POOL as int));
    let a = header_word(b, 4 + 2 * T_POOL) as usize + off as usize;
    let ok = canonical_exec(b, a, a + len as usize);
    proof {
        if ok {
            assert(pool_slice(b@, off as int, len as int) =~= b@.subrange(
                a as int,
                a as int + len as int,
            ));
        }
    }
    ok
}

/// The pool list `off..off + len` holds only [`path_entry_ok`] entries (V4).
pub(crate) fn paths_list_ok_exec(b: &[u8], off: u32, len: u32) -> (ok: bool)
    requires
        v1(b@),
        list_ref(b@, off as int, len as int),
    ensures
        ok ==> paths_list_ok(pool_slice(b@, off as int, len as int)),
{
    assert(table_ok(b@, T_POOL as int));
    let a = header_word(b, 4 + 2 * T_POOL) as usize + off as usize;
    let s = vstd::slice::slice_subrange(b, a, a + len as usize);
    elements_ok(s, 2)
}

/// Checks every pool reference of every record (V2).
pub(crate) fn check_pool_refs(b: &[u8]) -> (r: Result<(), DbError>)
    requires
        v1(b@),
    ensures
        r is Ok ==> v2(b@),
{
    assert(table_ok(b@, T_POOL as int));
    let start = header_word(b, 4 + 2 * T_POOL) as usize;
    let size = header_word(b, 5 + 2 * T_POOL) as usize;
    if let Err(at) = utf8_check(b, start, start + size) {
        return Err(DbError::Utf8 { offset: rid(at - start) });
    }
    assert(pool_valid(b@));
    let n = header_word(b, 5 + 2 * T_NODES) as usize;
    let mut i: usize = 0;
    while i < n
        invariant
            v1(b@),
            pool_valid(b@),
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
            pool_valid(b@),
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
            pool_valid(b@),
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
            pool_valid(b@),
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
