// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! V3 and V4 for the records: indices in range, enums in range, consistent fields, the group
//! and edge tables tiled, and the nodes sorted by name.
#![allow(clippy::many_single_char_names)] // `b`, `n`, `i`, `g`, `x`, `k` follow the spec names

use super::header::{field, header_word};
use super::keys::launch_keys_exec;
use super::paths::{first_elem_len, paths_cover_exec, paths_shape_exec};
use super::pool::{
    cwd_ok_exec, env_list_ok_exec, paths_list_ok_exec, pool_bytes, seccomp_list_ok_exec,
};
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use super::spec::*;
use super::{DbError, rid, tid};
#[allow(clippy::wildcard_imports)] // the layout constants, used throughout
use crate::layout::*;
use vstd::prelude::*;

verus! {

fn index_or_none_ok(v: u32, n: u32) -> (r: bool)
    ensures
        r == index_or_none(v as int, n as int),
{
    v == NONE || v < n
}

/// Every limit of record `i` of table `t` is [`limit_ok`] (`mask` is its limit mask word).
#[allow(clippy::cast_possible_truncation)]  // `k < RLIMIT_COUNT`, so the shift count fits
#[allow(unused_variables)]  // `mask_w` appears only in the contract
pub(crate) fn check_limits(
    b: &[u8],
    t: usize,
    i: usize,
    mask_w: usize,
    base_w: usize,
    mask: u32,
) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        t < T_POOL,
        i < tcnt(b@, t as int),
        mask_w < spec_words(t as int),
        base_w + 2 * RLIMIT_COUNT <= spec_words(t as int),
        mask == rw(b@, t as int, i as int, mask_w as int) as u32,
    ensures
        r is Ok ==> forall|k: usize|
            k < RLIMIT_COUNT ==> #[trigger] limit_ok(b@, t as int, i as int, mask_w, base_w, k),
{
    let mut k: usize = 0;
    while k < RLIMIT_COUNT
        invariant
            v1(b@),
            t < T_POOL,
            i < tcnt(b@, t as int),
            mask_w < spec_words(t as int),
            base_w + 2 * RLIMIT_COUNT <= spec_words(t as int),
            mask == rw(b@, t as int, i as int, mask_w as int) as u32,
            k <= RLIMIT_COUNT,
            forall|j: usize|
                j < k ==> #[trigger] limit_ok(b@, t as int, i as int, mask_w, base_w, j),
        decreases RLIMIT_COUNT - k,
    {
        let lo = field(b, t, i, base_w + 2 * k);
        let hi = field(b, t, i, base_w + 2 * k + 1);
        let bad = if (mask >> (k as u32)) & 1 == 0 {
            lo != 0 || hi != 0
        } else {
            (k == RLIMIT_NOFILE as usize && ((lo == 0 && hi == 0) || (lo == u32::MAX && hi
                == u32::MAX))) || (k == RLIMIT_NICE as usize && (hi != 0 || lo > MAX_RLIMIT_NICE))
                || (k == RLIMIT_RTPRIO as usize && (hi != 0 || lo > MAX_RLIMIT_RTPRIO))
        };
        if bad {
            return Err(DbError::Consistency { table: tid(t), record: rid(i) });
        }
        k += 1;
    }
    Ok(())
}

fn check_node(b: &[u8], i: usize) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        v2(b@),
        i < nodes(b@),
    ensures
        r is Ok ==> node_index_ok(b@, i as int) && node_enum_ok(b@, i as int),
{
    let t = T_NODES;
    assert(node_pool_ok(b@, i as int));
    let index = DbError::Index { table: tid(t), record: rid(i) };
    let routes = header_word(b, 5 + 2 * T_ROUTES);
    let creds = header_word(b, 5 + 2 * T_CREDS);
    if !index_or_none_ok(field(b, t, i, N_OUTPUT), routes) || !index_or_none_ok(
        field(b, t, i, N_ERRORS),
        routes,
    ) || !index_or_none_ok(field(b, t, i, N_CRED), creds) {
        return Err(index);
    }
    let kind = field(b, t, i, N_KIND);
    let policy = field(b, t, i, N_RESTART_POLICY);
    if kind > 2 || field(b, t, i, N_READY_KIND) > 3 || policy > 2 || field(b, t, i, N_STOP_MODE) > 1
        || field(b, t, i, N_UMASK) > MAX_UMASK || field(b, t, i, N_RELOAD) > 3 || field(
        b,
        t,
        i,
        N_LAUNCH_CONCURRENCY,
    ) > MAX_LAUNCH_CONCURRENCY || field(b, t, i, N_LAUNCH_ARGV_TAIL) > MAX_ARGV_TAIL || field(
        b,
        t,
        i,
        N_LAUNCH_FDS,
    ) > 7 {
        return Err(DbError::Enum { table: tid(t), record: rid(i) });
    }
    let mask = field(b, t, i, N_RLIMIT_MASK);
    if mask & !RLIMIT_MASK_ALLOWED != 0 {
        return Err(DbError::Enum { table: tid(t), record: rid(i) });
    }
    check_limits(b, T_NODES, i, N_RLIMIT_MASK, N_RLIMIT_BASE, mask)?;
    let cred = field(b, t, i, N_CRED);
    if (kind <= 1 && cred == NONE) || (kind == 2 && cred != NONE) {
        return Err(DbError::Consistency { table: tid(t), record: rid(i) });
    }
    if !cwd_ok_exec(b, field(b, t, i, N_CWD_OFF), field(b, t, i, N_CWD_LEN)) || !env_list_ok_exec(
        b,
        field(b, t, i, N_ENV_OFF),
        field(b, t, i, N_ENV_LEN),
    ) {
        return Err(DbError::Consistency { table: tid(t), record: rid(i) });
    }
    let concurrency = field(b, t, i, N_LAUNCH_CONCURRENCY);
    if (kind != 1 && concurrency != 0) || (concurrency == 0 && (field(b, t, i, N_LAUNCH_ARGV_TAIL)
        != 0 || field(b, t, i, N_LAUNCH_ENV_LEN) != 0 || field(b, t, i, N_LAUNCH_FDS) != 0)) {
        return Err(DbError::Consistency { table: tid(t), record: rid(i) });
    }
    if !launch_keys_exec(b, field(b, t, i, N_LAUNCH_ENV_OFF), field(b, t, i, N_LAUNCH_ENV_LEN)) {
        return Err(DbError::Consistency { table: tid(t), record: rid(i) });
    }
    if (kind != 0 && policy != 0) || (kind == 2 && field(b, t, i, N_EXEC_LEN) != 0) || field(
        b,
        t,
        i,
        N_RESTART_DELAY_MS,
    ) < MIN_DELAY_MS || field(b, t, i, N_STOP_GRACE_MS) < MIN_DELAY_MS || (field(
        b,
        t,
        i,
        N_RESTART_MAX,
    ) > 0 && field(b, t, i, N_RESTART_WINDOW_MS) == 0) {
        return Err(DbError::Consistency { table: tid(t), record: rid(i) });
    }
    Ok(())
}

fn check_edge(b: &[u8], x: usize) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        x < tcnt(b@, T_EDGES as int),
    ensures
        r is Ok ==> edge_index_ok(b@, x as int) && edge_enum_ok(b@, x as int),
{
    let t = T_EDGES;
    let kind = field(b, t, x, E_TARGET_KIND);
    let mode = field(b, t, x, E_MODE);
    if kind > 1 || mode > 1 || field(b, t, x, E_RESTART_ON) > 3 || field(b, t, x, E_FLAGS) > 3 {
        return Err(DbError::Enum { table: tid(t), record: rid(x) });
    }
    if kind == 0 && field(b, t, x, E_TARGET) >= header_word(b, 5 + 2 * T_NODES) {
        return Err(DbError::Index { table: tid(t), record: rid(x) });
    }
    if (kind == 0 && field(b, t, x, E_TARGET_LEN) != 0) || (mode == 0 && field(
        b,
        t,
        x,
        E_DEADLINE_MS,
    ) != 0) {
        return Err(DbError::Consistency { table: tid(t), record: rid(x) });
    }
    Ok(())
}

/// `s` is the user name `root`.
#[must_use]
pub fn is_root_exec(s: &[u8]) -> (r: bool)
    ensures
        r == is_root(s@),
{
    s.len() == 4 && s[0] == 0x72 && s[1] == 0x6f && s[2] == 0x6f && s[3] == 0x74
}

fn check_cred(b: &[u8], c: usize) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        v2(b@),
        c < tcnt(b@, T_CREDS as int),
    ensures
        r is Ok ==> cred_enum_ok(b@, c as int),
{
    let t = T_CREDS;
    assert(cred_pool_ok(b@, c as int));
    let nnp = field(b, t, c, C_NNP);
    let seccomp = field(b, t, c, C_SECCOMP);
    let seccomp_len = field(b, t, c, C_SECCOMP_LEN);
    if field(b, t, c, C_USER_LEN) == 0 || field(b, t, c, C_CAPS_HI) > 0x1ff || field(
        b,
        t,
        c,
        C_SECUREBITS,
    ) > 2 || nnp > 1 || field(b, t, c, C_NS) > 0x3f || field(b, t, c, C_USER_MAP) > 1 || seccomp > 3
        || ((seccomp <= 1) != (seccomp_len == 0)) {
        return Err(DbError::Enum { table: tid(t), record: rid(c) });
    }
    let ns = field(b, t, c, C_NS);
    if field(b, t, c, C_USER_MAP) == 1 && ns & 32 == 0 {
        return Err(DbError::Consistency { table: tid(t), record: rid(c) });
    }
    let user = pool_bytes(b, field(b, t, c, C_USER_OFF), field(b, t, c, C_USER_LEN));
    if ns & 32 != 0 && is_root_exec(user) {
        return Err(DbError::Consistency { table: tid(t), record: rid(c) });
    }
    let caps_lo = field(b, t, c, C_CAPS_LO);
    if nnp == 0 && (field(b, t, c, C_PATHS_LEN) > 0 || seccomp != 0) && caps_lo & CAP_SYS_ADMIN_MASK
        == 0 {
        assert(!has_sys_admin(b@, c as int));
        return Err(DbError::Consistency { table: tid(t), record: rid(c) });
    }
    if !seccomp_list_ok_exec(b, field(b, t, c, C_SECCOMP_OFF), seccomp_len) {
        return Err(DbError::Consistency { table: tid(t), record: rid(c) });
    }
    if !paths_list_ok_exec(b, field(b, t, c, C_PATHS_OFF), field(b, t, c, C_PATHS_LEN)) {
        return Err(DbError::Consistency { table: tid(t), record: rid(c) });
    }
    let paths = pool_bytes(b, field(b, t, c, C_PATHS_OFF), field(b, t, c, C_PATHS_LEN));
    if !paths_shape_exec(paths, field(b, t, c, C_NS)) {
        return Err(DbError::Consistency { table: tid(t), record: rid(c) });
    }
    Ok(())
}

/// A node with credentials runs inside its credential's path list (checked after the credentials).
fn check_node_paths(b: &[u8], i: usize) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        v2(b@),
        i < nodes(b@),
        node_index_ok(b@, i as int),
        forall|c: int| 0 <= c < tcnt(b@, T_CREDS as int) ==> #[trigger] cred_enum_ok(b@, c),
    ensures
        r is Ok ==> node_paths_ok(b@, i as int),
{
    let t = T_NODES;
    assert(node_pool_ok(b@, i as int));
    let cred = field(b, t, i, N_CRED);
    if cred == NONE {
        return Ok(());
    }
    assert(cred < tcnt(b@, T_CREDS as int));
    assert(cred_pool_ok(b@, cred as int));
    assert(cred_enum_ok(b@, cred as int));
    let c = cred as usize;
    let paths = pool_bytes(b, field(b, T_CREDS, c, C_PATHS_OFF), field(b, T_CREDS, c, C_PATHS_LEN));
    let exec = pool_bytes(b, field(b, t, i, N_EXEC_OFF), field(b, t, i, N_EXEC_LEN));
    let cwd = pool_bytes(b, field(b, t, i, N_CWD_OFF), field(b, t, i, N_CWD_LEN));
    let m = first_elem_len(exec);
    let exec0 = vstd::slice::slice_subrange(exec, 0, m);
    if !paths_cover_exec(paths, exec0, cwd) {
        return Err(DbError::Consistency { table: tid(t), record: rid(i) });
    }
    assert forall|e: Seq<u8>| is_first(exec@, e) implies paths_cover_ok(paths@, e, cwd@) by {
        if is_first(exec@, e) {
            if e.len() < m {
                assert(exec@[e.len() as int] != 0);
            }
            if e.len() > m {
                assert(e[m as int] != 0);
                assert(e[m as int] == exec@[m as int]);
            }
            assert(e.len() == m);
            assert(e =~= exec0@);
        }
    }
    Ok(())
}

fn check_route(b: &[u8], r: usize) -> (res: Result<(), DbError>)
    requires
        v1(b@),
        r < tcnt(b@, T_ROUTES as int),
    ensures
        res is Ok ==> route_index_ok(b@, r as int) && route_enum_ok(b@, r as int),
{
    let t = T_ROUTES;
    let kind = field(b, t, r, R_KIND);
    if kind > 1 {
        return Err(DbError::Enum { table: tid(t), record: rid(r) });
    }
    if kind == 1 {
        let a = field(b, t, r, R_A);
        if a >= header_word(b, 5 + 2 * T_NODES) {
            return Err(DbError::Index { table: tid(t), record: rid(r) });
        }
        if field(b, T_NODES, a as usize, N_KIND) != 0 || field(b, t, r, R_B) != 0 {
            return Err(DbError::Consistency { table: tid(t), record: rid(r) });
        }
    }
    Ok(())
}

/// `b[pa..pa + la]` sorts strictly before `b[pc..pc + lc]`, bytewise.
pub(crate) fn bytes_lt(b: &[u8], pa: usize, la: usize, pc: usize, lc: usize) -> (r: bool)
    requires
        pa + la <= b@.len(),
        pc + lc <= b@.len(),
    ensures
        r ==> lex_lt(b@.subrange(pa as int, pa + la), b@.subrange(pc as int, pc + lc)),
{
    let ghost a = b@.subrange(pa as int, pa + la);
    let ghost c = b@.subrange(pc as int, pc + lc);
    assert(b@.len() == b.len());
    let mut k: usize = 0;
    while k < la && k < lc
        invariant
            pa + la <= b.len(),
            pc + lc <= b.len(),
            a == b@.subrange(pa as int, pa + la),
            c == b@.subrange(pc as int, pc + lc),
            k <= la,
            k <= lc,
            a.subrange(0, k as int) == c.subrange(0, k as int),
        decreases la - k,
    {
        let x = b[pa + k];
        let y = b[pc + k];
        if x != y {
            assert(a[k as int] == x && c[k as int] == y);
            return x < y;
        }
        assert(a.subrange(0, k + 1) =~= a.subrange(0, k as int).push(x));
        assert(c.subrange(0, k + 1) =~= c.subrange(0, k as int).push(y));
        k += 1;
    }
    k == la && k < lc
}

/// Checks that node names are strictly ascending (V4, `Order`).
fn check_names(b: &[u8]) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        v2(b@),
    ensures
        r is Ok ==> forall|i: int| 0 < i < nodes(b@) ==> #[trigger] name_sorted(b@, i),
{
    let n = header_word(b, 5 + 2 * T_NODES) as usize;
    let pool = header_word(b, 4 + 2 * T_POOL) as usize;
    let mut i: usize = 1;
    while i < n
        invariant
            v1(b@),
            v2(b@),
            n == nodes(b@),
            pool == toff(b@, T_POOL as int),
            1 <= i,
            i <= n || n == 0,
            forall|j: int| 0 < j < i && j < n ==> #[trigger] name_sorted(b@, j),
        decreases n - i,
    {
        assert(node_pool_ok(b@, i - 1));
        assert(node_pool_ok(b@, i as int));
        assert(table_ok(b@, T_POOL as int));
        let pa = pool + field(b, T_NODES, i - 1, N_NAME_OFF) as usize;
        let la = field(b, T_NODES, i - 1, N_NAME_LEN) as usize;
        let pc = pool + field(b, T_NODES, i, N_NAME_OFF) as usize;
        let lc = field(b, T_NODES, i, N_NAME_LEN) as usize;
        if !bytes_lt(b, pa, la, pc, lc) {
            return Err(DbError::Order);
        }
        i += 1;
    }
    Ok(())
}

/// Checks every record (V3 less the lists, and V4).
#[allow(clippy::too_many_lines)]  // one loop per table, each with its Verus invariants
pub(crate) fn check_records(b: &[u8]) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        v2(b@),
    ensures
        r is Ok ==> {
            &&& forall|i: int| 0 <= i < nodes(b@) ==> #[trigger] node_index_ok(b@, i)
            &&& forall|x: int| 0 <= x < tcnt(b@, T_EDGES as int) ==> #[trigger] edge_index_ok(b@, x)
            &&& forall|r: int|
                0 <= r < tcnt(b@, T_ROUTES as int) ==> #[trigger] route_index_ok(b@, r)
            &&& tiled(b@)
            &&& v4(b@)
        },
{
    let n = header_word(b, 5 + 2 * T_NODES) as usize;
    let groups = header_word(b, 5 + 2 * T_GROUPS) as usize;
    let edges = header_word(b, 5 + 2 * T_EDGES) as usize;
    assert(table_ok(b@, T_NODES as int));
    assert(table_ok(b@, T_GROUPS as int));
    assert(table_ok(b@, T_EDGES as int));
    // Nodes, and the running sum of their groups.
    let mut sum: usize = 0;
    let mut i: usize = 0;
    while i < n
        invariant
            v1(b@),
            v2(b@),
            n == nodes(b@),
            n <= MAX_NODES,
            i <= n,
            sum == ngsum(b@, i as int),
            sum <= MAX_GROUPS_PER_NODE * i,
            forall|j: int| 0 <= j < i ==> #[trigger] node_index_ok(b@, j),
            forall|j: int| 0 <= j < i ==> #[trigger] node_enum_ok(b@, j),
            forall|j: int| 0 <= j < i ==> #[trigger] node_tile_ok(b@, j),
        decreases n - i,
    {
        check_node(b, i)?;
        let count = field(b, T_NODES, i, N_GROUP_COUNT) as usize;
        if field(b, T_NODES, i, N_GROUP_FIRST) as usize != sum || count > MAX_GROUPS_PER_NODE {
            return Err(DbError::Tiling { table: tid(T_NODES), record: rid(i) });
        }
        sum += count;
        i += 1;
    }
    if sum != groups {
        return Err(DbError::Tiling { table: tid(T_NODES), record: rid(n) });
    }
    // Groups, and the running sum of their edges.

    let mut sum: usize = 0;
    let mut g: usize = 0;
    while g < groups
        invariant
            v1(b@),
            groups == tcnt(b@, T_GROUPS as int),
            groups <= MAX_GROUPS,
            g <= groups,
            sum == gesum(b@, g as int),
            sum <= MAX_EDGES_PER_GROUP * g,
            forall|j: int| 0 <= j < g ==> #[trigger] group_enum_ok(b@, j),
            forall|j: int| 0 <= j < g ==> #[trigger] group_tile_ok(b@, j),
        decreases groups - g,
    {
        if field(b, T_GROUPS, g, G_KIND) > 3 {
            return Err(DbError::Enum { table: tid(T_GROUPS), record: rid(g) });
        }
        let count = field(b, T_GROUPS, g, G_EDGE_COUNT) as usize;
        if field(b, T_GROUPS, g, G_EDGE_FIRST) as usize != sum || count > MAX_EDGES_PER_GROUP {
            return Err(DbError::Tiling { table: tid(T_GROUPS), record: rid(g) });
        }
        sum += count;
        g += 1;
    }
    if sum != edges {
        return Err(DbError::Tiling { table: tid(T_GROUPS), record: rid(groups) });
    }
    let mut x: usize = 0;
    while x < edges
        invariant
            v1(b@),
            edges == tcnt(b@, T_EDGES as int),
            x <= edges,
            forall|j: int| 0 <= j < x ==> #[trigger] edge_index_ok(b@, j),
            forall|j: int| 0 <= j < x ==> #[trigger] edge_enum_ok(b@, j),
        decreases edges - x,
    {
        check_edge(b, x)?;
        x += 1;
    }
    let creds = header_word(b, 5 + 2 * T_CREDS) as usize;
    let mut c: usize = 0;
    while c < creds
        invariant
            v1(b@),
            v2(b@),
            creds == tcnt(b@, T_CREDS as int),
            c <= creds,
            forall|j: int| 0 <= j < c ==> #[trigger] cred_enum_ok(b@, j),
        decreases creds - c,
    {
        check_cred(b, c)?;
        c += 1;
    }
    let mut i: usize = 0;
    while i < n
        invariant
            v1(b@),
            v2(b@),
            n == nodes(b@),
            i <= n,
            forall|j: int| 0 <= j < nodes(b@) ==> #[trigger] node_index_ok(b@, j),
            forall|j: int| 0 <= j < tcnt(b@, T_CREDS as int) ==> #[trigger] cred_enum_ok(b@, j),
            forall|j: int| 0 <= j < i ==> #[trigger] node_paths_ok(b@, j),
        decreases n - i,
    {
        check_node_paths(b, i)?;
        i += 1;
    }
    let routes = header_word(b, 5 + 2 * T_ROUTES) as usize;
    let mut r: usize = 0;
    while r < routes
        invariant
            v1(b@),
            routes == tcnt(b@, T_ROUTES as int),
            r <= routes,
            forall|j: int| 0 <= j < r ==> #[trigger] route_index_ok(b@, j),
            forall|j: int| 0 <= j < r ==> #[trigger] route_enum_ok(b@, j),
        decreases routes - r,
    {
        check_route(b, r)?;
        r += 1;
    }
    check_names(b)?;
    let rules = header_word(b, 5 + 2 * T_POLICY) as usize;
    let heads = header_word(b, 5 + 2 * T_POLICY_HEAD) as usize;
    if rules > 0 && heads != 1 {
        return Err(DbError::Consistency { table: tid(T_POLICY), record: 0 });
    }
    let mut p: usize = 0;
    while p < rules
        invariant
            v1(b@),
            v2(b@),
            rules == tcnt(b@, T_POLICY as int),
            p <= rules,
            forall|j: int| 0 <= j < p ==> #[trigger] policy_rule_ok(b@, j),
        decreases rules - p,
    {
        super::policy::check_policy_rule(b, p)?;
        p += 1;
    }
    let mut h: usize = 0;
    while h < heads
        invariant
            v1(b@),
            heads == tcnt(b@, T_POLICY_HEAD as int),
            h <= heads,
            forall|j: int| 0 <= j < h ==> #[trigger] policy_head_ok(b@, j),
        decreases heads - h,
    {
        super::policy::check_policy_head(b, h)?;
        h += 1;
    }
    Ok(())
}

} // verus!
