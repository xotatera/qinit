// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! V3 and V4: cross-table indices, tiling, enums and name order.
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only use: Verus erases it
use super::paths::*;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only use: Verus erases it
use super::pool::*;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only use: Verus erases it
use super::tables::*;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use crate::layout::*;
use vstd::prelude::*;

verus! {

/// `NONE` or an index below `n`.
pub open spec fn index_or_none(v: int, n: int) -> bool {
    v == NONE as int || v < n
}

pub open spec fn node_index_ok(b: Seq<u8>, i: int) -> bool {
    &&& index_or_none(nf(b, i, N_OUTPUT), tcnt(b, T_ROUTES as int))
    &&& index_or_none(nf(b, i, N_ERRORS), tcnt(b, T_ROUTES as int))
    &&& index_or_none(nf(b, i, N_CRED), tcnt(b, T_CREDS as int))
}

pub open spec fn edge_index_ok(b: Seq<u8>, x: int) -> bool {
    ef(b, x, E_TARGET_KIND) == 0 ==> ef(b, x, E_TARGET) < nodes(b)
}

pub open spec fn route_index_ok(b: Seq<u8>, r: int) -> bool {
    rf(b, r, R_KIND) == 1 ==> rf(b, r, R_A) < nodes(b)
}

pub open spec fn list_index_ok(b: Seq<u8>, t: usize, k: int) -> bool {
    lf(b, t, k) < nodes(b)
}

/// The groups before node `i`: where node `i`'s groups start when the table is tiled.
pub open spec fn ngsum(b: Seq<u8>, i: int) -> int
    decreases i,
{
    if i <= 0 {
        0
    } else {
        ngsum(b, i - 1) + nf(b, i - 1, N_GROUP_COUNT)
    }
}

/// The edges before group `g`.
pub open spec fn gesum(b: Seq<u8>, g: int) -> int
    decreases g,
{
    if g <= 0 {
        0
    } else {
        gesum(b, g - 1) + gf(b, g - 1, G_EDGE_COUNT)
    }
}

/// Node `i`'s groups start at the running sum, and there are few enough.
pub open spec fn node_tile_ok(b: Seq<u8>, i: int) -> bool {
    &&& nf(b, i, N_GROUP_FIRST) == ngsum(b, i)
    &&& nf(b, i, N_GROUP_COUNT) <= MAX_GROUPS_PER_NODE
}

/// Group `g`'s edges start at the running sum, and there are few enough.
pub open spec fn group_tile_ok(b: Seq<u8>, g: int) -> bool {
    &&& gf(b, g, G_EDGE_FIRST) == gesum(b, g)
    &&& gf(b, g, G_EDGE_COUNT) <= MAX_EDGES_PER_GROUP
}

/// The nodes tile the group table and the groups tile the edge table.
pub open spec fn tiled(b: Seq<u8>) -> bool {
    &&& forall|i: int| 0 <= i < nodes(b) ==> #[trigger] node_tile_ok(b, i)
    &&& ngsum(b, nodes(b)) == tcnt(b, T_GROUPS as int)
    &&& forall|g: int| 0 <= g < tcnt(b, T_GROUPS as int) ==> #[trigger] group_tile_ok(b, g)
    &&& gesum(b, tcnt(b, T_GROUPS as int)) == tcnt(b, T_EDGES as int)
}

/// V3: every cross-table index is `NONE` (where allowed) or in range, and the group and edge
/// runs tile their tables.
pub open spec fn v3(b: Seq<u8>) -> bool {
    &&& forall|i: int| 0 <= i < nodes(b) ==> #[trigger] node_index_ok(b, i)
    &&& forall|x: int| 0 <= x < tcnt(b, T_EDGES as int) ==> #[trigger] edge_index_ok(b, x)
    &&& forall|r: int| 0 <= r < tcnt(b, T_ROUTES as int) ==> #[trigger] route_index_ok(b, r)
    &&& forall|k: int|
        0 <= k < tcnt(b, T_ENABLED as int) ==> #[trigger] list_index_ok(b, T_ENABLED, k)
    &&& forall|k: int|
        0 <= k < tcnt(b, T_PRESYSLOG as int) ==> #[trigger] list_index_ok(b, T_PRESYSLOG, k)
    &&& tiled(b)
}

/// Node `i`'s launch environment keys.
pub open spec fn launch_env(b: Seq<u8>, i: int) -> Seq<u8> {
    pool_slice(b, nf(b, i, N_LAUNCH_ENV_OFF), nf(b, i, N_LAUNCH_ENV_LEN))
}

/// Adjacent elements of the NUL-separated list `s` ascend strictly, bytewise.
pub open spec fn keys_ascending(s: Seq<u8>) -> bool {
    forall|p1: int, q1: int, p2: int, q2: int|
        #![trigger is_elem(s, p1, q1), is_elem(s, p2, q2)]
        is_elem(s, p1, q1) && is_elem(s, p2, q2) && q1 + 1 == p2 ==> lex_lt(
            s.subrange(p1, q1),
            s.subrange(p2, q2),
        )
}

/// One resource limit of a node: both words 0 when unset; `nofile` at least 1 and finite;
/// `nice` and `rtprio` within their ceilings.
pub open spec fn rlimit_ok(b: Seq<u8>, i: int, r: usize) -> bool {
    super::policy::limit_ok(b, T_NODES as int, i, N_RLIMIT_MASK, N_RLIMIT_BASE, r)
}

/// The limit mask holds no bit but `RLIMIT_MASK_ALLOWED`'s and every limit is [`rlimit_ok`].
pub open spec fn rlimits_ok(b: Seq<u8>, i: int) -> bool {
    &&& (nf(b, i, N_RLIMIT_MASK) as u32) & !RLIMIT_MASK_ALLOWED == 0
    &&& forall|r: usize| r < RLIMIT_COUNT ==> #[trigger] rlimit_ok(b, i, r)
}

pub open spec fn node_enum_ok(b: Seq<u8>, i: int) -> bool {
    &&& nf(b, i, N_KIND) <= 2
    &&& nf(b, i, N_READY_KIND) <= 3
    &&& nf(b, i, N_RESTART_POLICY) <= 2
    &&& (nf(b, i, N_KIND) != 0 ==> nf(b, i, N_RESTART_POLICY) == 0)
    &&& (nf(b, i, N_KIND) == 2 ==> nf(b, i, N_EXEC_LEN) == 0)
    &&& nf(b, i, N_STOP_MODE) <= 1
    &&& nf(b, i, N_RESTART_DELAY_MS) >= MIN_DELAY_MS
    &&& nf(b, i, N_STOP_GRACE_MS) >= MIN_DELAY_MS
    &&& (nf(b, i, N_RESTART_MAX) > 0 ==> nf(b, i, N_RESTART_WINDOW_MS) > 0)
    &&& nf(b, i, N_UMASK) <= MAX_UMASK
    &&& (nf(b, i, N_KIND) <= 1 ==> nf(b, i, N_CRED) != NONE)
    &&& (nf(b, i, N_KIND) == 2 ==> nf(b, i, N_CRED) == NONE)
    &&& cwd_ok(b, nf(b, i, N_CWD_OFF), nf(b, i, N_CWD_LEN))
    &&& env_list_ok(pool_slice(b, nf(b, i, N_ENV_OFF), nf(b, i, N_ENV_LEN)))
    &&& nf(b, i, N_RELOAD) <= 3
    &&& nf(b, i, N_LAUNCH_CONCURRENCY) <= MAX_LAUNCH_CONCURRENCY
    &&& nf(b, i, N_LAUNCH_ARGV_TAIL) <= MAX_ARGV_TAIL
    &&& nf(b, i, N_LAUNCH_FDS) <= 7
    &&& rlimits_ok(b, i)
    &&& (nf(b, i, N_KIND) != 1 ==> nf(b, i, N_LAUNCH_CONCURRENCY) == 0)
    &&& (nf(b, i, N_LAUNCH_CONCURRENCY) == 0 ==> nf(b, i, N_LAUNCH_ARGV_TAIL) == 0 && nf(
        b,
        i,
        N_LAUNCH_ENV_LEN,
    ) == 0 && nf(b, i, N_LAUNCH_FDS) == 0)
    &&& launch_keys_ok(launch_env(b, i))
    &&& keys_ascending(launch_env(b, i))
}

pub open spec fn group_enum_ok(b: Seq<u8>, g: int) -> bool {
    gf(b, g, G_KIND) <= 3
}

pub open spec fn edge_enum_ok(b: Seq<u8>, x: int) -> bool {
    &&& ef(b, x, E_TARGET_KIND) <= 1
    &&& ef(b, x, E_MODE) <= 1
    &&& ef(b, x, E_RESTART_ON) <= 3
    &&& ef(b, x, E_FLAGS) <= 3
    &&& (ef(b, x, E_TARGET_KIND) == 0 ==> ef(b, x, E_TARGET_LEN) == 0)
    &&& (ef(b, x, E_MODE) == 0 ==> ef(b, x, E_DEADLINE_MS) == 0)
}

/// The credential's capability word holds `CAP_SYS_ADMIN`.
pub open spec fn has_sys_admin(b: Seq<u8>, c: int) -> bool {
    (cf(b, c, C_CAPS_LO) as u32) & CAP_SYS_ADMIN_MASK != 0
}

pub open spec fn cred_enum_ok(b: Seq<u8>, c: int) -> bool {
    &&& cf(b, c, C_USER_LEN) >= 1
    &&& cf(b, c, C_CAPS_HI) <= 0x1ff
    &&& cf(b, c, C_SECUREBITS) <= 2
    &&& cf(b, c, C_NNP) <= 1
    &&& cf(b, c, C_NS) <= 0x3f
    &&& cf(b, c, C_USER_MAP) <= 1
    &&& cf(b, c, C_SECCOMP) <= 3
    &&& (cf(b, c, C_SECCOMP) <= 1) == (cf(b, c, C_SECCOMP_LEN) == 0)
    &&& (cf(b, c, C_NNP) == 0 && (cf(b, c, C_PATHS_LEN) > 0 || cf(b, c, C_SECCOMP) != 0)
        ==> has_sys_admin(b, c))
    &&& seccomp_list_ok(pool_slice(b, cf(b, c, C_SECCOMP_OFF), cf(b, c, C_SECCOMP_LEN)))
    &&& (cf(b, c, C_USER_MAP) == 1 ==> (cf(b, c, C_NS) as u32) & 32u32 != 0u32)
    &&& ((cf(b, c, C_NS) as u32) & 32u32 != 0u32 ==> !is_root(
        pool_slice(b, cf(b, c, C_USER_OFF), cf(b, c, C_USER_LEN)),
    ))
    &&& paths_list_ok(pool_slice(b, cf(b, c, C_PATHS_OFF), cf(b, c, C_PATHS_LEN)))
    &&& paths_shape_ok(
        pool_slice(b, cf(b, c, C_PATHS_OFF), cf(b, c, C_PATHS_LEN)),
        cf(b, c, C_NS) as u32,
    )
}

/// `s` is the user name `root`.
pub open spec fn is_root(s: Seq<u8>) -> bool {
    s.len() == 4 && s[0] == 0x72 && s[1] == 0x6f && s[2] == 0x6f && s[3] == 0x74
}

/// `e` is the first element of the NUL-separated list `s`: its bytes up to the first NUL.
pub open spec fn is_first(s: Seq<u8>, e: Seq<u8>) -> bool {
    &&& e.len() <= s.len()
    &&& e == s.subrange(0, e.len() as int)
    &&& (e.len() == s.len() || s[e.len() as int] == 0)
    &&& forall|k: int| 0 <= k < e.len() ==> #[trigger] e[k] != 0
}

/// A node with credentials runs inside its credential's path list: the program and the
/// working directory are covered.
pub open spec fn node_paths_ok(b: Seq<u8>, i: int) -> bool {
    nf(b, i, N_CRED) != NONE ==> forall|e: Seq<u8>|
        #![trigger is_first(pool_slice(b, nf(b, i, N_EXEC_OFF), nf(b, i, N_EXEC_LEN)), e)]
        is_first(pool_slice(b, nf(b, i, N_EXEC_OFF), nf(b, i, N_EXEC_LEN)), e) ==> paths_cover_ok(
            pool_slice(
                b,
                cf(b, nf(b, i, N_CRED) as int, C_PATHS_OFF),
                cf(b, nf(b, i, N_CRED) as int, C_PATHS_LEN),
            ),
            e,
            pool_slice(b, nf(b, i, N_CWD_OFF), nf(b, i, N_CWD_LEN)),
        )
}

pub open spec fn route_enum_ok(b: Seq<u8>, r: int) -> bool {
    &&& rf(b, r, R_KIND) <= 1
    &&& (rf(b, r, R_KIND) == 1 ==> nf(b, rf(b, r, R_A), N_KIND) == 0 && rf(b, r, R_B) == 0)
}

/// `a` sorts strictly before `c`, bytewise.
pub open spec fn lex_lt(a: Seq<u8>, c: Seq<u8>) -> bool {
    exists|k: int|
        #![trigger a.subrange(0, k)]
        0 <= k <= a.len() && k <= c.len() && a.subrange(0, k) == c.subrange(0, k) && ((k == a.len()
            && k < c.len()) || (k < a.len() && k < c.len() && a[k] < c[k]))
}

/// Node `i`'s name.
pub open spec fn name(b: Seq<u8>, i: int) -> Seq<u8> {
    pool_slice(b, nf(b, i, N_NAME_OFF), nf(b, i, N_NAME_LEN))
}

/// Node `i`'s name sorts after node `i - 1`'s.
pub open spec fn name_sorted(b: Seq<u8>, i: int) -> bool {
    lex_lt(name(b, i - 1), name(b, i))
}

/// V4: enums in range, reserved bits clear, the kind-dependent fields consistent, and the
/// nodes sorted by name.
pub open spec fn v4(b: Seq<u8>) -> bool {
    &&& forall|i: int| 0 <= i < nodes(b) ==> #[trigger] node_enum_ok(b, i)
    &&& forall|g: int| 0 <= g < tcnt(b, T_GROUPS as int) ==> #[trigger] group_enum_ok(b, g)
    &&& forall|x: int| 0 <= x < tcnt(b, T_EDGES as int) ==> #[trigger] edge_enum_ok(b, x)
    &&& forall|c: int| 0 <= c < tcnt(b, T_CREDS as int) ==> #[trigger] cred_enum_ok(b, c)
    &&& forall|i: int| 0 <= i < nodes(b) ==> #[trigger] node_paths_ok(b, i)
    &&& forall|r: int| 0 <= r < tcnt(b, T_ROUTES as int) ==> #[trigger] route_enum_ok(b, r)
    &&& forall|i: int| 0 < i < nodes(b) ==> #[trigger] name_sorted(b, i)
    &&& forall|p: int|
        0 <= p < tcnt(b, T_POLICY as int) ==> #[trigger] super::policy::policy_rule_ok(b, p)
    &&& forall|h: int|
        0 <= h < tcnt(b, T_POLICY_HEAD as int) ==> #[trigger] super::policy::policy_head_ok(b, h)
    &&& super::policy::policy_tables_ok(b)
}

} // verus!
