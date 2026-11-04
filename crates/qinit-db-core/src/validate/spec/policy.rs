// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The policy tables (sandbox design §6.3): pool references, enums and the shape of one rule
//! record and of the header record.
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only use: Verus erases it
use super::pool::*;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only use: Verus erases it
use super::records::*;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only use: Verus erases it
use super::tables::*;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use crate::layout::*;
use vstd::prelude::*;

verus! {

/// Rule `p`, word `w`.
pub open spec fn pf(b: Seq<u8>, p: int, w: usize) -> int {
    rw(b, T_POLICY as int, p, w as int)
}

/// Header record `h`, word `w`.
pub open spec fn hf(b: Seq<u8>, h: int, w: usize) -> int {
    rw(b, T_POLICY_HEAD as int, h, w as int)
}

/// A byte of a node name (`[A-Za-z0-9._@:+-]`), `*`, or `~`.
pub open spec fn pattern_byte(c: u8) -> bool {
    ||| 0x30 <= c <= 0x39
    ||| 0x41 <= c <= 0x5a
    ||| 0x61 <= c <= 0x7a
    ||| c == 0x2e
    ||| c == 0x5f
    ||| c == 0x40
    ||| c == 0x3a
    ||| c == 0x2b
    ||| c == 0x2d
    ||| c == 0x2a
    ||| c == 0x7e
}

/// A rule's pattern: 1 to `MAX_PATTERN_LEN` pattern bytes.
pub open spec fn pattern_ok(s: Seq<u8>) -> bool {
    &&& 1 <= s.len() <= MAX_PATTERN_LEN
    &&& forall|k: int| 0 <= k < s.len() ==> #[trigger] pattern_byte(s[k])
}

/// A user name: `^[a-z_][a-z0-9_-]{0,31}$`.
pub open spec fn user_name_ok(e: Seq<u8>) -> bool {
    &&& 1 <= e.len() <= 32
    &&& (0x61 <= e[0] <= 0x7a || e[0] == 0x5f)
    &&& forall|k: int|
        1 <= k < e.len() ==> (0x61 <= #[trigger] e[k] <= 0x7a || 0x30 <= e[k] <= 0x39 || e[k]
            == 0x5f || e[k] == 0x2d)
}

/// Every element of the NUL-separated list `s` is a [`user_name_ok`] name.
pub open spec fn users_list_ok(s: Seq<u8>) -> bool {
    s.len() == 0 || forall|p: int, q: int| #[trigger]
        is_elem(s, p, q) ==> user_name_ok(s.subrange(p, q))
}

/// V2 for rule `p`.
pub open spec fn policy_pool_ok(b: Seq<u8>, p: int) -> bool {
    &&& pool_ref(b, pf(b, p, P_PATTERN_OFF), pf(b, p, P_PATTERN_LEN))
    &&& list_ref(b, pf(b, p, P_USERS_OFF), pf(b, p, P_USERS_LEN))
}

/// A limit of record `i` of table `t`, its mask at word `mask_w` and its pairs from `base_w`:
/// both words 0 when unset; `nofile` at least 1 and finite; `nice` and `rtprio` within their
/// ceilings.
pub open spec fn limit_ok(
    b: Seq<u8>,
    t: int,
    i: int,
    mask_w: usize,
    base_w: usize,
    r: usize,
) -> bool {
    let lo = rw(b, t, i, (base_w + 2 * r) as int);
    let hi = rw(b, t, i, (base_w + 2 * r + 1) as int);
    if ((rw(b, t, i, mask_w as int) as u32) >> (r as u32)) & 1 == 0 {
        lo == 0 && hi == 0
    } else {
        &&& (r == RLIMIT_NOFILE as usize ==> !(lo == 0 && hi == 0) && !(lo == u32::MAX as int && hi
            == u32::MAX as int))
        &&& (r == RLIMIT_NICE as usize ==> hi == 0 && lo <= MAX_RLIMIT_NICE as int)
        &&& (r == RLIMIT_RTPRIO as usize ==> hi == 0 && lo <= MAX_RLIMIT_RTPRIO as int)
    }
}

/// The limit mask of the record holds no bit but `RLIMIT_MASK_ALLOWED`'s and every limit is
/// [`limit_ok`].
pub open spec fn limits_ok(b: Seq<u8>, t: int, i: int, mask_w: usize, base_w: usize) -> bool {
    &&& (rw(b, t, i, mask_w as int) as u32) & !RLIMIT_MASK_ALLOWED == 0
    &&& forall|r: usize| r < RLIMIT_COUNT ==> #[trigger] limit_ok(b, t, i, mask_w, base_w, r)
}

/// V4 for rule `p`: flags and enums in range, a pattern and users that parse, and ceilings that
/// follow the node limit rules.
pub open spec fn policy_rule_ok(b: Seq<u8>, p: int) -> bool {
    &&& pf(b, p, P_USERS_ANY) <= 1
    &&& pf(b, p, P_CAPS_HI) <= 0x1ff
    &&& pf(b, p, P_REQUIRE_NNP) <= 1
    &&& pf(b, p, P_REQUIRE_SECCOMP) <= 1
    &&& pf(b, p, P_ALLOW_USERNS) <= 2
    &&& pattern_ok(pool_slice(b, pf(b, p, P_PATTERN_OFF), pf(b, p, P_PATTERN_LEN)))
    &&& (pf(b, p, P_USERS_ANY) == 1 ==> pf(b, p, P_USERS_LEN) == 0)
    &&& users_list_ok(pool_slice(b, pf(b, p, P_USERS_OFF), pf(b, p, P_USERS_LEN)))
    &&& limits_ok(b, T_POLICY as int, p, P_RLIMIT_MASK, P_RLIMIT_BASE)
}

/// V4 for the header record `h`.
pub open spec fn policy_head_ok(b: Seq<u8>, h: int) -> bool {
    &&& hf(b, h, PH_ALLOW) <= 1
    &&& limits_ok(b, T_POLICY_HEAD as int, h, PH_RLIMIT_MASK, PH_RLIMIT_BASE)
}

/// V3/V4 for the pair of tables: rules need their header.
pub open spec fn policy_tables_ok(b: Seq<u8>) -> bool {
    tcnt(b, T_POLICY as int) > 0 ==> tcnt(b, T_POLICY_HEAD as int) == 1
}

} // verus!
