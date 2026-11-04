// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The policy tables' record checks (V2 and V4): a rule's pattern and users, its flags and its
//! ceilings, and the header record.
use super::header::field;
use super::pool::{elements_ok, list_ok, pool_bytes, pool_ref_ok};
use super::records::check_limits;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use super::spec::*;
use super::{DbError, rid, tid};
#[allow(clippy::wildcard_imports)] // the layout constants, used throughout
use crate::layout::*;
use vstd::prelude::*;

verus! {

/// A byte of a node name, `*` or `~` ([`pattern_byte`]).
#[allow(clippy::manual_range_contains)]  // `RangeInclusive::contains` is not available inside `verus!`
fn pattern_byte_exec(c: u8) -> (ok: bool)
    ensures
        ok == pattern_byte(c),
{
    (0x30 <= c && c <= 0x39) || (0x41 <= c && c <= 0x5a) || (0x61 <= c && c <= 0x7a) || c == 0x2e
        || c == 0x5f || c == 0x40 || c == 0x3a || c == 0x2b || c == 0x2d || c == 0x2a || c == 0x7e
}

/// `s` is a [`pattern_ok`] pattern.
#[allow(clippy::len_zero)]  // `is_empty` is not available inside `verus!`
fn pattern_exec(s: &[u8]) -> (ok: bool)
    ensures
        ok ==> pattern_ok(s@),
{
    if s.len() < 1 || s.len() > MAX_PATTERN_LEN {
        return false;
    }
    let mut k: usize = 0;
    while k < s.len()
        invariant
            k <= s@.len(),
            forall|j: int| 0 <= j < k ==> #[trigger] pattern_byte(s@[j]),
        decreases s@.len() - k,
    {
        if !pattern_byte_exec(s[k]) {
            return false;
        }
        k += 1;
    }
    true
}

/// `s[p..q]` is a [`user_name_ok`] name.
#[allow(clippy::manual_range_contains, clippy::many_single_char_names)]  // `RangeInclusive::contains` is not available inside `verus!`; `s`, `p`, `q`, `k` and `c` follow the spec
pub(crate) fn user_name_exec(s: &[u8], p: usize, q: usize) -> (ok: bool)
    requires
        p <= q <= s@.len(),
    ensures
        ok ==> user_name_ok(s@.subrange(p as int, q as int)),
{
    if q - p < 1 || q - p > 32 {
        return false;
    }
    let first = s[p];
    if !((0x61 <= first && first <= 0x7a) || first == 0x5f) {
        return false;
    }
    let ghost name = s@.subrange(p as int, q as int);
    assert(name[0] == s@[p as int]);
    let mut k = p + 1;
    while k < q
        invariant
            p + 1 <= k <= q <= s@.len(),
            name == s@.subrange(p as int, q as int),
            name.len() == q - p,
            forall|j: int|
                1 <= j < k - p ==> (0x61 <= #[trigger] name[j] <= 0x7a || 0x30 <= name[j] <= 0x39
                    || name[j] == 0x5f || name[j] == 0x2d),
        decreases q - k,
    {
        let c = s[k];
        if !((0x61 <= c && c <= 0x7a) || (0x30 <= c && c <= 0x39) || c == 0x5f || c == 0x2d) {
            return false;
        }
        assert(name[(k - p) as int] == s@[k as int]);
        k += 1;
    }
    true
}

/// V2 for rule `p`: its pattern and its users list are pool references.
pub(crate) fn check_policy_pool(b: &[u8], p: usize) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        pool_valid(b@),
        p < tcnt(b@, T_POLICY as int),
    ensures
        r is Ok ==> policy_pool_ok(b@, p as int),
{
    let t = T_POLICY;
    let (tb, rec) = (tid(t), rid(p));
    pool_ref_ok(b, field(b, t, p, P_PATTERN_OFF), field(b, t, p, P_PATTERN_LEN), tb, rec)?;
    list_ok(b, field(b, t, p, P_USERS_OFF), field(b, t, p, P_USERS_LEN), tb, rec)
}

/// V4 for rule `p`.
pub(crate) fn check_policy_rule(b: &[u8], p: usize) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        v2(b@),
        p < tcnt(b@, T_POLICY as int),
    ensures
        r is Ok ==> policy_rule_ok(b@, p as int),
{
    let t = T_POLICY;
    assert(policy_pool_ok(b@, p as int));
    let enum_error = DbError::Enum { table: tid(t), record: rid(p) };
    let bad = DbError::Consistency { table: tid(t), record: rid(p) };
    let any = field(b, t, p, P_USERS_ANY);
    let mask = field(b, t, p, P_RLIMIT_MASK);
    if any > 1 || field(b, t, p, P_CAPS_HI) > 0x1ff || field(b, t, p, P_REQUIRE_NNP) > 1 || field(
        b,
        t,
        p,
        P_REQUIRE_SECCOMP,
    ) > 1 || field(b, t, p, P_ALLOW_USERNS) > 2 || field(b, t, p, P_ALLOW_INSIDE_IDS) > 1 || mask
        & !RLIMIT_MASK_ALLOWED != 0 {
        return Err(enum_error);
    }
    let pattern = pool_bytes(b, field(b, t, p, P_PATTERN_OFF), field(b, t, p, P_PATTERN_LEN));
    if !pattern_exec(pattern) {
        return Err(bad);
    }
    let users_len = field(b, t, p, P_USERS_LEN);
    if any == 1 && users_len != 0 {
        return Err(bad);
    }
    let users = pool_bytes(b, field(b, t, p, P_USERS_OFF), users_len);
    if !elements_ok(users, 4) {
        return Err(bad);
    }
    check_limits(b, t, p, P_RLIMIT_MASK, P_RLIMIT_BASE, mask)?;
    Ok(())
}

/// V4 for the header record `h`.
pub(crate) fn check_policy_head(b: &[u8], h: usize) -> (r: Result<(), DbError>)
    requires
        v1(b@),
        h < tcnt(b@, T_POLICY_HEAD as int),
    ensures
        r is Ok ==> policy_head_ok(b@, h as int),
{
    let t = T_POLICY_HEAD;
    let mask = field(b, t, h, PH_RLIMIT_MASK);
    if field(b, t, h, PH_ALLOW) > 1 || mask & !RLIMIT_MASK_ALLOWED != 0 {
        return Err(DbError::Enum { table: tid(t), record: rid(h) });
    }
    check_limits(b, t, h, PH_RLIMIT_MASK, PH_RLIMIT_BASE, mask)?;
    Ok(())
}

} // verus!
