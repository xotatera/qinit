// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The credential policy check (sandbox design §6.3): whether the policy compiled into the
//! database allows a launch request under a name, proved equal to its specification
//! ([`verdict`]). The frames compiler's `violations` is the same function over the model; a
//! test requires the two to agree.
#[allow(unused_imports, clippy::wildcard_imports)]
// the layout constants and the request's spec
use crate::layout::*;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use crate::plan::*;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use crate::spec::*;
#[allow(unused_imports, clippy::wildcard_imports)] // the db-core helpers and spec items
use qinit_db_core::*;
use vstd::prelude::*;

verus! {

/// Whether `n` matches the glob `p`: `*` matches any run of bytes (possibly empty), every other
/// byte matches itself.
pub open spec fn glob(p: Seq<u8>, n: Seq<u8>) -> bool
    decreases p.len() + n.len(),
{
    if p.len() == 0 {
        n.len() == 0
    } else if p[0] == 0x2a {
        glob(p.skip(1), n) || (n.len() > 0 && glob(p, n.skip(1)))
    } else {
        n.len() > 0 && p[0] == n[0] && glob(p.skip(1), n.skip(1))
    }
}

/// The longest name a pattern is matched against: a node name, or `~` and a launch name.
pub const MAX_MATCH_NAME: usize = 96;

/// [`glob`], computed from the end of the pattern with one row of results per pattern suffix,
/// in at most `p.len() * (n.len() + 1)` steps.
#[must_use]
#[allow(clippy::too_many_lines, clippy::many_single_char_names, clippy::semicolon_if_nothing_returned)]  // two loops with their Verus invariants; `p`, `n`, `i`, `j`, `c` follow the spec
pub fn glob_exec(p: &[u8], n: &[u8]) -> (r: bool)
    requires
        p@.len() <= MAX_PATTERN_LEN,
        n@.len() <= MAX_MATCH_NAME,
    ensures
        r == glob(p@, n@),
{
    let nl = n.len();
    let mut row = [false;MAX_MATCH_NAME + 1];
    // The empty pattern suffix matches the empty name suffix only.
    row[nl] = true;
    let mut i: usize = p.len();
    while i > 0
        invariant
            i <= p@.len(),
            nl == n@.len(),
            nl <= MAX_MATCH_NAME,
            row@.len() == MAX_MATCH_NAME + 1,
            forall|j: int|
                0 <= j <= nl ==> #[trigger] row@[j] == glob(p@.skip(i as int), n@.skip(j)),
        decreases i,
    {
        let c = p[i - 1];
        let ghost old_row = row@;
        let ghost sp = p@.skip(i as int - 1);
        assert(sp.len() >= 1);
        assert(sp[0] == c);
        assert(sp.skip(1) =~= p@.skip(i as int));
        if c == 0x2a {
            // row'[j] = row[j] || row'[j + 1], from the end of the name down.
            let mut j: usize = nl + 1;
            while j > 0
                invariant
                    0 <= j <= nl + 1,
                    nl == n@.len(),
                    nl <= MAX_MATCH_NAME,
                    row@.len() == MAX_MATCH_NAME + 1,
                    old_row.len() == MAX_MATCH_NAME + 1,
                    c == 0x2a,
                    sp.len() >= 1,
                    sp[0] == c,
                    sp.skip(1) =~= p@.skip(i as int),
                    sp == p@.skip(i as int - 1),
                    forall|k: int|
                        0 <= k <= nl ==> #[trigger] old_row[k] == glob(
                            p@.skip(i as int),
                            n@.skip(k),
                        ),
                    forall|k: int| j <= k <= nl ==> #[trigger] row@[k] == glob(sp, n@.skip(k)),
                    forall|k: int| 0 <= k < j ==> #[trigger] row@[k] == old_row[k],
                decreases j,
            {
                j -= 1;
                let skipped = row[j];
                let more = j < nl && row[j + 1];
                proof {
                    reveal_with_fuel(glob, 2);
                    assert(glob(sp, n@.skip(j as int)) == (glob(sp.skip(1), n@.skip(j as int)) || (
                    n@.skip(j as int).len() > 0 && glob(sp, n@.skip(j as int).skip(1)))));
                    if j < nl {
                        assert(n@.skip(j as int).skip(1) =~= n@.skip(j as int + 1));
                    }
                }
                row[j] = skipped || more;
            }
        } else {
            // row'[j] = j < nl && p[i-1] == n[j] && row[j + 1], from the start of the name up.
            let mut j: usize = 0;
            while j <= nl
                invariant
                    0 <= j <= nl + 1,
                    nl == n@.len(),
                    nl <= MAX_MATCH_NAME,
                    row@.len() == MAX_MATCH_NAME + 1,
                    old_row.len() == MAX_MATCH_NAME + 1,
                    c != 0x2a,
                    sp.len() >= 1,
                    sp[0] == c,
                    sp.skip(1) =~= p@.skip(i as int),
                    sp == p@.skip(i as int - 1),
                    forall|k: int|
                        0 <= k <= nl ==> #[trigger] old_row[k] == glob(
                            p@.skip(i as int),
                            n@.skip(k),
                        ),
                    forall|k: int| 0 <= k < j ==> #[trigger] row@[k] == glob(sp, n@.skip(k)),
                    forall|k: int| j <= k <= nl ==> #[trigger] row@[k] == old_row[k],
                decreases nl + 1 - j,
            {
                let next = if j < nl {
                    c == n[j] && row[j + 1]
                } else {
                    false
                };
                proof {
                    if j < nl {
                        assert(n@.skip(j as int).skip(1) =~= n@.skip(j as int + 1));
                        assert(n@.skip(j as int)[0] == n@[j as int]);
                    }
                    reveal_with_fuel(glob, 2);
                    assert(glob(sp, n@.skip(j as int)) == (n@.skip(j as int).len() > 0 && sp[0]
                        == n@.skip(j as int)[0] && glob(sp.skip(1), n@.skip(j as int).skip(1))));
                }
                row[j] = next;
                j += 1;
            }
        }
        i -= 1;
        proof {
            assert forall|j: int| 0 <= j <= nl implies #[trigger] row@[j] == glob(
                p@.skip(i as int),
                n@.skip(j),
            ) by {
                assert(p@.skip(i as int) == sp);
            }
        }
    }
    assert(p@.skip(0) =~= p@);
    assert(n@.skip(0) =~= n@);
    row[0]
}

/// Why a request is not allowed, in the order the clauses are checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denial {
    /// The database holds no policy.
    NoPolicy,
    /// The user is not one the matching rule names.
    User,
    /// A capability is above the rule's ceiling.
    Caps,
    /// The rule requires `no_new_privs`.
    Nnp,
    /// The rule requires a seccomp filter.
    Seccomp,
    /// The rule does not allow this user namespace map.
    Userns,
    /// The rule does not allow a non-zero inside id.
    InsideIds,
    /// The rule does not allow an idmapped path entry.
    Idmap,
    /// A limit is above its ceiling.
    Limit,
    /// No rule matches and the default is to deny.
    Default,
}

impl Denial {
    /// The number a reply carries: 1 `NoPolicy`, 2 `User`, 3 `Caps`, 4 `Nnp`, 5 `Seccomp`,
    /// 6 `Userns`, 7 `Limit`, 8 `Default`, 9 `InsideIds`, 10 `Idmap`.
    #[must_use]
    pub fn code(self) -> (c: u32)
        ensures
            1 <= c <= 10,
    {
        match self {
            Denial::NoPolicy => 1,
            Denial::User => 2,
            Denial::Caps => 3,
            Denial::Nnp => 4,
            Denial::Seccomp => 5,
            Denial::Userns => 6,
            Denial::Limit => 7,
            Denial::Default => 8,
            Denial::InsideIds => 9,
            Denial::Idmap => 10,
        }
    }
}

/// The request's user name.
pub open spec fn req_user(req: Seq<u8>) -> Seq<u8> {
    field_slice(req, Q_USER_OFF, Q_USER_LEN)
}

/// Bit `r` of `mask`.
pub open spec fn bit_set(mask: int, r: int) -> bool {
    ((mask as u32) >> (r as u32)) & 1u32 == 1u32
}

/// The limit `r` of record `i` of table `t` (a policy rule or the header), if its mask sets it.
pub open spec fn ceiling(
    db: Seq<u8>,
    t: int,
    i: int,
    mask_w: usize,
    base_w: usize,
    r: int,
) -> Option<int> {
    if bit_set(rw(db, t, i, mask_w as int), r) {
        Some(
            rw(db, t, i, (base_w + 2 * r) as int) + rw(db, t, i, (base_w + 2 * r + 1) as int)
                * 0x1_0000_0000,
        )
    } else {
        None
    }
}

/// The top-level ceiling of resource `r`.
pub open spec fn head_max(db: Seq<u8>, r: int) -> Option<int> {
    ceiling(db, T_POLICY_HEAD as int, 0, PH_RLIMIT_MASK, PH_RLIMIT_BASE, r)
}

/// Rule `i`'s ceiling of resource `r`, falling back to the top-level one.
pub open spec fn rule_max(db: Seq<u8>, i: int, r: int) -> Option<int> {
    match ceiling(db, T_POLICY as int, i, P_RLIMIT_MASK, P_RLIMIT_BASE, r) {
        Some(m) => Some(m),
        None => head_max(db, r),
    }
}

/// `v` is above the ceiling `max`; no ceiling means any value is.
pub open spec fn above(max: Option<int>, v: int) -> bool {
    match max {
        None => true,
        Some(m) => v > m,
    }
}

/// The request sets limit `r` and above the ceiling that applies: rule `rule`'s (falling back to
/// the top level) with `with_rule`, else the top-level one.
#[verifier::opaque]
pub open spec fn over_at(db: Seq<u8>, req: Seq<u8>, with_rule: bool, rule: int, r: int) -> bool {
    &&& rlimit_set(req, r)
    &&& above(
        if with_rule {
            rule_max(db, rule, r)
        } else {
            head_max(db, r)
        },
        rlimit_value(req, r),
    )
}

/// Some limit below `n` is [`over_at`].
#[verifier::opaque]
pub open spec fn raised_upto(db: Seq<u8>, req: Seq<u8>, with_rule: bool, rule: int, n: int) -> bool
    decreases n,
{
    if n <= 0 {
        false
    } else {
        raised_upto(db, req, with_rule, rule, n - 1) || over_at(db, req, with_rule, rule, n - 1)
    }
}

/// [`raised_upto`] is the existence of an [`over_at`] limit below `n`.
proof fn lemma_raised_upto(db: Seq<u8>, req: Seq<u8>, with_rule: bool, rule: int, n: int)
    requires
        n >= 0,
    ensures
        raised_upto(db, req, with_rule, rule, n) == exists|k: int|
            0 <= k < n && #[trigger] over_at(db, req, with_rule, rule, k),
    decreases n,
{
    reveal_with_fuel(raised_upto, 2);
    if n > 0 {
        lemma_raised_upto(db, req, with_rule, rule, n - 1);
        if over_at(db, req, with_rule, rule, n - 1) {
            assert(0 <= n - 1 < n);
        }
    }
}

/// The request sets a limit above the top-level ceilings.
pub open spec fn raised_top(db: Seq<u8>, req: Seq<u8>) -> bool {
    raised_upto(db, req, false, 0, RLIMIT_COUNT as int)
}

/// The request sets a limit above what rule `i` and the top level allow.
pub open spec fn raised_rule(db: Seq<u8>, i: int, req: Seq<u8>) -> bool {
    raised_upto(db, req, true, i, RLIMIT_COUNT as int)
}

/// A request that holds no privilege: not `root`, no capabilities, `no_new_privs`, no user
/// namespace, every limit within the top-level ceilings. It needs no rule.
pub open spec fn unprivileged(db: Seq<u8>, req: Seq<u8>) -> bool {
    &&& !is_root(req_user(req))
    &&& qw(req, Q_CAPS_LO) == 0
    &&& qw(req, Q_CAPS_HI) == 0
    &&& qw(req, Q_NNP) == 1
    &&& (qw(req, Q_NS) as u32) & 32u32 == 0u32
    &&& !raised_top(db, req)
}

/// The users of rule `i`.
pub open spec fn rule_users(db: Seq<u8>, i: int) -> Seq<u8> {
    pool_slice(db, pf(db, i, P_USERS_OFF), pf(db, i, P_USERS_LEN))
}

/// The request's user is one of rule `i`'s users.
pub open spec fn user_listed(db: Seq<u8>, i: int, req: Seq<u8>) -> bool {
    exists|p: int, q: int|
        #![trigger is_elem(rule_users(db, i), p, q)]
        is_elem(rule_users(db, i), p, q) && rule_users(db, i).subrange(p, q) =~= req_user(req)
}

/// Rule `i` of the pool: whether its pattern matches `name`.
pub open spec fn rule_matches(db: Seq<u8>, name: Seq<u8>, i: int) -> bool {
    glob(pool_slice(db, pf(db, i, P_PATTERN_OFF), pf(db, i, P_PATTERN_LEN)), name)
}

/// The first rule from `from` on whose pattern matches `name`.
#[verifier::opaque]
pub open spec fn first_match(db: Seq<u8>, name: Seq<u8>, from: int) -> Option<int>
    decreases tcnt(db, T_POLICY as int) - from,
{
    if from >= tcnt(db, T_POLICY as int) {
        None
    } else if rule_matches(db, name, from) {
        Some(from)
    } else {
        first_match(db, name, from + 1)
    }
}

/// The clause on users: the rule names no users, or names the request's.
pub open spec fn rule_user_ok(db: Seq<u8>, i: int, req: Seq<u8>) -> bool {
    pf(db, i, P_USERS_ANY) == 1 || user_listed(db, i, req)
}

/// The clause on capabilities: none above the rule's ceiling.
pub open spec fn rule_caps_ok(db: Seq<u8>, i: int, req: Seq<u8>) -> bool {
    &&& (qw(req, Q_CAPS_LO) as u32) & !(pf(db, i, P_CAPS_LO) as u32) == 0u32
    &&& (qw(req, Q_CAPS_HI) as u32) & !(pf(db, i, P_CAPS_HI) as u32) == 0u32
}

/// The clause on `no_new_privs`.
pub open spec fn rule_nnp_ok(db: Seq<u8>, i: int, req: Seq<u8>) -> bool {
    pf(db, i, P_REQUIRE_NNP) == 1 ==> qw(req, Q_NNP) == 1
}

/// The clause on seccomp.
pub open spec fn rule_seccomp_ok(db: Seq<u8>, i: int, req: Seq<u8>) -> bool {
    pf(db, i, P_REQUIRE_SECCOMP) == 1 ==> qw(req, Q_SECCOMP) != 0
}

/// The clause on user namespaces: a request with one needs a rule that allows its map.
pub open spec fn rule_userns_ok(db: Seq<u8>, i: int, req: Seq<u8>) -> bool {
    (qw(req, Q_NS) as u32) & 32u32 != 0u32 ==> (pf(db, i, P_ALLOW_USERNS) == 2 || (pf(
        db,
        i,
        P_ALLOW_USERNS,
    ) == 1 && qw(req, Q_USER_MAP) == 0))
}

/// The clause on inside ids: a request that runs as a non-zero id inside its user namespace
/// needs a rule that allows it.
pub open spec fn rule_inside_ok(db: Seq<u8>, i: int, req: Seq<u8>) -> bool {
    (qw(req, Q_INSIDE_UID) != 0 || qw(req, Q_INSIDE_GID) != 0) ==> pf(db, i, P_ALLOW_INSIDE_IDS)
        == 1
}

/// The clause on idmapped entries: an idmapped mount hands the service the ownership of disk
/// ids, so a request with one needs a rule that allows it.
pub open spec fn rule_idmap_ok(db: Seq<u8>, i: int, req: Seq<u8>) -> bool {
    !paths_no_idmapped(field_slice(req, Q_PATHS_OFF, Q_PATHS_LEN)) ==> pf(db, i, P_ALLOW_IDMAP) == 1
}

/// What rule `i` says about the request, clause by clause in the order of [`Denial`].
pub open spec fn rule_verdict(db: Seq<u8>, i: int, req: Seq<u8>) -> Result<(), Denial> {
    if !rule_user_ok(db, i, req) {
        Err(Denial::User)
    } else if !rule_caps_ok(db, i, req) {
        Err(Denial::Caps)
    } else if !rule_nnp_ok(db, i, req) {
        Err(Denial::Nnp)
    } else if !rule_seccomp_ok(db, i, req) {
        Err(Denial::Seccomp)
    } else if !rule_userns_ok(db, i, req) {
        Err(Denial::Userns)
    } else if !rule_inside_ok(db, i, req) {
        Err(Denial::InsideIds)
    } else if !rule_idmap_ok(db, i, req) {
        Err(Denial::Idmap)
    } else if raised_rule(db, i, req) {
        Err(Denial::Limit)
    } else {
        Ok(())
    }
}

/// The policy's verdict on `req` launched as `name` (a frame's name, or `~` and a launch name).
pub open spec fn verdict(db: Seq<u8>, name: Seq<u8>, req: Seq<u8>) -> Result<(), Denial> {
    if tcnt(db, T_POLICY_HEAD as int) == 0 {
        Err(Denial::NoPolicy)
    } else if unprivileged(db, req) {
        Ok(())
    } else {
        match first_match(db, name, 0) {
            Some(i) => rule_verdict(db, i, req),
            None => if hf(db, 0, PH_ALLOW) == 1 {
                Ok(())
            } else {
                Err(Denial::Default)
            },
        }
    }
}

/// [`over_at`] for limit `r`.
#[allow(clippy::cast_possible_truncation, clippy::cast_lossless)]  // `r < RLIMIT_COUNT`; `u64::from` is not available inside `verus!`
#[allow(clippy::many_single_char_names)]  // `r` and `v` follow the spec
fn over_exec(db: &[u8], req: &[u8], rule: usize, with_rule: bool, r: usize) -> (o: bool)
    requires
        well_formed(db@),
        accepted(req@),
        tcnt(db@, T_POLICY_HEAD as int) == 1,
        with_rule ==> rule < tcnt(db@, T_POLICY as int),
        r < RLIMIT_COUNT,
    ensures
        o == over_at(db@, req@, with_rule, rule as int, r as int),
{
    proof {
        reveal(over_at);
    }
    let mask = crate::req(req, Q_RLIMIT_MASK);
    if (mask >> (r as u32)) & 1 != 1 {
        return false;
    }
    let lo = crate::req(req, Q_RLIMIT_BASE + 2 * r);
    let hi = crate::req(req, Q_RLIMIT_BASE + 2 * r + 1);
    let v: u64 = (hi as u64) * 0x1_0000_0000u64 + (lo as u64);
    let hmask = policy_head_word(db, PH_RLIMIT_MASK);
    let head_set = (hmask >> (r as u32)) & 1 == 1;
    let head_v: u64 = if head_set {
        let hl = policy_head_word(db, PH_RLIMIT_BASE + 2 * r);
        let hh = policy_head_word(db, PH_RLIMIT_BASE + 2 * r + 1);
        (hh as u64) * 0x1_0000_0000u64 + (hl as u64)
    } else {
        0
    };
    let rule_set = with_rule && (policy_word(db, rule, P_RLIMIT_MASK) >> (r as u32)) & 1 == 1;
    let rule_v: u64 = if rule_set {
        let rl = policy_word(db, rule, P_RLIMIT_BASE + 2 * r);
        let rh = policy_word(db, rule, P_RLIMIT_BASE + 2 * r + 1);
        (rh as u64) * 0x1_0000_0000u64 + (rl as u64)
    } else {
        0
    };
    if rule_set {
        v > rule_v
    } else if head_set {
        v > head_v
    } else {
        true
    }
}

/// Whether the request sets a limit above its ceiling: [`raised_rule`] of `rule` with
/// `with_rule`, else [`raised_top`].
fn raised_exec(db: &[u8], req: &[u8], rule: usize, with_rule: bool) -> (r: bool)
    requires
        well_formed(db@),
        accepted(req@),
        tcnt(db@, T_POLICY_HEAD as int) == 1,
        with_rule ==> rule < tcnt(db@, T_POLICY as int),
        !with_rule ==> rule == 0,
    ensures
        r == if with_rule {
            raised_rule(db@, rule as int, req@)
        } else {
            raised_top(db@, req@)
        },
{
    proof {
        reveal_with_fuel(raised_upto, 1);
    }
    let mut r: usize = 0;
    let mut found = false;
    while r < RLIMIT_COUNT
        invariant
            well_formed(db@),
            accepted(req@),
            tcnt(db@, T_POLICY_HEAD as int) == 1,
            with_rule ==> rule < tcnt(db@, T_POLICY as int),
            r <= RLIMIT_COUNT,
            found == raised_upto(db@, req@, with_rule, rule as int, r as int),
        decreases RLIMIT_COUNT - r,
    {
        proof {
            reveal_with_fuel(raised_upto, 2);
        }
        if over_exec(db, req, rule, with_rule, r) {
            found = true;
        }
        r += 1;
    }
    found
}

/// The element of a NUL-separated list that ends at `i` starts at `es`, where `s[es..i]` has no
/// NUL and `es` follows a NUL or is 0.
proof fn lemma_start(s: Seq<u8>, es: int, i: int, p: int)
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

/// The request's user is one of the NUL-separated `users`.
fn user_listed_exec(users: &[u8], user: &[u8]) -> (r: bool)
    requires
        nul_list(users@),
        user@.len() > 0,
    ensures
        r == exists|p: int, q: int|
            #![trigger is_elem(users@, p, q)]
            is_elem(users@, p, q) && users@.subrange(p, q) =~= user@,
{
    let n = users.len();
    if n == 0 {
        return false;
    }
    let mut es: usize = 0;
    let mut i: usize = 0;
    while i < n
        invariant
            n == users@.len(),
            0 < n,
            nul_list(users@),
            es <= i <= n,
            es == 0 || users@[es - 1] == 0,
            forall|k: int| es <= k < i ==> #[trigger] users@[k] != 0,
            forall|p: int, q: int|
                #![trigger is_elem(users@, p, q)]
                is_elem(users@, p, q) && q < i ==> !(users@.subrange(p, q) =~= user@),
        decreases n - i,
    {
        if users[i] == 0 {
            if same_bytes(users, es, i, user) {
                assert(is_elem(users@, es as int, i as int));
                return true;
            }
            assert forall|p: int, q: int| is_elem(users@, p, q) && q < i + 1 implies !(
            users@.subrange(p, q) =~= user@) by {
                if q == i {
                    lemma_start(users@, es as int, i as int, p);
                }
            }
            es = i + 1;
        }
        i += 1;
    }
    if same_bytes(users, es, n, user) {
        assert(is_elem(users@, es as int, n as int));
        return true;
    }
    assert forall|p: int, q: int| is_elem(users@, p, q) implies !(users@.subrange(p, q)
        =~= user@) by {
        if q == n {
            lemma_start(users@, es as int, n as int, p);
        }
    }
    false
}

/// `s[p..q]` has the bytes of `t`.
#[allow(clippy::many_single_char_names)]  // `s`, `p`, `q`, `t`, `k` and `r` follow the spec
fn same_bytes(s: &[u8], p: usize, q: usize, t: &[u8]) -> (r: bool)
    requires
        p <= q <= s@.len(),
    ensures
        r == (s@.subrange(p as int, q as int) =~= t@),
{
    if q - p != t.len() {
        return false;
    }
    let mut k: usize = 0;
    while k < t.len()
        invariant
            q - p == t@.len(),
            p <= q <= s@.len(),
            k <= t@.len(),
            forall|j: int| 0 <= j < k ==> s@[p + j] == t@[j],
        decreases t@.len() - k,
    {
        if s[p + k] != t[k] {
            assert(s@.subrange(p as int, q as int)[k as int] == s@[p + k]);
            return false;
        }
        k += 1;
    }
    assert(s@.subrange(p as int, q as int) =~= t@);
    true
}

/// [`unprivileged`].
fn unprivileged_exec(db: &[u8], req: &[u8], user: &[u8]) -> (r: bool)
    requires
        well_formed(db@),
        accepted(req@),
        tcnt(db@, T_POLICY_HEAD as int) == 1,
        user@ == req_user(req@),
    ensures
        r == unprivileged(db@, req@),
{
    !is_root_exec(user) && crate::req(req, Q_CAPS_LO) == 0 && crate::req(req, Q_CAPS_HI) == 0
        && crate::req(req, Q_NNP) == 1 && crate::req(req, Q_NS) & 32 == 0 && !raised_exec(
        db,
        req,
        0,
        false,
    )
}

/// The first rule whose pattern matches `name` ([`first_match`] from 0).
fn first_match_exec(db: &[u8], name: &[u8]) -> (m: Option<usize>)
    requires
        well_formed(db@),
        name@.len() <= MAX_MATCH_NAME,
    ensures
        match m {
            Some(i) => first_match(db@, name@, 0) == Some(i as int) && i < tcnt(
                db@,
                T_POLICY as int,
            ),
            None => first_match(db@, name@, 0) == None::<int>,
        },
{
    let rules = policy_rule_count(db);
    let mut p: usize = 0;
    while p < rules
        invariant
            well_formed(db@),
            rules == tcnt(db@, T_POLICY as int),
            p <= rules,
            name@.len() <= MAX_MATCH_NAME,
            first_match(db@, name@, 0) == first_match(db@, name@, p as int),
        decreases rules - p,
    {
        let pattern = policy_pattern(db, p);
        proof {
            assert(policy_rule_ok(db@, p as int));
            reveal_with_fuel(first_match, 2);
        }
        if glob_exec(pattern, name) {
            return Some(p);
        }
        p += 1;
    }
    proof {
        reveal_with_fuel(first_match, 2);
    }
    None
}

/// What the policy compiled into `db` says about the accepted request `req` launched as `name`
/// (a frame's name, or `~` and a launch name: at most 96 bytes): `Ok` exactly when
/// [`verdict`] is, and the same [`Denial`] otherwise.
///
/// # Errors
/// The first failing clause, as [`Denial`].
pub fn check_policy(db: &[u8], name: &[u8], req: &[u8]) -> (r: Result<(), Denial>)
    requires
        well_formed(db@),
        accepted(req@),
        name@.len() <= MAX_MATCH_NAME,
    ensures
        r == verdict(db@, name@, req@),
{
    if policy_head_count(db) == 0 {
        return Err(Denial::NoPolicy);
    }
    assert(table_ok(db@, T_POLICY_HEAD as int));
    let user = crate::pool(req, crate::req(req, Q_USER_OFF), crate::req(req, Q_USER_LEN));
    if unprivileged_exec(db, req, user) {
        return Ok(());
    }
    match first_match_exec(db, name) {
        Some(p) => rule_exec(db, p, req, user),
        None => if policy_head_word(db, PH_ALLOW) == 1 {
            Ok(())
        } else {
            Err(Denial::Default)
        },
    }
}

/// [`rule_user_ok`] of rule `p`.
#[allow(unused_variables)]  // `req` appears only in the contract
fn user_clause(db: &[u8], p: usize, user: &[u8], req: &[u8]) -> (ok: bool)
    requires
        well_formed(db@),
        accepted(req@),
        p < tcnt(db@, T_POLICY as int),
        user@ == req_user(req@),
    ensures
        ok == rule_user_ok(db@, p as int, req@),
{
    if policy_word(db, p, P_USERS_ANY) == 1 {
        return true;
    }
    assert(policy_pool_ok(db@, p as int));
    assert(req_user(req@).len() > 0);
    let users = policy_users(db, p);
    assert(users@ == rule_users(db@, p as int));
    let listed = user_listed_exec(users, user);
    assert(listed == user_listed(db@, p as int, req@));
    listed
}

/// [`rule_verdict`] of rule `p`.
fn rule_exec(db: &[u8], p: usize, req: &[u8], user: &[u8]) -> (r: Result<(), Denial>)
    requires
        well_formed(db@),
        accepted(req@),
        p < tcnt(db@, T_POLICY as int),
        tcnt(db@, T_POLICY_HEAD as int) == 1,
        user@ == req_user(req@),
    ensures
        r == rule_verdict(db@, p as int, req@),
{
    if !user_clause(db, p, user, req) {
        return Err(Denial::User);
    }
    let caps_ok = crate::req(req, Q_CAPS_LO) & !policy_word(db, p, P_CAPS_LO) == 0 && crate::req(
        req,
        Q_CAPS_HI,
    ) & !policy_word(db, p, P_CAPS_HI) == 0;
    if !caps_ok {
        return Err(Denial::Caps);
    }
    let nnp_ok = policy_word(db, p, P_REQUIRE_NNP) != 1 || crate::req(req, Q_NNP) == 1;
    if !nnp_ok {
        return Err(Denial::Nnp);
    }
    let seccomp_ok = policy_word(db, p, P_REQUIRE_SECCOMP) != 1 || crate::req(req, Q_SECCOMP) != 0;
    if !seccomp_ok {
        return Err(Denial::Seccomp);
    }
    let allow = policy_word(db, p, P_ALLOW_USERNS);
    let userns_ok = crate::req(req, Q_NS) & 32 == 0 || allow == 2 || (allow == 1 && crate::req(
        req,
        Q_USER_MAP,
    ) == 0);
    if !userns_ok {
        return Err(Denial::Userns);
    }
    let inside_ok = (crate::req(req, Q_INSIDE_UID) == 0 && crate::req(req, Q_INSIDE_GID) == 0)
        || policy_word(db, p, P_ALLOW_INSIDE_IDS) == 1;
    if !inside_ok {
        return Err(Denial::InsideIds);
    }
    let idmap_ok = {
        proof {
            assert(req_pool_ref(req@, qw(req@, Q_PATHS_OFF), qw(req@, Q_PATHS_LEN)));
        }
        let len = crate::req(req, Q_PATHS_LEN);
        no_idmapped_exec(crate::pool(req, crate::req(req, Q_PATHS_OFF), len)) || policy_word(
            db,
            p,
            P_ALLOW_IDMAP,
        ) == 1
    };
    if !idmap_ok {
        return Err(Denial::Idmap);
    }
    if raised_exec(db, req, p, true) {
        return Err(Denial::Limit);
    }
    Ok(())
}

} // verus!
