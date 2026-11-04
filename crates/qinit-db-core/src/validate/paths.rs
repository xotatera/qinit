// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The executable checks of the canonical-path rules, proved against [`canonical`] and
//! [`path_entry_ok`]; the database validator and the launch decoder both call them.
#[allow(unused_imports, clippy::wildcard_imports)] // the lemma is proof-only; Verus erases it
use super::pool::*;
use super::records::bytes_lt;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use super::spec::*;
use vstd::prelude::*;

verus! {

/// `s[p..q]` is a [`canonical`] path.
#[must_use]
pub fn canonical_exec(s: &[u8], p: usize, q: usize) -> (ok: bool)
    requires
        p <= q <= s@.len(),
    ensures
        ok ==> canonical(s@.subrange(p as int, q as int)),
{
    if q == p || s[p] != 0x2f {
        return false;
    }
    if q - p > 1 && s[q - 1] == 0x2f {
        return false;
    }
    let ghost e = s@.subrange(p as int, q as int);
    let mut i = p;
    while i < q
        invariant
            p < q <= s@.len(),
            e == s@.subrange(p as int, q as int),
            e.len() == q - p,
            p <= i <= q,
            forall|k: int|
                0 <= k && k + 1 < e.len() && k < i - p ==> !(#[trigger] e[k] == 0x2f && e[k + 1]
                    == 0x2f),
            forall|k: int| 1 <= k < e.len() && k < i - p ==> !(#[trigger] dot_at(e, k)),
            forall|k: int| 1 <= k < e.len() && k < i - p ==> !(#[trigger] dotdot_at(e, k)),
        decreases q - i,
    {
        if i + 1 < q && s[i] == 0x2f && s[i + 1] == 0x2f {
            assert(e[(i - p) as int] == s@[i as int]);
            assert(e[(i - p) as int + 1] == s@[i + 1]);
            return false;
        }
        if i > p && s[i - 1] == 0x2f && s[i] == 0x2e {
            if i + 1 == q || s[i + 1] == 0x2f {
                assert(e[(i - p) as int - 1] == s@[i - 1]);
                assert(e[(i - p) as int] == s@[i as int]);
                return false;
            }
            if s[i + 1] == 0x2e && (i + 2 == q || s[i + 2] == 0x2f) {
                assert(e[(i - p) as int - 1] == s@[i - 1]);
                assert(e[(i - p) as int] == s@[i as int]);
                assert(e[(i - p) as int + 1] == s@[i + 1]);
                return false;
            }
        }
        proof {
            let r = (i - p) as int;
            assert(e[r] == s@[i as int]);
            if r + 1 < e.len() {
                assert(e[r + 1] == s@[i + 1]);
            }
            if r >= 1 {
                assert(e[r - 1] == s@[i - 1]);
            }
            if r + 2 < e.len() {
                assert(e[r + 2] == s@[i + 2]);
            }
            assert(!dot_at(e, r));
            assert(!dotdot_at(e, r));
        }
        i += 1;
    }
    true
}

/// `s[p..q]` is a [`path_entry_ok`] entry: a mode (`ro:` `rw:` `ri:` `wi:` `rs:` `ws:`) and a
/// canonical path.
#[must_use]
pub fn path_entry_ok_exec(s: &[u8], p: usize, q: usize) -> (ok: bool)
    requires
        p <= q <= s@.len(),
    ensures
        ok ==> path_entry_ok(s@.subrange(p as int, q as int)),
{
    if q - p < 4 {
        return false;
    }
    let m0 = s[p];
    let m1 = s[p + 1];
    let mode = (m0 == 0x72 && (m1 == 0x6f || m1 == 0x77 || m1 == 0x69 || m1 == 0x73)) || (m0 == 0x77
        && (m1 == 0x69 || m1 == 0x73));
    let prefix = mode && s[p + 2] == 0x3a;
    if !prefix || !canonical_exec(s, p + 3, q) {
        return false;
    }
    let ghost entry = s@.subrange(p as int, q as int);
    assert(entry[0] == s@[p as int] && entry[1] == s@[p + 1] && entry[2] == s@[p + 2]);
    assert(entry.subrange(3, entry.len() as int) =~= s@.subrange(p + 3, q as int));
    true
}

/// Two elements of a NUL-separated list that end at the same place start at the same place.
proof fn lemma_same_end(s: Seq<u8>, p: int, p2: int, q: int)
    requires
        is_elem(s, p, q),
        is_elem(s, p2, q),
    ensures
        p == p2,
{
    if p < p2 {
        assert(s[p2 - 1] == 0);
        assert(s[p2 - 1] != 0);
    }
    if p2 < p {
        assert(s[p - 1] == 0);
        assert(s[p - 1] != 0);
    }
}

/// `s[p..q]` (an entry of at least four bytes) is not a [`forbidden_entry`].
#[allow(clippy::many_single_char_names)]  // `s`, `p`, `q` and `l` follow the spec names
fn allowed_exec(s: &[u8], p: usize, q: usize) -> (ok: bool)
    requires
        p + 4 <= q <= s@.len(),
    ensures
        ok ==> !forbidden_entry(s@.subrange(p as int, q as int)),
{
    let l = q - p - 3;
    let a = s[p + 3];
    if l == 1 && a == 0x2f {
        return false;
    }
    if l == 4 && a == 0x2f && ((s[p + 4] == 0x64 && s[p + 5] == 0x65 && s[p + 6] == 0x76) || (s[p
        + 4] == 0x74 && s[p + 5] == 0x6d && s[p + 6] == 0x70)) {
        return false;
    }
    if l == 5 && (s[p] == 0x77 || s[p + 1] == 0x77) && a == 0x2f && s[p + 4] == 0x70 && s[p + 5]
        == 0x72 && s[p + 6] == 0x6f && s[p + 7] == 0x63 {
        return false;
    }
    true
}

/// No entry of the list is idmapped (`ri:` or `wi:`).
#[must_use]
pub fn no_idmapped_exec(s: &[u8]) -> (ok: bool)
    requires
        nul_list(s@),
        paths_list_ok(s@),
    ensures
        ok <==> paths_no_idmapped(s@),
{
    let n = s.len();
    if n == 0 {
        assert(paths_no_idmapped(s@)) by {
            assert forall|p: int, q: int| is_elem(s@, p, q) && q - p >= 4 implies !entry_idmapped(
                s@.subrange(p, q),
            ) by {}
        }
        return true;
    }
    let mut es: usize = 0;
    let mut i: usize = 0;
    while i < n
        invariant
            n == s@.len(),
            0 < n,
            nul_list(s@),
            paths_list_ok(s@),
            es <= i <= n,
            es == 0 || s@[es - 1] == 0,
            forall|k: int| es <= k < i ==> #[trigger] s@[k] != 0,
            forall|p: int, q: int|
                #![trigger is_elem(s@, p, q)]
                is_elem(s@, p, q) && q < i && q - p >= 4 ==> !entry_idmapped(s@.subrange(p, q)),
        decreases n - i,
    {
        if s[i] == 0 {
            proof {
                assert(is_elem(s@, es as int, i as int));
                assert(path_entry_ok(s@.subrange(es as int, i as int)));
            }
            if s[es + 1] == 0x69 {
                proof {
                    let e = s@.subrange(es as int, i as int);
                    assert(e[1] == s@[es + 1]);
                    assert(entry_idmapped(e));
                    assert(is_elem(s@, es as int, i as int) && i - es >= 4);
                }
                return false;
            }
            assert forall|p: int, q: int|
                is_elem(s@, p, q) && q < i + 1 && q - p >= 4 implies !entry_idmapped(
                s@.subrange(p, q),
            ) by {
                if q == i {
                    lemma_elem_start(s@, es as int, i as int, p);
                }
            }
            es = i + 1;
        }
        i += 1;
    }
    proof {
        assert(is_elem(s@, es as int, n as int));
        assert(path_entry_ok(s@.subrange(es as int, n as int)));
    }
    if s[es + 1] == 0x69 {
        proof {
            let e = s@.subrange(es as int, n as int);
            assert(e[1] == s@[es + 1]);
            assert(entry_idmapped(e));
            assert(is_elem(s@, es as int, n as int) && n - es >= 4);
        }
        return false;
    }
    assert forall|p: int, q: int| is_elem(s@, p, q) && q - p >= 4 implies !entry_idmapped(
        s@.subrange(p, q),
    ) by {
        if q == n {
            lemma_elem_start(s@, es as int, n as int, p);
        }
    }
    true
}

/// Every entry of the list is allowed, adjacent entries ascend by path, and a non-empty list
/// has the mount namespace.
#[must_use]
#[allow(clippy::too_many_lines)]  // one loop with its Verus invariants
pub fn paths_shape_exec(s: &[u8], ns: u32) -> (ok: bool)
    requires
        nul_list(s@),
        paths_list_ok(s@),
    ensures
        ok ==> paths_shape_ok(s@, ns),
{
    let n = s.len();
    if n == 0 {
        assert(paths_ordered(s@) && paths_allowed(s@) && paths_no_idmapped(s@)) by {
            assert forall|p: int, q: int| is_elem(s@, p, q) && q - p >= 4 implies !forbidden_entry(
                s@.subrange(p, q),
            ) by {}
            assert forall|p: int, q: int| is_elem(s@, p, q) && q - p >= 4 implies !entry_idmapped(
                s@.subrange(p, q),
            ) by {}
        }
        return true;
    }
    if ns & 1 == 0 {
        return false;
    }
    if ns & 32 == 0 && !no_idmapped_exec(s) {
        return false;
    }
    let mut es: usize = 0;
    let mut ps: usize = 0;
    let mut pe: usize = 0;
    let mut have_prev = false;
    let mut i: usize = 0;
    while i < n
        invariant
            n == s@.len(),
            0 < n,
            nul_list(s@),
            paths_list_ok(s@),
            es <= i <= n,
            es == 0 || s@[es - 1] == 0,
            forall|k: int| es <= k < i ==> #[trigger] s@[k] != 0,
            ns & 32u32 == 0u32 ==> paths_no_idmapped(s@),
            have_prev ==> ps + 4 <= pe && pe + 1 == es && is_elem(s@, ps as int, pe as int),
            !have_prev ==> es == 0,
            forall|p: int, q: int|
                #![trigger is_elem(s@, p, q)]
                is_elem(s@, p, q) && q < i && q - p >= 4 ==> !forbidden_entry(s@.subrange(p, q)),
            forall|p1: int, q1: int, p2: int, q2: int|
                #![trigger is_elem(s@, p1, q1), is_elem(s@, p2, q2)]
                is_elem(s@, p1, q1) && is_elem(s@, p2, q2) && q1 + 1 == p2 && q2 < i && q1 - p1 >= 3
                    && q2 - p2 >= 3 ==> lex_lt(s@.subrange(p1 + 3, q1), s@.subrange(p2 + 3, q2)),
        decreases n - i,
    {
        if s[i] == 0 {
            proof {
                assert(is_elem(s@, es as int, i as int));
                assert(path_entry_ok(s@.subrange(es as int, i as int)));
            }
            if !allowed_exec(s, es, i) {
                return false;
            }
            if have_prev && !bytes_lt(s, ps + 3, pe - ps - 3, es + 3, i - es - 3) {
                return false;
            }
            assert forall|p: int, q: int|
                is_elem(s@, p, q) && q < i + 1 && q - p >= 4 implies !forbidden_entry(
                s@.subrange(p, q),
            ) by {
                if q == i {
                    lemma_elem_start(s@, es as int, i as int, p);
                }
            }
            assert forall|p1: int, q1: int, p2: int, q2: int|
                is_elem(s@, p1, q1) && is_elem(s@, p2, q2) && q1 + 1 == p2 && q2 < i + 1 && q1 - p1
                    >= 3 && q2 - p2 >= 3 implies lex_lt(
                s@.subrange(p1 + 3, q1),
                s@.subrange(p2 + 3, q2),
            ) by {
                if q2 == i {
                    lemma_elem_start(s@, es as int, i as int, p2);
                    assert(have_prev);
                    lemma_same_end(s@, p1, ps as int, q1);
                }
            }
            ps = es;
            pe = i;
            have_prev = true;
            es = i + 1;
        }
        i += 1;
    }
    proof {
        assert(is_elem(s@, es as int, n as int));
        assert(path_entry_ok(s@.subrange(es as int, n as int)));
    }
    if !allowed_exec(s, es, n) {
        return false;
    }
    if have_prev && !bytes_lt(s, ps + 3, pe - ps - 3, es + 3, n - es - 3) {
        return false;
    }
    assert forall|p: int, q: int| is_elem(s@, p, q) && q - p >= 4 implies !forbidden_entry(
        s@.subrange(p, q),
    ) by {
        if q == n {
            lemma_elem_start(s@, es as int, n as int, p);
        }
    }
    assert forall|p1: int, q1: int, p2: int, q2: int|
        is_elem(s@, p1, q1) && is_elem(s@, p2, q2) && q1 + 1 == p2 && q1 - p1 >= 3 && q2 - p2
            >= 3 implies lex_lt(s@.subrange(p1 + 3, q1), s@.subrange(p2 + 3, q2)) by {
        if q2 == n {
            lemma_elem_start(s@, es as int, n as int, p2);
            assert(have_prev);
            lemma_same_end(s@, p1, ps as int, q1);
        }
    }
    true
}

/// `t` is `s[a..b]` or below it, by whole components.
#[allow(clippy::many_single_char_names)]  // `t`, `s`, `a`, `b`, `l` and `k` follow the spec names
fn below_exec(t: &[u8], s: &[u8], a: usize, b: usize) -> (r: bool)
    requires
        a <= b <= s@.len(),
    ensures
        r ==> at_or_below(t@, s@.subrange(a as int, b as int)),
{
    let l = b - a;
    if t.len() < l {
        return false;
    }
    let mut k: usize = 0;
    while k < l
        invariant
            a <= b <= s@.len(),
            l == b - a,
            l <= t@.len(),
            k <= l,
            forall|j: int| 0 <= j < k ==> t@[j] == s@[a + j],
        decreases l - k,
    {
        if t[k] != s[a + k] {
            return false;
        }
        k += 1;
    }
    let ghost q = s@.subrange(a as int, b as int);
    proof {
        assert(t@.subrange(0, l as int) =~= q);
    }
    if t.len() == l {
        assert(t@ =~= q);
        return true;
    }
    t[l] == 0x2f
}

/// Some entry of the list is `t` or an ancestor of it.
fn covered_exec(s: &[u8], t: &[u8]) -> (ok: bool)
    requires
        nul_list(s@),
        paths_list_ok(s@),
    ensures
        ok ==> covered(s@, t@),
{
    let n = s.len();
    if n == 0 {
        return false;
    }
    let mut es: usize = 0;
    let mut i: usize = 0;
    while i < n
        invariant
            n == s@.len(),
            0 < n,
            nul_list(s@),
            paths_list_ok(s@),
            es <= i <= n,
            es == 0 || s@[es - 1] == 0,
            forall|k: int| es <= k < i ==> #[trigger] s@[k] != 0,
        decreases n - i,
    {
        if s[i] == 0 {
            proof {
                assert(is_elem(s@, es as int, i as int));
                assert(path_entry_ok(s@.subrange(es as int, i as int)));
            }
            if below_exec(t, s, es + 3, i) {
                assert(path_of(s@.subrange(es as int, i as int)) =~= s@.subrange(
                    es as int + 3,
                    i as int,
                ));
                return true;
            }
            es = i + 1;
        }
        i += 1;
    }
    proof {
        assert(is_elem(s@, es as int, n as int));
        assert(path_entry_ok(s@.subrange(es as int, n as int)));
    }
    if below_exec(t, s, es + 3, n) {
        assert(path_of(s@.subrange(es as int, n as int)) =~= s@.subrange(es as int + 3, n as int));
        return true;
    }
    false
}

/// With a non-empty list, the program and the working directory are inside it.
#[must_use]
#[allow(clippy::len_zero)]  // `is_empty` is not available inside `verus!`
pub fn paths_cover_exec(s: &[u8], exec0: &[u8], cwd: &[u8]) -> (ok: bool)
    requires
        nul_list(s@),
        paths_list_ok(s@),
    ensures
        ok ==> paths_cover_ok(s@, exec0@, cwd@),
{
    if s.len() == 0 {
        return true;
    }
    if exec0.len() < 1 || exec0[0] != 0x2f {
        return false;
    }
    if !covered_exec(s, exec0) {
        return false;
    }
    if cwd.len() == 1 && cwd[0] == 0x2f {
        return true;
    }
    covered_exec(s, cwd)
}

/// The length of the first element of the NUL-separated list `s`: its bytes up to the first NUL.
#[must_use]
pub fn first_elem_len(s: &[u8]) -> (m: usize)
    ensures
        m <= s@.len(),
        m == s@.len() || s@[m as int] == 0,
        forall|k: int| 0 <= k < m ==> #[trigger] s@[k] != 0,
{
    let mut m: usize = 0;
    while m < s.len() && s[m] != 0
        invariant
            m <= s@.len(),
            forall|k: int| 0 <= k < m ==> #[trigger] s@[k] != 0,
        decreases s@.len() - m,
    {
        m += 1;
    }
    m
}

} // verus!
