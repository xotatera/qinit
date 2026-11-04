// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! NUL-separated lists: the rule that every element is non-empty, the environment-entry rule,
//! and the scanners proved against them. Copied from `qinit-db-core`, which an MPL crate may not
//! depend on (plan ruling P2).
use vstd::prelude::*;

verus! {

/// A NUL-separated list of non-empty elements: empty, or no NUL first or last and no two NULs
/// in a row.
pub open spec fn nul_list(s: Seq<u8>) -> bool {
    s.len() == 0 || (s[0] != 0 && s[s.len() - 1] != 0 && forall|k: int|
        0 <= k < s.len() - 1 ==> #[trigger] s[k] != 0 || s[k + 1] != 0)
}

/// `s[p..q]` is one element of the NUL-separated list `s`: bounded by NULs or the ends of `s`,
/// with no NUL inside.
pub open spec fn is_elem(s: Seq<u8>, p: int, q: int) -> bool {
    &&& 0 <= p <= q <= s.len()
    &&& (p == 0 || s[p - 1] == 0)
    &&& (q == s.len() || s[q] == 0)
    &&& forall|k: int| p <= k < q ==> #[trigger] s[k] != 0
}

/// An environment entry: `KEY=VALUE` with a non-empty key, so the first `=` is at index 1 or
/// later (the value may be empty and may hold `=`).
pub open spec fn env_entry_ok(e: Seq<u8>) -> bool {
    &&& e.len() >= 2
    &&& e[0] != 0x3d
    &&& exists|k: int| 1 <= k < e.len() && #[trigger] e[k] == 0x3d
}

/// Every element of the NUL-separated list `s` is an [`env_entry_ok`] entry.
pub open spec fn env_list_ok(s: Seq<u8>) -> bool {
    s.len() == 0 || forall|p: int, q: int| #[trigger]
        is_elem(s, p, q) ==> env_entry_ok(s.subrange(p, q))
}

/// The NUL bytes in `s`.
pub open spec fn nuls(s: Seq<u8>) -> int
    decreases s.len(),
{
    if s.len() == 0 {
        0
    } else {
        nuls(s.drop_last()) + if s.last() == 0 {
            1int
        } else {
            0int
        }
    }
}

/// The elements of the NUL-separated list `s`: none when empty, one more than its NULs
/// otherwise.
pub open spec fn elems(s: Seq<u8>) -> int {
    if s.len() == 0 {
        0
    } else {
        nuls(s) + 1
    }
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

/// Every element of the NUL-separated list `s` is an [`env_entry_ok`] entry.
#[must_use]
pub fn env_elements_ok(s: &[u8]) -> (ok: bool)
    requires
        nul_list(s@),
    ensures
        ok ==> env_list_ok(s@),
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
            es <= i <= n,
            es == 0 || s@[es - 1] == 0,
            forall|k: int| es <= k < i ==> #[trigger] s@[k] != 0,
            forall|p: int, q: int| #[trigger]
                is_elem(s@, p, q) && q < i ==> env_entry_ok(s@.subrange(p, q)),
        decreases n - i,
    {
        if s[i] == 0 {
            if !env_entry_ok_exec(s, es, i) {
                return false;
            }
            assert forall|p: int, q: int| #[trigger]
                is_elem(s@, p, q) && q < i + 1 implies env_entry_ok(s@.subrange(p, q)) by {
                if q == i {
                    lemma_elem_start(s@, es as int, i as int, p);
                }
            }
            es = i + 1;
        }
        i += 1;
    }
    if !env_entry_ok_exec(s, es, n) {
        return false;
    }
    assert forall|p: int, q: int| #[trigger] is_elem(s@, p, q) implies env_entry_ok(
        s@.subrange(p, q),
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

} // verus!
