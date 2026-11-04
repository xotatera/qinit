// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The executable checks of the canonical-path rules, proved against [`canonical`] and
//! [`path_entry_ok`]; the database validator and the launch decoder both call them.
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

/// `s[p..q]` is a [`path_entry_ok`] entry: `ro:` or `rw:` and a canonical path.
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
    let prefix = s[p] == 0x72 && (s[p + 1] == 0x6f || s[p + 1] == 0x77) && s[p + 2] == 0x3a;
    if !prefix || !canonical_exec(s, p + 3, q) {
        return false;
    }
    let ghost entry = s@.subrange(p as int, q as int);
    assert(entry[0] == s@[p as int] && entry[1] == s@[p + 1] && entry[2] == s@[p + 2]);
    assert(entry.subrange(3, entry.len() as int) =~= s@.subrange(p + 3, q as int));
    true
}

} // verus!
