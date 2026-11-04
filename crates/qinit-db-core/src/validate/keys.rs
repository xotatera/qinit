// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! V4 for a forager's launch environment keys: each key is a name without `=`, and the keys
//! ascend strictly (so none repeats).
use super::header::header_word;
use super::pool::launch_key_ok_exec;
#[allow(unused_imports, clippy::wildcard_imports)] // the lemma is proof-only; Verus erases it
use super::pool::*;
use super::records::bytes_lt;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use super::spec::*;
#[allow(clippy::wildcard_imports)] // the layout constants, used throughout
use crate::layout::*;
use vstd::prelude::*;

verus! {

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

/// Every key of the NUL-separated list `s` is a [`launch_key_ok`] key and adjacent keys ascend.
fn keys_exec(s: &[u8]) -> (ok: bool)
    requires
        nul_list(s@),
    ensures
        ok ==> launch_keys_ok(s@) && keys_ascending(s@),
{
    let n = s.len();
    if n == 0 {
        assert(launch_keys_ok(s@));
        assert forall|p1: int, q1: int, p2: int, q2: int|
            is_elem(s@, p1, q1) && is_elem(s@, p2, q2) && q1 + 1 == p2 implies lex_lt(
            s@.subrange(p1, q1),
            s@.subrange(p2, q2),
        ) by {}
        return true;
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
            es <= i <= n,
            es == 0 || s@[es - 1] == 0,
            forall|k: int| es <= k < i ==> #[trigger] s@[k] != 0,
            have_prev ==> ps <= pe && pe + 1 == es && is_elem(s@, ps as int, pe as int),
            !have_prev ==> es == 0,
            forall|p: int, q: int| #[trigger]
                is_elem(s@, p, q) && q < i ==> launch_key_ok(s@.subrange(p, q)),
            forall|p1: int, q1: int, p2: int, q2: int|
                #![trigger is_elem(s@, p1, q1), is_elem(s@, p2, q2)]
                is_elem(s@, p1, q1) && is_elem(s@, p2, q2) && q1 + 1 == p2 && q2 < i ==> lex_lt(
                    s@.subrange(p1, q1),
                    s@.subrange(p2, q2),
                ),
        decreases n - i,
    {
        if s[i] == 0 {
            if !launch_key_ok_exec(s, es, i) {
                return false;
            }
            if have_prev && !bytes_lt(s, ps, pe - ps, es, i - es) {
                return false;
            }
            assert forall|p: int, q: int| #[trigger]
                is_elem(s@, p, q) && q < i + 1 implies launch_key_ok(s@.subrange(p, q)) by {
                if q == i {
                    lemma_elem_start(s@, es as int, i as int, p);
                }
            }
            assert forall|p1: int, q1: int, p2: int, q2: int|
                is_elem(s@, p1, q1) && is_elem(s@, p2, q2) && q1 + 1 == p2 && q2 < i
                    + 1 implies lex_lt(s@.subrange(p1, q1), s@.subrange(p2, q2)) by {
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
    if !launch_key_ok_exec(s, es, n) {
        return false;
    }
    if have_prev && !bytes_lt(s, ps, pe - ps, es, n - es) {
        return false;
    }
    assert forall|p: int, q: int| #[trigger] is_elem(s@, p, q) implies launch_key_ok(
        s@.subrange(p, q),
    ) by {
        if q == n {
            lemma_elem_start(s@, es as int, n as int, p);
        }
    }
    assert forall|p1: int, q1: int, p2: int, q2: int|
        is_elem(s@, p1, q1) && is_elem(s@, p2, q2) && q1 + 1 == p2 implies lex_lt(
        s@.subrange(p1, q1),
        s@.subrange(p2, q2),
    ) by {
        if q2 == n {
            lemma_elem_start(s@, es as int, n as int, p2);
            assert(have_prev);
            lemma_same_end(s@, p1, ps as int, q1);
        }
    }
    true
}

/// The launch environment keys of the pool list `off..off + len` are well formed and ascend (V4).
pub(crate) fn launch_keys_exec(b: &[u8], off: u32, len: u32) -> (ok: bool)
    requires
        v1(b@),
        list_ref(b@, off as int, len as int),
    ensures
        ok ==> {
            let keys = pool_slice(b@, off as int, len as int);
            launch_keys_ok(keys) && keys_ascending(keys)
        },
{
    assert(table_ok(b@, T_POOL as int));
    let a = header_word(b, 4 + 2 * T_POOL) as usize + off as usize;
    let s = vstd::slice::slice_subrange(b, a, a + len as usize);
    keys_exec(s)
}

} // verus!
