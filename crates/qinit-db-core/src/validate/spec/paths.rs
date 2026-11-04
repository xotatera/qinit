// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Canonical absolute paths (spec §2.1 of the sandbox design): the one rule the frames, the
//! database validator and the launch decoder share for sandbox path entries and working
//! directories.
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only use: Verus erases it
use super::pool::*;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only use: Verus erases it
use super::records::*;
use vstd::prelude::*;

verus! {

/// A `.` component ends at `k`: `p[k - 1] == '/'`, `p[k] == '.'`, and `p[k]` is the last byte
/// or followed by `/`.
pub open spec fn dot_at(p: Seq<u8>, k: int) -> bool {
    &&& 1 <= k < p.len()
    &&& p[k - 1] == 0x2f
    &&& p[k] == 0x2e
    &&& (k + 1 == p.len() || p[k + 1] == 0x2f)
}

/// A `..` component starts at `k`.
pub open spec fn dotdot_at(p: Seq<u8>, k: int) -> bool {
    &&& 1 <= k
    &&& k + 1 < p.len()
    &&& p[k - 1] == 0x2f
    &&& p[k] == 0x2e
    &&& p[k + 1] == 0x2e
    &&& (k + 2 == p.len() || p[k + 2] == 0x2f)
}

/// A canonical absolute path: starts with `/`, has no empty, `.` or `..` component and no
/// trailing `/` (except `/` itself).
pub open spec fn canonical(p: Seq<u8>) -> bool {
    &&& p.len() >= 1
    &&& p[0] == 0x2f
    &&& (p.len() == 1 || p[p.len() - 1] != 0x2f)
    &&& forall|k: int| 0 <= k && k + 1 < p.len() ==> !(#[trigger] p[k] == 0x2f && p[k + 1] == 0x2f)
    &&& forall|k: int| 1 <= k < p.len() ==> !(#[trigger] dot_at(p, k))
    &&& forall|k: int| 1 <= k < p.len() ==> !(#[trigger] dotdot_at(p, k))
}

/// A sandbox path entry: `ro:` or `rw:` and a canonical path.
pub open spec fn path_entry_ok(e: Seq<u8>) -> bool {
    &&& e.len() >= 4
    &&& e[0] == 0x72
    &&& (e[1] == 0x6f || e[1] == 0x77)
    &&& e[2] == 0x3a
    &&& canonical(e.subrange(3, e.len() as int))
}

/// The path of an entry: everything after `ro:` or `rw:`.
pub open spec fn path_of(e: Seq<u8>) -> Seq<u8> {
    e.subrange(3, e.len() as int)
}

/// `/`, `/dev` or `/tmp`: a view builds these itself, so a list never names them.
pub open spec fn forbidden_path(p: Seq<u8>) -> bool {
    ||| p.len() == 1 && p[0] == 0x2f
    ||| p.len() == 4 && p[0] == 0x2f && p[1] == 0x64 && p[2] == 0x65 && p[3] == 0x76
    ||| p.len() == 4 && p[0] == 0x2f && p[1] == 0x74 && p[2] == 0x6d && p[3] == 0x70
}

/// An entry a list may not hold: a forbidden path, or `/proc` writable.
pub open spec fn forbidden_entry(e: Seq<u8>) -> bool {
    &&& e.len() >= 4
    &&& (forbidden_path(path_of(e)) || (e[1] == 0x77 && path_of(e).len() == 5 && path_of(e)[0]
        == 0x2f && path_of(e)[1] == 0x70 && path_of(e)[2] == 0x72 && path_of(e)[3] == 0x6f
        && path_of(e)[4] == 0x63))
}

/// Adjacent entries of the NUL-separated list `s` ascend strictly by path, bytewise (so no
/// path repeats).
pub open spec fn paths_ordered(s: Seq<u8>) -> bool {
    forall|p1: int, q1: int, p2: int, q2: int|
        #![trigger is_elem(s, p1, q1), is_elem(s, p2, q2)]
        is_elem(s, p1, q1) && is_elem(s, p2, q2) && q1 + 1 == p2 && q1 - p1 >= 3 && q2 - p2 >= 3
            ==> lex_lt(s.subrange(p1 + 3, q1), s.subrange(p2 + 3, q2))
}

/// No entry of the list is forbidden.
pub open spec fn paths_allowed(s: Seq<u8>) -> bool {
    forall|p: int, q: int|
        #![trigger is_elem(s, p, q)]
        is_elem(s, p, q) && q - p >= 4 ==> !forbidden_entry(s.subrange(p, q))
}

/// A non-empty list needs the mount namespace (bit 0 of `ns`).
pub open spec fn paths_shape_ok(s: Seq<u8>, ns: u32) -> bool {
    &&& paths_ordered(s)
    &&& paths_allowed(s)
    &&& (s.len() > 0 ==> ns & 1u32 != 0u32)
}

/// `p` is `q` or below it, by whole components.
pub open spec fn at_or_below(p: Seq<u8>, q: Seq<u8>) -> bool {
    ||| p == q
    ||| p.len() > q.len() && p.subrange(0, q.len() as int) == q && p[q.len() as int] == 0x2f
}

/// Some entry of the list is `t` or an ancestor of it.
pub open spec fn covered(s: Seq<u8>, t: Seq<u8>) -> bool {
    exists|p: int, q: int|
        #![trigger is_elem(s, p, q)]
        is_elem(s, p, q) && q - p >= 4 && at_or_below(t, path_of(s.subrange(p, q)))
}

/// With a non-empty list, the program and the working directory are inside it.
pub open spec fn paths_cover_ok(s: Seq<u8>, exec0: Seq<u8>, cwd: Seq<u8>) -> bool {
    s.len() > 0 ==> {
        &&& exec0.len() >= 1
        &&& exec0[0] == 0x2f
        &&& covered(s, exec0)
        &&& ((cwd.len() == 1 && cwd[0] == 0x2f) || covered(s, cwd))
    }
}

} // verus!
