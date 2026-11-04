// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Canonical absolute paths (spec §2.1 of the sandbox design): the one rule the frames, the
//! database validator and the launch decoder share for sandbox path entries and working
//! directories.
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

} // verus!
