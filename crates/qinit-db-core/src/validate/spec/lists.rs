// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! V8: the enabled closure and the pre-syslog list.
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only use: Verus erases it
use super::tables::*;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use crate::layout::*;
use vstd::prelude::*;

verus! {

/// List table `t` is ascending and free of duplicates at entry `k`.
pub open spec fn list_sorted(b: Seq<u8>, t: usize, k: int) -> bool {
    lf(b, t, k - 1) < lf(b, t, k)
}

/// Node `v` is in the enabled closure.
pub open spec fn enabled_has(b: Seq<u8>, v: int) -> bool {
    exists|k: int| 0 <= k < tcnt(b, T_ENABLED as int) && #[trigger] lf(b, T_ENABLED, k) == v
}

pub open spec fn edge_closed(b: Seq<u8>, x: int) -> bool {
    ef(b, x, E_TARGET_KIND) == 0 ==> enabled_has(b, ef(b, x, E_TARGET))
}

pub open spec fn group_closed(b: Seq<u8>, g: int) -> bool {
    gf(b, g, G_KIND) <= 1 ==> forall|x: int|
        gf(b, g, G_EDGE_FIRST) <= x < gf(b, g, G_EDGE_FIRST) + gf(b, g, G_EDGE_COUNT)
            ==> #[trigger] edge_closed(b, x)
}

pub open spec fn node_closed(b: Seq<u8>, i: int) -> bool {
    forall|g: int|
        nf(b, i, N_GROUP_FIRST) <= g < nf(b, i, N_GROUP_FIRST) + nf(b, i, N_GROUP_COUNT)
            ==> #[trigger] group_closed(b, g)
}

/// V8: both lists ascending and free of duplicates, and the enabled set closed under the
/// `require_all` and `require_any` node targets of its members.
pub open spec fn v8(b: Seq<u8>) -> bool {
    &&& forall|k: int| 0 < k < tcnt(b, T_ENABLED as int) ==> #[trigger] list_sorted(b, T_ENABLED, k)
    &&& forall|k: int|
        0 < k < tcnt(b, T_PRESYSLOG as int) ==> #[trigger] list_sorted(b, T_PRESYSLOG, k)
    &&& forall|k: int|
        0 <= k < tcnt(b, T_ENABLED as int) ==> #[trigger] node_closed(b, lf(b, T_ENABLED, k))
}

} // verus!
