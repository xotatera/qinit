// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The validator: total, never panics, and accepts only well-formed databases (V1-V9).
mod graph;
mod header;
mod keys;
mod lists;
mod pool;
mod records;
mod spec;
mod utf8;

pub use pool::{count_elements, elements_ok, nul_list_ok};
#[allow(unused_imports)] // the specs only; Verus erases them outside verification
pub use spec::*;
pub use utf8::{utf8_check, utf8_ok};

#[allow(clippy::wildcard_imports)] // the layout constants, used throughout
use crate::layout::*;
use graph::check_graph;
use header::{check_header, check_tables};
pub(crate) use header::{field, header_word};
use lists::check_lists;
use pool::check_pool_refs;
use qinit_graph_core::GEdge;
use records::check_records;
use vstd::prelude::*;

verus! {

/// Why a database is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbError {
    /// Too short for a header, or a bad magic.
    Header,
    /// An unknown format version.
    Version,
    /// The total length disagrees with the buffer.
    Length,
    /// Table `t` leaves the buffer or is misaligned.
    Table(u8),
    /// Tables overlap or are out of header order.
    Overlap,
    /// Table `t` holds more records than its limit.
    Count(u8),
    /// A string reference of a record leaves the pool or splits a character, a name is empty or
    /// too long, or a list has an empty element.
    Pool { table: u8, record: u32 },
    /// The pool is not UTF-8; `offset` is the pool offset of the first byte that starts no
    /// character.
    Utf8 { offset: u32 },
    /// A cross-table index is out of range.
    Index { table: u8, record: u32 },
    /// An enum is out of range or a reserved bit is set.
    Enum { table: u8, record: u32 },
    /// Groups or edges do not tile their tables.
    Tiling { table: u8, record: u32 },
    /// Fields of one record contradict each other.
    Consistency { table: u8, record: u32 },
    /// The ordering edges form a cycle.
    Cycle,
    /// A hard edge may stop in parallel.
    HardParallel,
    /// The enabled set is not closed under the `require_all` and `require_any` node targets of
    /// its members, sync and async alike.
    Closure,
    /// Node names, or a node list, are not strictly ascending.
    Order,
    /// The caller's scratch buffers are smaller than `MAX_EDGES` edges or `MAX_NODES` levels.
    Scratch,
}

/// Table id `t` as a [`DbError`] field.
#[allow(clippy::cast_possible_truncation)]  // `t < 8`, so the cast is exact
pub(crate) fn tid(t: usize) -> (r: u8)
    requires
        t < 8,
    ensures
        r as int == t as int,
{
    t as u8
}

/// Index `i` as a [`DbError`] record field or a graph node.
#[allow(clippy::cast_possible_truncation)]  // `i` is a table count or index, so it fits
pub(crate) fn rid(i: usize) -> (r: u32)
    requires
        i <= u32::MAX,
    ensures
        r as int == i as int,
{
    i as u32
}

/// Validates `bytes` as a compiled database (spec §3.1): `Ok` only if it is
/// [`well_formed`], and then every reader accessor is in bounds
/// ([`lemma_accessors_in_bounds`], V9). `edges` and `levels` are scratch space of at least
/// `MAX_EDGES` and `MAX_NODES` entries; smaller buffers are refused with [`DbError::Scratch`].
///
/// # Errors
/// The first rule the database breaks, checked in the order header, tables, pool references,
/// records, graph, lists.
pub fn validate(bytes: &[u8], edges: &mut [GEdge], levels: &mut [u32]) -> (r: Result<(), DbError>)
    ensures
        r is Ok ==> well_formed(bytes@),
{
    if edges.len() < MAX_EDGES || levels.len() < MAX_NODES {
        return Err(DbError::Scratch);
    }
    check_header(bytes)?;
    check_tables(bytes)?;
    check_pool_refs(bytes)?;
    check_records(bytes)?;
    assert(table_ok(bytes@, T_NODES as int));
    let n = header_word(bytes, 5 + 2 * T_NODES) as usize;
    let (lv, _) = levels.split_at_mut(n);
    check_graph(bytes, edges, lv)?;
    check_lists(bytes, lv)?;
    Ok(())
}

/// Word `i` is readable by [`word`].
pub open spec fn word_readable(b: Seq<u8>, i: int) -> bool {
    0 <= i < 0x4000_0000 && 4 * i + 4 <= b.len()
}

/// The pool bytes `off..off + len` are inside the buffer.
pub open spec fn slice_readable(b: Seq<u8>, off: int, len: int) -> bool {
    0 <= off && 0 <= len && toff(b, T_POOL as int) + off + len <= b.len()
}

/// Every string of node `i` is readable.
pub open spec fn node_strings_readable(b: Seq<u8>, i: int) -> bool {
    &&& slice_readable(b, nf(b, i, N_NAME_OFF), nf(b, i, N_NAME_LEN))
    &&& slice_readable(b, nf(b, i, N_EXEC_OFF), nf(b, i, N_EXEC_LEN))
    &&& slice_readable(b, nf(b, i, N_READY_OFF), nf(b, i, N_READY_LEN))
    &&& slice_readable(b, nf(b, i, N_INSTANCE_OF_OFF), nf(b, i, N_INSTANCE_OF_LEN))
    &&& slice_readable(b, nf(b, i, N_ENV_OFF), nf(b, i, N_ENV_LEN))
    &&& slice_readable(b, nf(b, i, N_CWD_OFF), nf(b, i, N_CWD_LEN))
}

/// Edge `x`'s path, if it has one, is readable.
pub open spec fn edge_string_readable(b: Seq<u8>, x: int) -> bool {
    ef(b, x, E_TARGET_KIND) == 1 ==> slice_readable(b, ef(b, x, E_TARGET), ef(b, x, E_TARGET_LEN))
}

/// Credential `c`'s strings are readable.
pub open spec fn cred_strings_readable(b: Seq<u8>, c: int) -> bool {
    &&& slice_readable(b, cf(b, c, C_USER_OFF), cf(b, c, C_USER_LEN))
    &&& slice_readable(b, cf(b, c, C_LANDLOCK_OFF), cf(b, c, C_LANDLOCK_LEN))
    &&& slice_readable(b, cf(b, c, C_SECCOMP_OFF), cf(b, c, C_SECCOMP_LEN))
}

/// Route `r`'s path, if it has one, is readable.
pub open spec fn route_string_readable(b: Seq<u8>, r: int) -> bool {
    rf(b, r, R_KIND) == 0 ==> slice_readable(b, rf(b, r, R_A), rf(b, r, R_B))
}

/// Node `i`'s groups are records of the group table.
pub open spec fn node_groups_in_range(b: Seq<u8>, i: int) -> bool {
    nf(b, i, N_GROUP_FIRST) + nf(b, i, N_GROUP_COUNT) <= tcnt(b, T_GROUPS as int)
}

/// Group `g`'s edges are records of the edge table.
pub open spec fn group_edges_in_range(b: Seq<u8>, g: int) -> bool {
    gf(b, g, G_EDGE_FIRST) + gf(b, g, G_EDGE_COUNT) <= tcnt(b, T_EDGES as int)
}

/// V9: in an accepted database every header word and every word of every record is readable
/// by [`word`], every string the reader decodes is inside the buffer, and every group and edge
/// run a node or group names stays inside its table. With the indices of V3, every reader
/// accessor is in bounds.
pub proof fn lemma_accessors_in_bounds(b: Seq<u8>)
    requires
        well_formed(b),
    ensures
        forall|i: int| 0 <= i < HEADER_WORDS ==> #[trigger] word_readable(b, i),
        forall|t: int, r: int, w: int|
            0 <= t < 7 && 0 <= r < tcnt(b, t) && 0 <= w < spec_words(t)
                ==> #[trigger] word_readable(b, widx(b, t, r, w)),
        forall|i: int| 0 <= i < nodes(b) ==> #[trigger] node_strings_readable(b, i),
        forall|x: int| 0 <= x < tcnt(b, T_EDGES as int) ==> #[trigger] edge_string_readable(b, x),
        forall|c: int| 0 <= c < tcnt(b, T_CREDS as int) ==> #[trigger] cred_strings_readable(b, c),
        forall|r: int| 0 <= r < tcnt(b, T_ROUTES as int) ==> #[trigger] route_string_readable(b, r),
        forall|i: int| 0 <= i < nodes(b) ==> #[trigger] node_groups_in_range(b, i),
        forall|g: int| 0 <= g < tcnt(b, T_GROUPS as int) ==> #[trigger] group_edges_in_range(b, g),
{
    assert(table_ok(b, T_POOL as int));
    assert forall|t: int, r: int, w: int|
        0 <= t < 7 && 0 <= r < tcnt(b, t) && 0 <= w < spec_words(
            t,
        ) implies #[trigger] word_readable(b, widx(b, t, r, w)) by {
        header::lemma_widx(b, t, r, w);
    }
    assert forall|i: int| 0 <= i < nodes(b) implies #[trigger] node_strings_readable(b, i) by {
        assert(node_pool_ok(b, i));
    }
    assert forall|x: int| 0 <= x < tcnt(b, T_EDGES as int) implies #[trigger] edge_string_readable(
        b,
        x,
    ) by {
        assert(edge_pool_ok(b, x));
    }
    assert forall|c: int| 0 <= c < tcnt(b, T_CREDS as int) implies #[trigger] cred_strings_readable(
        b,
        c,
    ) by {
        assert(cred_pool_ok(b, c));
    }
    assert forall|r: int|
        0 <= r < tcnt(b, T_ROUTES as int) implies #[trigger] route_string_readable(b, r) by {
        assert(route_pool_ok(b, r));
    }
    assert forall|i: int| 0 <= i < nodes(b) implies #[trigger] node_groups_in_range(b, i) by {
        assert(node_tile_ok(b, i));
        graph::lemma_ngsum_mono(b, i + 1, nodes(b));
    }
    assert forall|g: int| 0 <= g < tcnt(b, T_GROUPS as int) implies #[trigger] group_edges_in_range(
        b,
        g,
    ) by {
        assert(group_tile_ok(b, g));
        graph::lemma_gesum_mono(b, g + 1, tcnt(b, T_GROUPS as int));
    }
}

} // verus!
