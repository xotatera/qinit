// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! V1 and the field accessors: header words, table bounds and record words.
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use crate::layout::*;
use vstd::prelude::*;

verus! {

/// Word `i` of `b` as an integer.
pub open spec fn hw(b: Seq<u8>, i: int) -> int {
    spec_word(b, i) as int
}

/// Byte offset of table `t`.
pub open spec fn toff(b: Seq<u8>, t: int) -> int {
    hw(b, spec_offset_word(t))
}

/// Record count of table `t` (the pool: its length in bytes).
pub open spec fn tcnt(b: Seq<u8>, t: int) -> int {
    hw(b, spec_count_word(t))
}

/// Words per record of table `t` (`WORDS`).
pub open spec fn spec_words(t: int) -> int {
    if t == 0 {
        36
    } else if t == 1 {
        3
    } else if t == 2 {
        7
    } else if t == 3 {
        12
    } else if t == 4 {
        3
    } else {
        1
    }
}

/// Record limit of table `t` (the pool: its byte limit).
pub open spec fn spec_limit(t: int) -> int {
    if t == 0 {
        MAX_NODES as int
    } else if t == 1 {
        MAX_GROUPS as int
    } else if t == 2 {
        MAX_EDGES as int
    } else if t == 3 {
        MAX_CREDS as int
    } else if t == 4 {
        MAX_ROUTES as int
    } else if t == 5 || t == 6 {
        MAX_NODES as int
    } else {
        MAX_POOL as int
    }
}

/// Bytes table `t` occupies.
pub open spec fn tlen(b: Seq<u8>, t: int) -> int {
    if t == 7 {
        tcnt(b, t)
    } else {
        tcnt(b, t) * spec_words(t) * 4
    }
}

/// Where table `t` may start at the earliest: after the header or after the table before it.
pub open spec fn tmin(b: Seq<u8>, t: int) -> int {
    if t == 0 {
        4 * HEADER_WORDS as int
    } else {
        toff(b, t - 1) + tlen(b, t - 1)
    }
}

/// V1 for the header: long enough, magic, version, and the total length is the buffer's.
pub open spec fn header_ok(b: Seq<u8>) -> bool {
    &&& b.len() >= 4 * HEADER_WORDS
    &&& hw(b, H_MAGIC as int) == MAGIC as int
    &&& hw(b, H_VERSION as int) == VERSION as int
    &&& hw(b, H_TOTAL_LEN as int) == b.len()
}

/// V1 for table `t`: within its limit, inside the buffer, word-aligned (the pool excepted), and
/// after the table before it.
pub open spec fn table_ok(b: Seq<u8>, t: int) -> bool {
    &&& tcnt(b, t) <= spec_limit(t)
    &&& toff(b, t) + tlen(b, t) <= b.len()
    &&& (t < 7 ==> toff(b, t) % 4 == 0)
    &&& toff(b, t) >= tmin(b, t)
}

/// V1: the header and all eight tables.
pub open spec fn v1(b: Seq<u8>) -> bool {
    &&& header_ok(b)
    &&& forall|t: int| 0 <= t < 8 ==> #[trigger] table_ok(b, t)
}

/// Word index of word `w` of record `r` in table `t`.
pub open spec fn widx(b: Seq<u8>, t: int, r: int, w: int) -> int {
    toff(b, t) / 4 + r * spec_words(t) + w
}

/// Word `w` of record `r` in table `t`.
pub open spec fn rw(b: Seq<u8>, t: int, r: int, w: int) -> int {
    hw(b, widx(b, t, r, w))
}

/// Node `i`, word `w`.
pub open spec fn nf(b: Seq<u8>, i: int, w: usize) -> int {
    rw(b, T_NODES as int, i, w as int)
}

/// Group `g`, word `w`.
pub open spec fn gf(b: Seq<u8>, g: int, w: usize) -> int {
    rw(b, T_GROUPS as int, g, w as int)
}

/// Edge `x`, word `w`.
pub open spec fn ef(b: Seq<u8>, x: int, w: usize) -> int {
    rw(b, T_EDGES as int, x, w as int)
}

/// Credential `c`, word `w`.
pub open spec fn cf(b: Seq<u8>, c: int, w: usize) -> int {
    rw(b, T_CREDS as int, c, w as int)
}

/// Route `r`, word `w`.
pub open spec fn rf(b: Seq<u8>, r: int, w: usize) -> int {
    rw(b, T_ROUTES as int, r, w as int)
}

/// Entry `k` of list table `t` (enabled or pre-syslog).
pub open spec fn lf(b: Seq<u8>, t: usize, k: int) -> int {
    rw(b, t as int, k, 0)
}

/// Nodes.
pub open spec fn nodes(b: Seq<u8>) -> int {
    tcnt(b, T_NODES as int)
}

} // verus!
