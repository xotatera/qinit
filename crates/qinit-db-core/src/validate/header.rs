// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! V1: the header and the table bounds, and the record field reader built on them.

#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use super::spec::*;
use super::{DbError, tid};
#[allow(clippy::wildcard_imports)] // the layout constants, used throughout
use crate::layout::*;
use vstd::prelude::*;

verus! {

/// Words per record of table `t`.
pub(crate) fn words_of(t: usize) -> (w: usize)
    requires
        t < 7,
    ensures
        w as int == spec_words(t as int),
        w == WORDS[t as int],
{
    if t == 0 {
        24
    } else if t == 1 {
        3
    } else if t == 2 {
        7
    } else if t == 3 {
        10
    } else if t == 4 {
        3
    } else {
        1
    }
}

/// Record limit of table `t`.
fn limit_of(t: usize) -> (l: u64)
    requires
        t < 8,
    ensures
        l as int == spec_limit(t as int),
{
    if t == 0 {
        MAX_NODES as u64
    } else if t == 1 {
        MAX_GROUPS as u64
    } else if t == 2 {
        MAX_EDGES as u64
    } else if t == 3 {
        MAX_CREDS as u64
    } else if t == 4 {
        MAX_ROUTES as u64
    } else if t == 5 || t == 6 {
        MAX_NODES as u64
    } else {
        MAX_POOL as u64
    }
}

/// Header word `i`.
pub(crate) fn header_word(b: &[u8], i: usize) -> (v: u32)
    requires
        header_ok(b@),
        i < HEADER_WORDS,
    ensures
        v as int == hw(b@, i as int),
{
    word(b, i)
}

/// A record word index is readable by [`word`] in a database that passes V1.
pub proof fn lemma_widx(b: Seq<u8>, t: int, r: int, w: int)
    requires
        v1(b),
        0 <= t < 7,
        0 <= r < tcnt(b, t),
        0 <= w < spec_words(t),
    ensures
        0 <= r * spec_words(t),
        0 <= widx(b, t, r, w) < 0x4000_0000,
        4 * widx(b, t, r, w) + 4 <= b.len(),
{
    assert(table_ok(b, t));
    let ws = spec_words(t);
    let c = tcnt(b, t);
    assert((r + 1) * ws <= c * ws) by (nonlinear_arith)
        requires
            r + 1 <= c,
            ws >= 0,
    ;
    assert(0 <= r * ws) by (nonlinear_arith)
        requires
            r >= 0,
            ws >= 0,
    ;
    assert((r + 1) * ws == r * ws + ws) by (nonlinear_arith);
    assert(c * ws * 4 == 4 * (c * ws)) by (nonlinear_arith);
}

/// Word `w` of record `r` in table `t`.
pub(crate) fn field(b: &[u8], t: usize, r: usize, w: usize) -> (v: u32)
    requires
        v1(b@),
        t < 7,
        r < tcnt(b@, t as int),
        w < spec_words(t as int),
    ensures
        v as int == rw(b@, t as int, r as int, w as int),
{
    proof {
        lemma_widx(b@, t as int, r as int, w as int);
    }
    let off = word(b, 4 + 2 * t) as usize;
    let ws = words_of(t);
    word(b, off / 4 + r * ws + w)
}

/// Checks the header: length, magic, version and total length (V1).
pub(crate) fn check_header(b: &[u8]) -> (r: Result<(), DbError>)
    ensures
        r is Ok ==> header_ok(b@),
{
    if b.len() < 4 * HEADER_WORDS || word(b, H_MAGIC) != MAGIC {
        return Err(DbError::Header);
    }
    if word(b, H_VERSION) != VERSION {
        return Err(DbError::Version);
    }
    if word(b, H_TOTAL_LEN) as usize != b.len() {
        return Err(DbError::Length);
    }
    Ok(())
}

/// Bytes a table of `cnt` records of table `t` occupies.
fn table_bytes(t: usize, cnt: u64) -> (n: u64)
    requires
        t < 8,
        cnt <= spec_limit(t as int),
    ensures
        n == (if t == 7 {
            cnt as int
        } else {
            cnt * spec_words(t as int) * 4
        }),
{
    if t == 7 {
        cnt
    } else {
        cnt * (words_of(t) as u64) * 4
    }
}

/// Checks every table's offset and count against the buffer and the limits, and that the
/// tables follow each other in header order (V1).
#[allow(clippy::cast_lossless, clippy::manual_is_multiple_of)]  // `From` and `is_multiple_of` have no Verus specs
pub(crate) fn check_tables(b: &[u8]) -> (r: Result<(), DbError>)
    requires
        header_ok(b@),
    ensures
        r is Ok ==> v1(b@),
{
    let len = b.len() as u64;
    let mut end: u64 = (4 * HEADER_WORDS) as u64;
    let mut t: usize = 0;
    while t < 8
        invariant
            header_ok(b@),
            len == b@.len(),
            t <= 8,
            end <= len,
            end as int == tmin(b@, t as int),
            forall|u: int| 0 <= u < t ==> #[trigger] table_ok(b@, u),
        decreases 8 - t,
    {
        let off = header_word(b, 4 + 2 * t) as u64;
        let cnt = header_word(b, 5 + 2 * t) as u64;
        if cnt > limit_of(t) {
            return Err(DbError::Count(tid(t)));
        }
        let size = table_bytes(t, cnt);
        if off > len || size > len - off || (t < 7 && off % 4 != 0) {
            return Err(DbError::Table(tid(t)));
        }
        if off < end {
            return Err(DbError::Overlap);
        }
        assert(table_ok(b@, t as int));
        end = off + size;
        t += 1;
    }
    Ok(())
}

} // verus!
