// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! The encoder: lays a record, its list entries and its strings out in a buffer, then asks the
//! proved decoder whether it built an accepted message. The encoder therefore cannot return a
//! message `check` would refuse, whatever it was given.
use crate::decode::check;
#[allow(clippy::wildcard_imports)] // the layout constants, used throughout
use crate::layout::*;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use crate::spec::*;
use vstd::prelude::*;

verus! {

/// Why a message could not be encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The record, entries and strings do not fit the buffer or `MAX_MESSAGE`.
    TooLarge = 1,
    /// A value breaks a rule of the format (a name length, a list cap, a wait, an enum).
    Invalid = 2,
}

/// One piece of a record: a word, or a string that goes to the pool and takes two words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Piece<'a> {
    /// A record word.
    Word(u32),
    /// A string: the record gets its offset and length.
    Str(&'a [u8]),
}

/// One entry of a list page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryIn<'a> {
    pub name: &'a [u8],
    pub kind: u32,
    pub state: u32,
    pub detail: u32,
}

/// The most pieces a record has.
pub const MAX_PIECES: usize = 16;

/// Writes `v` as little-endian word `i`.
fn put_word(out: &mut [u8], i: usize, v: u32)
    requires
        i < 0x4000_0000,
        4 * i + 4 <= old(out)@.len(),
    ensures
        final(out)@.len() == old(out)@.len(),
{
    out[4 * i] = (v & 0xff) as u8;
    out[4 * i + 1] = ((v >> 8) & 0xff) as u8;
    out[4 * i + 2] = ((v >> 16) & 0xff) as u8;
    out[4 * i + 3] = ((v >> 24) & 0xff) as u8;
}

/// Copies `s` to `out[at..]`.
fn put_bytes(out: &mut [u8], at: usize, s: &[u8])
    requires
        at + s@.len() <= old(out)@.len(),
        at + s@.len() <= MAX_MESSAGE,
    ensures
        final(out)@.len() == old(out)@.len(),
{
    let mut k: usize = 0;
    while k < s.len()
        invariant
            at + s@.len() <= out@.len(),
            at + s@.len() <= MAX_MESSAGE,
            k <= s@.len(),
            out@.len() == old(out)@.len(),
        decreases s@.len() - k,
    {
        assert(at + k < out@.len());
        out[at + k] = s[k];
        k += 1;
    }
}

/// The words the pieces take in the record.
fn piece_words(pieces: &[Piece<'_>]) -> (n: usize)
    requires
        pieces@.len() <= MAX_PIECES,
    ensures
        n <= 2 * MAX_PIECES,
{
    let mut n: usize = 0;
    let mut i: usize = 0;
    while i < pieces.len()
        invariant
            i <= pieces@.len() <= MAX_PIECES,
            n <= 2 * i,
        decreases pieces@.len() - i,
    {
        n +=
        match pieces[i] {
            Piece::Word(_) => 1,
            Piece::Str(_) => 2,
        };
        i += 1;
    }
    n
}

/// Encodes a message of type `t` with the record `pieces` and the list `entries` into `out`,
/// declaring `fd_count` descriptors. Returns the length of the message.
///
/// The strings are laid out in the order the record and then the entries name them, so the
/// same value always gives the same bytes.
///
/// # Errors
/// `TooLarge` when the message does not fit `out` or `MAX_MESSAGE`; `Invalid` when the result
/// is not a message `check` accepts.
#[allow(clippy::many_single_char_names, clippy::cast_possible_truncation)]  // `t`, `w`, `p`, `i`, `k` follow the layout names; every cast is of a value bounded by `MAX_MESSAGE`
pub fn encode_pieces(
    t: u32,
    fd_count: u32,
    pieces: &[Piece<'_>],
    entries: &[EntryIn<'_>],
    out: &mut [u8],
) -> (r: Result<usize, EncodeError>)
    ensures
        r is Ok ==> r.unwrap() <= final(out)@.len() && accepted(
            final(out)@.subrange(0, r.unwrap() as int),
            fd_count as int,
        ),
{
    if pieces.len() > MAX_PIECES || entries.len() > MAX_LIST_ENTRIES {
        return Err(EncodeError::TooLarge);
    }
    let rec_words = piece_words(pieces) + ENTRY_WORDS * entries.len();
    let pool_off = 4 * (HEADER_WORDS + rec_words);
    if pool_off > out.len() || pool_off > MAX_MESSAGE {
        return Err(EncodeError::TooLarge);
    }
    let cap = if out.len() < MAX_MESSAGE {
        out.len()
    } else {
        MAX_MESSAGE
    };
    put_word(out, H_MAGIC, QCP_MAGIC);
    put_word(out, H_VERSION, QCP_VERSION);
    put_word(out, H_TYPE, t);
    put_word(out, H_FD_COUNT, fd_count);
    let mut w: usize = HEADER_WORDS;
    let mut p: usize = pool_off;
    let mut i: usize = 0;
    while i < pieces.len()
        invariant
            pieces@.len() <= MAX_PIECES,
            i <= pieces@.len(),
            cap <= out@.len(),
            cap <= MAX_MESSAGE,
            pool_off <= cap,
            p <= cap,
            4 * w <= pool_off,
            out@.len() == old(out)@.len(),
        decreases pieces@.len() - i,
    {
        match pieces[i] {
            Piece::Word(v) => {
                if 4 * (w + 1) > pool_off {
                    return Err(EncodeError::Invalid);
                }
                put_word(out, w, v);
                w += 1;
            },
            Piece::Str(s) => {
                if 4 * (w + 2) > pool_off || s.len() > cap - p {
                    return Err(EncodeError::TooLarge);
                }
                put_bytes(out, p, s);
                put_word(out, w, p as u32);
                put_word(out, w + 1, s.len() as u32);
                p += s.len();
                w += 2;
            },
        }
        i += 1;
    }
    let mut k: usize = 0;
    while k < entries.len()
        invariant
            k <= entries@.len() <= MAX_LIST_ENTRIES,
            cap <= out@.len(),
            cap <= MAX_MESSAGE,
            pool_off <= cap,
            p <= cap,
            4 * w <= pool_off,
            out@.len() == old(out)@.len(),
        decreases entries@.len() - k,
    {
        let e = entries[k];
        if 4 * (w + ENTRY_WORDS) > pool_off || e.name.len() > cap - p {
            return Err(EncodeError::TooLarge);
        }
        put_bytes(out, p, e.name);
        put_word(out, w + EN_NAME_OFF, p as u32);
        put_word(out, w + EN_NAME_LEN, e.name.len() as u32);
        put_word(out, w + EN_KIND, e.kind);
        put_word(out, w + EN_STATE, e.state);
        put_word(out, w + EN_DETAIL, e.detail);
        p += e.name.len();
        w += ENTRY_WORDS;
        k += 1;
    }
    put_word(out, H_TOTAL_LEN, p as u32);
    let sealed = vstd::slice::slice_subrange(out, 0, p);
    match check(sealed, fd_count as usize) {
        Ok(()) => Ok(p),
        Err(_) => Err(EncodeError::Invalid),
    }
}

} // verus!
