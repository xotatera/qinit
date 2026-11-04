// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! A UTF-8 scanner proved against `vstd::utf8::valid_utf8`, which rejects overlong encodings,
//! surrogates and values above U+10FFFF as `core::str::from_utf8` does.
use vstd::prelude::*;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use vstd::utf8::*;

verus! {

#[allow(clippy::manual_range_contains)]  // `contains` has no Verus spec
fn is_cont(c: u8) -> (r: bool)
    ensures
        r == is_continuation_byte(c),
{
    0x80 <= c && c <= 0xbf
}

/// The length of the scalar starting at `b[i]` and ending by `end`, or 0 if it is not one.
#[allow(clippy::cast_lossless, clippy::manual_range_contains)]  // `From` and `contains` have no Verus specs; the code mirrors `vstd::utf8`
fn scalar_len(b: &[u8], i: usize, end: usize) -> (n: usize)
    requires
        i < end <= b@.len(),
    ensures
        n != 0 ==> n <= end - i && valid_first_scalar(b@.subrange(i as int, end as int))
            && length_of_first_scalar(b@.subrange(i as int, end as int)) == n,
{
    let ghost s = b@.subrange(i as int, end as int);
    let b0 = b[i];
    assert(s[0] == b0);
    if b0 <= 0x7f {
        return 1;
    }
    if 0xc0 <= b0 && b0 <= 0xdf {
        if end - i < 2 {
            return 0;
        }
        let b1 = b[i + 1];
        assert(s[1] == b1);
        if !is_cont(b1) {
            return 0;
        }
        let cp: u32 = (((b0 & 0x1f) as u32) << 6) | ((b1 & 0x3f) as u32);
        assert(cp == decode_first_codepoint(s));
        if cp < 0x80 || (0xd800 <= cp && cp <= 0xdfff) {
            return 0;
        }
        return 2;
    }
    if 0xe0 <= b0 && b0 <= 0xef {
        if end - i < 3 {
            return 0;
        }
        let b1 = b[i + 1];
        let b2 = b[i + 2];
        assert(s[1] == b1 && s[2] == b2);
        if !is_cont(b1) || !is_cont(b2) {
            return 0;
        }
        let cp: u32 = (((b0 & 0x0f) as u32) << 12) | (((b1 & 0x3f) as u32) << 6) | ((b2
            & 0x3f) as u32);
        assert(cp == decode_first_codepoint(s));
        if cp < 0x800 || (0xd800 <= cp && cp <= 0xdfff) {
            return 0;
        }
        return 3;
    }
    if 0xf0 <= b0 && b0 <= 0xf7 {
        if end - i < 4 {
            return 0;
        }
        let b1 = b[i + 1];
        let b2 = b[i + 2];
        let b3 = b[i + 3];
        assert(s[1] == b1 && s[2] == b2 && s[3] == b3);
        if !is_cont(b1) || !is_cont(b2) || !is_cont(b3) {
            return 0;
        }
        let cp: u32 = (((b0 & 0x07) as u32) << 18) | (((b1 & 0x3f) as u32) << 12) | (((b2
            & 0x3f) as u32) << 6) | ((b3 & 0x3f) as u32);
        assert(cp == decode_first_codepoint(s));
        if cp < 0x10000 || cp > 0x0010_ffff || (0xd800 <= cp && cp <= 0xdfff) {
            return 0;
        }
        return 4;
    }
    0
}

/// `b[start..end]` is valid UTF-8, or the index of the first byte that starts no scalar.
///
/// # Errors
/// The index in `b` of the first byte that starts no valid scalar.
pub fn utf8_check(b: &[u8], start: usize, end: usize) -> (r: Result<(), usize>)
    requires
        start <= end <= b@.len(),
    ensures
        r is Ok ==> valid_utf8(b@.subrange(start as int, end as int)),
        r is Err ==> start <= r->Err_0 < end,
{
    let ghost s = b@.subrange(start as int, end as int);
    let mut i = start;
    assert(s.subrange(0, 0) =~= Seq::<u8>::empty());
    while i < end
        invariant
            start <= i <= end <= b@.len(),
            s == b@.subrange(start as int, end as int),
            partial_valid_utf8(s, i - start),
        decreases end - i,
    {
        let n = scalar_len(b, i, end);
        if n == 0 {
            return Err(i);
        }
        proof {
            assert(s.subrange(i - start, s.len() as int) =~= b@.subrange(i as int, end as int));
            partial_valid_utf8_extend(s, i - start);
        }
        i += n;
    }
    assert(s.subrange(0, s.len() as int) =~= s);
    Ok(())
}

/// `b[start..end]` is valid UTF-8.
#[must_use]
pub fn utf8_ok(b: &[u8], start: usize, end: usize) -> (ok: bool)
    requires
        start <= end <= b@.len(),
    ensures
        ok ==> valid_utf8(b@.subrange(start as int, end as int)),
{
    match utf8_check(b, start, end) {
        Ok(()) => true,
        Err(_) => false,
    }
}

} // verus!
