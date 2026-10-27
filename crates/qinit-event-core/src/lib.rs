// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! `qinit-event-core`: the pure half of the event loop: tokens and the bounds of inotify
//! records, proved by Verus (`proof:qinit-event-core`). Seeded from alloy's
//! `common-event-core`. `qinit-event` runs the loop and re-exports this crate.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use vstd::prelude::*;

verus! {

/// The caller's name for a source.
pub type Token = u64;

/// Bytes of an inotify event's header (`struct inotify_event` without its name).
pub const HEAD: usize = 16;

/// The native-endian `u32` at `buf[off..off + 4]`: `u32::from_ne_bytes` in the byte order vstd
/// leaves open (`endianness`), so the contracts hold on either.
pub open spec fn u32_of(buf: Seq<u8>, off: int) -> u32 {
    let (b0, b1, b2, b3) = (
        buf[off] as int,
        buf[off + 1] as int,
        buf[off + 2] as int,
        buf[off + 3] as int,
    );
    (match vstd::endian::endianness() {
        vstd::endian::Endian::Little => b0 + 0x100 * b1 + 0x1_0000 * b2 + 0x100_0000 * b3,
        vstd::endian::Endian::Big => b3 + 0x100 * b2 + 0x1_0000 * b1 + 0x100_0000 * b0,
    }) as u32
}

/// The native-endian `u32` at `buf[off..off + 4]`. Trusted: `from_ne_bytes` has no Verus
/// spec; the postcondition is its definition.
#[verifier::external_body]
pub(crate) fn u32_at(  // disciplines:allow-trusted (from_ne_bytes has no Verus spec)
    buf: &[u8],
    off: usize,
) -> (v: u32)
    requires
        off + 4 <= buf@.len(),
    ensures
        v == u32_of(buf@, off as int),
{
    u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// The event at `off` in an inotify buffer: its mask, the byte range of its (NUL-padded) name
/// and the offset of the next event; `None` when no complete event starts at `off`.
#[must_use]
pub fn next_event(buf: &[u8], off: usize) -> (r: Option<(u32, core::ops::Range<usize>, usize)>)
    ensures
        match r {
            Some((mask, name, next)) => {
                &&& off + HEAD <= buf@.len()
                &&& mask == u32_of(buf@, off + 4)
                &&& name.start == off + HEAD
                &&& name.end == name.start + u32_of(buf@, off + 12)
                &&& name.end <= buf@.len()
                &&& next == name.end
                &&& next > off
            },
            None => {
                ||| off + HEAD > buf@.len()
                ||| off + HEAD + u32_of(buf@, off + 12) > buf@.len()
            },
        },
{
    if off > buf.len() || buf.len() - off < HEAD {
        return None;
    }
    let mask = u32_at(buf, off + 4);
    let len = u32_at(buf, off + 12) as usize;
    let start = off + HEAD;
    if len > buf.len() - start {
        return None;
    }
    let end = start + len;
    Some((mask, start..end, end))
}

} // verus!
