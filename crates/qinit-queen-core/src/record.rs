// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The channel's records: 16 bytes, little-endian `u32` kind, `u32` arg, `u64` key. A decoder
//! takes the bytes and the number of descriptors that came with them, and accepts only a record
//! that is whole, from the right side, with unused words zero, a known mode and the descriptor
//! count its kind needs.
use vstd::prelude::*;

verus! {

/// Bytes in a record.
pub const RECORD_LEN: usize = 16;

/// What the machine is going to do at the end, as colony names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Halt,
    Poweroff,
    Reboot,
}

/// A record colony sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FromColony {
    /// Hold this descriptor (it comes with the record) under `key`.
    Put { key: u64 },
    /// Let go of `key`.
    Drop { key: u64 },
    /// The shutdown has begun, ending in `mode`.
    Shutdown { mode: Mode },
}

/// A record queen sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToColony {
    /// One held entry (its descriptor comes with the record).
    Held { key: u64 },
    /// The hand-over is complete: `count` entries were sent.
    HeldEnd { count: u32 },
    /// Queen reaped something: statuses of re-adopted mains may be readable now.
    Reaped,
    /// Ctrl-Alt-Del or `SIGPWR`: please shut down, ending in `mode`.
    Request { mode: Mode },
    /// A `Put` for `key` was refused: the store is full.
    Refused { key: u64 },
}

pub const KIND_PUT: u32 = 1;

pub const KIND_DROP: u32 = 2;

pub const KIND_SHUTDOWN: u32 = 3;

pub const KIND_HELD: u32 = 65;

pub const KIND_HELD_END: u32 = 66;

pub const KIND_REAPED: u32 = 67;

pub const KIND_REQUEST: u32 = 68;

pub const KIND_REFUSED: u32 = 69;

/// The little-endian `u32` at `b[off..off + 4]`.
pub open spec fn u32_le(b: Seq<u8>, off: int) -> u32 {
    (b[off] as int + 0x100 * b[off + 1] as int + 0x1_0000 * b[off + 2] as int + 0x100_0000 * b[off
        + 3] as int) as u32
}

/// The little-endian `u64` at `b[off..off + 8]`.
pub open spec fn u64_le(b: Seq<u8>, off: int) -> u64 {
    (u32_le(b, off) as int + 0x1_0000_0000 * u32_le(b, off + 4) as int) as u64
}

/// The word that names a mode.
pub open spec fn mode_word(m: Mode) -> u32 {
    match m {
        Mode::Halt => 0,
        Mode::Poweroff => 1,
        Mode::Reboot => 2,
    }
}

/// The mode a word names; only meaningful for 0 to 2.
pub open spec fn word_mode(w: u32) -> Mode {
    if w == 0 {
        Mode::Halt
    } else if w == 1 {
        Mode::Poweroff
    } else {
        Mode::Reboot
    }
}

/// The record `b` with `fds` descriptors is, as far as colony may send it.
pub open spec fn from_colony_spec(b: Seq<u8>, fds: int) -> Option<FromColony> {
    if b.len() != 16 {
        None
    } else {
        let kind = u32_le(b, 0);
        let arg = u32_le(b, 4);
        let key = u64_le(b, 8);
        if kind == KIND_PUT {
            if arg == 0 && key != 0 && fds == 1 {
                Some(FromColony::Put { key })
            } else {
                None
            }
        } else if kind == KIND_DROP {
            if arg == 0 && key != 0 && fds == 0 {
                Some(FromColony::Drop { key })
            } else {
                None
            }
        } else if kind == KIND_SHUTDOWN {
            if key == 0 && arg <= 2 && fds == 0 {
                Some(FromColony::Shutdown { mode: word_mode(arg) })
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// The record `b` with `fds` descriptors is, as far as queen may send it.
pub open spec fn to_colony_spec(b: Seq<u8>, fds: int) -> Option<ToColony> {
    if b.len() != 16 {
        None
    } else {
        let kind = u32_le(b, 0);
        let arg = u32_le(b, 4);
        let key = u64_le(b, 8);
        if kind == KIND_HELD {
            if arg == 0 && key != 0 && fds == 1 {
                Some(ToColony::Held { key })
            } else {
                None
            }
        } else if kind == KIND_HELD_END {
            if key == 0 && fds == 0 {
                Some(ToColony::HeldEnd { count: arg })
            } else {
                None
            }
        } else if kind == KIND_REAPED {
            if arg == 0 && key == 0 && fds == 0 {
                Some(ToColony::Reaped)
            } else {
                None
            }
        } else if kind == KIND_REQUEST {
            if key == 0 && arg <= 2 && fds == 0 {
                Some(ToColony::Request { mode: word_mode(arg) })
            } else {
                None
            }
        } else if kind == KIND_REFUSED {
            if arg == 0 && key != 0 && fds == 0 {
                Some(ToColony::Refused { key })
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// The record with these words, as 16 little-endian bytes. Trusted: `to_le_bytes` has no Verus
/// spec; the postcondition is its definition.
#[verifier::external_body]
fn pack(  // disciplines:allow-trusted (to_le_bytes has no Verus spec)
    kind: u32,
    arg: u32,
    key: u64,
) -> (b: [u8; 16])
    ensures
        u32_le(b@, 0) == kind,
        u32_le(b@, 4) == arg,
        u64_le(b@, 8) == key,
{
    let mut b = [0u8;16];
    b[0..4].copy_from_slice(&kind.to_le_bytes());
    b[4..8].copy_from_slice(&arg.to_le_bytes());
    b[8..16].copy_from_slice(&key.to_le_bytes());
    b
}

/// The little-endian `u32` at `b[off..off + 4]`. Trusted like [`pack`].
#[verifier::external_body]
fn read_u32(  // disciplines:allow-trusted (from_le_bytes has no Verus spec)
    b: &[u8],
    off: usize,
) -> (v: u32)
    requires
        off + 4 <= b@.len(),
    ensures
        v == u32_le(b@, off as int),
{
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// The little-endian `u64` at `b[off..off + 8]`. Trusted like [`pack`].
#[verifier::external_body]
fn read_u64(  // disciplines:allow-trusted (from_le_bytes has no Verus spec)
    b: &[u8],
    off: usize,
) -> (v: u64)
    requires
        off + 8 <= b@.len(),
    ensures
        v == u64_le(b@, off as int),
{
    u64::from_le_bytes(
        [
            b[off],
            b[off + 1],
            b[off + 2],
            b[off + 3],
            b[off + 4],
            b[off + 5],
            b[off + 6],
            b[off + 7],
        ],
    )
}

fn word_of(m: Mode) -> (w: u32)
    ensures
        w == mode_word(m),
        w <= 2,
{
    match m {
        Mode::Halt => 0,
        Mode::Poweroff => 1,
        Mode::Reboot => 2,
    }
}

fn mode_of(w: u32) -> (m: Mode)
    requires
        w <= 2,
    ensures
        m == word_mode(w),
        mode_word(m) == w,
{
    if w == 0 {
        Mode::Halt
    } else if w == 1 {
        Mode::Poweroff
    } else {
        Mode::Reboot
    }
}

/// Whether `r` is a record the encoder may write: a held or dropped key is never 0.
pub open spec fn from_colony_wf(r: FromColony) -> bool {
    match r {
        FromColony::Put { key } => key != 0,
        FromColony::Drop { key } => key != 0,
        FromColony::Shutdown { .. } => true,
    }
}

/// The descriptors that travel with `r`.
pub open spec fn from_colony_fds(r: FromColony) -> int {
    match r {
        FromColony::Put { .. } => 1,
        _ => 0,
    }
}

/// Whether `r` is a record the encoder may write.
pub open spec fn to_colony_wf(r: ToColony) -> bool {
    match r {
        ToColony::Held { key } => key != 0,
        ToColony::Refused { key } => key != 0,
        _ => true,
    }
}

/// The descriptors that travel with `r`.
pub open spec fn to_colony_fds(r: ToColony) -> int {
    match r {
        ToColony::Held { .. } => 1,
        _ => 0,
    }
}

/// The 16 bytes of `r`. Decoding them with [`from_colony_fds`] descriptors gives `r` back.
#[must_use]
pub fn encode_from_colony(r: FromColony) -> (b: [u8; 16])
    requires
        from_colony_wf(r),
    ensures
        from_colony_spec(b@, from_colony_fds(r)) == Some(r),
{
    match r {
        FromColony::Put { key } => pack(KIND_PUT, 0, key),
        FromColony::Drop { key } => pack(KIND_DROP, 0, key),
        FromColony::Shutdown { mode } => pack(KIND_SHUTDOWN, word_of(mode), 0),
    }
}

/// The record in `b` that arrived with `fds` descriptors: `None` unless it is whole, one of
/// colony's, with unused words zero, a known mode and the descriptor count its kind needs.
#[must_use]
pub fn decode_from_colony(b: &[u8], fds: usize) -> (r: Option<FromColony>)
    ensures
        r == from_colony_spec(b@, fds as int),
{
    if b.len() != RECORD_LEN {
        return None;
    }
    let kind = read_u32(b, 0);
    let arg = read_u32(b, 4);
    let key = read_u64(b, 8);
    if kind == KIND_PUT {
        if arg == 0 && key != 0 && fds == 1 {
            Some(FromColony::Put { key })
        } else {
            None
        }
    } else if kind == KIND_DROP {
        if arg == 0 && key != 0 && fds == 0 {
            Some(FromColony::Drop { key })
        } else {
            None
        }
    } else if kind == KIND_SHUTDOWN {
        if key == 0 && arg <= 2 && fds == 0 {
            Some(FromColony::Shutdown { mode: mode_of(arg) })
        } else {
            None
        }
    } else {
        None
    }
}

/// The 16 bytes of `r`. Decoding them with [`to_colony_fds`] descriptors gives `r` back.
#[must_use]
pub fn encode_to_colony(r: ToColony) -> (b: [u8; 16])
    requires
        to_colony_wf(r),
    ensures
        to_colony_spec(b@, to_colony_fds(r)) == Some(r),
{
    match r {
        ToColony::Held { key } => pack(KIND_HELD, 0, key),
        ToColony::HeldEnd { count } => pack(KIND_HELD_END, count, 0),
        ToColony::Reaped => pack(KIND_REAPED, 0, 0),
        ToColony::Request { mode } => pack(KIND_REQUEST, word_of(mode), 0),
        ToColony::Refused { key } => pack(KIND_REFUSED, 0, key),
    }
}

/// The record in `b` that arrived with `fds` descriptors: `None` unless it is whole, one of
/// queen's, with unused words zero, a known mode and the descriptor count its kind needs.
#[must_use]
pub fn decode_to_colony(b: &[u8], fds: usize) -> (r: Option<ToColony>)
    ensures
        r == to_colony_spec(b@, fds as int),
{
    if b.len() != RECORD_LEN {
        return None;
    }
    let kind = read_u32(b, 0);
    let arg = read_u32(b, 4);
    let key = read_u64(b, 8);
    if kind == KIND_HELD {
        if arg == 0 && key != 0 && fds == 1 {
            Some(ToColony::Held { key })
        } else {
            None
        }
    } else if kind == KIND_HELD_END {
        if key == 0 && fds == 0 {
            Some(ToColony::HeldEnd { count: arg })
        } else {
            None
        }
    } else if kind == KIND_REAPED {
        if arg == 0 && key == 0 && fds == 0 {
            Some(ToColony::Reaped)
        } else {
            None
        }
    } else if kind == KIND_REQUEST {
        if key == 0 && arg <= 2 && fds == 0 {
            Some(ToColony::Request { mode: mode_of(arg) })
        } else {
            None
        }
    } else if kind == KIND_REFUSED {
        if arg == 0 && key != 0 && fds == 0 {
            Some(ToColony::Refused { key })
        } else {
            None
        }
    } else {
        None
    }
}

} // verus!
