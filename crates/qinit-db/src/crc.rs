// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! CRC-32 (IEEE 802.3, reflected, polynomial 0xEDB88320), bitwise: the database is small.

/// Feeds `bytes` into the running (inverted) state `c`.
fn update(mut c: u32, bytes: &[u8]) -> u32 {
    for b in bytes {
        c ^= u32::from(*b);
        for _ in 0..8 {
            c = if c & 1 == 1 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
    }
    c
}

/// The CRC-32 of `bytes`; `crc32(b"123456789") == 0xCBF43926`.
#[must_use]
pub fn crc32(bytes: &[u8]) -> u32 {
    !update(!0, bytes)
}

/// The CRC-32 of a whole database with the CRC word (bytes 12..16) treated as zero.
pub(crate) fn file_crc(bytes: &[u8]) -> u32 {
    let head = bytes.get(..12).unwrap_or(bytes);
    let tail = bytes.get(16..).unwrap_or(&[]);
    let mut c = update(!0, head);
    if bytes.len() >= 16 {
        c = update(c, &[0; 4]);
    }
    !update(c, tail)
}
