// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
mod common;

use common::sample;
use qinit_db::{ReadError, crc32, open, write};
use qinit_db_core::{H_CRC32, N_KIND, T_NODES, word};

#[test]
fn flipping_a_crc_byte_is_a_crc_error() {
    let bytes = write(&sample()).unwrap();
    for i in 4 * H_CRC32..4 * H_CRC32 + 4 {
        let mut copy = bytes.clone();
        copy[i] ^= 0x01;
        assert!(matches!(open(&copy), Err(ReadError::Crc)), "byte {i}");
    }
}

#[test]
fn every_single_byte_flip_is_rejected_or_validates() {
    let bytes = write(&sample()).unwrap();
    for i in 0..bytes.len() {
        for mask in [0x01u8, 0x80, 0xFF] {
            let mut copy = bytes.clone();
            copy[i] ^= mask;
            // The CRC catches every single-byte change.
            assert!(open(&copy).is_err(), "flip {mask:#x} at {i} accepted");
        }
    }
}

#[test]
fn every_truncation_is_rejected() {
    let bytes = write(&sample()).unwrap();
    for len in 0..bytes.len() {
        assert!(open(&bytes[..len]).is_err(), "length {len} accepted");
    }
}

/// Recomputes the CRC word of a patched database.
fn reseal(bytes: &mut [u8]) {
    bytes[4 * H_CRC32..4 * H_CRC32 + 4].fill(0);
    let crc = crc32(bytes);
    bytes[4 * H_CRC32..4 * H_CRC32 + 4].copy_from_slice(&crc.to_le_bytes());
}

#[test]
fn a_flip_that_keeps_the_crc_valid_is_caught_by_validate() {
    let mut bytes = write(&sample()).unwrap();
    assert!(open(&bytes).is_ok());
    let node_table = word(&bytes, 4 + 2 * T_NODES) as usize;
    bytes[node_table + 4 * N_KIND] = 9; // node 0, kind word: out of range
    assert!(matches!(open(&bytes), Err(ReadError::Crc)));
    reseal(&mut bytes);
    assert!(matches!(open(&bytes), Err(ReadError::Db(_))));
}
