// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The channel's records: round trips and every refusal.
use qinit_queen_core::{
    FromColony, Mode, RECORD_LEN, ToColony, decode_from_colony, decode_to_colony,
    encode_from_colony, encode_to_colony,
};

fn raw(kind: u32, arg: u32, key: u64) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..4].copy_from_slice(&kind.to_le_bytes());
    b[4..8].copy_from_slice(&arg.to_le_bytes());
    b[8..16].copy_from_slice(&key.to_le_bytes());
    b
}

const MODES: [Mode; 3] = [Mode::Halt, Mode::Poweroff, Mode::Reboot];

#[test]
fn each_record_round_trips() {
    let mut from = vec![
        (FromColony::Put { key: 16 }, 1),
        (FromColony::Put { key: u64::MAX }, 1),
        (FromColony::Drop { key: 3 }, 0),
    ];
    let mut to = vec![
        (ToColony::Held { key: 1 }, 1),
        (ToColony::HeldEnd { count: 0 }, 0),
        (ToColony::HeldEnd { count: 16_899 }, 0),
        (ToColony::Reaped, 0),
        (ToColony::Refused { key: 77 }, 0),
    ];
    for m in MODES {
        from.push((FromColony::Shutdown { mode: m }, 0));
        to.push((ToColony::Request { mode: m }, 0));
    }
    for (r, fds) in from {
        let b = encode_from_colony(r);
        assert_eq!(b.len(), RECORD_LEN);
        assert_eq!(decode_from_colony(&b, fds), Some(r), "{r:?}");
    }
    for (r, fds) in to {
        let b = encode_to_colony(r);
        assert_eq!(decode_to_colony(&b, fds), Some(r), "{r:?}");
    }
}

#[test]
fn the_bytes_are_little_endian_kind_arg_key() {
    assert_eq!(
        encode_from_colony(FromColony::Put {
            key: 0x0102_0304_0506_0708
        }),
        [1, 0, 0, 0, 0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1]
    );
    assert_eq!(
        encode_to_colony(ToColony::Request { mode: Mode::Reboot }),
        [68, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
}

#[test]
fn a_short_or_long_record_is_refused() {
    let b = raw(2, 0, 5);
    assert_eq!(decode_from_colony(&b[..15], 0), None);
    let mut long = b.to_vec();
    long.push(0);
    assert_eq!(decode_from_colony(&long, 0), None);
    let h = raw(66, 1, 0);
    assert_eq!(decode_to_colony(&h[..15], 0), None);
    let mut long = h.to_vec();
    long.push(0);
    assert_eq!(decode_to_colony(&long, 0), None);
}

#[test]
fn an_unknown_kind_is_refused() {
    for kind in [0, 4, 64, 70, u32::MAX] {
        assert_eq!(decode_from_colony(&raw(kind, 0, 5), 0), None, "{kind}");
        assert_eq!(decode_to_colony(&raw(kind, 0, 0), 0), None, "{kind}");
    }
}

#[test]
fn a_record_from_the_wrong_side_is_refused() {
    assert_eq!(decode_from_colony(&raw(65, 0, 5), 1), None, "Held to queen");
    assert_eq!(decode_from_colony(&raw(68, 0, 0), 0), None);
    assert_eq!(decode_to_colony(&raw(1, 0, 5), 1), None, "Put to colony");
    assert_eq!(decode_to_colony(&raw(3, 0, 0), 0), None);
}

#[test]
fn key_zero_is_refused() {
    assert_eq!(decode_from_colony(&raw(1, 0, 0), 1), None);
    assert_eq!(decode_from_colony(&raw(2, 0, 0), 0), None);
    assert_eq!(decode_to_colony(&raw(65, 0, 0), 1), None);
    assert_eq!(decode_to_colony(&raw(69, 0, 0), 0), None);
}

#[test]
fn a_put_without_its_descriptor_is_refused() {
    assert_eq!(decode_from_colony(&raw(1, 0, 9), 0), None);
    assert_eq!(decode_from_colony(&raw(1, 0, 9), 2), None);
}

#[test]
fn a_drop_with_a_descriptor_is_refused() {
    assert_eq!(decode_from_colony(&raw(2, 0, 9), 1), None);
    assert_eq!(decode_from_colony(&raw(3, 0, 0), 1), None);
    assert_eq!(decode_to_colony(&raw(67, 0, 0), 1), None);
    assert_eq!(decode_to_colony(&raw(66, 1, 0), 1), None);
    assert_eq!(decode_to_colony(&raw(69, 0, 9), 1), None);
}

#[test]
fn an_unused_word_that_is_not_zero_is_refused() {
    assert_eq!(decode_from_colony(&raw(1, 1, 9), 1), None, "Put arg");
    assert_eq!(decode_from_colony(&raw(2, 1, 9), 0), None, "Drop arg");
    assert_eq!(decode_from_colony(&raw(3, 0, 1), 0), None, "Shutdown key");
    assert_eq!(decode_to_colony(&raw(65, 1, 9), 1), None, "Held arg");
    assert_eq!(decode_to_colony(&raw(66, 1, 1), 0), None, "HeldEnd key");
    assert_eq!(decode_to_colony(&raw(67, 1, 0), 0), None, "Reaped arg");
    assert_eq!(decode_to_colony(&raw(67, 0, 1), 0), None, "Reaped key");
    assert_eq!(decode_to_colony(&raw(68, 0, 1), 0), None, "Request key");
    assert_eq!(decode_to_colony(&raw(69, 1, 9), 0), None, "Refused arg");
}

#[test]
fn an_unknown_mode_is_refused() {
    assert_eq!(decode_from_colony(&raw(3, 3, 0), 0), None);
    assert_eq!(decode_from_colony(&raw(3, u32::MAX, 0), 0), None);
    assert_eq!(decode_to_colony(&raw(68, 3, 0), 0), None);
}

#[test]
fn a_held_without_its_descriptor_is_refused() {
    assert_eq!(decode_to_colony(&raw(65, 0, 9), 0), None);
    assert_eq!(decode_to_colony(&raw(65, 0, 9), 2), None);
}
