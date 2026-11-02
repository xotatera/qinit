// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The validator's UTF-8 scanner against `core::str::from_utf8`, through a node name.
mod common;

use common::*;

fn accepts(scratch: &mut Scratch, name: &[u8]) -> bool {
    let spec = DbSpec {
        nodes: vec![NodeSpec {
            name: name.to_vec(),
            ..node("x", vec![])
        }],
        ..DbSpec::default()
    };
    match scratch.check(&build(&spec)) {
        Ok(()) => true,
        Err(qinit_db_core::DbError::Utf8) => false,
        Err(e) => panic!("{name:x?}: {e:?}"),
    }
}

fn agree(scratch: &mut Scratch, name: &[u8]) {
    assert_eq!(
        accepts(scratch, name),
        core::str::from_utf8(name).is_ok(),
        "{name:x?}"
    );
}

#[test]
fn the_scanner_agrees_with_core_on_edge_cases() {
    let cases: &[&[u8]] = &[
        b"a",
        b"\x7f",
        b"\x80",
        b"\xc0\x80",         // overlong NUL
        b"\xc1\xbf",         // overlong
        b"\xc2\x80",         // U+0080
        b"\xdf\xbf",         // U+07FF
        b"\xe0\x80\x80",     // overlong
        b"\xe0\x9f\xbf",     // overlong U+07FF
        b"\xe0\xa0\x80",     // U+0800
        b"\xed\x9f\xbf",     // U+D7FF
        b"\xed\xa0\x80",     // surrogate D800
        b"\xed\xbf\xbf",     // surrogate DFFF
        b"\xee\x80\x80",     // U+E000
        b"\xef\xbf\xbf",     // U+FFFF
        b"\xf0\x8f\xbf\xbf", // overlong U+FFFF
        b"\xf0\x90\x80\x80", // U+10000
        b"\xf4\x8f\xbf\xbf", // U+10FFFF
        b"\xf4\x90\x80\x80", // U+110000
        b"\xf5\x80\x80\x80",
        b"\xf7\xbf\xbf\xbf",
        b"\xf8\x88\x80\x80\x80",
        b"\xff",
        b"\xc2",         // truncated 2-byte
        b"\xe0\xa0",     // truncated 3-byte
        b"\xf0\x90\x80", // truncated 4-byte
        b"a\xc2",
        b"\xc2a",
        b"\xe2\x82\xac\xf0\x9f\x98\x80", // U+20AC U+1F600
        b"\xe2\x82\xac\x80",
        b"\xc2\x80\xc2",
    ];
    let mut s = Scratch::new();
    for c in cases {
        agree(&mut s, c);
    }
}

#[test]
fn the_scanner_agrees_with_core_on_every_two_byte_string() {
    let mut s = Scratch::new();
    for a in 0..=255u8 {
        agree(&mut s, &[a]);
        for b in 0..=255u8 {
            agree(&mut s, &[a, b]);
        }
    }
}

#[test]
fn the_scanner_agrees_with_core_on_three_and_four_byte_boundaries() {
    let edges = [0x00, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xff];
    let mut s = Scratch::new();
    for a in 0xc0..=0xffu8 {
        for b in 0..=255u8 {
            for c in edges {
                agree(&mut s, &[a, b, c]);
                for d in edges {
                    agree(&mut s, &[a, b, c, d]);
                }
            }
        }
    }
}
