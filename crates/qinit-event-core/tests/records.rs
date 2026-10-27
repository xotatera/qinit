// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use qinit_event_core::{HEAD, next_event};

fn record(mask: u32, name: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&1i32.to_ne_bytes());
    b.extend_from_slice(&mask.to_ne_bytes());
    b.extend_from_slice(&0u32.to_ne_bytes());
    b.extend_from_slice(&u32::try_from(name.len()).unwrap().to_ne_bytes());
    b.extend_from_slice(name);
    b
}

#[test]
fn a_complete_record_gives_mask_name_and_next() {
    let b = record(2, b"cgroup.events\0\0\0");
    let (mask, name, next) = next_event(&b, 0).unwrap();
    assert_eq!(mask, 2);
    assert_eq!(name, HEAD..HEAD + 16);
    assert_eq!(next, b.len());
}

#[test]
fn a_truncated_header_or_name_is_none() {
    let b = record(2, b"abcd");
    assert!(next_event(&b[..10], 0).is_none());
    assert!(next_event(&b[..HEAD + 2], 0).is_none());
    assert!(next_event(&b, b.len() + 1).is_none());
}
