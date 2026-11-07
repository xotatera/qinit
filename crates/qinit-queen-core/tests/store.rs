// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The store table: fixed size, linear scan, one entry per key.
use qinit_queen_core::store::{CAPACITY, Entry, FREE, Put, count, next_held, put, take};
use std::collections::HashMap;

fn table(n: usize) -> Vec<Entry> {
    vec![FREE; n]
}

#[test]
fn the_capacity_is_what_the_spec_counts() {
    assert_eq!(CAPACITY, 4352 * 2 + 4096 * 2 + 3);
}

#[test]
fn a_put_stores_a_new_key() {
    let mut t = table(4);
    assert!(matches!(put(&mut t, 16, 7), Put::Stored));
    assert_eq!(count(&t), 1);
    assert_eq!(take(&mut t, 16), Some(7));
}

#[test]
fn a_put_replaces_and_names_the_old_descriptor() {
    let mut t = table(4);
    assert!(matches!(put(&mut t, 16, 7), Put::Stored));
    assert!(matches!(put(&mut t, 16, 9), Put::Replaced(7)));
    assert_eq!(count(&t), 1);
    assert_eq!(take(&mut t, 16), Some(9));
}

#[test]
fn a_full_table_refuses_a_new_key_and_still_replaces_an_old_one() {
    let mut t = table(2);
    assert!(matches!(put(&mut t, 1, 10), Put::Stored));
    assert!(matches!(put(&mut t, 2, 11), Put::Stored));
    assert!(matches!(put(&mut t, 3, 12), Put::Full));
    assert_eq!(count(&t), 2);
    assert!(matches!(put(&mut t, 2, 13), Put::Replaced(11)));
    assert_eq!(take(&mut t, 3), None, "the refused key is not held");
}

#[test]
fn take_forgets_the_key() {
    let mut t = table(4);
    put(&mut t, 5, 50);
    assert_eq!(take(&mut t, 5), Some(50));
    assert_eq!(take(&mut t, 5), None);
    assert_eq!(count(&t), 0);
}

#[test]
fn take_of_an_unknown_key_is_none() {
    let mut t = table(4);
    put(&mut t, 5, 50);
    assert_eq!(take(&mut t, 6), None);
    assert_eq!(count(&t), 1);
}

#[test]
fn each_key_is_held_once() {
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..200 {
        let mut t = table(8);
        let mut model: HashMap<u64, i32> = HashMap::new();
        for fd in 0..300_i32 {
            let key = next() % 12 + 1;
            if next() % 3 == 0 {
                assert_eq!(take(&mut t, key), model.remove(&key), "take {key}");
            } else {
                match put(&mut t, key, fd) {
                    Put::Stored => assert!(model.insert(key, fd).is_none()),
                    Put::Replaced(old) => assert_eq!(model.insert(key, fd), Some(old)),
                    Put::Full => {
                        assert!(!model.contains_key(&key) && model.len() == 8);
                    }
                }
            }
            assert_eq!(count(&t) as usize, model.len());
            let mut keys: Vec<u64> = t.iter().map(|e| e.key).filter(|&k| k != 0).collect();
            keys.sort_unstable();
            keys.dedup();
            assert_eq!(keys.len(), model.len(), "no key is held twice");
        }
    }
}

#[test]
fn next_held_walks_every_entry_once() {
    let mut t = table(6);
    put(&mut t, 4, 40);
    put(&mut t, 9, 90);
    put(&mut t, 2, 20);
    take(&mut t, 9);
    let mut seen = Vec::new();
    let mut cursor = 0;
    while let Some((at, e)) = next_held(&t, cursor) {
        assert!(at >= cursor);
        seen.push((e.key, e.fd));
        cursor = at + 1;
    }
    seen.sort_unstable();
    assert_eq!(seen, [(2, 20), (4, 40)]);
    assert_eq!(next_held(&t, 6), None);
    assert_eq!(next_held(&t, 100), None);
}
