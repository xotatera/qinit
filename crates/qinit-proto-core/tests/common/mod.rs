// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! A hand-built QCP1 message for the decoder tests, laid out from the word indices in
//! `layout.rs` alone.
#![allow(dead_code)] // each test binary uses a different part of the builder

use qinit_proto_core::*;

/// One word of a record: a plain value, or a string that goes to the pool as an
/// `(offset, length)` pair of words.
#[derive(Clone, Copy)]
pub enum W {
    N(u32),
    S(&'static str),
}

use W::{N, S};

fn n32(x: usize) -> u32 {
    u32::try_from(x).unwrap()
}

/// A message of type `t` with `fds` in the header, the record `words`, `entries` after a list
/// page's fixed record, and the pool after that.
pub fn build(t: u32, fds: u32, words: &[W], entries: &[(&'static str, u32, u32, u32)]) -> Vec<u8> {
    let list = t == T_LIST_PAGE;
    let rec_words = words
        .iter()
        .map(|w| if matches!(w, S(_)) { 2 } else { 1 })
        .sum::<usize>()
        + ENTRY_WORDS * entries.len();
    let pool_off = 4 * (HEADER_WORDS + rec_words);
    let mut pool: Vec<u8> = Vec::new();
    let mut intern = |s: &str| {
        let off = pool_off + pool.len();
        pool.extend_from_slice(s.as_bytes());
        (n32(off), n32(s.len()))
    };
    let mut rec: Vec<u32> = Vec::new();
    for w in words {
        match w {
            N(v) => rec.push(*v),
            S(s) => {
                let (o, l) = intern(s);
                rec.extend([o, l]);
            }
        }
    }
    if list {
        for (name, kind, state, detail) in entries {
            let (o, l) = intern(name);
            rec.extend([o, l, *kind, *state, *detail]);
        }
    }
    let total = pool_off + pool.len();
    let header = [QCP_MAGIC, QCP_VERSION, n32(total), t, fds];
    let mut out: Vec<u8> = header
        .iter()
        .chain(rec.iter())
        .flat_map(|w| w.to_le_bytes())
        .collect();
    out.extend_from_slice(&pool);
    out
}

/// A valid message of type `t` and the descriptors that go with it.
pub fn valid(t: u32) -> (Vec<u8>, usize) {
    let (fds, words): (u32, Vec<W>) = match t {
        T_STATUS => (0, vec![S("sshd")]),
        T_LIST => (0, vec![N(0), N(0)]),
        T_CHANGE => (0, vec![S("sshd"), N(0), N(1), N(5000)]),
        T_LAUNCH => (
            2,
            vec![
                S("backup"),
                S("--full\0/data"),
                S("TARGET=/data"),
                N(5),
                N(5000),
                N(0),
            ],
        ),
        T_REFRESH => (1, vec![N(1), N(5000)]),
        T_SHUTDOWN => (0, vec![N(1), N(1), N(5000)]),
        T_ERROR => (0, vec![N(CODE_DENIED), N(0), N(1)]),
        T_NODE_STATUS => (
            0,
            vec![
                S("sshd"),
                N(0),
                N(1),
                N(2),
                N(0),
                S("mount-var"),
                N(0),
                N(0),
                N(0),
                N(0),
                N(0),
            ],
        ),
        T_INSTANCE_STATUS => (0, vec![S("backup"), N(7), N(4), N(1), N(256), N(0)]),
        T_LIST_PAGE => (0, vec![N(2), N(NONE)]),
        T_ACCEPTED => (0, vec![]),
        T_SETTLED | T_PENDING | T_SUPERSEDED => (0, vec![N(3), N(0)]),
        T_LAUNCHED => (0, vec![N(7)]),
        T_LAUNCH_FAILED => (0, vec![N(11), N(13)]),
        T_EXITED => (0, vec![N(0)]),
        _ => panic!("no such type {t}"),
    };
    let entries: &[(&str, u32, u32, u32)] = if t == T_LIST_PAGE {
        &[("sshd", 0, 3, 0), ("mount-var", 1, 4, 0)]
    } else {
        &[]
    };
    (build(t, fds, &words, entries), fds as usize)
}

/// Every message type of the format.
pub const TYPES: [u32; 17] = [
    T_STATUS,
    T_LIST,
    T_CHANGE,
    T_LAUNCH,
    T_REFRESH,
    T_SHUTDOWN,
    T_ERROR,
    T_NODE_STATUS,
    T_INSTANCE_STATUS,
    T_LIST_PAGE,
    T_ACCEPTED,
    T_SETTLED,
    T_PENDING,
    T_SUPERSEDED,
    T_LAUNCHED,
    T_LAUNCH_FAILED,
    T_EXITED,
];

/// `bytes` with its words patched by `f` (the trailing partial word kept as it was).
pub fn with(bytes: &[u8], f: impl FnOnce(&mut Vec<u32>)) -> Vec<u8> {
    let mut words: Vec<u32> = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c))
        .collect();
    f(&mut words);
    let mut out: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    out.extend_from_slice(&bytes[out.len()..]);
    out
}

/// Word index of record word `w`.
pub fn at(w: usize) -> usize {
    HEADER_WORDS + w
}

/// Byte index of the first pool byte of `bytes` (the end of the record region).
pub fn pool_at(bytes: &[u8]) -> usize {
    let t = u32::from_le_bytes(bytes[4 * H_TYPE..4 * H_TYPE + 4].try_into().unwrap());
    let mut words = record_words(t);
    if t == T_LIST_PAGE {
        let count = u32::from_le_bytes(
            bytes[4 * at(LP_COUNT)..4 * at(LP_COUNT) + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        words += ENTRY_WORDS * count;
    }
    4 * (HEADER_WORDS + words)
}
