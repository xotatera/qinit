// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
use qinit_db_core::*;

#[test]
fn word_reads_little_endian() {
    assert_eq!(
        word(&[0x78, 0x56, 0x34, 0x12, 0xff, 0, 0, 0], 0),
        0x1234_5678
    );
    assert_eq!(word(&[0, 0, 0, 0, 0xff, 0, 0, 0], 1), 0xff);
}

#[test]
fn word_keeps_the_high_bit() {
    assert_eq!(word(&[0x00, 0x00, 0x00, 0x80], 0), 0x8000_0000);
    assert_eq!(word(&[0xff, 0xff, 0xff, 0xff], 0), u32::MAX);
}

#[test]
fn word_reads_the_last_whole_word() {
    // 13 bytes hold three whole words; the trailing byte belongs to none.
    let buf = [0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x84, 0xee];
    assert_eq!(word(&buf, buf.len() / 4 - 1), 0x8403_0201);
}

#[test]
fn the_magic_spells_qdb1() {
    assert_eq!(&MAGIC.to_le_bytes(), b"QDB1");
    assert_eq!(VERSION, 1);
    assert_eq!(HEADER_WORDS, 20);
}

#[test]
fn the_limits_match_the_graph_core() {
    assert_eq!(qinit_db_core::MAX_NODES, qinit_graph_core::MAX_NODES);
    assert_eq!(qinit_db_core::MAX_EDGES, qinit_graph_core::MAX_EDGES);
}

#[test]
fn the_record_sizes_match_the_word_indices() {
    assert_eq!(N_RLIMIT_BASE + 2 * RLIMIT_COUNT, WORDS[T_NODES]);
    assert_eq!(G_EDGE_COUNT + 1, WORDS[T_GROUPS]);
    assert_eq!(E_FLAGS + 1, WORDS[T_EDGES]);
    assert_eq!(C_USER_MAP + 1, WORDS[T_CREDS]);
    assert_eq!(R_B + 1, WORDS[T_ROUTES]);
    assert_eq!(WORDS[T_ENABLED], 1);
    assert_eq!(WORDS[T_PRESYSLOG], 1);
}

#[test]
fn the_tables_fill_the_header() {
    assert_eq!(4 + 2 * 8, HEADER_WORDS);
    assert_eq!(
        [
            T_NODES,
            T_GROUPS,
            T_EDGES,
            T_CREDS,
            T_ROUTES,
            T_ENABLED,
            T_PRESYSLOG,
            T_POOL
        ],
        [0, 1, 2, 3, 4, 5, 6, 7]
    );
}
