// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Database layout: limits, header words, table ids, record word indices and the word reader.
//! The byte-level description is `docs/db-format.md`.

use vstd::prelude::*;

verus! {

/// Format magic: "QDB1" read as a little-endian word.
pub const MAGIC: u32 = 0x3142_4451;

/// Format version.
pub const VERSION: u32 = 1;

/// Absent index.
pub const NONE: u32 = u32::MAX;

/// Nodes (equals `qinit_graph_core::MAX_NODES`).
pub const MAX_NODES: usize = 4096;

/// Dependency groups.
pub const MAX_GROUPS: usize = 16384;

/// Edges (equals `qinit_graph_core::MAX_EDGES`).
pub const MAX_EDGES: usize = 32768;

/// Edges in one group.
pub const MAX_EDGES_PER_GROUP: usize = 64;

/// Groups on one node.
pub const MAX_GROUPS_PER_NODE: usize = 16;

/// Credential records.
pub const MAX_CREDS: usize = 4096;

/// Output routes.
pub const MAX_ROUTES: usize = 8192;

/// String pool bytes.
pub const MAX_POOL: usize = 1 << 20;

/// Bytes in a name.
pub const MAX_NAME_LEN: usize = 96;

/// Words in the header.
pub const HEADER_WORDS: usize = 20;

/// Table id `T_NODES` (header order).
pub const T_NODES: usize = 0;

/// Table id `T_GROUPS` (header order).
pub const T_GROUPS: usize = 1;

/// Table id `T_EDGES` (header order).
pub const T_EDGES: usize = 2;

/// Table id `T_CREDS` (header order).
pub const T_CREDS: usize = 3;

/// Table id `T_ROUTES` (header order).
pub const T_ROUTES: usize = 4;

/// Table id `T_ENABLED` (header order).
pub const T_ENABLED: usize = 5;

/// Table id `T_PRESYSLOG` (header order).
pub const T_PRESYSLOG: usize = 6;

/// Table id `T_POOL` (header order).
pub const T_POOL: usize = 7;

/// Words per record, tables 0..=6.
pub const WORDS: [usize; 7] = [20, 3, 7, 10, 3, 1, 1];

/// Header word: magic.
pub const H_MAGIC: usize = 0;

/// Header word: version.
pub const H_VERSION: usize = 1;

/// Header word: total length in bytes.
pub const H_TOTAL_LEN: usize = 2;

/// Header word: CRC-32 of the body.
pub const H_CRC32: usize = 3;

/// Node record word 0: `kind`.
pub const N_KIND: usize = 0;

/// Node record word 1: `name_off`.
pub const N_NAME_OFF: usize = 1;

/// Node record word 2: `name_len`.
pub const N_NAME_LEN: usize = 2;

/// Node record word 3: `exec_off`.
pub const N_EXEC_OFF: usize = 3;

/// Node record word 4: `exec_len`.
pub const N_EXEC_LEN: usize = 4;

/// Node record word 5: `ready_kind`.
pub const N_READY_KIND: usize = 5;

/// Node record word 6: `ready_off`.
pub const N_READY_OFF: usize = 6;

/// Node record word 7: `ready_len`.
pub const N_READY_LEN: usize = 7;

/// Node record word 8: `restart_policy`.
pub const N_RESTART_POLICY: usize = 8;

/// Node record word 9: `restart_max`.
pub const N_RESTART_MAX: usize = 9;

/// Node record word 10: `restart_window_ms`.
pub const N_RESTART_WINDOW_MS: usize = 10;

/// Node record word 11: `output`.
pub const N_OUTPUT: usize = 11;

/// Node record word 12: `errors`.
pub const N_ERRORS: usize = 12;

/// Node record word 13: `cred`.
pub const N_CRED: usize = 13;

/// Node record word 14: `group_first`.
pub const N_GROUP_FIRST: usize = 14;

/// Node record word 15: `group_count`.
pub const N_GROUP_COUNT: usize = 15;

/// Node record word 16: `memory_max_kib`.
pub const N_MEMORY_MAX_KIB: usize = 16;

/// Node record word 17: `pids_max`.
pub const N_PIDS_MAX: usize = 17;

/// Node record word 18: `instance_of_off`.
pub const N_INSTANCE_OF_OFF: usize = 18;

/// Node record word 19: `instance_of_len`.
pub const N_INSTANCE_OF_LEN: usize = 19;

/// Group record word 0: `kind`.
pub const G_KIND: usize = 0;

/// Group record word 1: `edge_first`.
pub const G_EDGE_FIRST: usize = 1;

/// Group record word 2: `edge_count`.
pub const G_EDGE_COUNT: usize = 2;

/// Edge record word 0: `target_kind`.
pub const E_TARGET_KIND: usize = 0;

/// Edge record word 1: `target`.
pub const E_TARGET: usize = 1;

/// Edge record word 2: `target_len`.
pub const E_TARGET_LEN: usize = 2;

/// Edge record word 3: `mode`.
pub const E_MODE: usize = 3;

/// Edge record word 4: `deadline_ms`.
pub const E_DEADLINE_MS: usize = 4;

/// Edge record word 5: `restart_on`.
pub const E_RESTART_ON: usize = 5;

/// Edge record word 6: `flags`.
pub const E_FLAGS: usize = 6;

/// Credential record word 0: `user_off`.
pub const C_USER_OFF: usize = 0;

/// Credential record word 1: `user_len`.
pub const C_USER_LEN: usize = 1;

/// Credential record word 2: `caps_lo`.
pub const C_CAPS_LO: usize = 2;

/// Credential record word 3: `caps_hi`.
pub const C_CAPS_HI: usize = 3;

/// Credential record word 4: `securebits`.
pub const C_SECUREBITS: usize = 4;

/// Credential record word 5: `nnp`.
pub const C_NNP: usize = 5;

/// Credential record word 6: `ns`.
pub const C_NS: usize = 6;

/// Credential record word 7: `seccomp`.
pub const C_SECCOMP: usize = 7;

/// Credential record word 8: `landlock_off`.
pub const C_LANDLOCK_OFF: usize = 8;

/// Credential record word 9: `landlock_len`.
pub const C_LANDLOCK_LEN: usize = 9;

/// Route record word 0: `kind`.
pub const R_KIND: usize = 0;

/// Route record word 1: `a`.
pub const R_A: usize = 1;

/// Route record word 2: `b`.
pub const R_B: usize = 2;

/// Header word holding the offset of table `t`.
pub open spec fn spec_offset_word(t: int) -> int {
    4 + 2 * t
}

/// Header word holding the count of table `t`.
pub open spec fn spec_count_word(t: int) -> int {
    5 + 2 * t
}

/// Little-endian word `i` of `buf`.
pub open spec fn spec_word(buf: Seq<u8>, i: int) -> u32 {
    ((buf[4 * i] as u32) | ((buf[4 * i + 1] as u32) << 8u32) | ((buf[4 * i + 2] as u32) << 16u32)
        | ((buf[4 * i + 3] as u32) << 24u32))
}

/// Little-endian word `i` of `buf`.
#[must_use]
#[allow(clippy::cast_lossless)]  // `u32::from` is not available inside `verus!`
pub fn word(buf: &[u8], i: usize) -> (w: u32)
    requires
        i < 0x4000_0000,
        4 * i + 4 <= buf@.len(),
    ensures
        w == spec_word(buf@, i as int),
{
    (buf[4 * i] as u32) | ((buf[4 * i + 1] as u32) << 8) | ((buf[4 * i + 2] as u32) << 16) | ((buf[4
        * i + 3] as u32) << 24)
}

} // verus!
