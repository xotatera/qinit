// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! The launch request layout: a five-word header, a 67-word record and a string pool. Every
//! word is little-endian; pool references are `(offset, length)` into the pool.
use vstd::prelude::*;

verus! {

/// Request magic: "QLR1" read as a little-endian word.
pub const LAUNCH_MAGIC: u32 = 0x3152_4C51;

/// Request format version.
pub const LAUNCH_VERSION: u32 = 1;

/// Words in the header: magic, version, total length, pool offset, pool length.
pub const HEADER_WORDS: usize = 5;

/// Words in the record, which follows the header.
pub const REQ_WORDS: usize = 67;

/// Bytes of the header and the record together; the pool starts at or after this.
pub const FIXED_BYTES: usize = 4 * (HEADER_WORDS + REQ_WORDS);

/// Bytes a request may hold at most.
pub const MAX_REQUEST: usize = 65536;

/// Landlock entries a request may hold at most.
pub const MAX_LANDLOCK_ENTRIES: usize = 64;

/// Seccomp list entries a request may hold at most.
pub const MAX_SECCOMP_LIST: usize = 512;

/// Environment entries a request may hold at most.
pub const MAX_ENV_ENTRIES: usize = 256;

/// Lowest descriptor number a routed stream or the ready pipe may name (3 is the request, 4
/// the status pipe).
pub const MIN_ROUTED_FD: u32 = 5;

/// Highest descriptor number a routed stream or the ready pipe may name.
pub const MAX_ROUTED_FD: u32 = 5 + 32;

/// Header word 0: magic.
pub const H_MAGIC: usize = 0;

/// Header word 1: version.
pub const H_VERSION: usize = 1;

/// Header word 2: total length in bytes.
pub const H_TOTAL_LEN: usize = 2;

/// Header word 3: byte offset of the pool.
pub const H_POOL_OFF: usize = 3;

/// Header word 4: length of the pool in bytes.
pub const H_POOL_LEN: usize = 4;

/// Record word 0: `argv_off`, NUL-separated argv in the pool, non-empty.
pub const Q_ARGV_OFF: usize = 0;

/// Record word 1: `argv_len`.
pub const Q_ARGV_LEN: usize = 1;

/// Record word 2: `env_off`, NUL-separated `KEY=VALUE` entries.
pub const Q_ENV_OFF: usize = 2;

/// Record word 3: `env_len`.
pub const Q_ENV_LEN: usize = 3;

/// Record word 4: `cwd_off`, a non-empty absolute path.
pub const Q_CWD_OFF: usize = 4;

/// Record word 5: `cwd_len`.
pub const Q_CWD_LEN: usize = 5;

/// Record word 6: `umask`, at most `MAX_UMASK`.
pub const Q_UMASK: usize = 6;

/// Record word 7: `rlimit_mask`, the resource limits to set: bit `r` for kernel resource number
/// `r` (the database's `N_RLIMIT_MASK` rules).
pub const Q_RLIMIT_MASK: usize = 7;

/// Record word 8: `user_off`, the user name, non-empty.
pub const Q_USER_OFF: usize = 8;

/// Record word 9: `user_len`.
pub const Q_USER_LEN: usize = 9;

/// Record word 10: `caps_lo`, capability bits 0..=31.
pub const Q_CAPS_LO: usize = 10;

/// Record word 11: `caps_hi`, capability bits 32..=40 in its bits 0..=8.
pub const Q_CAPS_HI: usize = 11;

/// Record word 12: `securebits`, 0 none, 1 noroot, 2 noroot-locked.
pub const Q_SECUREBITS: usize = 12;

/// Record word 13: `nnp`, 0 or 1.
pub const Q_NNP: usize = 13;

/// Record word 14: `ns`, namespace bits 0..=4: mount, pid, ipc, uts, net.
pub const Q_NS: usize = 14;

/// Record word 15: `seccomp`, 0 none, 1 default, 2 deny-list, 3 allow-list.
pub const Q_SECCOMP: usize = 15;

/// Record word 16: `seccomp_off`, NUL-separated canonical decimals.
pub const Q_SECCOMP_OFF: usize = 16;

/// Record word 17: `seccomp_len`, 0 exactly when `seccomp` is 0 or 1.
pub const Q_SECCOMP_LEN: usize = 17;

/// Record word 18: `landlock_off`, NUL-separated `ro:/path` or `rw:/path` entries.
pub const Q_LANDLOCK_OFF: usize = 18;

/// Record word 19: `landlock_len`.
pub const Q_LANDLOCK_LEN: usize = 19;

/// Record word 20: `stdout_kind`, `STREAM_PATH` or `STREAM_FD`.
pub const Q_STDOUT_KIND: usize = 20;

/// Record word 21: `stdout_a`, the path offset or the descriptor number.
pub const Q_STDOUT_A: usize = 21;

/// Record word 22: `stdout_b`, the path length; 0 for a descriptor.
pub const Q_STDOUT_B: usize = 22;

/// Record word 23: `stderr_kind`, `STREAM_PATH`, `STREAM_FD` or `STREAM_SAME`.
pub const Q_STDERR_KIND: usize = 23;

/// Record word 24: `stderr_a`.
pub const Q_STDERR_A: usize = 24;

/// Record word 25: `stderr_b`.
pub const Q_STDERR_B: usize = 25;

/// Record word 26: `ready_kind`, `READY_NONE` or `READY_PIPE`.
pub const Q_READY_KIND: usize = 26;

/// Record word 27: `ready_fd`, the descriptor the ready pipe arrives on; 0 without one.
pub const Q_READY_FD: usize = 27;

/// Record word 28: `flags`, bit 0 `FLAG_DIE_WITH_PARENT`.
pub const Q_FLAGS: usize = 28;

/// Record word 29: `deadline_ms`, at least 1.
pub const Q_DEADLINE_MS: usize = 29;

/// Record word 30: reserved, 0.
pub const Q_RESERVED_0: usize = 30;

/// Record word 31: reserved, 0.
pub const Q_RESERVED_1: usize = 31;

/// Record word 32: `stdin_kind`, `STREAM_PATH` or `STREAM_FD`.
pub const Q_STDIN_KIND: usize = 32;

/// Record word 33: `stdin_a`, the path offset or the descriptor number.
pub const Q_STDIN_A: usize = 33;

/// Record word 34: `stdin_b`, the path length; 0 for a descriptor.
pub const Q_STDIN_B: usize = 34;

/// Record word 35: the first of 16 limit values. Resource `r` has its low word at
/// `Q_RLIMIT_BASE + 2 * r` and its high word one later; both are 0 unless bit `r` of
/// `rlimit_mask` is set, and all ones is infinity.
pub const Q_RLIMIT_BASE: usize = 35;

/// A stream goes to a path opened by the executor.
pub const STREAM_PATH: u32 = 0;

/// A stream goes to a routed descriptor.
pub const STREAM_FD: u32 = 1;

/// Standard error goes where standard output goes.
pub const STREAM_SAME: u32 = 2;

/// No ready pipe.
pub const READY_NONE: u32 = 0;

/// The ready pipe arrives on `ready_fd`.
pub const READY_PIPE: u32 = 1;

/// `flags` bit 0: the service gets `SIGKILL` when its parent thread exits.
pub const FLAG_DIE_WITH_PARENT: u32 = 1;

} // verus!
