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
pub const HEADER_WORDS: usize = 24;

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

/// Table id `T_POLICY` (header order): one record per policy rule, in file order.
pub const T_POLICY: usize = 7;

/// Table id `T_POLICY_HEAD` (header order): none, or the one record of the policy's defaults.
pub const T_POLICY_HEAD: usize = 8;

/// Table id `T_POOL` (header order); the last table.
pub const T_POOL: usize = 9;

/// Words per record, tables 0..=8.
pub const WORDS: [usize; 9] = [68, 3, 7, 13, 3, 1, 1, 43, 34];

/// Policy rules.
pub const MAX_POLICY_RULES: usize = 1024;

/// Bytes in a policy rule's pattern.
pub const MAX_PATTERN_LEN: usize = 128;

/// Policy rule record word 0: `pattern_off`, a glob over `~name` or a frame name.
pub const P_PATTERN_OFF: usize = 0;

/// Policy rule record word 1: `pattern_len`, 1 to `MAX_PATTERN_LEN`.
pub const P_PATTERN_LEN: usize = 1;

/// Policy rule record word 2: `users_off`, NUL-separated user names.
pub const P_USERS_OFF: usize = 2;

/// Policy rule record word 3: `users_len`.
pub const P_USERS_LEN: usize = 3;

/// Policy rule record word 4: `users_any`, 1 when the rule names no users (any user matches);
/// then `users_len` is 0.
pub const P_USERS_ANY: usize = 4;

/// Policy rule record word 5: `caps_lo`, the capability ceiling's bits 0..=31.
pub const P_CAPS_LO: usize = 5;

/// Policy rule record word 6: `caps_hi`, bits 32..=40 in its bits 0..=8.
pub const P_CAPS_HI: usize = 6;

/// Policy rule record word 7: `require_nnp`, 0 or 1.
pub const P_REQUIRE_NNP: usize = 7;

/// Policy rule record word 8: `require_seccomp`, 0 or 1.
pub const P_REQUIRE_SECCOMP: usize = 8;

/// Policy rule record word 9: `allow_userns`, 0 none, 1 own map, 2 own or range.
pub const P_ALLOW_USERNS: usize = 9;

/// Policy rule record word 10: `rlimit_mask`, the limits the rule sets a ceiling for (the
/// node record's encoding).
pub const P_RLIMIT_MASK: usize = 10;

/// Policy rule record word 11: the first of 16 ceiling pairs (low word, high word), as the
/// node record's limits.
pub const P_RLIMIT_BASE: usize = 11;

/// Policy header record word 0: `allow`, 1 when the default is to allow.
pub const PH_ALLOW: usize = 0;

/// Policy header record word 1: `rlimit_mask`, the limits with a top-level ceiling.
pub const PH_RLIMIT_MASK: usize = 1;

/// Policy header record word 2: the first of 16 ceiling pairs.
pub const PH_RLIMIT_BASE: usize = 2;

/// Header word: magic.
pub const H_MAGIC: usize = 0;

/// Header word: version.
pub const H_VERSION: usize = 1;

/// Header word: total length in bytes.
pub const H_TOTAL_LEN: usize = 2;

/// Header word: CRC-32 (IEEE) of the whole file with this word taken as zero.
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

/// Node record word 20: `restart_delay_ms`, the base of the restart back-off.
pub const N_RESTART_DELAY_MS: usize = 20;

/// Node record word 21: `stop_mode`, 0 main, 1 cell.
pub const N_STOP_MODE: usize = 21;

/// Node record word 22: `stop_grace_ms`, the polite-stop grace period.
pub const N_STOP_GRACE_MS: usize = 22;

/// Node record word 23: `start_timeout_ms`, 0 for none.
pub const N_START_TIMEOUT_MS: usize = 23;

/// Node record word 24: `env_off`, NUL-separated `KEY=VALUE` entries sorted by key.
pub const N_ENV_OFF: usize = 24;

/// Node record word 25: `env_len`.
pub const N_ENV_LEN: usize = 25;

/// Node record word 26: `cwd_off`, a non-empty absolute path.
pub const N_CWD_OFF: usize = 26;

/// Node record word 27: `cwd_len`.
pub const N_CWD_LEN: usize = 27;

/// Node record word 28: `umask`, at most `MAX_UMASK`.
pub const N_UMASK: usize = 28;

/// Node record word 29: `rlimit_mask`, the resource limits that are set: bit `r` for the
/// resource numbered `r` (`RLIMIT_COUNT` of them), only the bits of `RLIMIT_MASK_ALLOWED`.
pub const N_RLIMIT_MASK: usize = 29;

/// Node record word 30: `reload`, the signal that re-reads configuration: 0 none, 1 `SIGHUP`,
/// 2 `SIGUSR1`, 3 `SIGUSR2`.
pub const N_RELOAD: usize = 30;

/// Node record word 31: `launch_concurrency`, instances at once: 0 for a node that is not
/// launchable, else 1 to `MAX_LAUNCH_CONCURRENCY` (foragers only).
pub const N_LAUNCH_CONCURRENCY: usize = 31;

/// Node record word 32: `launch_argv_tail`, extra argv elements a caller may append, at most
/// `MAX_ARGV_TAIL`.
pub const N_LAUNCH_ARGV_TAIL: usize = 32;

/// Node record word 33: `launch_env_off`, the keys a caller may set: NUL-separated, none
/// containing `=`, strictly ascending bytewise.
pub const N_LAUNCH_ENV_OFF: usize = 33;

/// Node record word 34: `launch_env_len`.
pub const N_LAUNCH_ENV_LEN: usize = 34;

/// Node record word 35: `launch_fds`, the standard descriptors a caller may supply: a mask of
/// `FD_STDIN`, `FD_STDOUT` and `FD_STDERR`.
pub const N_LAUNCH_FDS: usize = 35;

/// Node record word 36: the first of `RLIMIT_COUNT` limit values. Resource `r` has its low word
/// at `N_RLIMIT_BASE + 2 * r` and its high word at `N_RLIMIT_BASE + 2 * r + 1`; both are 0 unless
/// bit `r` of `rlimit_mask` is set, and all ones is infinity.
pub const N_RLIMIT_BASE: usize = 36;

/// Resources with a limit slot, in kernel numbering: cpu 0, fsize 1, data 2, stack 3, core 4,
/// rss 5, nproc 6, nofile 7, memlock 8, as 9, locks 10, sigpending 11, msgqueue 12, nice 13,
/// rtprio 14, rttime 15.
pub const RLIMIT_COUNT: usize = 16;

/// The `core` resource, which is never set (the overseer always disables core dumps).
pub const RLIMIT_CORE: u32 = 4;

/// The `nofile` resource: a set value is at least 1 and finite.
pub const RLIMIT_NOFILE: u32 = 7;

/// The `nice` resource: a set value is at most `MAX_RLIMIT_NICE`.
pub const RLIMIT_NICE: u32 = 13;

/// The `rtprio` resource: a set value is at most `MAX_RLIMIT_RTPRIO`.
pub const RLIMIT_RTPRIO: u32 = 14;

/// Ceiling of a `nice` limit.
pub const MAX_RLIMIT_NICE: u32 = 40;

/// Ceiling of an `rtprio` limit.
pub const MAX_RLIMIT_RTPRIO: u32 = 99;

/// The `rlimit_mask` bits that may be set: every resource but `core`.
pub const RLIMIT_MASK_ALLOWED: u32 = 0xFFEF;

/// `launch_fds` bit: the caller may supply stdin.
pub const FD_STDIN: u32 = 1;

/// `launch_fds` bit: the caller may supply stdout.
pub const FD_STDOUT: u32 = 2;

/// `launch_fds` bit: the caller may supply stderr.
pub const FD_STDERR: u32 = 4;

/// Ceiling of `launch_concurrency`.
pub const MAX_LAUNCH_CONCURRENCY: u32 = 64;

/// Ceiling of `launch_argv_tail`.
pub const MAX_ARGV_TAIL: u32 = 64;

/// Floor of `restart_delay_ms` and `stop_grace_ms`, milliseconds.
pub const MIN_DELAY_MS: u32 = 100;

/// Ceiling of `umask`.
pub const MAX_UMASK: u32 = 0o777;

/// Every syscall number in a seccomp list is below this.
pub const MAX_SYSCALL: u32 = 512;

/// Bit of `CAP_SYS_ADMIN` in `caps_lo`.
pub const CAP_SYS_ADMIN_BIT: u32 = 21;

/// `caps_lo` mask of `CAP_SYS_ADMIN`: bit `CAP_SYS_ADMIN_BIT`.
pub const CAP_SYS_ADMIN_MASK: u32 = 0x20_0000;

/// `seccomp` 0: no filter.
pub const SECCOMP_NONE: u32 = 0;

/// `seccomp` 1: the default denylist.
pub const SECCOMP_DEFAULT: u32 = 1;

/// `seccomp` 2: deny the listed calls.
pub const SECCOMP_DENY: u32 = 2;

/// `seccomp` 3: allow only the listed calls.
pub const SECCOMP_ALLOW: u32 = 3;

/// Edge flags bit 0: `stop = "parallel"`.
pub const E_FLAG_PARALLEL: u32 = 1;

/// Edge flags bit 1: a quarantined target quarantines the dependent (`require_all` node edges).
pub const E_FLAG_CASCADE: u32 = 2;

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

/// Credential record word 6: `ns`, namespace bits 0..=5: mount, pid, ipc, uts, net, user.
pub const C_NS: usize = 6;

/// Credential record word 7: `seccomp`.
pub const C_SECCOMP: usize = 7;

/// Credential record word 8: `paths_off`.
pub const C_PATHS_OFF: usize = 8;

/// Credential record word 9: `paths_len`.
pub const C_PATHS_LEN: usize = 9;

/// Credential record word 10: `seccomp_off`, NUL-separated canonical decimals below
/// `MAX_SYSCALL`.
pub const C_SECCOMP_OFF: usize = 10;

/// Credential record word 11: `seccomp_len`, 0 exactly when `seccomp` is 0 or 1.
pub const C_SECCOMP_LEN: usize = 11;

/// Credential record word 12: `user_map`, 0 own, 1 range; 1 only with the `user` namespace.
pub const C_USER_MAP: usize = 12;

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
