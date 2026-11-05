<!--
SPDX-FileCopyrightText: 2026 Xota Tera
SPDX-License-Identifier: CC-BY-4.0
-->

# Compiled database format (version 1)

The database is one flat byte string. Everything is little-endian, every record has a fixed
number of 32-bit words, and every cross-reference is a `u32` index. `NONE` (`0xFFFF_FFFF`) means
"absent". The constants below are defined in `crates/qinit-db-core/src/layout.rs`.

## Header

The header is `HEADER_WORDS` = 24 words:

| Word | Meaning |
| --- | --- |
| 0 | `MAGIC` = `0x3142_4451` (the bytes `QDB1`) |
| 1 | `VERSION` = 1 |
| 2 | total length in bytes |
| 3 | CRC-32 (IEEE) of the whole file with this word taken as zero (detects corruption only; no integrity or authenticity claim). `qinit-db`'s reader checks it; the validator does not |
| 4 + 2t | byte offset of table `t` |
| 5 + 2t | record count of table `t` (for the pool: its length in bytes) |

## Tables

Table ids, in header order, with the words per record (`WORDS`):

| Id | Table | Words |
| --- | --- | --- |
| 0 `T_NODES` | nodes | 68 |
| 1 `T_GROUPS` | dependency groups | 3 |
| 2 `T_EDGES` | edges | 7 |
| 3 `T_CREDS` | credentials | 15 |
| 4 `T_ROUTES` | output routes | 3 |
| 5 `T_ENABLED` | enabled closure | 1 |
| 6 `T_PRESYSLOG` | pre-syslog list | 1 |
| 7 `T_POLICY` | policy rules | 45 |
| 8 `T_POLICY_HEAD` | the policy's defaults | 34 |
| 9 `T_POOL` | string pool | bytes |

Strings (names, argv, paths) live in the pool and are referenced by (offset, length).

## Limits

`MAX_NODES` 4096, `MAX_GROUPS` 16384, `MAX_EDGES` 32768, `MAX_EDGES_PER_GROUP` 64,
`MAX_GROUPS_PER_NODE` 16, `MAX_CREDS` 4096, `MAX_ROUTES` 8192, `MAX_POOL` 1 MiB,
`MAX_POLICY_RULES` 1024, `MAX_PATTERN_LEN` 128, `MAX_NAME_LEN` 96, `MAX_UMASK` `0o777`, `MAX_SYSCALL` 512. `MAX_NODES` and `MAX_EDGES` equal the
limits of `qinit-graph-core`.

## Records

### Node (68 words)

| Word | Name | Meaning |
| --- | --- | --- |
| 0 | `N_KIND` | 0 worker, 1 forager, 2 brood |
| 1, 2 | `N_NAME_OFF`, `N_NAME_LEN` | name in the pool |
| 3, 4 | `N_EXEC_OFF`, `N_EXEC_LEN` | argv in the pool, NUL-separated |
| 5 | `N_READY_KIND` | 0 pipe, 1 exit, 2 socket (a socket created at the path after the start), 3 path (a path created at `PATH` after the start). A path *edge* (`E_TARGET_KIND` 1) means the path exists. A frame with a `launch` table has neither 2 nor 3 |
| 6, 7 | `N_READY_OFF`, `N_READY_LEN` | readiness argument in the pool |
| 8 | `N_RESTART_POLICY` | 0 never, 1 on-failure, 2 always |
| 9 | `N_RESTART_MAX` | restarts allowed in the window |
| 10 | `N_RESTART_WINDOW_MS` | restart window, milliseconds |
| 11 | `N_OUTPUT` | route index or `NONE` |
| 12 | `N_ERRORS` | route index or `NONE` |
| 13 | `N_CRED` | credential index for a worker or forager, `NONE` for a brood (see "Credentials are required") |
| 14, 15 | `N_GROUP_FIRST`, `N_GROUP_COUNT` | the node's groups, a run in the group table |
| 16 | `N_MEMORY_MAX_KIB` | memory limit |
| 17 | `N_PIDS_MAX` | process limit |
| 18, 19 | `N_INSTANCE_OF_OFF`, `N_INSTANCE_OF_LEN` | name of the instanced frame (the node name before its `@`) in the pool; length 0 if not an instance |
| 20 | `N_RESTART_DELAY_MS` | base of the restart back-off, milliseconds, at least 100 |
| 21 | `N_STOP_MODE` | 0 main, 1 cell |
| 22 | `N_STOP_GRACE_MS` | polite-stop grace period, milliseconds, at least 100 |
| 23 | `N_START_TIMEOUT_MS` | start timeout, milliseconds; 0 for none |
| 24, 25 | `N_ENV_OFF`, `N_ENV_LEN` | environment entries `KEY=VALUE` in the pool, NUL-separated, sorted by key; length 0 for none |
| 26, 27 | `N_CWD_OFF`, `N_CWD_LEN` | working directory in the pool, a non-empty absolute path |
| 28 | `N_UMASK` | file-mode creation mask, at most `MAX_UMASK` |
| 29 | `N_RLIMIT_MASK` | the resource limits that are set: bit `r` for kernel resource number `r` (cpu 0, fsize 1, data 2, stack 3, core 4, rss 5, nproc 6, nofile 7, memlock 8, as 9, locks 10, sigpending 11, msgqueue 12, nice 13, rtprio 14, rttime 15); bit 4 (`core`) and bits above 15 are never set |
| 30 | `N_RELOAD` | the signal that makes the process re-read its configuration: 0 none, 1 `SIGHUP`, 2 `SIGUSR1`, 3 `SIGUSR2`; at most 3 |
| 31 | `N_LAUNCH_CONCURRENCY` | instances of a forager at once, 1 to `MAX_LAUNCH_CONCURRENCY` (64); 0 for a node that cannot be launched, which every node but a forager must be |
| 32 | `N_LAUNCH_ARGV_TAIL` | extra argv elements a caller may append, at most `MAX_ARGV_TAIL` (64); 0 when `N_LAUNCH_CONCURRENCY` is 0 |
| 33, 34 | `N_LAUNCH_ENV_OFF`, `N_LAUNCH_ENV_LEN` | the environment keys a caller may set, in the pool, NUL-separated: no key is empty or holds `=`, and the keys ascend strictly bytewise (so none repeats); length 0 for none, and always 0 when `N_LAUNCH_CONCURRENCY` is 0 |
| 35 | `N_LAUNCH_FDS` | the standard descriptors a caller may supply: a mask of `FD_STDIN` (1), `FD_STDOUT` (2) and `FD_STDERR` (4); at most 7, and 0 when `N_LAUNCH_CONCURRENCY` is 0 |
| 36–67 | `N_RLIMIT_BASE` + 2`r`, + 2`r` + 1 | the low and high word of resource `r`'s limit (soft and hard are both set to it); both 0 when bit `r` of `N_RLIMIT_MASK` is clear; all ones is infinity; `nofile` is at least 1 and finite, `nice` at most 40, `rtprio` at most 99 |

#### Resource limits at launch

The overseer sets each limit with soft equal to hard, in resource order, and `core` to 0 always.
Three kernel facts decide what a value means:

- `nice` is the kernel's ceiling value, `20 - nice`: the limit 40 allows a nice of -20, 0 allows 20.
- `rss` is accepted and ignored by the kernel.
- `nofile` above `fs.nr_open` fails at launch, at the step `rlimit-nofile`.

A limit that stops the executor's own later steps (a small `nofile`, `as` or `nproc`) fails at that
later step, not at the limit's own.

### Group (3 words)

| Word | Name | Meaning |
| --- | --- | --- |
| 0 | `G_KIND` | 0 require_all, 1 require_any, 2 optional_all, 3 exclude_all |
| 1, 2 | `G_EDGE_FIRST`, `G_EDGE_COUNT` | a run in the edge table |

### Edge (7 words)

| Word | Name | Meaning |
| --- | --- | --- |
| 0 | `E_TARGET_KIND` | 0 node, 1 path |
| 1 | `E_TARGET` | node index, or pool offset for a path |
| 2 | `E_TARGET_LEN` | 0 for a node, path length otherwise |
| 3 | `E_MODE` | 0 sync, 1 async |
| 4 | `E_DEADLINE_MS` | deadline in milliseconds (0 for a sync edge) |
| 5 | `E_RESTART_ON` | 0 none, 1 error, 2 restart, 3 refresh |
| 6 | `E_FLAGS` | bit 0 = `stop = "parallel"`, bit 1 = cascade (a quarantined `require_all` target quarantines the dependent); all other bits zero |

### Credential (15 words)

| Word | Name | Meaning |
| --- | --- | --- |
| 0, 1 | `C_USER_OFF`, `C_USER_LEN` | user name in the pool, non-empty |
| 2, 3 | `C_CAPS_LO`, `C_CAPS_HI` | capability set as 64 bits; only bits 0..=40 may be set |
| 4 | `C_SECUREBITS` | 0 none, 1 noroot, 2 noroot-locked |
| 5 | `C_NNP` | no_new_privs, 0 or 1 |
| 6 | `C_NS` | namespaces, bits 0..=5: mount, pid, ipc, uts, net, user |
| 7 | `C_SECCOMP` | 0 none, 1 default, 2 deny-list, 3 allow-list |
| 8, 9 | `C_PATHS_OFF`, `C_PATHS_LEN` | the sandbox path list: entries `<mode>:<path>`, the mode one of `ro` `rw` `ri` `wi` `rs` `ws` (read-only, writable, idmapped read-only, idmapped writable, read-only and following the host's later mounts, writable and following), with a canonical absolute path (starts `/`, no empty, `.` or `..` component, no trailing `/`), NUL-separated |
| 10, 11 | `C_SECCOMP_OFF`, `C_SECCOMP_LEN` | syscall numbers of the deny- or allow-list, NUL-separated canonical decimals; length 0 exactly when `C_SECCOMP` is 0 or 1 |
| 12 | `C_USER_MAP` | the user namespace's id map: 0 own, 1 range; 1 only with the `user` bit of `C_NS` |
| 13, 14 | `C_INSIDE_UID`, `C_INSIDE_GID` | the user and group id the service runs as inside its user namespace, at most 4294967294; 0 unless `C_NS` has the `user` bit |

The default program answers `clone`, `unshare`, `clone3` and `setns` itself (`clone` and
`unshare` by their namespace flags, `setns` always, `clone3` with `ENOSYS`), so a deny-list
may not name them. An allow-list replaces the default program, including that check: an
allow-list that names `clone` or `unshare` permits creating namespaces.

A canonical decimal is 1 to 3 ASCII digits with no leading zero (the single digit `0` is the
only entry starting with `0`), and its value is below `MAX_SYSCALL`. The compiler emits exactly
this form and the validator accepts only it.

### Policy rule (45 words)

A rule says what a request launched under a matching name may ask for. Rules are in file order
and the first match decides.

| Word | Name | Meaning |
| --- | --- | --- |
| 0, 1 | `P_PATTERN_OFF`, `P_PATTERN_LEN` | a glob over the launch name, 1 to `MAX_PATTERN_LEN` bytes of node-name bytes, `*` (any run of bytes) and `~` |
| 2, 3 | `P_USERS_OFF`, `P_USERS_LEN` | the users the rule applies to, NUL-separated names (1 to 32 bytes: a lowercase letter or `_`, then lowercase letters, digits, `_` or `-`) |
| 4 | `P_USERS_ANY` | 1 when the rule names no users and any user matches; then `P_USERS_LEN` is 0 |
| 5, 6 | `P_CAPS_LO`, `P_CAPS_HI` | the capability ceiling, bits 0..=40 |
| 7 | `P_REQUIRE_NNP` | 1 when the request must set `no_new_privs` |
| 8 | `P_REQUIRE_SECCOMP` | 1 when the request must carry a seccomp filter |
| 9 | `P_ALLOW_USERNS` | 0 no user namespace, 1 its own map, 2 its own or the range map |
| 10 | `P_RLIMIT_MASK` | the limits the rule sets a ceiling for (the node record's encoding) |
| 11 + 2r, 12 + 2r | `P_RLIMIT_BASE` | the ceiling of resource `r`, low and high word |
| 43 | `P_ALLOW_INSIDE_IDS` | 1 when a request may run as a non-zero id inside its user namespace; 0 or 1 |
| 44 | `P_ALLOW_IDMAP` | 1 when a request may have an idmapped path entry (`ri:`, `wi:`), which hands the service the ownership of disk ids; 0 or 1 |

### Policy header (34 words)

The one record of `T_POLICY_HEAD`, when a policy exists: word 0 `PH_ALLOW` (1 when a request no rule
matches is allowed), word 1 `PH_RLIMIT_MASK` and words 2.. `PH_RLIMIT_BASE` the top-level
ceilings, which hold under every rule (the boot ceilings are merged in by the compiler).

A database with no `T_POLICY_HEAD` record has no policy and `Run` refuses every request with the
detail "no policy"; one with rules has the header record. The check itself is
`qinit_overseer_core::check_policy`, proved equal to its specification: a request that does not
raise any ceiling and meets the first matching rule's requirements is allowed. The first failing
clause is reported in the order user, capabilities, `no_new_privs`, seccomp, user namespace,
limits.

A request that holds no privilege (not `root`, no capabilities, `no_new_privs`, no user
namespace, every limit within the top-level ceilings) needs no rule and is allowed whenever a
policy exists.

### Route (3 words)

| Word | Name | Meaning |
| --- | --- | --- |
| 0 | `R_KIND` | 0 path, 1 pipe |
| 1 | `R_A` | path: pool offset; pipe: logger node index |
| 2 | `R_B` | path: length; pipe: 0 |

### Enabled closure and pre-syslog list

One word per record, a node index. Both lists are ascending and free of duplicates.

## Credentials are required

Every worker and forager references a credential record (`N_CRED` is an index, never `NONE`),
and every credential record names a non-empty user; the overseer resolves that name through
`/etc/passwd` and `/etc/group` of the booted system. A brood runs nothing and has `N_CRED`
`NONE`. There is no default identity: a database whose worker has no credential, or whose
credential has an empty user, is refused. The sandbox fields of a credential (`C_NS`,
`C_SECCOMP`, the path and seccomp lists) go with the identity in the same record. A
credential with `C_NNP` 0 and a path list or a seccomp filter needs `CAP_SYS_ADMIN` (bit
`CAP_SYS_ADMIN_BIT` = 21 of `C_CAPS_LO`), because installing those without `no_new_privs`
requires it.

## Validation rules

The validator is total and never panics. It accepts a database only if all of the following hold:

1. **V1** Header fields, offsets and counts are in bounds and within the limits, and tables do not overlap.
2. **V2** The pool is valid UTF-8, and every pool reference is an in-bounds slice between two character boundaries, and within `MAX_NAME_LEN` where it names something. A NUL-separated list (argv, environment entries, path entries, seccomp lists) holds no empty element. `N_INSTANCE_OF` may be empty, but at most `MAX_NAME_LEN` bytes.
3. **V3** Every cross-table index is `NONE` or in range of its table.
4. **V4** Enums are in range, reserved bits are zero, and sync/async fields are consistent (a sync edge has no deadline). A node's `stop_mode` is 0 or 1, its `restart_delay_ms` and `stop_grace_ms` are at least 100, `restart_max > 0` implies `restart_window_ms > 0`, and its `umask` is at most `MAX_UMASK`. A worker or forager has a credential and a brood has none; the working directory is a canonical absolute path; every path entry starts with one of the six modes and a colon and has a canonical absolute path; every environment entry has a non-empty key before its first `=`. A credential's user is non-empty, `seccomp` is at most 3 and its list is non-empty exactly when `seccomp` is 2 or 3; every list entry is a canonical decimal below `MAX_SYSCALL`; `nnp` 0 with a path list or a seccomp filter requires `CAP_SYS_ADMIN` in `caps_lo`. A credential's path list is strictly ascending by path (so no path repeats), holds no `/`, `/dev` or `/tmp` and no writable (`rw:`, `wi:`, `ws:`) `/proc`, needs the `mount` bit of `C_NS`, and, when an entry is idmapped (`ri:`, `wi:`), the `user` bit; a node with a non-empty list has an absolute program (the first element of its `exec`) at or below an entry, and a working directory that is `/` or at or below an entry. A policy rule's flags and enums are in range (`users_any` and `require_*` 0 or 1, `allow_userns` at most 2, `caps_hi` at most `0x1ff`), its pattern is 1 to `MAX_PATTERN_LEN` bytes of node-name bytes, `*` and `~`, its users are valid names, `users_any` 1 goes with an empty users list, its limits are node-record limits, there is a header record whenever there is a rule, and the header record's flags and limits are in range. `C_NS` is at most `0x3f`, `C_USER_MAP` at most 1, `C_USER_MAP` 1 needs the `user` bit, and a credential with the `user` bit does not name `root`. `C_INSIDE_UID` and `C_INSIDE_GID` are at most 4294967294 and 0 without the `user` bit; a policy rule's `P_ALLOW_INSIDE_IDS` and `P_ALLOW_IDMAP` are 0 or 1.
5. **V5** The ordering-edge graph is acyclic.
6. **V6** The stop order derived by `qinit-graph-core` places every hard dependent before its dependency, whatever the opt-outs.
7. **V7** `stop = "parallel"` appears on no hard edge.
8. **V8** The pre-syslog list and the enabled closure are both ascending and duplicate-free, and the enabled closure is closed under the edges: every node target of a `require_all` or `require_any` group of an enabled node is enabled, sync or async. The roots are not stored, so the validator does not check that every member is reachable from one; the compiler builds the closure from the roots.
9. **V9** Every reader accessor is in bounds for any accepted database.

`qinit_db_core::validate` proves `Ok(())` implies `well_formed`, the conjunction of the spec
functions `v1` to `v8` in `crates/qinit-db-core/src/validate/spec/`, and
`lemma_accessors_in_bounds` proves V9 from it. In detail:

- Tables appear in header order, each starting at or after the end of the one before (the
  first after the header). Every table but the pool starts on a 4-byte boundary.
- Every pool reference (names, argv, readiness arguments, instanced-frame names, environment
  entries, working directories, path targets, users, path entries, seccomp lists, launch keys, route
  paths) is in the pool and starts and ends on a character boundary of the pool, which as a whole
  is valid UTF-8 as `core::str::from_utf8` defines it (`DbError::Utf8 { offset }` names the first
  bad pool offset; `DbError::Pool { table, record }` names the record whose reference leaves the
  pool or splits a character). Node names are 1 to `MAX_NAME_LEN` bytes and strictly ascending, bytewise.
- The argv, environment, path and seccomp lists are either empty (length 0) or have no NUL
  as their first or last byte and no two NULs in a row, so every element is non-empty
  (`DbError::Pool { table, record }` otherwise). The content of environment and seccomp entries and of the working
  directory is a V4 rule (`DbError::Consistency`), checked after V2 has placed the bytes in the
  pool. So is the launch key list: each key is non-empty and holds no `=`, and each key sorts
  strictly after the one before it.
- The launch words: `N_RELOAD` is at most 3 and `N_LAUNCH_CONCURRENCY` at most 64, `N_LAUNCH_ARGV_TAIL`
  at most 64 and `N_LAUNCH_FDS` at most 7 (`DbError::Enum`). Only a forager has a non-zero
  concurrency, and with concurrency 0 the other launch words are 0 (`DbError::Consistency`).
- Tiling: node `i`'s groups start where node `i - 1`'s end (node 0's at 0), and the last node's
  end at the group count; groups tile the edge table the same way. A node has at most
  `MAX_GROUPS_PER_NODE` groups, a group at most `MAX_EDGES_PER_GROUP` edges.
- A forager or brood has restart policy 0, and a brood has no argv and no credential; a worker
  or forager has a credential. A node-target edge has `target_len` 0. A pipe route names a
  worker and has `b` 0. `caps_hi` uses bits 0..=8 only.
- Ordering edges are the node-target edges of `require_all`, `require_any` and `optional_all`
  groups; an ordering edge is hard when its group is `require_all` or `require_any` and its
  mode is sync. `exclude_all` edges and path targets do not order anything.
- The enabled list is closed: every node target of a `require_all` or `require_any` group of
  an enabled node is enabled.

Errors are reported for the first rule broken, in the order header, tables, pool references,
records (nodes, groups, edges, credentials, routes, then name order), graph, lists.
