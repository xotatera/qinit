<!--
SPDX-FileCopyrightText: 2026 Xota Tera
SPDX-License-Identifier: CC-BY-4.0
-->

# Compiled database format (version 1)

The database is one flat byte string. Everything is little-endian, every record has a fixed
number of 32-bit words, and every cross-reference is a `u32` index. `NONE` (`0xFFFF_FFFF`) means
"absent". The constants below are defined in `crates/qinit-db-core/src/layout.rs`.

## Header

The header is `HEADER_WORDS` = 20 words:

| Word | Meaning |
| --- | --- |
| 0 | `MAGIC` = `0x3142_4451` (the bytes `QDB1`) |
| 1 | `VERSION` = 1 |
| 2 | total length in bytes |
| 3 | CRC-32 of the body (detects corruption only; no integrity or authenticity claim) |
| 4 + 2t | byte offset of table `t` |
| 5 + 2t | record count of table `t` (for the pool: its length in bytes) |

## Tables

Table ids, in header order, with the words per record (`WORDS`):

| Id | Table | Words |
| --- | --- | --- |
| 0 `T_NODES` | nodes | 20 |
| 1 `T_GROUPS` | dependency groups | 3 |
| 2 `T_EDGES` | edges | 7 |
| 3 `T_CREDS` | credentials | 10 |
| 4 `T_ROUTES` | output routes | 3 |
| 5 `T_ENABLED` | enabled closure | 1 |
| 6 `T_PRESYSLOG` | pre-syslog list | 1 |
| 7 `T_POOL` | string pool | bytes |

Strings (names, argv, paths) live in the pool and are referenced by (offset, length).

## Limits

`MAX_NODES` 4096, `MAX_GROUPS` 16384, `MAX_EDGES` 32768, `MAX_EDGES_PER_GROUP` 64,
`MAX_GROUPS_PER_NODE` 16, `MAX_CREDS` 4096, `MAX_ROUTES` 8192, `MAX_POOL` 1 MiB,
`MAX_NAME_LEN` 96. `MAX_NODES` and `MAX_EDGES` equal the limits of `qinit-graph-core`.

## Records

### Node (20 words)

| Word | Name | Meaning |
| --- | --- | --- |
| 0 | `N_KIND` | 0 worker, 1 forager, 2 brood |
| 1, 2 | `N_NAME_OFF`, `N_NAME_LEN` | name in the pool |
| 3, 4 | `N_EXEC_OFF`, `N_EXEC_LEN` | argv in the pool, NUL-separated |
| 5 | `N_READY_KIND` | 0 pipe, 1 exit, 2 socket, 3 path |
| 6, 7 | `N_READY_OFF`, `N_READY_LEN` | readiness argument in the pool |
| 8 | `N_RESTART_POLICY` | 0 never, 1 on-failure, 2 always |
| 9 | `N_RESTART_MAX` | restarts allowed in the window |
| 10 | `N_RESTART_WINDOW_MS` | restart window, milliseconds |
| 11 | `N_OUTPUT` | route index or `NONE` |
| 12 | `N_ERRORS` | route index or `NONE` |
| 13 | `N_CRED` | credential index or `NONE` |
| 14, 15 | `N_GROUP_FIRST`, `N_GROUP_COUNT` | the node's groups, a run in the group table |
| 16 | `N_MEMORY_MAX_KIB` | memory limit |
| 17 | `N_PIDS_MAX` | process limit |
| 18, 19 | `N_INSTANCE_OF_OFF`, `N_INSTANCE_OF_LEN` | template name in the pool (length 0 if not an instance) |

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
| 6 | `E_FLAGS` | bit 0 = `stop = "parallel"`; all other bits zero |

### Credential (10 words)

| Word | Name | Meaning |
| --- | --- | --- |
| 0, 1 | `C_USER_OFF`, `C_USER_LEN` | user name in the pool |
| 2, 3 | `C_CAPS_LO`, `C_CAPS_HI` | capability set as 64 bits; only bits 0..=40 may be set |
| 4 | `C_SECUREBITS` | 0 none, 1 noroot, 2 noroot-locked |
| 5 | `C_NNP` | no_new_privs, 0 or 1 |
| 6 | `C_NS` | namespaces, bits 0..=4: mount, pid, ipc, uts, net |
| 7 | `C_SECCOMP` | 0 none, 1 default |
| 8, 9 | `C_LANDLOCK_OFF`, `C_LANDLOCK_LEN` | entries `ro:/path` or `rw:/path`, NUL-separated |

### Route (3 words)

| Word | Name | Meaning |
| --- | --- | --- |
| 0 | `R_KIND` | 0 path, 1 pipe |
| 1 | `R_A` | path: pool offset; pipe: logger node index |
| 2 | `R_B` | path: length; pipe: 0 |

### Enabled closure and pre-syslog list

One word per record, a node index. Both lists are ascending and free of duplicates.

## Validation rules

The validator is total and never panics. It accepts a database only if all of the following hold:

1. **V1** Header fields, offsets and counts are in bounds and within the limits, and tables do not overlap.
2. **V2** Every pool reference is an in-bounds slice, valid UTF-8, and within `MAX_NAME_LEN` where it names something.
3. **V3** Every cross-table index is `NONE` or in range of its table.
4. **V4** Enums are in range, reserved bits are zero, and sync/async fields are consistent (a sync edge has no deadline).
5. **V5** The ordering-edge graph is acyclic.
6. **V6** The stop order derived by `qinit-graph-core` places every hard dependent before its dependency, whatever the opt-outs.
7. **V7** `stop = "parallel"` appears on no hard edge.
8. **V8** The pre-syslog list and the enabled closure are consistent with the edges: both are ascending and duplicate-free, and every closure member is reachable from an enabled root.
9. **V9** Every reader accessor is in bounds for any accepted database.
