<!--
SPDX-FileCopyrightText: 2026 Xota Tera
SPDX-License-Identifier: CC-BY-4.0
-->

# The launch request (QLR1)

A launch request is one flat byte string that says everything the overseer needs to start one
service: the program, the identity it runs as, its sandbox, its descriptors and its deadline.
Colony builds it from a database node (`Launch`) or receives it whole from a client (`Run`, see
`docs/control-protocol.md`); the overseer decodes it, plans the launch from it and executes the
plan. The format is precise enough to write an encoder in another language from this document
alone. The layout is `qinit-proto-core::launch` (constants, MPL-2.0), the encoder is
`qinit-launch`, and the judge of what is valid is `qinit_overseer_core::decode`, which is
proved with Verus. The examples at the end are decoded and re-encoded by a test, so they cannot
drift from the code.

## Layout

Every word is a 32-bit little-endian unsigned integer. A request is a header of 5 words, a
record of 67 words and a string pool, in that order; it is at most `MAX_REQUEST` = 65536 bytes.
A pool reference is an `(offset, length)` pair of words into the pool.

### Header

| Word | Name | Meaning |
| --- | --- | --- |
| 0 | `magic` | `0x3152_4C51`, the bytes `QLR1` |
| 1 | `version` | 1 |
| 2 | `total_len` | the length of the whole request in bytes, equal to the buffer's |
| 3 | `pool_off` | the byte offset of the pool, at least 288 (the end of the record) |
| 4 | `pool_len` | the pool's length; `pool_off + pool_len` is `total_len` |

### Record

| Word | Name | Meaning |
| --- | --- | --- |
| 0, 1 | `argv_off`, `argv_len` | the arguments, NUL-separated, non-empty; the first is the program |
| 2, 3 | `env_off`, `env_len` | `KEY=VALUE` entries, NUL-separated, at most 256, each with a non-empty key |
| 4, 5 | `cwd_off`, `cwd_len` | the working directory, a canonical absolute path |
| 6 | `umask` | at most `0o777` |
| 7 | `rlimit_mask` | bit `r` set means resource `r` is set; bits 0..=15 except bit 4 (`core`, which is always set to 0) |
| 8, 9 | `user_off`, `user_len` | the user name, 1 to 96 bytes; the overseer resolves it through `/etc/passwd` and `/etc/group` |
| 10, 11 | `caps_lo`, `caps_hi` | the capability set to keep; only bits 0..=40 (`caps_hi` at most `0x1ff`) |
| 12 | `securebits` | 0 none, 1 noroot, 2 noroot-locked |
| 13 | `nnp` | `no_new_privs`, 0 or 1 |
| 14 | `ns` | namespace bits: 1 mount, 2 pid, 4 ipc, 8 uts, 16 net, 32 user; at most `0x3f` |
| 15 | `seccomp` | 0 none, 1 default program, 2 deny-list, 3 allow-list |
| 16, 17 | `seccomp_off`, `seccomp_len` | the list: NUL-separated canonical decimal syscall numbers below 512; length 0 exactly when `seccomp` is 0 or 1; at most 512 entries |
| 18, 19 | `paths_off`, `paths_len` | the path list (below), NUL-separated `<mode>:<path>` entries (`ro` `rw` `ri` `wi` `rs` `ws`), at most 64 |
| 20, 21, 22 | `stdout_kind`, `stdout_a`, `stdout_b` | a stream (below); kind 0 or 1 |
| 23, 24, 25 | `stderr_kind`, `stderr_a`, `stderr_b` | a stream; kind 0, 1 or 2 |
| 26 | `ready_kind` | 0 none, 1 a readiness pipe |
| 27 | `ready_fd` | the descriptor number the pipe arrives on; 0 when `ready_kind` is 0 |
| 28 | `flags` | bit 0 `die_with_parent`: the service gets `SIGKILL` when its parent thread exits |
| 29 | `deadline_ms` | at least 1: the one timer that ends a launch that blocks |
| 30 | `user_map` | 0 own, 1 range; 1 only with the `user` bit of `ns` |
| 31 | reserved | 0 |
| 32, 33, 34 | `stdin_kind`, `stdin_a`, `stdin_b` | a stream; kind 0 or 1 |
| 35 + 2r, 36 + 2r | limit `r` | low and high word of the value of resource `r`, for `r` in 0..=15 (the kernel's resource numbers); both 0 unless bit `r` of `rlimit_mask` is set; all ones is infinity |

Limits: `nofile` (7) must not be 0 or infinity, `nice` (13) is at most 40 and `rtprio` (14) at
most 99, and the high word of those two is 0.

### Pool

The pool is valid UTF-8, and every reference lies inside it and starts and ends on a character
boundary. In a list, elements are separated by one NUL; there is none before the first or after
the last, so no element is empty. The pool may hold the same bytes more than once and nothing
requires an order; the encoder in `qinit-launch` appends each field in turn.

### Streams

A stream is `(kind, a, b)`:

- **0, path:** `a` is the pool offset and `b` the length of a path the executor opens by its file
  type.
- **1, descriptor:** `a` is a routed descriptor number and `b` is 0.
- **2, same** (standard error only): standard error is wherever standard output goes; `a` and
  `b` are 0.

### Readiness

With `ready_kind` 1 the readiness pipe arrives on `ready_fd`, which must be a routed
descriptor (below). `Run` refuses a request with a readiness pipe.

## Descriptors

The executor starts with the request on descriptor 3 (a sealed memfd) and a close-on-exec status
pipe on descriptor 4. Descriptors 5 to 37 (`MIN_ROUTED_FD` to `MAX_ROUTED_FD`) are routed: a
stream or the readiness pipe may name any of them, and no two of stdin, stdout, stderr and the
readiness pipe may name the same one. The service gets 0, 1 and 2 as its streams; every other
descriptor is closed before `execve`.

## Rules the decoder enforces

`decode` returns `Ok` or the first failing group, in this order:

1. **Header** (`LaunchError::Header`): at least 288 bytes and at most `MAX_REQUEST`, the magic
   and version, `total_len` equal to the length, the pool at or after offset 288 and ending at
   the end.
2. **Pool** (`Pool`): every reference inside the pool, valid UTF-8, no empty list element.
3. **Enums** (`Enum`): every field above in its range, the reserved word 0, the seccomp list
   present exactly for modes 2 and 3.
4. **Routes** (`Consistency`): a descriptor stream or readiness pipe names a routed number and
   has `b` 0; `same` has `a` and `b` 0; a readiness pipe of kind 0 has `ready_fd` 0; the routed
   numbers differ.
5. **Content** (`Consistency`):
   - argv is non-empty, `deadline_ms` is at least 1 and the limits obey the rules above;
   - the user is 1 to 96 bytes; the working directory is canonical (starts with `/`, no empty,
     `.` or `..` component, no trailing `/`, except `/` itself);
   - environment entries have a non-empty key before the first `=`;
   - `user_map` 1 needs the `user` bit of `ns`, and a request with the `user` bit does not run
     as `root`;
   - **the path list** (below);
   - `nnp` 0 together with a path list or a seccomp filter needs `CAP_SYS_ADMIN` (bit 21 of
     `caps_lo`), because installing those without `no_new_privs` requires it.

### The path list

Each entry is a mode (`ro:` `rw:` `ri:` `wi:` `rs:` `ws:`) and a canonical absolute path. The list is strictly ascending by path
(so a path never repeats), holds none of `/`, `/dev` or `/tmp`, and no writable `/proc`. A non-
empty list needs the `mount` bit of `ns`, the program (the first argv element) must be at or below
an entry, and the working directory must be `/` or at or below an entry.

With a path list the service does not see the host's filesystem. The overseer builds an empty
`tmpfs` root with a fixed `/dev` (`null`, `zero`, `full`, `random`, `urandom`) and a private
`/tmp`, binds each listed path into it, pivots into it, and seals it read-only; Landlock then
restricts the service to those paths. The view is built under `/.qinit-view` on the host's root filesystem, so
a launch with a path list needs a writable root directory (`EROFS` at `view-root` otherwise).
Every mount of the view is private, so a mount the host makes later is not seen inside.

### User namespace

With the `user` bit the service runs in its own user namespace, as `0` inside it. `user_map` 0
maps inside id 0 onto the user's own user and group id and denies `setgroups`; 1 also maps
inside ids 1 and up onto the user's subordinate ranges (`/etc/subuid`, `/etc/subgid`) and allows
`setgroups`. Whether a request may ask for a user namespace, and for the range map, is the
policy's decision (`allow_userns`, see `docs/db-format.md`).

## The failure record

The executor reports a failed launch on descriptor 4 as one record of 8 bytes, little-endian:
`step` (a `u32`) and `errno` (an `i32`). Success is end of file on the pipe, which happens at
`execve`. A failed launch exits 127.

`step` is an index into the launch plan, which is a function of the request, or:

| Value | Meaning |
| --- | --- |
| `0xFFFF_FFFF` | the request did not decode |
| `0xFFFF_FFFE` | the user did not resolve |

Colony turns the index into a name for its notice. The names are `setsid`, `unshare`,
`mount-slave-root`, `mount-tmp`, `loopback-up`, `fork`, `view-root`, `view-dev`, `view-tmp`,
`view-entry`, `view-pivot`, `view-seal`, `proc-self`, `clear-groups`, `user-namespace`,
`unshare-owned`, `arm-deadline`, `rearm-deadline`, `open-stdin`, `open-stdout`, `open-stderr`,
`route-ready`, `umask`, `rlimit-<name>` (`cpu`, `fsize`, `data`, `stack`, `core`, `rss`,
`nproc`, `nofile`, `memlock`, `as`, `locks`, `sigpending`, `msgqueue`, `nice`, `rtprio`,
`rttime`), `setgroups`, `setgid`, `securebits`, `drop-bounding`, `setuid`, `capset`,
`ambient-raise`, `pdeathsig`, `no-new-privs`, `chdir`, `landlock-ruleset`,
`landlock-view-rules`, `landlock-rule`, `landlock-restrict`, `seccomp`, `close-range` and
`exec`. A launch that blocks past `deadline_ms` ends by `SIGALRM` and writes no record.

## Examples

Every block below is one request. The hex is the request's bytes in order, in groups of four (so
the words read as little-endian words, and the pool bytes, which are not words, are grouped the
same way). Text after `#` is a comment.

### A minimal request

Run `/bin/true` as `svc`, in `/`, with standard input and output on `/dev/null` and standard
error following standard output.

```qlr1
514c5231 01000000 3f010000 20010000 1f000000  # header: magic, version, total_len, pool_off, pool_len
00000000 09000000  # argv_off, argv_len
09000000 00000000  # env_off, env_len
09000000 01000000  # cwd_off, cwd_len
17000000  # umask
00000000  # rlimit_mask
0a000000 03000000  # user_off, user_len
00000000 00000000  # caps_lo, caps_hi
00000000  # securebits
01000000  # nnp
00000000  # ns
00000000 0d000000 00000000  # seccomp, seccomp_off, seccomp_len
0d000000 00000000  # paths_off, paths_len
00000000 16000000 09000000  # stdout_kind, stdout_a, stdout_b
02000000 00000000 00000000  # stderr_kind, stderr_a, stderr_b
00000000 00000000  # ready_kind, ready_fd
00000000  # flags
30750000  # deadline_ms
00000000  # user_map
00000000  # reserved
00000000 0d000000 09000000  # stdin_kind, stdin_a, stdin_b
00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000  # limits: resource 0 to 3 (low, high)
00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000  # limits: resource 4 to 7
00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000  # limits: resource 8 to 11
00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000  # limits: resource 12 to 15
2f62696e 2f747275 652f7376 632f6465 762f6e75 6c6c2f64 65762f6e 756c6c  # pool: "/bin/true", "/", "svc", then "/dev/null" for stdin and again for stdout
```

### A sandboxed request

Run `/usr/bin/job --once` as `svc` with `LANG=C`, in `/work`, in new mount and user namespaces
with the subordinate range, with the noroot-locked securebits, the default seccomp program and the
paths `/usr` (read-only) and `/work` (writable). Standard output goes to routed descriptor 6, and
the service dies with its parent.

```qlr1
514c5231 01000000 5a010000 20010000 3a000000  # header: magic, version, total_len, pool_off, pool_len
00000000 13000000  # argv_off, argv_len
13000000 06000000  # env_off, env_len
19000000 05000000  # cwd_off, cwd_len
17000000  # umask
00000000  # rlimit_mask
1e000000 03000000  # user_off, user_len
00000000 00000000  # caps_lo, caps_hi
02000000  # securebits
01000000  # nnp
21000000  # ns
01000000 21000000 00000000  # seccomp, seccomp_off, seccomp_len
21000000 10000000  # paths_off, paths_len
01000000 06000000 00000000  # stdout_kind, stdout_a, stdout_b
02000000 00000000 00000000  # stderr_kind, stderr_a, stderr_b
00000000 00000000  # ready_kind, ready_fd
01000000  # flags
88130000  # deadline_ms
01000000  # user_map
00000000  # reserved
00000000 31000000 09000000  # stdin_kind, stdin_a, stdin_b
00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000  # limits: resource 0 to 3 (low, high)
00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000  # limits: resource 4 to 7
00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000  # limits: resource 8 to 11
00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000  # limits: resource 12 to 15
2f757372 2f62696e 2f6a6f62 002d2d6f 6e63654c 414e473d 432f776f 726b7376  # pool: "/usr/bin/job" NUL "--once", "LANG=C", "/work", "svc", "ro:/usr" NUL "rw:/work", "/dev/null" for stdin
63726f3a 2f757372 0072773a 2f776f72 6b2f6465 762f6e75 6c6c
```
