<!--
SPDX-FileCopyrightText: 2026 Xota Tera
SPDX-License-Identifier: CC-BY-4.0
-->

# The qinit control protocol (QCP1)

This document specifies the protocol clients use to talk to colony, the process that supervises
the services. It is precise enough to write a client in another language from this document
alone. The reference implementation is `qinit-proto-core` (the format, the decoder, the encoder
and the authorization function, all proved with Verus), `qinit-wire` (messages as values) and
`qinit-client` (a blocking Rust client). The examples at the end are decoded by a test, so they
cannot drift from the code.

## Transport

- One socket: an `AF_UNIX` `SOCK_SEQPACKET` socket at `/run/qinit/colony`. The directory
  `/run/qinit` is owned by root, mode 0755; the socket has mode 0666, because authorization is
  decided by who the peer is (below) and not by who may open the file.
- Sequenced packets keep message boundaries and keep the file descriptors of a message with
  that message. One message is one `sendmsg`/`recvmsg`; descriptors travel in one `SCM_RIGHTS`
  control message. Receive with `MSG_CMSG_CLOEXEC`.
- A message is at most 65536 bytes and carries at most 4 descriptors.

## Who is on the other end

At `accept`, colony reads the peer's `SO_PEERCRED` (user id, group id, process id) and
`SO_PEERPIDFD` (a pidfd, Linux 6.5 and later) and keeps both for the life of the connection. A
connection whose pidfd cannot be had is closed. The user id decides what the peer may do:

| Request | Who may send it |
| --- | --- |
| `Status`, `List` | any user |
| `Change`, `Launch`, `Refresh`, `Shutdown` | user id 0 only |

A request the peer may not make gets `Error(Denied)` and the connection stays open.

## The conversation

- **One request in flight per connection.** A client sends a request and reads replies until the
  last one for that request. A second request before the last reply is answered
  `Error(BadRequest)` with detail 6 (`Consistency`), and the connection is closed. A client that
  wants parallel work opens several connections. A client that does not read its replies is
  closed when its receive queue is full: the server never waits for it.
- **No handshake.** Every message carries the protocol version in its header (1). A server that
  does not speak the version answers `Error(Version)`, with the version it speaks in the error's
  `version` word, and closes the connection.
- **Limits.** At most 64 connections at once and at most 4 per user other than root. Past a
  limit, colony accepts the connection, sends `Error(Full)` and closes it.
- **Malformed input closes the connection** after one `Error(BadRequest)` whose detail is the
  decode error number (below): a message the decoder refuses, a truncated control message
  (`MSG_CTRUNC`), a descriptor count that differs from the count the message declares, a
  datagram over the limit (`MSG_TRUNC`). Every descriptor received with a refused message is
  closed.
- **Every wait ends.** A request that waits (a *settled* change, a refresh, a shutdown, or a
  launch) names a `wait_ms` from 1 to 600000. If the awaited state is not reached by then, the
  reply is `Pending(state)` and the request stays in effect. If another request changes what a
  parked wait waits for, or a refresh removes it, the wait is answered at once with
  `Superseded(state)`.
- **Closing a connection does not undo anything.** A request that was accepted stays in effect;
  a running instance continues.

## Message format

All numbers are unsigned 32-bit words in little-endian byte order. A message is a five-word
header, a fixed record whose size depends on the message type, and a string pool.

| Word | Name | Value |
| --- | --- | --- |
| 0 | `magic` | `0x31504351`, the bytes `QCP1` |
| 1 | `version` | 1 |
| 2 | `total_len` | the length of the whole message in bytes, equal to the datagram length |
| 3 | `type` | the message type (below) |
| 4 | `fd_count` | the descriptors that travel with this message |

The record follows the header. A string in a record is two words, `(offset, length)`: the offset
is in bytes from the start of the message, and must be at or after the end of the record region
and, with the length, inside `total_len`. Strings are UTF-8. A *list* is a string whose bytes are
elements separated by one NUL byte, with no empty element and no NUL first or last; the empty
string is the empty list. A name is 1 to 96 bytes. A *target* names a node (a name) or an
instance, `<frame>#<n>` with `n` in decimal without leading zeros and below 2^32, and is 1 to
107 bytes. The decoder checks only the length; a name that is not in the database, or an
instance that is not running, is answered `Error(UnknownNode)`.

Strings are laid out in the order the record names them, one after the other, so one value has
one encoding. An empty string takes the next offset with length 0.

A decoder refuses a message with the first of these errors, checked in this order:

| Number | Error | Meaning |
| --- | --- | --- |
| 1 | `Header` | shorter than the header or longer than 65536, bad magic, a `total_len` that disagrees with the datagram, or a record that does not fit |
| 2 | `Version` | a version other than 1 |
| 3 | `Type` | an unknown message type |
| 4 | `Pool` | a string leaves the message or enters the record region, is not UTF-8, or a list has an empty element |
| 5 | `Enum` | an enum word out of range |
| 6 | `Consistency` | a name or target of the wrong length, a list over its cap, a bad environment entry, a wait that disagrees with `settled`, or fields that contradict each other |
| 7 | `FdCount` | the descriptors received, the `fd_count` word and the count the record requires disagree (a `Launched` reply requires none or one) |

## Message types

Requests are below 64 and go from client to colony; replies are 64 and above. A request type
sent as a reply, or the other way round, is a protocol error.

| Type | Name | Direction |
| --- | --- | --- |
| 1 | `Status` | request |
| 2 | `List` | request |
| 3 | `Change` | request |
| 4 | `Launch` | request |
| 5 | `Refresh` | request |
| 6 | `Shutdown` | request |
| 7 | `Run` | request |
| 64 | `Error` | reply |
| 65 | `NodeStatus` | reply |
| 66 | `InstanceStatus` | reply |
| 67 | `ListPage` | reply |
| 68 | `Accepted` | reply |
| 69 | `Settled` | reply |
| 70 | `Pending` | reply |
| 71 | `Superseded` | reply |
| 72 | `Launched` | reply |
| 73 | `LaunchFailed` | reply |
| 74 | `Exited` | reply |

### Enum values

- **State** (words named `state`): 0 off, 1 waiting, 2 starting, 3 ready, 4 done, 5 stopping,
  6 quarantined. For an instance, 3 means running and 4 means exited. With every state goes a
  `detail` word: for a waiting node 0 if a dependency group is unsatisfied and 1 if the restart
  back-off has not elapsed; for a quarantined node 0 breaker, 1 cascade, 2 start timeout, 3 stop
  failed; otherwise 0.
- **Kind** (words named `kind` in replies): 0 worker, 1 forager, 2 brood. The `kind` filter of a
  `List` request: 0 all, 1 workers, 2 foragers, 3 broods.
- **Action** (`Change`): 0 start, 1 stop, 2 restart, 3 clear, 4 refresh, 5 run.
- **Mode** (`Shutdown`): 0 poweroff, 1 reboot, 2 halt.
- **Descriptor roles** (`Launch`): a mask of 1 stdin, 2 stdout, 4 stderr. The descriptors travel
  in that order, one per role set.
- **Error codes** (`Error`): 1 `Version`, 2 `BadRequest` (detail: the decode error number
  above), 3 `Denied`, 4 `Full`, 5 `Busy`, 6 `ShuttingDown`, 7 `UnknownNode`, 8 `NotLaunchable`,
  9 `Unsatisfied`, 10 `NoSlot`, 11 `NotNow` (detail: the node's state), 12 `Invalid` (detail: the
  reason a database was refused, below).

### Why a database is refused

The detail of `Invalid`: 1 CRC mismatch, 2 header, 3 version, 4 length, 5 table, 6 overlap,
7 count, 8 pool, 9 UTF-8, 10 index, 11 enum, 12 tiling, 13 consistency, 14 cycle, 15 hard
parallel edge, 16 closure, 17 order, 18 scratch, 19 larger than 8 MiB, 20 not readable. The
numbers 2 to 18 name the validator's errors in the order of `docs/db-format.md`.

## Requests

### `Status` (type 1), any user

| Word | Name | Meaning |
| --- | --- | --- |
| 0, 1 | `target_off`, `target_len` | the target: a node or an instance |

No descriptors. Reply: `NodeStatus` for a node, `InstanceStatus` for an instance, or `Error`.

### `List` (type 2), any user

| Word | Name | Meaning |
| --- | --- | --- |
| 0 | `cursor` | the index of the first entry wanted; 0 for the first page |
| 1 | `kind` | the kind filter |

No descriptors. Reply: `ListPage`. A cursor past the end gives an empty page with no next
cursor, not an error.

### `Change` (type 3), user id 0

| Word | Name | Meaning |
| --- | --- | --- |
| 0, 1 | `target_off`, `target_len` | a node, or an instance (which accepts only `stop`) |
| 2 | `action` | the action |
| 3 | `settled` | 0 reply on acceptance, 1 reply again when the node settles |
| 4 | `wait_ms` | 1 to 600000 when `settled`, otherwise 0 |

No descriptors. A target that is an instance accepts only `stop`; any other action is answered `Error(BadRequest)` with detail 6. `refresh` restarts the node, or sends it its reload signal if the frame declares
one; either way the `refresh` edges of the nodes that depend on it fire. Reply: `Accepted`, or
`Error` (`UnknownNode`, `NotNow` with the node's state when the request does nothing in that
state, `ShuttingDown`); and if `settled`, then `Settled`, `Pending` or `Superseded`, each with
the state the node reached or is in.

### `Launch` (type 4), user id 0

| Word | Name | Meaning |
| --- | --- | --- |
| 0, 1 | `frame_off`, `frame_len` | the name of a forager that declares a launch table |
| 2, 3 | `argv_off`, `argv_len` | a list: extra argv elements, at most 64 and at most the frame's `argv_tail` |
| 4, 5 | `env_off`, `env_len` | a list of `KEY=VALUE` entries, at most 64, each key one the frame lists |
| 6 | `fd_roles` | the roles of the descriptors sent, a subset of the frame's `fds` |
| 7 | `wait_ms` | 1 to 600000 |
| 8 | `flags` | bit 0 `pidfd`: ask for a pidfd of the instance's main process; other bits 0 |

One descriptor per role set. Reply: `Launched` with the instance id (and, when `pidfd` was set
and the server could open one, a pidfd of the instance's main process as its one descriptor; it
names the process even after the pid is reused and polls readable when the process exits), or `LaunchFailed` (the
step that failed and its errno; step 0 is the creation of the instance's cell), or `Error`
(`UnknownNode`, `NotLaunchable`, `Unsatisfied`, `NoSlot`, `ShuttingDown`, and `Denied` for a
request that breaks the frame's launch table: too long an argument tail, an environment key or
a descriptor role the frame does not list); after `Launched`, `Exited` with the wait status when the instance ends,
or `Pending` with the instance's state at `wait_ms`, after which the connection is idle and the
outcome is read with `Status` on `<frame>#<id>`.

### `Refresh` (type 5), user id 0

| Word | Name | Meaning |
| --- | --- | --- |
| 0 | `settled` | 0 reply on acceptance, 1 reply again when the swap is done |
| 1 | `wait_ms` | 1 to 600000 when `settled`, otherwise 0 |

One descriptor: a regular file or a memfd holding the new compiled database. Colony reads it
whole from offset 0 whatever the descriptor's current offset, and leaves the offset as it was
(at most 8 MiB), validates it, and swaps only if it is valid. Reply: `Accepted`, or
`Error(Invalid)` with the reason, or `Error(Busy)` while an earlier refresh is stopping nodes,
or `Error(ShuttingDown)`; and if `settled`, then `Settled` once the new graph is live and the
nodes that were running are back in their wanted state or have failed, or `Pending`.

### `Shutdown` (type 6), user id 0

| Word | Name | Meaning |
| --- | --- | --- |
| 0 | `mode` | the mode |
| 1 | `settled` | 0 reply on acceptance, 1 reply again when colony's part is done |
| 2 | `wait_ms` | 1 to 600000 when `settled`, otherwise 0 |

No descriptors. Colony stops every instance and then the whole graph in order. A second
`Shutdown` with another mode replaces the mode. While shutting down, every request except
`Status`, `List` and `Shutdown` gets `Error(ShuttingDown)`. Reply: `Accepted`, and if `settled`,
`Settled` once the graph and the instances are stopped, or `Pending`.

### `Run` (type 7), user id 0

Launches a whole launch request (QLR1, `docs/launch-request.md`) as an instance, checked against
the policy compiled into the database.

| Word | Name | Meaning |
| --- | --- | --- |
| 0, 1 | `name_off`, `name_len` | the launch name, 1 to 95 bytes; the instance is `~<name>#<id>` (`~` is not a node-name byte, so it never collides with a frame's instances) |
| 2 | `fd_roles` | 1 stdin, 2 stdout, 4 stderr, as `Launch` |
| 3 | `flags` | bit 0 `pidfd`, as `Launch` |
| 4 | `memory_max_kib` | 0 for none |
| 5 | `pids_max` | 0 for none |
| 6 | `stop_mode` | 0 main, 1 cell |
| 7 | `stop_grace_ms` | at least 100 |
| 8 | `wait_ms` | 1 to 600000 |

Descriptors: first the request, then one per role set in the order stdin, stdout, stderr. The
request is a memfd sealed with `F_SEAL_SHRINK`, `F_SEAL_GROW`, `F_SEAL_WRITE` and `F_SEAL_SEAL`
holding at most 65536 bytes, read whole from offset 0; any other descriptor is `Error(Invalid)`
(reason 21 not fully sealed, 19 too large, 20 unreadable). Colony checks, in order: the request
decodes (`Error(Invalid)`, detail 1 header, 2 pool, 3 enum, 4 consistency of the request, 0 for a name that does not fit); its streams agree with the
roles sent (stdin, stdout and stderr arrive as descriptors 5, 6 and 7; a stream `fd n` names a
sent role's number and every role sent is used) and it names no readiness pipe (`Error(Denied)`,
detail 0); the policy allows it under the name `~<name>` (`Error(Denied)`, the detail the
first failing clause: 1 no policy, 2 user, 3 capabilities, 4 `no_new_privs`, 5 seccomp, 6 user
namespace, 7 limits, 8 default); a slot is free (`Error(NoSlot)`). Then it runs as an instance
and replies, waits, and ends exactly as `Launch` does, with the record's stop mode and grace. It
has no frame, so a refresh never touches it; a shutdown stops it with the other instances.

## Replies

### `Error` (type 64)

| Word | Name | Meaning |
| --- | --- | --- |
| 0 | `code` | the error code, 1 to 12 |
| 1 | `detail` | the detail the code defines; 0 otherwise |
| 2 | `version` | the protocol version the server speaks |

### `NodeStatus` (type 65)

| Word | Name | Meaning |
| --- | --- | --- |
| 0, 1 | `name_off`, `name_len` | the node's name |
| 2 | `kind` | 0 worker, 1 forager, 2 brood |
| 3, 4 | `state`, `detail` | the state and its detail |
| 5 | `group` | the index of the first unsatisfied dependency group, or `0xFFFFFFFF` for none |
| 6, 7 | `target_off`, `target_len` | the first unsatisfied target of that group (a name or a path, a path clipped to its first 96 bytes at a character boundary); length 0 exactly when `group` is `0xFFFFFFFF` |
| 8 | `backoff_ms` | the restart back-off remaining |
| 9, 10 | `since_lo`, `since_hi` | milliseconds in this state, low and high half; 0 for a node that is off, done or quarantined, which keeps no timestamp |
| 11 | `restarts` | restarts since the database was loaded |
| 12 | `pid` | the main process, 0 for none |

A status carries state only: never the argument vector, the environment or the credentials of a
service.

### `InstanceStatus` (type 66)

| Word | Name | Meaning |
| --- | --- | --- |
| 0, 1 | `frame_off`, `frame_len` | the forager's name |
| 2 | `id` | the instance id |
| 3 | `state` | 2 starting, 3 running, 4 exited, 5 stopping |
| 4 | `has_status` | 1 exactly when the instance exited |
| 5 | `status` | the wait status; 0 unless `has_status` |
| 6 | `pid` | the main process, 0 for none |

The exit of the last 256 instances is remembered.

### `ListPage` (type 67)

| Word | Name | Meaning |
| --- | --- | --- |
| 0 | `count` | entries in this page, at most 256 |
| 1 | `next` | the cursor of the next page, or `0xFFFFFFFF` for none |

The fixed record is followed by `count` entries of five words each, then the pool:

| Word | Name | Meaning |
| --- | --- | --- |
| 0, 1 | `name_off`, `name_len` | the node's name |
| 2 | `kind` | 0 worker, 1 forager, 2 brood |
| 3, 4 | `state`, `detail` | the state and its detail |

The strings of a list page start after the last entry.

### `Accepted` (type 68)

No record.

### `Settled`, `Pending`, `Superseded` (types 69, 70, 71)

| Word | Name | Meaning |
| --- | --- | --- |
| 0, 1 | `state`, `detail` | the state of what was awaited, and its detail |

`Settled`: the awaited state was reached. `Pending`: `wait_ms` passed first; the request stays in
effect. `Superseded`: another request changed what the wait waited for, or a refresh removed it.

### `Launched` (type 72)

| Word | Name | Meaning |
| --- | --- | --- |
| 0 | `id` | the instance id, never reused within one colony run |

A `Launched` reply carries no descriptor, or one: the pidfd a `Launch` with the `pidfd` flag asked
for. A server that cannot open it replies without; the instance runs either way. A
`LaunchFailed` reply never carries one.

### `LaunchFailed` (type 73)

| Word | Name | Meaning |
| --- | --- | --- |
| 0 | `step` | the launch step that failed, as the overseer numbers its steps |
| 1 | `errno` | the error number |

### `Exited` (type 74)

| Word | Name | Meaning |
| --- | --- | --- |
| 0 | `status` | the wait status of the instance's main process, as a signed word; -1 when its exit was not seen (the cell was emptied first, for example by a stop) |

## Examples

Every block below is one message. The first comment line gives the number of descriptors that
travel with it. The hex is the message bytes in order, in groups of four (so the header words
read as little-endian words, and the pool bytes, which are not words, are grouped the same way).
Text after `#` is a comment.

### Status
```qcp1
# fds: 0
51435031 01000000 20000000 01000000 00000000  # header: magic, version, total_len, type, fd_count
1c000000 04000000  # record
73736864  # pool: "sshd"
```
### List
```qcp1
# fds: 0
51435031 01000000 1c000000 02000000 00000000  # header: magic, version, total_len, type, fd_count
00000000 00000000  # record
```
### Change
```qcp1
# fds: 0
51435031 01000000 2c000000 03000000 00000000  # header: magic, version, total_len, type, fd_count
28000000 04000000 00000000 01000000 88130000  # record
73736864  # pool: "sshd"
```
### Launch
```qcp1
# fds: 2
51435031 01000000 56000000 04000000 02000000  # header: magic, version, total_len, type, fd_count
38000000 06000000 3e000000 0c000000 4a000000 0c000000 05000000 88130000 00000000  # record
6261636b 75702d2d 66756c6c 002f6461 74615441 52474554 3d2f6461 7461  # pool: "backup--full\0/dataTARGET=/data"
```
### Refresh
```qcp1
# fds: 1
51435031 01000000 1c000000 05000000 01000000  # header: magic, version, total_len, type, fd_count
01000000 88130000  # record
```
### Shutdown
```qcp1
# fds: 0
51435031 01000000 20000000 06000000 00000000  # header: magic, version, total_len, type, fd_count
01000000 01000000 88130000  # record
```
### Run
```qcp1
# fds: 3
51435031 01000000 3b000000 07000000 03000000  # header: magic, version, total_len, type, fd_count
38000000 03000000 06000000 01000000 00040000 08000000 01000000 64000000 60ea0000  # record
6a6f62  # pool: "job"
```
### Error
```qcp1
# fds: 0
51435031 01000000 20000000 40000000 00000000  # header: magic, version, total_len, type, fd_count
03000000 00000000 01000000  # record
```
### NodeStatus
```qcp1
# fds: 0
51435031 01000000 55000000 41000000 00000000  # header: magic, version, total_len, type, fd_count
48000000 04000000 00000000 01000000 02000000 00000000 4c000000 09000000 00000000 00000000 00000000 00000000 00000000  # record
73736864 6d6f756e 742d7661 72  # pool: "sshdmount-var"
```
### InstanceStatus
```qcp1
# fds: 0
51435031 01000000 36000000 42000000 00000000  # header: magic, version, total_len, type, fd_count
30000000 06000000 07000000 04000000 01000000 00010000 00000000  # record
6261636b 7570  # pool: "backup"
```
### ListPage
```qcp1
# fds: 0
51435031 01000000 51000000 43000000 00000000  # header: magic, version, total_len, type, fd_count
02000000 ffffffff 44000000 04000000 00000000 03000000 00000000 48000000 09000000 01000000 04000000 00000000  # record
73736864 6d6f756e 742d7661 72  # pool: "sshdmount-var"
```
### Accepted
```qcp1
# fds: 0
51435031 01000000 14000000 44000000 00000000  # header: magic, version, total_len, type, fd_count
```
### Settled
```qcp1
# fds: 0
51435031 01000000 1c000000 45000000 00000000  # header: magic, version, total_len, type, fd_count
03000000 00000000  # record
```
### Pending
```qcp1
# fds: 0
51435031 01000000 1c000000 46000000 00000000  # header: magic, version, total_len, type, fd_count
03000000 00000000  # record
```
### Superseded
```qcp1
# fds: 0
51435031 01000000 1c000000 47000000 00000000  # header: magic, version, total_len, type, fd_count
03000000 00000000  # record
```
### Launched
```qcp1
# fds: 0
51435031 01000000 18000000 48000000 00000000  # header: magic, version, total_len, type, fd_count
07000000  # record
```
The same reply with a pidfd:
```qcp1
# fds: 1
51435031 01000000 18000000 48000000 01000000  # header: magic, version, total_len, type, fd_count
07000000  # record
```
### LaunchFailed
```qcp1
# fds: 0
51435031 01000000 1c000000 49000000 00000000  # header: magic, version, total_len, type, fd_count
0b000000 0d000000  # record
```
### Exited
```qcp1
# fds: 0
51435031 01000000 18000000 4a000000 00000000  # header: magic, version, total_len, type, fd_count
00000000  # record
```
