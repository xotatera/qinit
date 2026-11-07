<!--
SPDX-FileCopyrightText: 2026 Xota Tera
SPDX-License-Identifier: CC-BY-4.0
-->

# Queen

`queen` is the PID 1 of qinit. It is small on purpose and its decisions are proved: it starts
[colony](colony.md), restarts it under a limit, holds what must outlive it, runs a rescue program
when colony cannot be kept up, and hands the machine to zero at the end. The state machine is
`qinit-queen-core` (Verus: `proof:qinit-queen-core`); `qinit-queen` is the thin shell that turns
epoll wake-ups into inputs and the machine's actions into calls. It links with no
dependency beyond libc, and the guest images build it static (musl). It logs to `/dev/kmsg`, and
to the console when that does not open; a log write never blocks.

Queen does not mount anything, supervise services, read a database or speak the control protocol.
It assumes what zero makes before it starts: `/proc`, `/sys`, the cgroup2 mount, `/dev` and `/run`.

## Start

In this order, before anything that can fail: every signal but the five fault signals is blocked
and a handler for those, on an alternate stack, parks (see below); a process that is not PID 1
prints a line and exits 2; Ctrl-Alt-Del is switched off, so it arrives as `SIGINT`; the working
directory is `/` (queen pins no mount); the log is opened (`/dev/kmsg`, else `/dev/console`, else
`/dev/null`, each on a description of its own, non-blocking, so a console stopped by flow control
costs a line and not PID 1); `RLIMIT_NOFILE` is raised to 65536
so queen can hold the whole store (colony, rescue and zero are started with the limit queen
itself started with, so services do not inherit the raised one); the kernel command line is read
for the two [settings](#settings); the signalfd, timerfd and epoll instance are made; colony is
started. A failure from the Ctrl-Alt-Del step on logs what failed and parks.

## Children and colony's exit

Queen has at most one colony and one rescue program. Every wake-up on `SIGCHLD` drains
`waitpid(-1, WNOHANG)`, so coalesced signals lose nothing; a pid that is neither is an orphan,
counted and logged as one line a minute: the first drain at once, and then the next one after a
minute, which carries the count of every orphan since the last line. Colony runs as `/usr/lib/qinit/colony --queen-fd 3`
with the console on 0, 1 and 2, in a session of its own.

| Colony's exit | Before a shutdown | During a shutdown |
|---|---|---|
| 0, 10, 11 | Zero, as halt, poweroff or reboot | The same: the code decides |
| 2, 3 | Rescue at once | Zero with the recorded mode |
| anything else, a signal, a failed spawn | Counted; restart at once, or rescue if the limit trips | Zero with the recorded mode |

**The limit.** The times of the last five counted exits are kept. The sixth exit trips the limit
when the oldest of the five is under 60 s old. Restarts have no delay. Clearing the limit empties
the list.

## Rescue and hold

Rescue is `/etc/qinit/rescue`, run with the console as its controlling terminal in a session of
its own. Queen keeps running, reaping and holding the store. When rescue exits 0 after at least
10 s the limit is cleared and colony is started again. Anything else leaves the **hold**: the
program is missing, cannot start, exits non-zero, is killed or ran under 10 s. Queen logs and stays
in its loop, reaping.

| Input | Rescue | Hold |
|---|---|---|
| Ctrl-Alt-Del (`SIGINT`) | Logged | Clear the limit, start colony (unless a shutdown began) |
| `SIGPWR` | Zero, as poweroff | Zero, as poweroff |

## Shutdown

A shutdown starts when colony announces one (`Shutdown{mode}`, before it stops anything) or queen
asks for one (`Request{mode}`: `SIGINT` asks for a reboot, `SIGPWR` for a poweroff). Queen records
the mode, switches Ctrl-Alt-Del on (the machine can then be forced down) and arms a 5-minute timer.
A later `Shutdown` changes the mode and leaves the timer. If the timer fires, colony is killed and a
5-second timer armed; colony's reap or that timer leads to zero with the recorded mode. Colony's
exit code beats the recorded mode. Zero is `/usr/lib/qinit/zero final <halt|poweroff|reboot>`; a
failed exec is logged and runs rescue, then the hold. Queen never calls `reboot(2)` to halt, power
off or restart. Every other signal, the real-time ones (up to 64) included, is logged (once a minute
each) and ignored: queen reads every signal it can catch and leaves none pending.

## Parking

A panic or a fault (`SIGSEGV`, `SIGBUS`, `SIGILL`, `SIGFPE`, `SIGABRT`, including a stack overflow)
writes one kernel-log line and sleeps for good with every signal blocked. Nothing in queen calls
`exit` once it is PID 1, so a bug cannot reach the kernel as a panic. A parked queen reaps nothing;
colony, a process of its own, serves on (D69).

## The channel and the store

Queen holds a fixed table of key and descriptor (capacity 16 899: two per cell, two per logger pipe
and three fixed keys). Each colony gets a new `SOCK_SEQPACKET` pair; colony's end is descriptor 3.
Records are 16 bytes, little-endian: `u32` kind, `u32` arg, `u64` key. A decoder accepts only a whole
record from the right side with unused words zero, a known mode and the descriptor count its kind
needs.

| Direction | Record | Meaning |
|---|---|---|
| colony → queen | `Put{key}` + fd (1) | Hold it, replacing any entry under the key |
| colony → queen | `Drop{key}` (2) | Close and forget it |
| colony → queen | `Shutdown{mode}` (3) | A shutdown began; mode 0 halt, 1 poweroff, 2 reboot |
| colony → queen | `Alive` (4) | Colony's loop is turning; sent every 2 s |
| queen → colony | `Held{key}` + fd (65) | One per entry, sent at the start |
| queen → colony | `HeldEnd{count}` (66) | The hand-over is complete |
| queen → colony | `Reaped` (67) | Queen reaped an orphan (neither colony nor rescue): a status colony waits for may be readable now |
| queen → colony | `Request{mode}` (68) | Start this shutdown |
| queen → colony | `Refused{key}` (69) | The store is full; the descriptor was closed |

Queen never blocks on colony: it sends with `MSG_DONTWAIT` and waits for the socket to be writable;
a send that fails for good drops the channel. A turn reads at most 128 records from the channel (a
colony that floods it does not hold the signals, the reap and the timer back: the rest waits in the
socket, which keeps epoll awake), except that the records a dying colony queued are all read
before the reap restarts it. A `Put` scans the table, which costs under 12 µs in a full one
(measured), so a turn's 128 take about a millisecond at worst. A record that does not decode kills
colony and closes the channel: nothing queued behind it is read. Every held descriptor
is close-on-exec, so a successful exec of zero drops the store and a failed one keeps it.

Colony keeps three fixed keys: 1 the cell table, 2 the node state and the logger pipes, 3 the
database it runs. Everything else is a cell's directory, a main's pidfd or a pipe end, under keys
colony allocates from 16. When the machine leaves rescue (a clean exit) or the hold (Ctrl-Alt-Del),
queen drops key 3 first: the administrator has had the machine, and the new colony reads the
database file they repaired and not the copy that was in force when colony failed. The cells and
the nodes stay, and are adopted. Colony puts a descriptor before it saves the state that names it and
forgets a key after it saved the state that stopped naming it. See [colony.md](colony.md) for what
survives a restart.

## The heartbeat

A colony that is alive but no longer serving (a stuck loop) is noticed by a heartbeat. Colony
sends `Alive` from its loop every 2 s. While colony runs, queen's timer measures periods of
`qinit.heartbeat_ms` (30 s): at the end of a period in which no `Alive` arrived, queen logs
`colony is silent, killing it` and kills colony, which is then reaped and counted like any other
crash (restart, or rescue past the limit). A period with a beat starts the next. A new colony
starts a new period, so one that is slow to start has a whole period. The watch is off during a
shutdown (the shutdown bound covers it), in rescue and in the hold. A timer read in the turn that
restarted colony, before the new period is over, is ignored. A colony that is silent is killed
between one and two periods after it last spoke.

## Settings

The kernel command line (`/proc/cmdline`) holds queen's only two settings; the last of a
setting wins, and a value that is not allowed is logged (`ignoring ...`) and the default kept.

| Setting | Default | Allowed | Meaning |
|---|---|---|---|
| `qinit.shutdown_ms` | 300000 | 1 to 86400000 | How long colony has to end a shutdown before it is killed |
| `qinit.heartbeat_ms` | 30000 | 0, or 8000 to 86400000 | The heartbeat period; 0 turns the watch off |

A day is the ceiling because a timer holds no more; 8 s is the floor because colony beats every
2 s and four beats should fit in a period.

## Paths and limits

| Path | What |
|---|---|
| `/usr/lib/qinit/colony` | colony |
| `/usr/lib/qinit/zero` | zero |
| `/etc/qinit/rescue` | the rescue program |

Queen's other bounds are constants: five exits in 60 s, 10 s for rescue, 5 s after the kill of a
shutdown. Queen raises its own `RLIMIT_NOFILE` and gives colony, rescue and zero the limit it
started with (a failed exec of zero raises it again). Colony raises its own again before it reads
the hand-over, and gives its services the limit queen started with.

## Tests

`cargo test -p qinit-queen-core` runs the unit and property tests; `cargo xtask proofs --only
proof:qinit-queen-core` proves the decoder, the store and the machine. `cargo run -p qinit-vm --
run queen queen_panic queen_fault readopt` runs queen as a real PID 1 in QEMU, with a stand-in
for zero that logs its command line and starts queen over. The guests build queen with its
`testing` feature, which reads the bounds from `/run/queen-test` and lets `SIGUSR1` panic and
`SIGUSR2` fault. The guests boot with `qinit.heartbeat_ms=8000`, so the heartbeat is the real one
on a shorter period.
