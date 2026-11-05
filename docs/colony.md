<!--
SPDX-FileCopyrightText: 2026 Xota Tera
SPDX-License-Identifier: CC-BY-4.0
-->

# The colony program

`colony` is the service manager as a running program: it loads a compiled database
([db-format.md](db-format.md)), runs every node in a cgroup of its own through the overseer
([launch-request.md](launch-request.md)), and serves the control protocol
([control-protocol.md](control-protocol.md)) on a socket. It is one process with one event loop; it
never sleeps and never waits on a service, a logger or a client.

It is built from the crates `qinit-colonyd` (the program, this page), `qinit-colony` and
`qinit-colony-core` (the scheduler, proved), `qinit-cell` (cells), `qinit-event` (the loop),
`qinit-proto` (the server) and `qinit-overseer` (the launch executor).

Status: tested in QEMU guests on a real kernel (the VM suites `daemon`, `readiness`, `readopt`,
`logger` and `syslog`). It is not yet run under dinit or any other init on a host; queen, which
will start it as PID 1's child, is a later sub-project.

## Running it

```
colony [--db PATH] [--comb DIR] [--socket PATH] [--overseer PATH]
       [--syslog PATH] [--console PATH] [--run DIR]
```

| Flag | Default | Meaning |
|---|---|---|
| `--db` | `/etc/qinit/colony.db` | The compiled database (`qctl compile`). |
| `--comb` | `/sys/fs/cgroup/qinit` | The cgroup directory every cell is made in. |
| `--socket` | `/run/qinit/colony` | The control socket (mode 0666: authorization is the server's). |
| `--overseer` | `/usr/lib/qinit/overseer` | The launch executor. |
| `--syslog` | `/dev/log` | The datagram socket colony's own messages go to. |
| `--console` | `/dev/console` | Where those messages go when syslog is not there. |
| `--run` | `/run/qinit` | The runtime directory (mode 0755, created if absent); `state/` lives in it. |

Each flag is given at most once, as `--flag value` or `--flag=value`. There is no other
configuration: everything else is in the database. An argument it does not know is refused with a
usage line.

Colony must run **outside the comb**: its own cgroup (`/proc/self/cgroup`) may not be the comb or
below it. It becomes a subreaper, so an orphan of a service is reaped by colony and logged at
debug level.

### Start-up, in order

1. The kernel must be Linux 6.13 or later (`PIDFD_GET_INFO`).
2. Colony is not inside the comb.
3. The database is read and validated (the proved validator).
4. The run directory and `state/` are made; `state/` must be a directory of the running user's, not
   a symbolic link.
5. The comb is opened, and `+memory +pids` is written to its `cgroup.subtree_control`: a node with a
   limit does not start without the controller. The comb's parent must offer both.
6. The loop is built: signals, the one timer, the cells' own descriptor, the path watcher.
7. Logger pipes are made (below), then the graph is started or re-adopted (below).
8. The control socket is bound; a stale socket file is removed first, since the path is colony's.

A refusal is written to syslog, to the console path and to standard error, and ends colony with the
exit status that names it.

## Exit status

| Code | Meaning |
|---|---|
| 0 | The graph was shut down and the shutdown was a halt, or a stop signal. |
| 10 | The shutdown was a poweroff. |
| 11 | The shutdown was a reboot. |
| 2 | Usage: a flag it does not know, a missing value, a repeated flag. |
| 3 | The database was refused (unreadable, or rejected by the validator). |
| 4 | Start-up could not finish: kernel floor, colony inside the comb, the controllers, the state directory, the socket. |
| 5 | The loop failed while serving. The workers keep running in the comb, for the next colony to re-adopt. |

Under queen (a later sub-project) the code says what to do next; under any other parent it is only
information.

## Signals

| Signal | Effect |
|---|---|
| `SIGTERM`, `SIGINT` | The ordered shutdown, as a halt. |
| `SIGHUP` | Logged and ignored. A new database arrives through the `Refresh` request. |

A shutdown, from a signal or from the `Shutdown` request, stops the instances first, then the nodes
in reverse dependency order. Colony leaves when the graph is down **and** every cell it made is
removed (a cell the cell layer gave up on, `Failed(Stuck)`, is not waited for). It then closes its
connections, removes `state/` and the socket file and exits with the code above. A clean shutdown
leaves the comb empty.

## Cells and limits

Every node and every instance runs in a cell: a directory in the comb named after it. A node's cell
is named for the node; an instance's is `<frame>#<id>`, a `Run` instance's `~<name>#<id>`. A cell name
is 1 to 255 bytes of `[A-Za-z0-9._@:+#~-]`, not starting with `.`.

The compiler therefore refuses a node name whose part before the first `.` is `cgroup` or a cgroup
v2 controller name (`cpu cpuset io memory pids hugetlb misc rdma dmem irq`): the cell would collide
with an interface file such as `memory.max`.

A start is, in order: the launch request is built and sealed; the cell is created; `memory.max`
(the record's KiB times 1024) and `pids.max` are written, 0 meaning no limit and no write, so the
first instruction of the service already runs under them; the readiness watch is set (below); the
overseer is spawned into the cell. A failure after the cell exists removes it again and is a spawn
failure of the node. A directory of the node's name that colony did not make is somebody else's: it
is neither used nor removed, and the start fails with `EEXIST`.

The overseer is spawned with these descriptors: the sealed request at 3, the write end of a status
pipe at 4, the readiness pipe's write end at 5 when the node is ready by pipe, and then the routed
streams (a logger pipe, a caller's descriptors) from 6 up, in the order standard input, standard
output, standard error as far as present. The request's `deadline_ms` is the node's start timeout
capped at 30 s, or 30 s when it has none.

A launch that fails a step writes `(step, errno)` on the status pipe and exits 127; colony logs
`<node>: launch failed at <step>: <errno text>` at error level. End of file on the pipe is a launch
that reached its `execve`.

## Readiness

| `ready` | The node is ready when |
|---|---|
| `pipe` | the service writes a newline on its readiness pipe. |
| `exit` | the main process exits with status 0. |
| `socket = PATH` | a **socket is created at `PATH` after the start**. |
| `path = PATH` | a **path is created at `PATH` after the start**. |

For the last two, what exists at the start does not count: a stale pid file or socket from a crashed
run does not make a restarted service look ready. An event for the final component counts (a create
or a move into place), and for a socket the new file must also be a socket (a regular file where a
socket is expected is not ready). Then colony marks the cell ready and the cell reports `Ready` like
any other. The start timeout still bounds the wait: a path that never appears ends the node in
quarantine for its start timeout. The watch ends when the node is ready, exits, is stopped or is
released.

A **path edge** (a dependency on a path, not a readiness) means the path *exists*, now or later.

The compiler refuses `socket` and `path` readiness on a frame with a `launch` table: concurrent
instances would race on the one path.

Colony does not open the socket for the service (systemd, launchd and dinit's `socket-listen` do);
that is deferred, D62.

### Watching a path that may not exist

One inotify instance serves every watch. For a path, colony watches the nearest existing
directory above its last component for creates and moves into it. When the next component appears it
moves down one level; when a watched directory is removed or moved it climbs back. A watch is set
**before** the existence check it protects, so a path made between the two is seen by the check or
by the event and reported once. A symbolic link on the way is followed as `stat` follows it.

## Logger pipes

For every node that a pipe route names (a logger), colony makes one pipe when the database is
loaded or swapped in and holds both ends for as long as that node is a logger. A producer's request
routes the write end as its output or error stream (one descriptor when both name the same route),
the logger's request routes the read end as its input. Colony never reads or writes the pipe.

A producer or logger restart finds the same pipe, so nothing written while the other side was down
is lost. A refresh keeps the pipe of a logger that is still one, matched by name, and closes the
pipe of one that was removed. The compiler's implicit edge makes a producer require its logger, so a
logger that dies takes its producers down and brings them back after it.

Pipes do not survive a colony restart (below); that is D63.

## Colony's own messages

Lines `<PRI>colony[<pid>]: <text>` (RFC 3164, facility daemon) go to a datagram socket connected to
`--syslog`: node notices at info (`db: ready`, `db: failed (exit 1)`, `db: quarantined (too many
failures)`, `backup#3: exited (exit 0)`), effect errors and refusals at error, orphans at debug.
Nothing is read back, and a send never blocks.

* A **full** socket drops the line and counts it; the count is appended to the next line that goes
  through, as ` (dropped N lines)`.
* A socket that is **missing or refuses** sends the line to `--console` instead, and writes one
  marker to `/dev/kmsg` (`colony: syslog unavailable, writing to <console>`). Every later message
  tries syslog first; when it works again, a second marker (`colony: syslog back`) follows.

## What survives a colony restart

Colony keeps its own memory in `<run>/state` (mode 0700, owned by the running user), three files
of mode 0600, each written whole to a temporary file in the directory and renamed over the old
one after the change it records and before the loop waits again:

* **`cells`**, one line per cell colony made and has not removed:
  `<name> <cgroup id> <ready 0|1> <main pid> <main start time>`. The start time is field 22 of
  `/proc/<pid>/stat`.
* **`nodes`**, one line per node that is not plain off and unwanted:
  `<name> <wanted 0|1> <off|done|quarantined:<reason>> <burst_begin_ms> <burst_count> <backoff_exp>
  <last_start_ms> <ended_ms>`, the reason one of `breaker cascade start_timeout stop_failed`. The
  times are `CLOCK_MONOTONIC` milliseconds, valid across a colony restart within one boot.
* **`colony.db`**, the database colony runs, written at start and after every completed refresh, so a
  restart runs the graph its workers were started from.

A line that does not parse refuses its whole file: it is logged as an error and colony goes on as
if the file were absent.

If `cells` exists, the new colony loads `colony.db` (falling back to `--db` with the node file
ignored when it is missing or refused), then adopts each cell in this order:

1. **Look up.** A line naming an instance, or a node the database no longer has, is a cell to
   clear: it is adopted without a main, stopped as a cell and removed. Instance ids continue past
   the highest id seen.
2. **Recover the main first.** A pidfd is opened for the recorded pid and **three** things are
   checked: that the process's start time and its cgroup id (`PIDFD_GET_INFO`) are the recorded
   ones. A pid alone never names a process. Only then is the cell adopted, with that pidfd, or
   without a main if a check failed. A cell whose directory is gone or whose cgroup id differs was
   made by somebody else: it is logged as an error and left alone, and only its table slot is given
   back.
3. **Decide.** A cell that was ready with its main recovered is adopted ready. A cell that was
   ready whose main did not come back is adopted, and its exit is reported as a failure of unknown
   status. A cell not ready whose node is `ready = exit`, main recovered, runs on and is adopted
   starting (its start timeout runs again from now). Any other cell not ready is stopped and
   started again. A **logger and every node with a pipe route** is stopped and started again,
   after the new pipes exist.
4. **Restore.** The `nodes` lines and the adopted cells become the node table. The scheduler's
   invariant is checked first; a table that breaks it is refused whole (logged as an error) and only
   the cells are adopted.

A node the administrator stopped stays stopped; a quarantined node stays quarantined; a finished
one-shot is not run again; a crash-looping worker's failure count carries over, so its breaker
counts failures from before and after the restart. A cell directory in the comb that no line names
is logged and left alone.

Lost across a restart: the readiness pipes (their nodes are restarted), the logger pipes (D63),
the exit status of a re-adopted main (D65), the parked waits and watchers (their connections
closed with the old colony), the instance exit ring, and the instances themselves, which are
transient and are cleared. Under queen the `/run` files give way to queen's fd store (D64).

## Tests

`cargo test -p qinit-colonyd` runs the host tests without root: the argument parser, the deadline
queue, the path watcher over real inotify, the state files, the syslog writer, the effects and the
loop over a fake cell layer, and re-adoption over a fake process table. `cargo run -p qinit-vm --
run daemon readiness readopt logger syslog` runs the real program in QEMU guests, with the guest's
own helper programs as services.
