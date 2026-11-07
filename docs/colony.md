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
`logger` and `syslog`). [Queen](queen.md), the PID 1 that starts it, holds its state across a
restart and is tested with it in the suites `queen` and `readopt`. It is not yet run under dinit or
any other init on a host.

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
| `--run` | `/run/qinit` | The runtime directory (mode 0755, created if absent): the socket's parent. |
| `--queen-fd` | none | The descriptor number of queen's channel, given when queen starts colony. Colony sends queen an `Alive` record every 2 s, which queen's [heartbeat](queen.md#the-heartbeat) watches. |

Each flag is given at most once, as `--flag value` or `--flag=value`. There is no other
configuration: everything else is in the database. An argument it does not know is refused with a
usage line.

Colony must run **outside the comb**: its own cgroup (`/proc/self/cgroup`) may not be the comb or
below it. It becomes a subreaper, so an orphan of a service is reaped by colony and logged at
debug level.

### Start-up, in order

1. The kernel must be Linux 6.15 or later (`PIDFD_INFO_EXIT`).
2. Colony is not inside the comb.
3. Colony raises its own `RLIMIT_NOFILE` to 65536, soft and hard (it lowers neither), so it can hold
   its cells, pipes and status descriptors and take back all that queen's store holds for it. The
   services start with the limit colony started with; a frame's own `nofile` is set in the
   overseer. A colony that may not raise it (not root, with a lower hard limit) logs one error and
   goes on with the limit it has, which its services then get too.
4. With `--queen-fd`, queen's hand-over is read (each wait bounded by 10 s).
5. The database is chosen and validated (the proved validator): the copy queen held, if it loads,
   replaces `--db`; exit 3 is for when there is neither. The run directory is made.
6. The comb is opened, and `+memory +pids` is written to its `cgroup.subtree_control`: a node with a
   limit does not start without the controller. The comb's parent must offer both.
7. The loop is built: signals, the one timer, the cells' own descriptor, the path watcher.
8. The control socket is bound; a stale socket file is removed first, since the path is colony's.
   A client that connects before the graph is up waits in the socket's backlog.
9. Logger pipes are made (below), then the graph is started or re-adopted (below).

If the control socket cannot accept (out of descriptors), colony logs one error, takes the listener
out of the loop for 100 ms and tries again, rather than spinning. A path or readiness watch the
kernel refuses to move (for instance at the inotify watch limit) is logged as an error, naming the
node; a readiness watch lost that way ends in the node's start timeout.

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
| 4 | Start-up could not finish: kernel floor, colony inside the comb, the controllers, queen's hand-over, the socket. |
| 5 | The loop failed while serving. The workers keep running in the comb, for the next colony to re-adopt. |

Under [queen](queen.md) the code says what to do next: 0, 10 and 11 end in zero, 2 and 3 go to
rescue at once, anything else is counted and colony is restarted. Under any other parent it is only
information.

## Signals

| Signal | Effect |
|---|---|
| `SIGTERM`, `SIGINT` | The ordered shutdown, as a halt. |
| `SIGHUP` | Logged and ignored. A new database arrives through the `Refresh` request. |

A shutdown, from a signal or from the `Shutdown` request, stops the instances first, then the nodes
in reverse dependency order. Colony leaves when the graph is down **and** every cell it made is
removed (a cell the cell layer gave up on, `Failed(Stuck)`, is not waited for). It then closes its
connections, tells queen to forget what it held, removes the socket file and exits with the code
above. A clean shutdown leaves the comb empty. Colony tells queen the shutdown has begun, and in
which mode, before it stops anything; a request from queen (Ctrl-Alt-Del, `SIGPWR`) starts it too,
and the last request's mode wins.

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

Colony's memory is in [queen's store](queen.md): colony *puts* a descriptor under a key it
allocates, saves text that names the keys, and forgets a key once no saved text names it. It puts
before it saves and forgets after, so a state never names a key queen does not hold.

Every reply waits for the state it reports. A wake-up's replies, a request's own included
(`Launched`, `Accepted`, a wait already met), are sent after the state is saved: a client that has
its answer can kill colony, and the next colony knows what the request did. A save that waits more
than a second for a queen that does not read is dropped, logged and tried again at the next
wake-up; the replies do not wait for it, so colony keeps answering under a parked queen.

* **Descriptors:** each cell's directory, each main's pidfd and both ends of each logger pipe.
* **`cells`** (key 1), one line per cell colony made and has not removed:
  `<name> <cgroup id> <ready 0|1> <dir key> <main key>`; the main key is 0 for none.
* **`nodes`** (key 2), one line per node that is not plain off and unwanted:
  `<name> <wanted 0|1> <off|done|quarantined:<reason>> <burst_begin_ms> <burst_count> <backoff_exp>
  <last_start_ms> <ended_ms>`, the reason one of `breaker cascade start_timeout stop_failed`, and
  one `pipe <logger> <read key> <write key>` line per logger pipe. The times are
  `CLOCK_MONOTONIC` milliseconds, valid across a colony restart within one boot.
* **`colony.db`** (key 3), the database colony runs, saved at start and after every completed
  refresh. A copy that loads wins over `--db`, so a database broken on disk after a bad compile does
  not stop a restart.

A line that does not parse refuses its whole entry: it is logged as an error and colony goes on as
if the entry were absent. A clean shutdown forgets every key.

If `cells` is there, the new colony adopts each cell in this order:

1. **Look up.** A line naming an instance, or a node the database no longer has, is a cell to
   clear: it is adopted without a main, stopped as a cell and removed. Instance ids continue past
   the highest id seen. A line whose directory key queen no longer holds is dropped and logged.
2. **The main, by its pidfd.** Nothing is recovered by pid. The main's pidfd says whether the
   process runs (and its cgroup id must be the recorded one), has exited (its wait status is read
   from the pidfd, `PIDFD_INFO_EXIT`) or is gone. A cell is adopted with its directory as queen held
   it, and with the main only if it runs. A cell whose cgroup id differs from the recorded one was
   made by somebody else: logged as an error and left alone, and only its table slot is given back.
3. **Decide.** A cell that was ready with its main running is adopted ready. A cell that was ready
   whose main exited is adopted and the exit is reported with its status (`Failed(None)` only when
   the status is unknown). A cell not ready whose node is `ready = exit` and whose main runs on is
   adopted starting; if the main finished, it is not started again. Any other cell not ready is
   stopped and started again. A **logger and every node with a pipe route** is stopped and started
   again only if its pipe was not held.
4. **Restore.** The `nodes` lines and the adopted cells become the node table. The scheduler's
   invariant is checked first; a table that breaks it is refused whole (logged as an error) and only
   the cells are adopted.
5. **Statuses.** A main that exited while colony was away and is not yet reaped is waited for: queen
   tells colony when it reaped, and colony delivers the status; after a second it gives up and
   reports an unknown one.

A node the administrator stopped stays stopped; a quarantined node stays quarantined; a finished
one-shot is not run again; a crash-looping worker's failure count carries over. A held key no state
names is forgotten.

**Without queen** (no `--queen-fd`) nothing is held: colony writes nothing, re-adopts nothing and
logs a line for each directory it finds in the comb (D71). A name that collides with one makes that
node's create fail.

Lost across a restart: the readiness pipes (their nodes are restarted), the parked waits and
watchers (their connections closed with the old colony), the instance exit ring, and the instances
themselves, which are transient and are cleared.

## Tests

`cargo test -p qinit-colonyd` runs the host tests without root: the argument parser, the deadline
queue, the path watcher over real inotify, the state text, the store client against a fake queen, the syslog writer, the effects and the
loop over a fake cell layer, and re-adoption over fake descriptors. `cargo run -p qinit-vm --
run daemon readiness logger syslog` runs the real program in QEMU guests, and `queen readopt` under queen, with the guest's
own helper programs as services.
