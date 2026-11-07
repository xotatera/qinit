<!--
SPDX-FileCopyrightText: 2026 Xota Tera
SPDX-License-Identifier: CC-BY-4.0
-->

# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Words for the two defaults that had none (D58): `start_timeout = "none"` (no start timeout, on
  any node) and `sandbox.user_map = "own"` without a user namespace (`"range"` still needs one).
  Each compiles to the database its default gives, so `qctl show` prints them as keys, not
  comments, and `qctl fill` writes them.

- Queen's settings and heartbeat (D68, D70, D72), `docs/queen.md`: `qinit.shutdown_ms=` and
  `qinit.heartbeat_ms=` on the kernel command line set the shutdown bound (default 5 min) and the
  heartbeat period (default 30 s, 0 for none). Colony sends `Alive` every 2 s; queen kills a
  colony that sent nothing for a whole period, so a stuck loop is restarted like a crash. The
  proof (`proof:qinit-queen-core`) states that a silent period kills and a spoken one does not.

- Sub-project 8, queen (D8, D63, D64, D65), `docs/queen.md`: `queen` (`qinit-queen`, with the proved
  core `qinit-queen-core`) is the PID 1. It starts colony, restarts it under a limit of five exits
  in 60 s, holds colony's descriptors and state in a fixed store across a restart, runs
  `/etc/qinit/rescue` (then holds) when colony cannot be kept up, takes Ctrl-Alt-Del and `SIGPWR`
  as requests for an ordered shutdown, hands the machine to zero with the mode colony announced,
  reaps every orphan, and parks on a panic or fault instead of exiting. Colony's channel is
  `--queen-fd`. Leaving rescue or the hold, queen drops the database copy it held, so the next
  colony reads the file the administrator repaired. Four VM suites run it as a real PID 1: `queen`,
  `queen_panic`, `queen_fault` and `readopt`.

- Sub-project 7, the colony daemon (D27, D29, D31), `docs/colony.md`: `colony` (`qinit-colonyd`,
  GPL-3.0-or-later) loads a compiled database and runs every node and instance in a real cgroup
  through the overseer, in one `qinit-event` loop with a userspace deadline queue behind one timer.
  It writes `memory.max` and `pids.max` before the first instruction of a service (D31); watches
  paths with one inotify instance that walks down and back up the tree (D27); marks `ready = {
  socket }` and `ready = { path }` nodes ready when the socket or path is *created after the
  start*; holds the logger pipes across producer and logger restarts; writes its own messages to
  syslog (RFC 3164, never blocking, falling back to the console with a kernel-log marker); and
  after a restart re-adopts the comb from `<run>/state`, recovering each main by pid, start time
  and cgroup id and checking the node table against the core's invariant first (D29). Exit status
  0, 10 or 11 for a halt, poweroff or reboot, 2 to 5 for a refusal. Five VM suites run it on a real
  kernel: `daemon`, `readiness`, `readopt`, `logger` and `syslog`.
  - The cell machine has `ReadyMode::External` and `Request::MarkReady` (proved); the cell table
    holds 4352 cells and a cell name is 1 to 255 bytes of `[A-Za-z0-9._@:+#~-]` (the proof is
    re-run); `Cells` gains `set_limits`, `mark_ready`, `signal_main`, `main_pidfd`, `poll_fd` and
    `poll`. The event loop gains a shared inotify set, a re-armable timer and a non-blocking
    `poll`.
  - The colony core gains `restore` (a saved table without re-enabling the enabled list, so a
    stopped node stays stopped) and `inv_ok`, an executable `inv_all` proved equal to the spec. The
    runtime gains `Colony::restore`, `validate_restore`, `db`, `saved`, `seed_instance_ids` and
    `adopted_exit`.
  - The compiler refuses a node name whose first dotted part is `cgroup` or a controller name, and
    `socket` or `path` readiness on a frame with a `launch` table.
- Group 3, the notice stream (D37): `Watch` (control protocol type 8, any user) on a node, an
  instance `<frame>#<id>` or everything turns the connection into a stream of `Notice` replies
  (type 75: node, instance, database swapped, shutdown complete, each with its state, a report
  word and a status). A targeted watch starts with the current state; a refresh that removes the
  node ends it with `Superseded`; a watcher that does not read is closed and the server goes on.
  The proved decoder and `authorized` cover both records. The client gets `Client::watch`,
  `Scope`, `Event` and `Watcher::next` with a timeout; `docs/control-protocol.md` documents both
  with examples.
- Group 4, the C interface (D41): `qinit-client-c` (MPL-2.0) builds `libqinit_client_c` as a
  static archive and a shared object with the cbindgen-generated `include/qinit_client.h`, whose
  drift a test checks. Status, list, change, refresh, shutdown, launch, run (QLR1 bytes) and the
  notice stream; errors are an `int` kind plus `qinit_last_error`. A C smoke program is compiled
  against the header and linked into the crate's tests; `crates/qinit-client-c/README.md` is the
  C user's page.
- Group 5, `qctl` (D16, D26, D42), `docs/qctl.md`: `compile` (the database byte for byte the
  library's), `show` (a frame or the policy as effective TOML with each key's origin), `fill`
  (the implicit defaults written into the `etc` layer, the other bytes kept, the database
  unchanged), the control commands (`status`, `list`, `start`/`stop`/`restart`/`clear` with
  `--wait`, `refresh`, `poweroff`/`reboot`/`halt`), `launch`, `run` from a TOML request file, and
  `watch`. Run as root, `compile` and `show` refuse a policy or layer path, or an ancestor
  directory, that is a symbolic link, not root's or writable by group or other (D26); as root,
  `compile` also refuses such an output directory, and `fill` such a directory to create the
  `etc` layer in. `compile` writes through an exclusively created temporary file, and `fill`
  writes every file's temporary file before it renames any (D60).
- Group 2b, the view and the instance, hardened and finished (D43 to D49):
  - The view is built on `/run/qinit/view` from detached mount clones (`open_tree`,
    `mount_setattr`, `move_mount`), so a read-only host root works and nothing is left behind
    (D49); an entry below a writable one is opened without symlinks (`ELOOP`, D48).
  - Six path-entry modes: `ro:` `rw:` `ri:` `wi:` `rs:` `ws:`. `ri:`/`wi:` are idmapped through a
    helper user namespace with the service's maps and need the `user` namespace (D43); `rs:`/`ws:`
    follow the host's later mounts (D47). The proved path rules, the decoder and the plan change
    by a mode set; the plan has one new step, `IdmapNamespace`.
  - Inside ids (D44): `sandbox.inside_uid`/`inside_gid`, the credential record grows to 15 words,
    the launch request to 69 and a policy rule to 45 (`allow_inside_ids`, denial code 9;
    `allow_idmap`, denial code 10: an idmapped entry needs a rule that allows it).
  - `qinit_client::pidfd_exit` reads a launch's exit status from its pidfd on Linux 6.15 and later
    (D45).
  - `Run` flag bit 1 `wait_ready`: the second reply is `Settled` when the service writes its
    readiness byte (D46); the client gets `RunArgs::wait_ready` and `LaunchOutcome::Ready`.
  - `qinit-sys` gains `open_tree`, `mount_setattr` on a descriptor, `move_mount`, `open_path` and
    `open_beneath`; `bind_rec` and `setattr_rec` are gone.
- Group 2, sandbox and launch (D32, D33, D38, D39):
  - The path view: a credential or request with `sandbox.paths` runs in an empty `tmpfs` root with
    a fixed `/dev` and a private `/tmp`, a recursive bind of each listed path, a `pivot_root` and a
    read-only seal, then Landlock on the same paths. One proved plan step per phase.
  - User namespaces: the `user` namespace bit with `user_map` `own` or `range` (a forked map writer
    writes `/etc/subuid` and `/etc/subgid` ranges), refused for `root`.
  - The credential policy compiled into the database (`T_POLICY`, `T_POLICY_HEAD`; a rule's
    `allow_userns`) and the proved `check_policy`, which the frames compiler's check must agree
    with.
  - `Run` (control protocol type 7, root only): launches a whole launch request from a sealed
    memfd as the instance `~<name>#<id>`, checked against the policy. `docs/launch-request.md`
    specifies the format; its examples are decoded and re-encoded by a test.
  - `Launch` and `Run` take a `pidfd` flag and hand the instance's pidfd back in the reply;
    `MAX_FDS` is 4.
  - `qinit-sys` gains `mount_setattr`, `pivot_root`, recursive binds, `lstat`/`readlink`/`symlink`
    helpers, sealed memfds and absolute `CLOCK_MONOTONIC` alarms; the QLR1 layout moves to
    `qinit_proto_core::launch` and its encoder to the new `qinit-launch` crate (both MPL-2.0).
- Every kernel resource limit but `core` is a frame key under `rlimits` (`cpu fsize data stack rss
  nproc nofile memlock as locks sigpending msgqueue nice rtprio rttime`): a number, `"infinity"`
  or, for the byte limits, a size such as `"64M"`. The policy bounds them at the kernel's boot hard
  limits; a rule or the top level raises a ceiling with `rlimits_max`. `rlimits.nofile =
  "infinity"` is now refused (0 already was).
- Validator: `DbError::Pool { table, record }` and `DbError::Utf8 { offset }` carry their position.

- The control protocol (sub-project 6), `docs/control-protocol.md`: one `SOCK_SEQPACKET` socket,
  peer identity from `SO_PEERCRED` and `SO_PEERPIDFD`, status and list for every user and
  change, forager launch, refresh and shutdown for root, with settled waits that always end.
  - `qinit-proto-core` (MPL-2.0): the QCP1 message format with a Verus-proved total decoder, an
    encoder that only returns messages the decoder accepts, and the one `authorized` function.
  - `qinit-wire` (MPL-2.0): messages as borrowed values, and the encoder over them.
  - `qinit-ipc` (MPL-2.0): seqpacket sockets, `SCM_RIGHTS`, peer credentials and pidfd.
  - `qinit-client` (MPL-2.0): a blocking Rust client, one method per operation.
  - `qinit-proto`: the server (connections, limits, framing, dispatch into colony) and a small
    event-loop driver for tests.
  - Colony: `restart_on = "refresh"` edges with the SMF meaning and the reload signal
    (`Request::Refresh`), forager instance slots (a proved pool) and launches, the two-phase
    database swap (the proved `remap`), `Colony::handle`, settled waits, shutdown mode and status
    queries, and the VM suite `control` with root and a user other than root.
  - Frames: the `reload` key (workers only; a forager or brood refuses it) and the forager `[launch]` table (`concurrency`, `argv_tail`,
    `env`, `fds`); the node record of the database grows to 36 words.
  - The overseer launch request has a stdin route (the record grows to 35 words).
- `docs/design-principles.md`: the rules that decide whether a feature belongs in qinit and
  which part owns it, with a tie-break order and the patterns qinit does not use.
- `qinit-graph-core`: the dependency graph model, Verus-proved: cycle detection
  (a graph is reported cyclic exactly when it has a cycle) and level assignment
  in which every hard edge strictly orders its two ends, so a stop order exists
  whatever the opt-outs. Limits of 4096 nodes and 32768 edges.
- `qinit-db-core`: the compiled database layout (header, eight tables, limits,
  record word indices; `docs/db-format.md`) and a total, Verus-proved validator
  (V1-V9): bounds and tiling, UTF-8 pool references, non-empty NUL-separated
  argv and Landlock lists, enums and reserved bits, acyclic ordering edges,
  stop order, no parallel stop on a hard edge, sorted lists and a closed
  enabled set. An accepted database cannot make a reader accessor go out of bounds.
- `qinit-db`: the database runtime: `Model`, a deterministic writer (CRC-32,
  refuses models that cannot round-trip) and `open`, which checks length, CRC
  and the proved validator before `Reader::decode` returns the model.
- `qinit-frames`: the frames compiler library: strict TOML schema, units and
  amend-layer merge, template and instance expansion, reference resolution,
  credential policy ceilings (policy file with ordered rules), graph passes, a
  compile pipeline with a self-check (write, open, decode, compare) and a
  provenance dump, with golden, negative and fuzz tests. Provenance is kept
  per frame key with its layer and file; the dump marks each value with the
  layer that set it, `template <name>` or `default`. Errors carry codes, keys
  and, wherever the key belongs to a frame, its file and layer, and display as
  `<file>: <key> [<layer>]: <code>: <detail>`; policy shape errors name their
  rule and field. Least privilege by default: a worker without `credentials`,
  or with only a `sandbox` table, is unprivileged by contract (no root, no
  capabilities, no-new-privileges on) and needs no policy rule.
- `qinit-colony-core`: the node machine and the scheduler, Verus-proved over the compiled
  database read in place. Group evaluation (`require_all`, `require_any`, `optional_all`,
  `exclude_all` over sync and async edges), parallel starts, the restart breaker (more than `max`
  failures in `window` quarantine a node) with doubling back-off, start timeouts, hard-dependency
  stop order (a finished one-shot no longer excludes a dependent), `restart_on` propagation, per-edge quarantine cascade, foragers, and an ordered
  shutdown of the whole graph. Proved: a start needs satisfied groups and an elapsed back-off, a
  stop waits for every dependent that is going away, nothing starts or arms a timer once shut
  down, the breaker trips exactly past `max`, a forager is never quarantined or restarted, and
  one input leaves at most seven pending actions per node.
- `qinit-colony`: the runtime around the core: an `Effects` trait, the engine that feeds the core
  one input at a time and turns failed effects into events, a scripted simulation with virtual
  time, status text, scenario tests and a property test over random graphs.
- `qinit-overseer-core`: the launch request format with a total, Verus-proved decoder; the launch
  plan (request to ordered steps), proved well ordered (credential steps in the one order that
  works, bounding set before `setresuid`, sandbox last before exec) and complete and faithful
  to the request; and the seccomp program generator, proved against a bounded interpreter
  (wrong architecture killed, listed numbers answered `EPERM` or allowed, namespace flags of
  `clone`/`unshare` and `setns`/`clone3` handled in the default and deny modes).
- `qinit-overseer`: the `overseer` executor binary and its library: strict identity from
  `/etc/passwd` and `/etc/group` (no NSS), output routes by file type, the step runner over the
  proved plan with `(step, errno)` failure records, the pid-namespace supervisors and the request
  builder from the database model.
- `qinit-sys`: credential, namespace, Landlock, seccomp, rlimit, timer, sealed memfd, socket and
  descriptor primitives, and exec by descriptor.
- Guest kernel options for namespaces, seccomp and Landlock, the executor in the VM initrd, and
  five suites: `launch`, `sandbox`, `output`, `deadline` and `fail`.

- Workspace pins for `serde` and `toml`.
- Guest suites for cells: spawn (placement, exec failure, only routed
  descriptors), ready (pipe, EOF, exit), stop_main, stop_cell (setsid
  escapee, member dying mid-enumeration), escalate, reuse_guard, adopt (with a
  handed-over main process), orphan; `Cells::main_pid`. Verdicts require the
  declared number of distinct passing cases; missing, duplicate and malformed
  verdicts fail. Reuse-guard evidence includes the moved process's SIGKILL status.
- `qinit-cell`: the cell runtime (`Cells`): create, spawn into the cell,
  readiness, polite stop by main pidfd or freeze-signal-thaw with pidfds
  verified by cgroup id, escalation, adoption, removal (a failed adoption whose
  cgroup id did not match releases only its slot and never touches the
  directory), orphan reaping as a subreaper; refuses kernels below 6.13. Failed
  stop effects escalate immediately, failed kills report `Failed(Kill)`, and
  batches retain all events despite errors. Unknown adopted-main statuses are
  `None`; exec-error pipes are nonblocking and reap errors surface on the next wait.
- `qinit-cell-drive`: loop tokens and slot choice for the cell table, Verus-proved
  (each token routes to one cell and source; a full table refuses new cells).
- `qinit-cell-core`: the cell machine (create, spawn into the cell, readiness by
  pipe or exit, polite stop by main pidfd or freeze-signal-thaw, escalation to
  `cgroup.kill`, adoption, removal). Verus proves for every step: the grace
  deadline while stopping kills; a freeze is held until a thaw is emitted; the
  main process is signalled only through its live handle, which stops being
  live once its exit is observed; Empty is entered only with no live main
  process and no spawn outstanding, and only when the cell reads empty: a
  directory the machine just created counts as empty, a spawn marks the cell
  populated, adoption takes the `cgroup.events` reading, and only a reading
  clears `populated`; nothing reaches processes once the cell was empty; every
  non-terminal state has an armed deadline or an awaited event (the effect
  issued on entry, the caller's request after a report, the main process's
  exit or a level change); the kill deadline ends in Failed; a left deadline
  is cancelled. Effect-failure escalation and foreign-directory removal safety
  are proved, as are the token range bound and routing inverse.
- The `vm` gate: guest suites in QEMU on the pinned kernel, after the proof
  tier; the `probe` suite checks how `cgroup.events` notifies, placement by
  `CLONE_INTO_CGROUP`, cgroup ids, freeze and `cgroup.kill`.
- `qinit-vm`: builds the pinned guest kernel (Linux 6.18.59, checksum-verified,
  cached), writes newc initrds, builds static guest programs, boots QEMU with KVM
  or TCG and reads guest verdicts.
- `qinit-sys` spawns with `clone3` (into a cgroup, with a pidfd; only routed
  descriptors arrive; exec failures reported through an error pipe), cgroup
  operations through directory descriptors, `PIDFD_GET_INFO` cgroup ids, guest
  mounts and power-off from a child.
- `qinit-event`: the epoll loop (fds, priority notifications, pidfd exits,
  deadlines, signals, inotify) over the Verus-proved `qinit-event-core`; the
  root no-std gate runs.
- `qinit-sys`: the unsafe shim (descriptors, epoll, timers, signals, pidfd
  reaping), the first product crate; the repository stage's fmt, lint, layers
  and test gates now run.
- Repository disciplines bootstrap with a Rust/Verus-compatible pinned
  toolchain, virtual Cargo workspace, xtask alias, policy ledgers, and scan
  configuration.
- Disciplines gate runner (`cargo xtask gate`, `cargo xtask proofs`) with a
  repository stage (preflight, canary, REUSE, scans, duplication) and a
  tooling stage, accepted blockers recorded in `DEFERRED.md`, and pinned
  Verus and verusfmt releases checked once a Verus proof is declared.
- Review canary gate: fails in the main context while `README.md` still starts
  with the review canary, tolerant of a BOM, CRLF line endings, leading blank
  lines and surrounding whitespace.
- Opt-in git hooks (`sh .githooks/setup-hooks.sh`): branch guard, clean
  worktree check, full gate on merges into main, and a main guard that admits
  only gated merges. Installation behind a hook dispatcher is opt-in through
  `git config qinit.hooksDispatcher`.
- `pre-push` hook refusing any outgoing ref whose `README.md` still carries the
  review canary, or that has no `README.md`.
- `scripts/container-check.sh`: runs the full gate from a fresh clone in a
  stock Debian stable container with only the documented requirements, and
  a README "Requirements" section listing them.

### Changed

- `Client::watch` fails with `WatchRefused { client, error }` (D57): when colony refused the watch
  (`UnknownNode`, `Denied`), `client` is the connection back, still good; it is `None` only when
  the connection failed. `From<WatchRefused> for ClientError` keeps `?` working. A refused
  `qinit_watch` keeps its C client, which goes on asking; only a lost connection ends it.

- The kernel floor is 6.15 (`PIDFD_INFO_EXIT`). Colony's memory is queen's store, not files in `<run>/state`; re-adoption uses the held descriptors (D63, D64, D65).

- The kernel floor is 6.15 (`PIDFD_INFO_EXIT`). Colony's memory is queen's store, not files in
  `<run>/state`; re-adoption uses the held descriptors, so a restart keeps the logger pipes and the
  exit statuses of the mains that ended meanwhile. A database held by queen wins over `--db`.

- `Effects::start` and `start_instance` are given the database model, and `NodeSpec` carries the
  node's cgroup limits. `Server::on_readable` returns the connections it closed and the request's
  outcome (`Served`), so a caller that owns the loop can act on a refresh or a shutdown that
  completes inside the request.
- `qinit_frames::Compiled` carries the model it compiled: the frames as the layers merged them,
  the resolved model and the origin of every key (`merged`, `resolved`, `provenance`).
- `qinit_colony::Outcome` gains `stream`: notices become stream replies as they are pushed, so a
  node index always names the model it came from.
- The layer gate has an `ffi` layer for a C ABI over a runtime crate (it reaches edge, runtime,
  core, kernel and primitive; only tooling reaches it); `cc` is a tool of the test gate.
- A watch of an instance that has already exited starts with an exited notice carrying its status.
- `sandbox.landlock` is renamed `sandbox.paths` (database `C_PATHS_*`, request `paths`). The list
  is sorted and canonical, refuses `/`, `/dev`, `/tmp` and a writable `/proc`, needs the `mount`
  namespace, and must cover the program and the working directory.
- The credential record is 13 words (`C_USER_MAP`; 15 since group 2b), the database header 24 words, and the launch
  sequence is reordered (view, then user namespace, then identity, then Landlock): the plan
  has 25 phases and at most 320 steps, with a `RearmDeadline` step before the view.
- The proof timeouts of `qinit-overseer-core` (90s) and `qinit-colony-core` (100s) are raised to
  about three times their measured CPU time.
- The database node record is 68 words (a limit mask and 32 limit words) and the launch request
  67; the overseer plan has one `Rlimit` step per set limit instead of `RlimitNofile`.
- The validator checks the pool's UTF-8 once and each reference only for character boundaries, and
  labels the ordering graph once; a pool with a byte that starts no character is refused even when
  no reference uses it.
- A policy shape error is keyed by the `[[rule]]` the TOML parser finds, so inline `rule = [...]`
  arrays and `[[ rule ]]` headers are indexed.
- The compiled dump lists only the limits a frame sets.

- Format amendment (database `VERSION` stays 1): the node record has 30 words (`env`, `cwd`,
  `umask`, `rlimits.nofile`) and the credential record 12 (seccomp mode and syscall list). Every
  worker and forager must declare `credentials.uid`; a brood takes none. The validator checks
  both, the env entries, `cwd`, the `umask` range, the seccomp list rule and that `nnp = false`
  with a sandbox needs `sys_admin`. The privilege contract for undeclared workers is withdrawn.
- Frame keys: `env`, `cwd`, `umask` (default `0o027`), `rlimits = { nofile }`,
  `sandbox.seccomp = "none" | "default" | { deny } | { allow }` over a generated `x86_64`
  syscall table, and the policy field `require_seccomp`. The policy predicate for an
  unprivileged credential is now user other than `root`, no capabilities and `nnp`.
- The compiled database carries each node's restart delay, stop mode and grace period and start
  timeout (node record 20 to 24 words) and an edge cascade flag (edge flags bit 1); frames take
  `restart.delay`, `stop = { mode, grace }`, `start_timeout` and `cascade = true` on a
  `require_all` edge to a frame. Defaults: delay 1 s, stop mode `main`, grace 10 s, start timeout
  90 s (none for a node that is ready when it exits). A restart limit without a window gets
  `max x 10 x delay`; an explicit window shorter than the back-off up to `max` is a warning.
- `qinit_db_core::validate` refuses scratch buffers smaller than `MAX_EDGES` and `MAX_NODES` with
  `DbError::Scratch` instead of requiring them, and refuses an instanced-frame name longer than
  `MAX_NAME_LEN` with `DbError::Pool`.
- A frame that declares `credentials` without `nnp` gets no-new-privileges on; write
  `nnp = false` to opt out.
- The clean-container check installs Verus, verusfmt, QEMU and kernel build
  tools; it uses KVM when available, supports a TCG-only run and an optional
  checksum-verified local kernel tarball. Kernel builds scrub ambient make
  overrides; preflight checks libelf headers and unzip. Fake test executables
  are installed by a child process to avoid parallel-fork ETXTBSY races. Gate order is re-pinned from measured
  runs; the ledger records the cell substrate's accepted limitations.
- `cargo xtask gate` runs every gate in one fastest-first order across the
  repository and tooling workspaces, then the proof gates, and stops at the
  first failure, naming the gates it did not run. A failed proof stops new
  proofs from starting. Every other run of several steps (`--only` across
  both workspaces, `cargo xtask proofs`) also stops at its first failure.

### Fixed

- A booted colony no longer runs at the kernel's descriptor limit (D74): since D72 it started at
  1024 soft, 4096 hard, and a hand-over of more held descriptors than that did not fit. Colony
  raises its own `RLIMIT_NOFILE` to 65536, soft and hard, before it reads queen's hand-over, and
  starts its services with the limit it started with; a frame's own `nofile` still applies.
- A request's replies follow the state they report (D67): the server holds a request's own reply
  (`Server::flush`) until the daemon has saved the wake-up's state, so a colony killed the moment
  a client has its answer still leaves the record of what the request did, a launched instance
  included. `Server::on_readable` sends only refusals now; its caller sends the held replies with
  `flush` and then those the outcome owes with `on_outcome`.
- `qctl fill` undoes a failed commit (D60): it links every existing file to a backup name first,
  and a replacement that fails puts back every file already replaced (bytes, mode and owner) and
  removes the new files and the directories made for them. A backup name already taken stops the
  run with nothing changed.

- Services no longer inherit queen's raised descriptor limit (D72): queen starts colony, rescue
  and zero with the `RLIMIT_NOFILE` it started with.

- `Status` shows the pid of an adopted node's main after a colony restart, not only after the next
  start (D66).
- A wait that a refresh settles gets its reply. A stop or a start that failed at once during a
  refresh dropped the reply and cancelled the deadline, so the client was never answered (D56).
- `Colony::shutdown` stops the instances too. Only the protocol's `Shutdown` request did, so a
  shutdown from a signal left every instance running.
- `overseer`: an output route never follows a symlink at its last component (a service-writable
  directory could redirect the root-opened file to another one); a pid-namespace supervisor
  cannot miss its child's exit between reaping and waiting, closes the descriptors it inherits,
  and reports a failed privilege drop; an exit code that stands for a stopping signal is no
  longer re-raised; a user in group 0 other than `root` is refused; capabilities of newer kernels
  leave the bounding set; descriptors 0-2 that open onto themselves keep working; a seccomp
  filter no longer meets an allocation in `exec`. A `deny` list may not name `clone`,
  `unshare`, `clone3` or `setns`.
- The fmt gate decides whether a file needs verusfmt from its parsed source:
  only a real `verus!` invocation counts (also one inside another macro's
  body), not a mention in a comment or a string, so trees without Verus code
  no longer require verusfmt. A file the parser cannot read whole falls back
  to the earlier text rules.
- Proof cgroup cleanup kills leftover processes with the shell's `kill`
  built-in, so a base system without procps no longer fails the cleanup.
- Tests no longer depend on the developer's machine: they signal through the
  shell's `kill`, and scratch workspaces pin the repository toolchain instead
  of relying on rustup's default or downloading another toolchain.
