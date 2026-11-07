<!--
SPDX-FileCopyrightText: 2026 Xota Tera
SPDX-License-Identifier: CC-BY-4.0
-->

# Deferred work

This is qinit's single living ledger for deferred work, accepted limitations,
and decisions awaiting the maintainer. Add an entry when work is deliberately
put off; resolve it in the same change that completes it. Do not create a
second public work list.

Status values: `OPEN` (work remains), `DECISION` (maintainer decision needed),
`ACCEPTED` (known limitation), and `RESOLVED`. IDs are stable and never reused.

## Open work

### D1 — User-session tracking and elogind/turnstile replacement · `OPEN`

Deferred by the approved design, §9. This belongs to the later privilege
project.

### D2 — Overseer adoption, additional binaries, and queen live upgrade · `OPEN`

Deferred by the approved design, §9. None of these may enter qinit without an
approved design amendment.

### D3 — Product workspace gates · `RESOLVED`

Resolved by the event-loop sub-project: `qinit-sys` is the first product package; the four gates run.

### D4 — no-std tooling gate · `ACCEPTED`

The root `no-std` gate runs since the event-loop sub-project added `qinit-event-core`,
the first core crate. The tooling `no-std` gate is separately blocked: the
`xtask` workspace has no kernel or core crate.
Unblock it only in the change that adds a primitive, kernel, or core crate to the `xtask` workspace.

### D5 — Tooling-stage repository-wide scans · `ACCEPTED`

The repository stage runs the placeholder, sleep, changelog, and duplication
scans over the whole tree, including `xtask/`. The tooling stage blocks its
copies so they do not run without the root policy files and ledger; unblock
only if it gains a separate, reviewed tooling policy.

### D6 — Run-scope sharing across a full gate run · `ACCEPTED`

A full `cargo xtask gate` runs each gate as its own step in the global
fastest-first order, so the template's run scope (`run_scope::will_run`,
`shared`), which lets one gate reuse another's results within a single run,
no longer spans gates. No qinit gate uses it. Revisit when a gate starts to
depend on another's results (the template's `test` / `zero-coverage` pattern).

### D7 — fmt gate `verus!` detection edge cases · `ACCEPTED`

The fmt gate finds `verus!` calls from tree-sitter's parse. Known contrived
misses: inside a token tree, `verus !x` counts as a call, and a path-qualified
call is located at its `verus` identifier, so one at column 0 reads as
indented. A file the parser cannot read whole falls back to the earlier text
rules, which miss `r#verus!`, `verus ! {}` and a call after other code on its
line. Revisit if real Verus code hits one.

### D8 — Exit status of a handed-over main process · `RESOLVED`

A main queen handed over is read through `PIDFD_INFO_EXIT` (Linux 6.15, now the kernel floor): when
the pidfd turns readable and the kernel has recorded a status, the cell reports it. A main whose
parent has not reaped it yet is waited for (`Notice::StatusPending`): queen's `Reaped` wake lets
colony read it, and after a second the exit is reported with an unknown status, as before. Without
a queen nothing waits (`Cells::wait_for_status` is opt-in).
### D9 — Released child the loop refuses to watch · `ACCEPTED`

When a cell lets go of a child that is still running (a late exec result
after the cell failed, a released slot, the cleanup of a spawn that could not
be watched), `qinit-cell` watches its pidfd under a stray token so the loop
reaps it at exit and reports it as an orphan. If the loop refuses that
registration (`epoll_ctl` out of memory), the child is kept and tried at every
later wake-up of the loop instead: it is still reaped and reported, but may
stay a zombie until something else wakes the loop. Closing that gap needs a
second watch mechanism for an `epoll_ctl` failure the loop itself already
cannot survive.

### D10 — A main exit during a stop is recorded, not reported · `ACCEPTED`

While a cell is Stopping or Killing, the proved machine records the main
process's exit status (`Main::Reaped`) but emits no `MainExited` report; the
stop ends with `Empty` (or `Failed(Stuck)`). By design: the stop's outcome is
the report the caller waits for. The cell sub-project's `escalate` suite
therefore asserts escalation by the report sequence ending `Empty` after the
kill deadline path plus the helper's own evidence, not by a
`MainExited(SIGKILL)` report.

### D11 — Unkillable process in VM suites · `ACCEPTED`

VM suites cannot produce an unkillable process (uninterruptible sleep): the
'still populated after the kill deadline → Failed(Stuck)' path is covered by
the Verus proof (`good`, obligation 6) and the host engine test
`deadlines_escalate_then_report_stuck` only (spec §6.2).
Queen's case of the same kind (a colony that cannot be reaped, so the shutdown ends at the kill
wait) rests on the proof and the machine test `an_unreaped_colony_does_not_stop_the_way_down` too.
### D12 — Adoption open failure · `ACCEPTED`

Adoption treats a cell that cannot be opened as an id mismatch
(`Failed(IdMismatch)`), not as a separate failure.

### D13 — x86_64 syscall shim · `ACCEPTED`

`qinit-sys` is written for x86_64 (raw child path, kernel structure layouts);
another architecture needs its own `KernelSigaction` and checked layouts. The seccomp syscall
table and the default denylist of the overseer are `x86_64` only as well.

### D14 — clone3 signal mask and threaded credential changes · `ACCEPTED`

Blocking all signals around clone3, including glibc's SIGSETXID and musl's
synccall signal, lets a threaded caller create a child with credentials from
before a concurrent setxid change. Sub-project 5 (privilege) must revisit
this before using spawn from a threaded caller that changes credentials. The overseer is
single-threaded and changes its own credentials (SP5), so it is not such a caller.

### D15 — Runtime group evaluation · `RESOLVED`

Resolved by the colony core sub-project: `qinit-colony-core` evaluates the groups over the
observed node states and `qinit-colony` runs it against simulated cells.

### D16 — `qctl` command-line tool · `RESOLVED`

Resolved by `qctl` (spec 2026-11-05 §4; commits 52184eb, 5b0bc92, 0211d91, 4170248, 0e62ac7), an
`edge`-layer crate with a hand-written argument grammar: `compile` (the layers
`vendor=/usr/lib/qinit/frames` and `etc=/etc/qinit/frames`, the policy `/etc/qinit/policy.toml` when it exists,
the output `/etc/qinit/colony.db`, byte for byte the library's database), `show`, `fill`, and the
control commands over the protocol: `status`, `list`, `start`/`stop`/`restart`/`clear` with
`--wait`, `refresh`, `poweroff`/`reboot`/`halt`, `launch`, `run` from a TOML request file, and `watch`, one line
per notice. Exit codes are 0 done, 1 refused or failed, 2 usage. `docs/qctl.md` is its page; the
control suite runs it in-process as root in the guest.

### D42 — Implicit defaults are not written back to frame and policy TOML · `RESOLVED`

A frame or policy that leaves a key out gets the compiler's default (`cwd = "/"`, `umask`, no
limits, the built-in rlimit ceiling), and nothing showed the effective value in the file. Resolved
by `qctl show` and `qctl fill` (spec 2026-11-05 §4.3, §4.4; commits bf7cfef, bedef46, 7dad1ec):
`show` prints a frame or the policy as effective TOML, each key with the layer it came from or
`# default`; `fill` writes the implicit defaults into the `etc` layer (an amend table when the
layer has none; vendor files are never edited), marked `# default, filled by qctl`, preserving the
file's other bytes, idempotent, and the compiled database is byte-identical before and after. Two
defaults have no TOML word and stay comments (D58).

### D17 — Policy signature verification · `OPEN`

The policy file given to the compiler is read as is. Verifying a signature on
it belongs to the later privilege project (see D1).

### D18 — Ready line plus exit in one wait · `ACCEPTED`

A service that writes its ready line and exits within the same wait is
reported as exited, never as ready. The event loop sorts exits first in a
batch (`qinit-event`, `Loop::wait`: `Ready::Exited` before the rest), so the
cell engine handles the main exit (`qinit-cell`, `main_exited`) before the
readable ready pipe and the machine goes to Empty without a `Ready` report.
Accepted as is: a service that is already gone when readiness is read cannot
be supervised as ready. The colony sub-project (sub-project 4), which owns
service state, revisited it and kept it: a `ready = pipe` worker whose exit
arrives before its ready line has exited before ready, a failure; `ready =
exit` is unaffected.

### D19 — Validator worst-case cost · `RESOLVED`

`pool_ref_ok` used to check UTF-8 by rescanning the pool bytes for every reference (about
6.9e10 byte steps for a crafted maximal database). `check_pool_refs` now scans the whole pool
once and each reference needs only two boundary tests, proved to give a valid slice
(`lemma_ref_utf8`): the worst case is one pass over at most `MAX_POOL` bytes plus a constant per
reference. A pool holding unreferenced garbage is now refused too.

### D20 — Policy error rule index by line scan · `RESOLVED`

`qinit-frames` used to find the `[[rule]]` index of a policy shape error by scanning for
`[[rule]]` header lines. It now takes the index from a `toml::de::DeTable` parse: the `rule`
element whose span holds the error, so inline arrays, `[[ rule ]]` and header-like lines in
strings are indexed correctly.

### D21 — Overseer runs undeclared workers unprivileged · `RESOLVED`

Resolved by the overseer sub-project: every worker and forager declares its user, and the
contract that left undeclared ones unprivileged is withdrawn (`docs/db-format.md`).

### D22 — no-new-privileges default for declared credentials · `RESOLVED`

Resolved by the maintainer: a frame that declares `credentials` without `nnp` gets
no-new-privileges on; it has to write `nnp = false` to opt out. A policy rule with
`require_nnp = true` still refuses the opt-out where needed.

### D23 — Instanced-frame name not bounded by the validator · `RESOLVED`

The validator now holds `N_INSTANCE_OF` to `MAX_NAME_LEN` (an empty name is still allowed),
proved with V2. Readers can rely on the bound.

### D24 — Second graph pass in the validator · `RESOLVED`

The scratch-length precondition of `qinit_db_core::validate` is now a run-time check that
returns `DbError::Scratch`, so there is nothing left for a caller to break. The second `levels`
call in `check_graph` (stop order, honouring `stop = "parallel"`) is logically redundant once
the first succeeded: honouring the opt-outs only drops constraints, so the first pass's
labelling also satisfies the second, and the hard-parallel check is the same in both. A lemma
stating that halves the worst-case graph cost (about 134 million steps): `check_graph` now runs `levels` once and proves the labelling serves both orders.

### D25 — Pool and UTF-8 errors carry no position · `RESOLVED`

`DbError::Pool { table, record }` names the record whose reference failed and
`DbError::Utf8 { offset }` the first bad pool offset, like the record errors.

### D26 — No ownership or mode check on policy and layers · `RESOLVED`

The compiler read the policy file and the layer directories as given, with no check of their
owner or mode, although the design calls the policy root-owned. Resolved in `qctl` (spec
2026-11-05 §4.2; commits 4e364ae, 400f3b2, bedef46): run as root, `compile` and `show` refuse a
policy file, a layer, any file or directory below a layer, or any ancestor directory of them that
is a symbolic link, is not owned by uid 0 or is writable by group or other, naming the first path
and its owner and mode; an effective uid that cannot be read fails closed. Run as another user,
`qctl` prints a notice that the check is skipped. The library itself still reads what it is given.
The control suite checks the refusal and the success as root in the guest.

### D27 — Real path watching · `RESOLVED`

The colony core waits for a path edge through a `WatchPath` action and a `PathAppeared` input.
Resolved by the colony daemon (SP7, `qinit-colonyd::watch`, `docs/colony.md`): one inotify instance
watches the nearest existing directory above a path, walks down as components appear and climbs
back when a directory goes, and sets every watch before the check it protects, so a path made in
between is seen once. The same watcher serves `ready = { path }` and `ready = { socket }`, which
mean *created after the start*. The `readiness` VM suite runs it on a real kernel.

### D28 — Refresh operation · `RESOLVED`

Resolved by the control protocol (sub-project 6): `Change(refresh)` signals a worker that
declares `reload` and otherwise restarts it, and `restart_on = "refresh"` edges fire for a
refreshed target; `restart_on = "restart"` edges do not fire for a reload. A new database is
swapped in by the `Refresh` request, in two phases (see `docs/control-protocol.md`).

### D29 — Real cells, event loop and re-adoption · `RESOLVED`

`qinit-colony` ran against a simulated cell layer. Resolved by the colony daemon (SP7,
`docs/colony.md`): `qinit-colonyd` implements `Effects` over the real `Cells`, one `qinit-event`
loop and a userspace deadline queue behind one timer, so `Effects::arm` cannot fail and the failure
class this item described no longer exists; and it re-adopts the comb after a restart from the
`state/` files (verified by pid, start time and cgroup id, with the node table checked against the
core's invariant first). The `daemon` and `readopt` VM suites run both on a real kernel.

### D30 — Reconcile worst case · `ACCEPTED`

After each input the scheduler repeats a pass over all nodes and edges until nothing changes, at
most `MAX_NODES` passes. A pass runs propagation to a fixpoint (at most `MAX_NODES` rounds over
the edges) and lets every running node that is to stop check its dependents (an edge scan each),
so the worst case is about `MAX_NODES`² times `MAX_EDGES` steps per input. A long chain of broods
can need that many passes; ordinary graphs need a handful. A reverse-adjacency index would remove
the edge scans; add it if a real graph makes this visible.

### D31 — Cgroup limits at cell creation · `RESOLVED`

`memory.max` and `pids.max` are attributes of the cgroup the colony owns, not of the launch. The
colony daemon (SP7) writes them after the cell is created and before the overseer is spawned, so
the first instruction of the service runs under them; the comb's `cgroup.subtree_control` gets
`+memory +pids` at start-up and colony refuses to start without them. The `daemon` VM suite reads
the values back from the cells.

### D32 — Bind-built empty-root mount view · `RESOLVED`

A credential or launch request with a `paths` list gets a view: an empty `tmpfs` root with a
fixed `/dev` (`null zero full random urandom`) and a private `/tmp`, a recursive bind of every
listed path (read-only or writable, `nosuid`, and `nodev` except below `/dev`; every mount of the view is made private, so a mount the host makes later does not appear in it), a `pivot_root` into it and a read-only
seal, then Landlock on the same paths. The list is the old `sandbox.landlock` renamed
`sandbox.paths`; it is sorted, canonical, refuses `/`, `/dev`, `/tmp` and a writable `/proc`, and
needs the `mount` namespace. The plan has one proved step per phase of the view. What the view
adds since is in D43, D47, D48 and D49.

### D33 — User namespaces · `RESOLVED`

A credential or request with the `user` namespace bit unshares a user namespace after the view
is locked. `user_map` `own` maps the service's inside id (0 unless D44 sets it) onto the
service's user and group; `range` also maps inside 1.. onto its `/etc/subuid` and `/etc/subgid` ranges, written by a forked map writer that
stays in the host namespace. A user namespace needs a user other than `root`, and a policy
rule's `allow_userns` (0 none, 1 own, 2 own or range). The initrd and the kernel config of the VM
suites carry `CONFIG_USER_NS` and subordinate ranges. The inside ids are 0 unless D44 sets them.

### D34 — Other rlimits · `RESOLVED`

Every kernel resource but `core` (always 0) is a frame key: `cpu fsize data stack rss nproc
nofile memlock as locks sigpending msgqueue nice rtprio rttime`, as a number, `"infinity"` or for
the byte limits a size. Soft and hard are both set to the value. The node record grows to 68
words, the launch request to 67, and the overseer plan has one proved `Rlimit` step per set
limit. The policy bounds them at the kernel's boot hard limits (`rlimits_max` on a rule, or at
the top level, raises a ceiling). A low `nofile` or `nproc` can make a later launch step fail;
the step name says which. `nofile` above `fs.nr_open` fails at launch with `EPERM`.

### D35 — Dumpable after exec · `ACCEPTED`

The kernel sets the dumpable flag at every exec of a plain binary, so a service is dumpable; its
`RLIMIT_CORE` is 0 and the default seccomp denylist denies `ptrace` and `process_vm_*`. The
supervisors of a pid-namespace launch never exec and are non-dumpable.

### D36 — Pid-namespace status relay · `ACCEPTED`

The init of a pid namespace cannot raise a default-action signal on itself, so it exits with
`128 + n` and the supervisor outside turns an exit code of `128 + n` back into signal `n`. A
service that itself exits with such a code in a pid namespace is reported as killed by that
signal.

### D37 — Notice stream · `RESOLVED`

A client could not subscribe to node state changes or instance exits. Resolved (spec 2026-11-05
§2; commits faeeea4, 7fc6352, 7af11a4, bc1fdc4, b146efc, 49cb551): `Watch` (type 8, any user, a
node, an instance `<frame>#<id>` or everything) is answered `Accepted` and then the connection
carries `Notice` replies (type 75: node, instance, database swapped, shutdown complete, with the
state, a report word and a status). A targeted watch starts with the current state (an instance
that has already exited says exited, with its status); a refresh that removes the node ends the
stream with `Superseded`; a watcher that does not read is closed and the server goes on. Colony
keys watchers by name and turns notices into stream replies as they are pushed into an `Outcome`.
The client has `Client::watch` and `Watcher::next` with a timeout; the control suite watches a
change made by a second connection.

### D38 — A pidfd in the launch reply · `RESOLVED`

`Launch` and `Run` take `flags` bit 0 `pidfd`; the `Launched` reply then carries a pidfd of the
instance as its descriptor, and colony keeps stopping it itself. The exit status still comes from
colony, not from the pidfd (D45 for `PIDFD_INFO_EXIT`). With a `pid` namespace the pidfd names the
supervisor.

### D39 — Launching a full request · `RESOLVED`

`Run` (type 7, user id 0) takes a sealed memfd holding a whole launch request
(`docs/launch-request.md`) and starts it as an instance named `~<name>#<id>`. Colony decodes it,
checks it against the policy compiled into the database (`T_POLICY`, `T_POLICY_HEAD`; the proved
`qinit_overseer_core::check_policy`, which the frames compiler's check must agree with) and runs
it with the record's stop mode and grace. The credential policy is part of the database; a
database with no policy refuses every `Run`. `MAX_FDS` is 4.

### D40 — Non-root authority beyond status · `OPEN`

Any user may read status and the list; everything else needs user id 0, decided by the one
`authorized` function. Finer authority (per service, per user) belongs to the privilege authority
project, which plugs in at that function.

### D41 — A C interface to the client library · `RESOLVED`

Resolved by `qinit-client-c` (MPL-2.0, the `ffi` layer; spec 2026-11-05 §3; commits 761fc78,
c1a747e, 5f5695f): `libqinit_client_c` as a static archive and a shared object, with the header
`include/qinit_client.h` generated by cbindgen and checked for drift by a test. Status, list,
change, refresh, shutdown, launch and run (QLR1 bytes, D53) and the notice stream are exported;
errors are an `int` kind plus `qinit_last_error`, names are copied into 97-byte arrays. A C smoke
program, compiled against the header and linked into the test binary by the build script, runs
its sequence against the test server in the test gate. `crates/qinit-client-c/README.md` is the
C user's page.

### D43 — Idmapped mounts in the view · `RESOLVED`

An entry with the mode `ri:` (read-only) or `wi:` (writable) is bound as an idmapped mount: the
overseer creates a helper user namespace (plan step `IdmapNamespace`) with the maps the service's
own namespace will get, and passes it to `mount_setattr(MOUNT_ATTR_IDMAP)` on the entry's
detached clone. A disk id `i` the map covers is then the service's inside id `i`, and what the
service creates under inside id `i` is disk id `i`; every other disk id shows as `nobody`, and an
inode whose disk owner the map does not cover cannot be written (the kernel refuses). The mode
needs the `user` namespace bit (frames, the validator and the decoder alike) and fails the launch
at the entry (`EINVAL`) when a filesystem below cannot be idmapped; it never falls back to a
plain bind. An idmapped entry should lie on one filesystem: the clone is recursive and fails
whole. A rule's `allow_idmap = true` is needed for a request with an idmapped entry (proved
clause, denial code 10, after the inside-ids clause), because the mount gives the service the
ownership of disk ids.

### D44 — An inside user other than root · `RESOLVED`

`sandbox.inside_uid` and `sandbox.inside_gid` (request words 67 and 68, credential words 13 and
14) choose the ids the service runs as inside its user namespace; both default to 0, are at most
4294967294, and are non-zero only with the `user` bit. The map writer maps the chosen inside id
(own map) or inside 0 and `1..count` (range map) and the credential steps set the chosen ids. A
range map whose inside id is above the subordinate count fails at the `identity` step with
`ERANGE`. A policy rule needs `allow_inside_ids = true` for a non-zero inside id (the proved
check; denial code 9, between the user-namespace and limit clauses). Mapping a group other than
the service's own is not offered.

### D45 — `PIDFD_INFO_EXIT` for the pidfd reply · `RESOLVED`

`qinit_client::pidfd_exit` reads the exit status from a launch's pidfd with `PIDFD_GET_INFO`
and `PIDFD_INFO_EXIT` (Linux 6.15, the kernel floor): `Exited(status)` once the parent
has reaped the process (the kernel records the status at the reap, not at the exit), `Running` before
that, `Unsupported` on a kernel without it. The implementation lives in `qinit-ipc` (MPL) because
the client library cannot depend on `qinit-sys`.

### D46 — Readiness for instances · `RESOLVED`

`Run` flag bit 1 `wait_ready`: the request must route a readiness pipe, the instance starts with
readiness by pipe, and the second reply is `Settled` (state running) when the service writes its
byte, `Exited` if it ends first, or `Pending` at `wait_ms`. `Launch` refuses the flag. A request with a
pipe and no flag stays refused (`Denied`, detail 0). A service that never writes the byte is
bounded only by `wait_ms` and an explicit stop.

### D47 — Host mount propagation into views · `RESOLVED`

The modes `rs:` and `ws:` leave their mounts slaves of the host's, so a mount the host makes later
below the path appears in the view; every other mode is cut off as before. Making the host's own
mounts shared is zero's, early (SP10), not queen's: the entry follows only if the host's tree is
shared.
### D48 — A listed path below a directory the service can write · `RESOLVED`

An entry below a writable one (`rw:`, `wi:`, `ws:` above it in the list, by whole components) is
opened with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` below that
entry: a symlink anywhere on the way, the last component included, fails the launch at the entry
with `ELOOP`. An entry that is not below a writable one still follows symlinks (ordinary host
layouts such as `/lib -> usr/lib` keep working). See D50 for what this does not cover.

### D49 — The view is built on the host root · `RESOLVED`

The view's root is `/run/qinit/view` (`/run` is a writable `tmpfs` on every host this runs on)
and every entry is a detached clone (`open_tree`, `mount_setattr`, `move_mount`) that carries its
attributes before it is attached, so a launch no longer needs a writable host root and leaves no
`/.qinit-view` behind.

### D50 — A symlink planted in a writable directory the launch does not list · `OPEN`

D48 closes the symlink a service can plant below a *listed* writable entry. A symlink planted in
a directory that is writable by the service but not listed `rw:` (a world-writable `/var/tmp`, a
home directory listed `ro:` by a different launch of the same user) can still redirect a later
launch that lists a path through it. Resolving every entry without symlinks would break ordinary
host layouts and is not proposed; the answer is to list such paths only from directories the
service cannot write.

### D51 — Machine-readable `qctl` output · `OPEN`

`qctl` prints lines for people (`state: ready`, `node db ready ready`). A `--json` form for
scripts is deferred; until then a script uses the client library or the C interface.

### D52 — A notice backlog · `OPEN`

A watch sees only what happens after it is in place (and, for a target, its current state). A
watcher that connects late cannot read what it missed; a backlog it could replay is deferred.

### D53 — A C builder for launch requests · `OPEN`

`qinit_run_begin` takes the QLR1 bytes of a launch request (`docs/launch-request.md`); the C
interface has no builder for them, so a C program encodes the request itself.

### D54 — `qctl run` from a frame file · `OPEN`

`qctl run` takes a TOML request file. Compiling one frame into a request, so a frame can be run
as an instance directly, is deferred.

### D55 — `qctl show` and `fill` for `enable.toml` · `OPEN`

`show` and `fill` act on frames and the policy. The enable list (`enable.toml`) has neither an
effective view nor written-back defaults.

### D56 — Outcome merges that drop parked replies · `RESOLVED`

Several places in colony merged the `Outcome` of an inner call into their own and carried the
notices, the stream and the errors but not `replies`. A refresh reached it: a stop or a start in
either phase that failed at once settled a parked wait inside the inner call, which removed the
wait and cancelled its deadline, and the reply was dropped, so the client was never answered. Every
merge now goes through `Outcome::absorb`, which names each field, so a new field does not compile
until it is merged. `tests/handle.rs` covers both phases of a refresh.

### D57 — `Client::watch` spends the client on a refusal · `OPEN`

`Client::watch(self)` consumes the client, and on a refusal (`UnknownNode`, `Denied`) it returns
the error without the client, although the server keeps the connection open. The C interface
inherits it: a refused `qinit_watch` spends its client, which must be connected again. Returning
the client with the error would keep the connection.

### D58 — Defaults with no TOML word · `OPEN`

Two defaults have no TOML spelling in the frame schema: no start timeout (`start_timeout =
"none"`, a node ready on exit) and `sandbox.user_map = "own"` without a user namespace. `qctl
show` and `qctl fill` print them as comments instead of keys, since a written key would not
compile; a schema word for each would let them be written.

### D59 — Intermittent failures of the xtask CLI tests · `RESOLVED`

In one full gate run two tests of `xtask/runner/tests/cli.rs` failed,
`empty_proofs_are_a_successful_no_op` (exit 2) and
`full_gate_names_the_malformed_repository_proof_declaration` (`cannot run cargo metadata: No such
file or directory`); they passed alone and in the next gate runs. `Fixture::new` named its
temporary root by `SystemTime` nanoseconds only, so two parallel tests could get the same root and
one's `Drop` could remove it under the other. The names do repeat (eight threads drew 4,941
duplicates in 400,000), though that one failure was never reproduced. The name now has the process
id and an atomic counter as well, and `fixture_roots_never_repeat` pins it. If these failures come
back, the cause is something else.

### D60 — `qctl fill` renames its files one by one · `OPEN`

`qctl fill` edits every file and writes every new text to a temporary file, with the old file's
owner and mode, before it renames any, so a failed edit, write, `chown` or `chmod` leaves every
file as it was. The renames themselves then run one after another: a rename that fails after the
first leaves the earlier files filled and the rest not. Each file is still whole, and a second
`fill` completes the rest, but the files of one run are not replaced as one. Directories made
for a new file are not removed when a later file fails.

### D61 — Test directories left in `/tmp` by other crates · `RESOLVED`

Runs of `cargo test` left directories in `/tmp`: `qinit-sys-fs-*`, `qinit-ipc-*` and
`qinit-sys-det-*`, twelve per run. Each of the three harnesses now holds its directory in a guard
that removes it when dropped, as the qctl, client and protocol tests do.

### D62 — Pre-opened sockets · `OPEN`

`ready = { socket }` means a socket is created at the path after the start, and colony watches for
it. Colony does not bind and listen on the socket itself and hand the descriptor to the service
(systemd and launchd do; dinit's `socket-listen` does), which would close the gap between the
service's `bind` and `listen` and let clients connect before the service is up. Queen's store now
exists to carry such a descriptor across a colony restart; the feature itself is still to do.
### D63 — Logger pipes across a colony restart · `RESOLVED`

Queen holds both ends of every logger pipe. A new colony takes them back and restarts neither the
logger nor its producers, so nothing a producer wrote between the old colony's death and the new
one's start is lost. A pipe queen no longer holds is made again and its nodes restarted.
### D64 — Re-adoption through queen · `RESOLVED`

Colony's state is in queen's store: each cell's directory descriptor, each main's pidfd and both
ends of each logger pipe, with the text that names them. Re-adoption uses the held descriptors; the
`/run/qinit/state` files and the pid, start time and cgroup id check are gone.
### D65 — The exit status of a re-adopted main · `RESOLVED`

A main that exits after a colony restart has its wait status recorded by the kernel when queen, its
new parent, reaps it, and colony reads it from the pidfd it adopted. A status of 0 is told apart
from a crash; the unknown status remains only for a main whose status was not recorded within a
second.
### D66 — A re-adopted node has no pid in `Status` · `RESOLVED`

`Colony::pid` was the pid the effects layer reported when it started the node, so a node colony
adopted showed no pid in `Status` until it was started again. The adoption plan now passes the pid
of a recovered main to `restore` (`RestoredNode::pid`; none when the main is gone), and the
`readopt` VM suite reads it back from `Status`.

### D67 — A request's replies come before the state files are rewritten · `OPEN`

The daemon delivers the replies an event owes parked waits and watchers (a cell report, a timer, a
path) after it has logged and saved state, so a client that sees a change can rely on both. The
replies a *request* causes are sent by the server inside the request, before the `cells` and
`nodes` files are rewritten: the one the request gets for itself (`Launched`, `Accepted`, a wait
that is already met) and the ones it releases for other connections' waits and watchers. A client that kills colony the moment it has
that reply can lose the record of what the request did: an instance launched in that window is
unknown to the next colony, which leaves its cell running. Instances are transient and the window
is microseconds, so it is accepted; closing it would make the server hand a request's reply back
to the daemon instead of sending it.

The same window has a second face under queen: a colony killed after it made a cell and before it
put the cell's directory in queen's store leaves a cell nobody holds. The next colony cannot adopt
it and a later start of the same node fails to create its cell. The `queen` suite's kills wait for
the state to reach queen for this reason.
### D68 — A configurable shutdown bound · `OPEN`

Queen's shutdown bound is five minutes, then a kill and five seconds more (M12). A deployment that
needs another figure needs a setting; today only the guests' `testing` build reads one.

### D69 — A parked queen reaps nothing · `ACCEPTED`

After a panic or a fault queen parks (M11): zombies pile up and nothing restarts, until the machine
is reset. The alternative, to exit, would panic the kernel, and a loop that carries on after a fault
cannot be trusted. Colony, a process of its own, keeps serving.

### D70 — A colony that hangs but is alive is not noticed · `OPEN`

Queen restarts a colony that dies, and kills a colony that has not finished a shutdown in time. A
colony that is alive and no longer serving (a stuck loop) is noticed by neither before a shutdown.
A heartbeat on the channel would catch it.

### D71 — Colony without queen does not re-adopt · `ACCEPTED`

Without `--queen-fd` colony holds nothing: a colony restart starts everything again, leaves what it
finds in the comb alone (one log line each) and fails the create of a node whose cell name is taken
(M10).

### D72 — Services inherit queen's descriptor limit · `OPEN`

Queen raises `RLIMIT_NOFILE` to 65536 to hold the whole store and colony inherits it, so services
whose frame sets no `nofile` start with that limit and not the kernel's default.

### D73 — `readopt` VM case `a_pipe_worker_still_starting_is_restarted` fails about one run in thirteen · `OPEN`

Under queen, in rare runs the adopted `slow` node is restarted, its old main exits, and colony logs
`slow: failed (status unknown)` and does not start it again: the node ends off, so the case waits
its hang guard for a second start. The adopted exit then reaches the machine as a failure and not as
the result of the requested stop. The cause is not found: the guess is an ordering of the pidfd
becoming readable, queen's `Reaped` wake and the restart request. The other cases of the suite did
not show it in more than forty runs.
