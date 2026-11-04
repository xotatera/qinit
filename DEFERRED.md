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

### D8 — Exit status of a handed-over main process · `ACCEPTED`

A main process queen hands over on adoption need not be the runtime's child,
so `qinit-cell` watches its pidfd without reaping it and reports its exit as
`MainExited(None)`. If that handed-over main is actually our child, its exit
is separately reported as an Orphan with its real status, while its cell gets
`MainExited(None)`. The status of a process that is not a child is only readable
through `PIDFD_INFO_EXIT` (Linux 6.15), above the 6.13 floor. Revisit
if the floor reaches 6.15.

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

### D16 — `qctl` command-line tool · `OPEN`

`qinit-frames` is a library: it has no command-line front end. The `qctl`
compiler and administrative CLI, which will call it, is a later sub-project.

### D42 — Implicit defaults are not written back to frame and policy TOML · `OPEN`

A frame or policy that leaves a key out gets the compiler's default (`cwd = "/"`, `umask`, no
limits, the built-in rlimit ceiling), and nothing shows the effective value in the file. Writing
the implicit defaults back into the frame and policy TOML, before or after compilation, would make
them visible. Home: `qctl` (D16).

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
be supervised as ready. The maintainer decided to revisit this in the colony
sub-project (sub-project 4), which owns service state.

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

### D26 — No ownership or mode check on policy and layers · `ACCEPTED`

The compiler reads the policy file and the layer directories as given, with
no check of their owner or mode, although the design calls the policy
root-owned. The `qctl` front end (D16) is the place to enforce it.

### D27 — Real path watching · `OPEN`

The colony core waits for a path edge through a `WatchPath` action and a `PathAppeared` input.
Watching a real filesystem path (inotify, with the race between setting the watch and the first
check) belongs to the colony daemon sub-project.

### D28 — Refresh operation · `RESOLVED`

Resolved by the control protocol (sub-project 6): `Change(refresh)` signals a worker that
declares `reload` and otherwise restarts it, and `restart_on = "refresh"` edges fire for a
refreshed target; `restart_on = "restart"` edges do not fire for a reload. A new database is
swapped in by the `Refresh` request, in two phases (see `docs/control-protocol.md`).

### D29 — Real cells, event loop and re-adoption · `OPEN`

`qinit-colony` runs against a simulated cell layer. Wiring the real `Cells`, the event loop and
the timers behind its `Effects` trait, and building the list of nodes already running from the
comb after a colony restart (the `initial` argument of `Colony::load`), belong to the colony
daemon sub-project. The real `Effects::arm` can fail; the engine reports that as an error and the
core still believes the timer is armed, so a back-off or start-timeout timer that failed to arm
leaves its node waiting for good. That sub-project must re-arm or synthesize the deadline.

### D30 — Reconcile worst case · `ACCEPTED`

After each input the scheduler repeats a pass over all nodes and edges until nothing changes, at
most `MAX_NODES` passes. A pass runs propagation to a fixpoint (at most `MAX_NODES` rounds over
the edges) and lets every running node that is to stop check its dependents (an edge scan each),
so the worst case is about `MAX_NODES`² times `MAX_EDGES` steps per input. A long chain of broods
can need that many passes; ordinary graphs need a handful. A reverse-adjacency index would remove
the edge scans; add it if a real graph makes this visible.

### D31 — Cgroup limits at cell creation · `OPEN`

`memory.max` and `pids.max` are attributes of the cgroup the colony owns, not of the launch. The
node record carries them; writing them when the cell is created belongs to the colony daemon
sub-project (SP7).

### D32 — Bind-built empty-root mount view · `OPEN`

A `mount` namespace is a private copy of the host tree with a private `/tmp`; Landlock is the
restriction. A view built from bind mounts of only what a service needs is deferred.

### D33 — User namespaces · `OPEN`

The overseer starts services as the uid they declare and offers no `user` namespace. A service
that wants to be root in a namespace only needs a sandbox design of its own.

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

### D37 — Notice stream · `OPEN`

A client cannot subscribe to node state changes or instance exits: it asks, or it waits on a
request with a deadline. A watch request that streams notices on a connection is deferred.

### D38 — A pidfd in the launch reply · `OPEN`

`Launch` answers with an instance id and then the exit status; it does not hand the caller a pidfd.
A pidfd would take the sole control of a stop away from colony, needs `PIDFD_INFO_EXIT` (Linux
6.15) for the exit status, names the supervisor when the service runs in a pid namespace, and is
hard to remove once offered. It can be added as an optional field.

### D39 — Launching a full request · `OPEN`

A caller can only start a forager frame that declares a `[launch]` table, adding an argument
tail, environment keys the frame lists and the standard descriptors it lists. A root-only
request that carries a whole launch request (arbitrary program, identity and sandbox) is
deferred as its own record type.

### D40 — Non-root authority beyond status · `OPEN`

Any user may read status and the list; everything else needs user id 0, decided by the one
`authorized` function. Finer authority (per service, per user) belongs to the privilege authority
project, which plugs in at that function.

### D41 — A C interface to the client library · `OPEN`

`qinit-client` is a Rust library. Other languages implement the protocol from
`docs/control-protocol.md`; a C ABI over the client is deferred.
