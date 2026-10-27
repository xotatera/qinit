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

Resolved by sub-project 2 Task 1: `qinit-sys` is the first product package; the four gates run.

### D4 — no-std tooling gate · `ACCEPTED`

The root `no-std` gate runs since sub-project 2 Task 2 (`qinit-event-core` is
the first core crate). The tooling `no-std` gate is separately blocked: the
`xtask` workspace has no kernel or core crate.
Unblock it only in the change that adds a
primitive, kernel, or core crate to the `xtask` workspace.

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
`STATUS_UNKNOWN` (`qinit-cell-core`). The status of a process that is not a
child is only readable through `PIDFD_INFO_EXIT` (Linux 6.15), above the 6.13
floor (spec R9). Revisit if the floor reaches 6.15.

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
the report the caller waits for. Sub-project 2 Task 9's `escalate` suite
therefore asserts escalation by the report sequence ending `Empty` after the
kill deadline path plus the helper's own evidence, not by a
`MainExited(SIGKILL)` report.
