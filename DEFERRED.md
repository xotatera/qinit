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

### D3 — Product workspace gates · `ACCEPTED`

The repository has no product package while disciplines are being set up.
The root `fmt`, `lint`, `layers`, and `test` gates are therefore blocked:
running them would format, lint, inspect, or test an empty virtual workspace.
Unblock each gate in the same change that adds its first product package.

### D4 — no-std product gate · `ACCEPTED`

The repository has no kernel or core product crate. The root `no-std` gate is
blocked until one exists; unblock it in the change that adds that crate. The
tooling `no-std` gate is separately blocked because the `xtask` workspace also
has no kernel or core crate. Unblock it only in the change that adds a
primitive, kernel, or core crate to the `xtask` workspace.

### D5 — Tooling-stage repository-wide scans · `ACCEPTED`

The repository stage runs the placeholder, sleep, changelog, and duplication
scans over the whole tree, including `xtask/`. The tooling stage blocks its
copies so they do not run without the root policy files and ledger; unblock
only if it gains a separate, reviewed tooling policy.
