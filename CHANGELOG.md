<!--
SPDX-FileCopyrightText: 2026 Xota Tera
SPDX-License-Identifier: CC-BY-4.0
-->

# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Guest suites for cells: spawn (placement, exec failure, only routed
  descriptors), ready (pipe, EOF, exit), stop_main, stop_cell (setsid
  escapee, member dying mid-enumeration), escalate, reuse_guard, adopt (with a
  handed-over main process), orphan; `Cells::main_pid`.
- `qinit-cell`: the cell runtime (`Cells`): create, spawn into the cell,
  readiness, polite stop by main pidfd or freeze-signal-thaw with pidfds
  verified by cgroup id, escalation, adoption, removal, orphan reaping as a
  subreaper; refuses kernels below 6.13.
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
  is cancelled.
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

- `cargo xtask gate` runs every gate in one fastest-first order across the
  repository and tooling workspaces, then the proof gates, and stops at the
  first failure, naming the gates it did not run. A failed proof stops new
  proofs from starting. Every other run of several steps (`--only` across
  both workspaces, `cargo xtask proofs`) also stops at its first failure.

### Fixed

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
