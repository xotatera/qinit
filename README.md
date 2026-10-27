> [!IMPORTANT]
> Remove these two lines to confirm that a human has reviewed this change.

# qinit: Queen Init, Native Integrated Tree

qinit is an init and service-supervision system for Linux. It is one design built from separate parts:

- **queen**: PID 1. It is kept small and proved: it reaps children, handles signals and shutdown, and
  starts the hive.
- **colony**: the service manager, which runs as a supervised process. It owns the dependency graph,
  cgroups, transient units and readiness.
- **overseer**: the compartment launcher. It starts process trees in root-owned cgroups with their own
  identity and sandbox, and offers a launch API to other system components.
- **zero**: one binary with early-boot and final-shutdown modes.
- **qctl**: the configuration compiler and administrative CLI.
- **client library**: the library for the control protocol.

Status: cell substrate implemented; no init daemon or service manager is usable yet.

qinit is a standalone project. Alloy Linux consumes it as a package.

## Scope

qinit boots and shuts down the machine, and starts, stops, supervises and contains processes.
A feature belongs in qinit only if it is about one of those things **and** cannot be done well
outside it (it needs PID 1, ownership of the cgroup tree, or the fd store). Everything else is a
separate program that uses qinit's open control protocol. The set of programs above is fixed;
adding one is a design decision, not a patch.

### Cells

Sub-project 2 provides the cell substrate, not a daemon: `qinit-sys` supplies
Linux primitives, `qinit-event` the event loop, `qinit-cell` the cell runtime,
and `qinit-vm` the QEMU guest tests. Verus proves the event and cell core
machines and cell routing. The runtime refuses kernels older than Linux 6.13.

Not part of qinit, now or later:

- a logging daemon or journal (qinit writes its own messages to the kernel log and hands service
  output to pipes for any logger to consume);
- device management, network configuration, name resolution or time synchronization;
- login or session tracking;
- timers, tmpfiles or sysusers handling, container management, home-directory, hostname or
  locale services.

## Licensing

| Part | License |
|---|---|
| queen, colony, overseer, zero and the command-line tools | GPL-3.0-or-later |
| The client library | MPL-2.0 |
| Protocol specifications and prose documentation | CC-BY-4.0 |

Every file carries an SPDX header, or is covered by `REUSE.toml`. The license texts are in
`LICENSES/`. The project follows the [REUSE](https://reuse.software/) specification.

## Development

Status: the cell substrate is implemented and tested; qinit is not usable yet as an init system.

The first implementation sub-project was repository disciplines setup. The pinned
[Rust toolchain](rust-toolchain.toml) is Rust 1.98.1 with `rustfmt` and `clippy`.
The root workspace declares three Verus proofs (`qinit-event-core`,
`qinit-cell-core`, `qinit-cell-drive`). The gate verifies the selected Verus
release `0.2026.10.04.426d8b0` through `cargo-verus` and its paired
`verusfmt` release `0.7.4` (`cargo install --locked verusfmt --version 0.7.4`).
The full gate needs both (see Requirements). Run the complete local gate from the repository
root:

```sh
cargo xtask gate --no-cache
```

This runs the configured repository and tooling checks fresh, fastest first
in one order across both workspaces (`cargo xtask gate --list` prints it), then
the three declared proofs, then the `vm` gate (nine guest suites in QEMU),
and stops at the first failure. Every run of several steps stops at its first
failure, `--only` across both workspaces and `cargo xtask proofs` included.
`cargo xtask proofs` runs only declared proof obligations. Gates are portable
and do not require a host scheduler. There is no CI at this stage.

### Requirements

The gate needs only these on a stock Linux system (Debian stable package
names): `git`, `build-essential` (a C toolchain and `make`), `reuse`, `curl`
and `ca-certificates` (to install rustup), a POSIX `sh`, `qemu-system-x86`,
and to build the guest kernel `make gcc flex bison bc perl libelf-dev
xz-utils unzip util-linux`; Verus 0.2026.10.04.426d8b0 (release zip, see above) and
`cargo install --locked verusfmt --version 0.7.4` now that the workspace has
`verus!` code. Install [rustup](https://rustup.rs) without a default
toolchain; it installs the pinned toolchain from
[`rust-toolchain.toml`](rust-toolchain.toml) on first use.

`sh scripts/container-check.sh [<commit-ish>]` (default `HEAD`) checks this
list: it clones the repository fresh in a pinned Debian stable container,
installs these packages, Verus and verusfmt, and runs the full gate as an
unprivileged user (podman, or docker with `CONTAINER=docker`). It passes
`/dev/kvm` when it opens read-write and verifies the unprivileged builder can
open it too (rootless podman uses the local engine and retains supplementary
groups); set `QINIT_CHECK_KVM=0` to exercise TCG.
Optionally set `QINIT_KERNEL_TARBALL` to a local kernel archive to mount it
read-only instead of downloading it (the guest builder still verifies its
checksum). To check `main` itself, pass `main` by name.

### Hooks

The committed hooks are opt-in; install them only in a clone where you want local checks.

```sh
sh .githooks/setup-hooks.sh
```

The installer refuses a non-default effective `core.hooksPath` and conflicting
existing hooks rather than claiming they are protected. If `core.hooksPath`
points to a hook dispatcher you trust, declare it first with
`git config qinit.hooksDispatcher <path>`, naming the same directory as
`core.hooksPath`. The installer then installs as usual and reminds you that the
dispatcher must chain to `<git-common-dir>/hooks/<hook>`; without that chaining
the hooks never run. It copies qinit-owned
sources into that clone's common Git directory and links the active hooks; rerun
it only to refresh an installation it already recognizes. The hooks enforce the
review canary locally on protected branches and refuse to push a ref whose
README retains it. They are not server-side enforcement.

The first two lines of this README are the review canary. They remain while an
agent change awaits human review; removing them is the human confirmation. The
canary gate fails in the main context, merge hooks refuse a main merge with it,
and the opt-in pre-push hook refuses any outgoing ref that contains it.

### Accepted gate blockers

The complete gate passes while printing these accepted `SKIP`s. They are
intentional, recorded in the single [deferred-work ledger](DEFERRED.md), and
must be resolved with the stated implementation change rather than hidden:

- **D4 — tooling no-std gate:** the tooling workspace has no kernel or core
  crate; its no-std gate waits for one (the root no-std gate runs).
- **D5 — tooling repository-wide scans:** the repository stage already owns the
  placeholder, sleep, changelog, and duplication scans; the tooling stage does
  not duplicate that policy.

### Disciplines traceability

| Relevant design clause | Setup status | Repository evidence |
|---|---|---|
| Approved qinit design §1 fixes qinit's public component scope and keeps unrelated services out. | No product component or additional binary is introduced by this setup. | [DEFERRED.md](DEFERRED.md) D2. |
| Approved qinit design §2 requires Rust, Verus, four layers, event-driven waits, and bounded operations. | Rust is pinned; three Verus core proofs run in the proof tier, and the `vm` gate tests cell transitions after proofs. The `qinit-sys`, `qinit-event`, `qinit-cell` and `qinit-vm` crates implement the substrate, not the daemon. | `rust-toolchain.toml`; `Cargo.toml`; `xtask/runner/src/lib.rs`; `crates/`. |
| Approved qinit design §§3–7 define the queen, colony, overseer, zero, graph, logging, protocol, and shutdown behavior. | These product behaviors remain design-only; this task adds no daemon, protocol, or systemd-derived code. | [Scope](#scope); [DEFERRED.md](DEFERRED.md). |
| Approved qinit design §8 makes disciplines setup the first sub-project: pinned tools; portable format, test, proof, REUSE, and canary gates; opt-in hooks; and no CI. | `cargo xtask gate --no-cache` is the fresh full check; Rust is pinned and declared Verus proofs assert their selected release; the hook installation above is local and optional. | `rust-toolchain.toml`; `xtask/disciplines/src/gates.rs`; `.githooks/setup-hooks.sh`; `xtask/runner/src/lib.rs`; `xtask/runner/tests/repo.rs`. |
| Approved qinit design §9 defers user-session work, adoption/additional binaries/live upgrade, CI, and size budgets. | D1–D2 remain open design deferrals; no CI or size-budget commitment is made. | [DEFERRED.md](DEFERRED.md). |
| Approved qinit design §10 records the research provenance for later implementation. | This public documentation records repository setup evidence and accepted gate blockers; D3 was resolved by the first product crate. Cell-substrate provenance is recorded privately in the workbench. | [Development](#development); [DEFERRED.md](DEFERRED.md). |

qinit is developed with AI assistance. A human reviews every change and takes responsibility for it.
See [CONTRIBUTING.md](CONTRIBUTING.md).
