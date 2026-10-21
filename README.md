# qinit: Queen Init, Native Integrated Tree

qinit is an init and service-supervision system for Linux. It is one design built from separate parts:

- **queen**: PID 1. It is kept small and proved: it reaps children, handles signals and shutdown, and
  starts the hive.
- **hivemind**: the service manager, which runs as a supervised process. It owns the dependency graph,
  cgroups, transient units and readiness.
- **overseer**: the compartment launcher. It starts process trees in root-owned cgroups with their own
  identity and sandbox, and offers a launch API to other system components.
- **zero**: stage zero (early boot and/or final shutdown). Its role will be decided during design.

Status: design. Nothing here is usable yet.

qinit is a standalone project. Alloy Linux consumes it as a package.

## Licensing

| Part | License |
|---|---|
| queen, hivemind, overseer, zero and the command-line tools | GPL-3.0-or-later |
| The client library | MPL-2.0 |
| Protocol specifications and prose documentation | CC-BY-4.0 |

Every file carries an SPDX header, or is covered by `REUSE.toml`. The license texts are in
`LICENSES/`. The project follows the [REUSE](https://reuse.software/) specification.

## Development

qinit is developed with AI assistance. A human reviews every change and takes responsibility for it.
See [CONTRIBUTING.md](CONTRIBUTING.md).
