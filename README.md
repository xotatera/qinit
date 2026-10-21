# qinit — Queen Init: Native Integrated Tree

An init and service-supervision system for Linux, built as one design with separate parts:

- **queen**: PID 1. Small and proved: it reaps, handles signals and shutdown, and starts the hive.
- **hivemind**: the service manager, a supervised process. It owns the dependency graph, cgroups,
  transient units and readiness.
- **overseer**: the compartment launcher. It starts processes in root-owned cgroups with their own
  identity and sandbox, and offers a launch API to other system components.
- **zero**: stage zero (early boot and/or final shutdown); its role is decided during design.

Status: design. Nothing here is usable yet. Research and specs live under `docs/`.

qinit is a standalone project. Alloy Linux consumes it as a package.
