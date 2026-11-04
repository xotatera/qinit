<!--
SPDX-FileCopyrightText: 2026 Xota Tera
SPDX-License-Identifier: CC-BY-4.0
-->

# Design principles

These principles decide whether a feature belongs in qinit and, if it does, which part owns it.
Each one gives the rule, the reason for it, and a question to ask of a proposal. A proposal that
answers a question wrongly needs a design change, not an exception.

## 1. Stays out of the system

**Rule.** qinit boots and shuts down the machine, and starts, stops, supervises and contains
processes. A feature belongs in qinit only if it is about one of those things and needs PID 1,
ownership of the cgroup tree, or the fd store.

**Reason.** An init system runs on every machine for its whole uptime, and everything in it is
trusted. Each feature added to it is code every user must run and every reviewer must read. Work
that can live in an ordinary program should, so it can be replaced, restarted or left out.

**Question.** Could this run as a separate program over the control protocol? If so, it does not
go in.

## 2. One job per process

**Rule.** queen, colony, overseer and zero each do one job. A feature fits an existing role or
it is not added. The set of programs changes only by an amendment to the design.

**Reason.** A process with one job can be understood, tested and proved on its own, and when it
fails the fault stays inside it. queen only reaps, handles signals and keeps colony running;
colony manages services; overseer launches one compartment and exits; zero brings the machine up
to queen and takes it down after colony.

**Question.** Which one program owns this, and does the feature fit that program's job as
written? If it needs two programs to share state, or a new program, it needs a design change first.

## 3. Contain from birth

**Rule.** Every child starts inside its root-owned cgroup cell (`clone3` with
`CLONE_INTO_CGROUP`) and is tracked by a pidfd. A whole tree is ended with `cgroup.kill`.

**Reason.** A process that is moved into its cgroup after the fork can escape in the meantime,
and a PID number can be reused by an unrelated process. Starting in the cell and holding a pidfd
leaves no window and no guess about which process is meant.

**Question.** Does any process exist, even briefly, outside its cell, or is any process named by
its PID number alone?

## 4. Every wait is bounded

**Rule.** Every lifecycle operation ends on an event or a deadline. Event loops are
single-threaded and blocking work goes to a helper. Nothing waits by sleeping and checking again.

**Reason.** A boot or shutdown that hangs gives the administrator nothing to act on. When every
wait has a deadline, the system can always say what it is waiting for and how long it will wait.
Polling with sleeps is slow when the event comes early and wrong when it comes late.

**Question.** What ends this wait if the event never comes, and how does the operator see it?

## 5. Refuse rather than guess

**Rule.** Input that is invalid or ambiguous is rejected whole, with an error that names it: at
compile time in `qctl`, at load time when colony opens the database, and at decode time in the
overseer. Nothing is repaired, defaulted around or partly applied.

**Reason.** A guess made silently at boot is a behaviour nobody wrote and nobody reviewed. A
rejected configuration is found by the person who wrote it, at the time they wrote it.

**Question.** If this input is wrong, does qinit stop and say so, or does it pick a meaning?

## 6. Proved cores, thin shims

**Rule.** Parsing, planning and policy live in fixed-size `no_std` cores proved with Verus.
Unsafe code is one narrow syscall layer that translates and does not decide. Untrusted input is
never parsed in PID 1.

**Reason.** The decisions that matter, such as dependency order, what a launch may do and which
system calls a sandbox allows, are the ones a proof can cover. Keeping them out of the unsafe
layer means that layer is small enough to read in full.

**Question.** Where does the decision this feature makes live, and is it inside a proved core?

## 7. Open protocol, one plane

**Rule.** Programs outside qinit use the documented control protocol, and so do qinit's own
tools. colony serves one control plane; the overseer launch API is part of it.

**Reason.** If qinit's own tools used private interfaces, outside programs could never do what
they do, and the "separate program" answer in principle 1 would be a dead end. One plane also
means one place to authorize and audit.

**Question.** Could a program outside this repository do the same thing through the protocol?

## 8. Stateless where possible

**Rule.** overseer and zero keep no state. queen keeps only what must outlive colony: the fd
store, the cell directories and the hand-over pidfds. colony can be restarted and re-adopts its
workers instead of starting them again.

**Reason.** State that only one process holds is lost when that process fails. Keeping state small
and in the kernel's own objects (cgroups, pidfds, file descriptors) makes a restart an ordinary
event instead of a recovery.

**Question.** What is lost if this process is restarted now?

## When principles conflict

The principle higher in this list wins:

1. Stays out of the system
2. One job per process
3. Contain from birth
4. Every wait is bounded
5. Refuse rather than guess
6. Proved cores, thin shims
7. Open protocol, one plane
8. Stateless where possible

Convenience, compatibility and requested features do not outrank any of them.

## Patterns qinit does not use

| Pattern | Principle |
|---|---|
| A manager that takes over neighbouring services: logging, networking, logins, timers | 1, 2 |
| One process holding every role and all the state, so that one fault stops everything | 2, 8 |
| Tracking processes by PID number, or moving them into a cgroup after the fork | 3 |
| Sleep-and-poll loops, and waits with no deadline | 4 |
| Behaviour inferred by heuristics, or units generated from other configuration, instead of declared | 5 |
| Repairing or loosely accepting bad configuration | 5 |
| Untrusted parsing, or policy decisions, inside PID 1 or the unsafe layer | 6 |
| Private interfaces between bundled tools that other programs cannot use | 7 |
