// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Re-adoption after a colony restart: what the new colony makes of the `cells` and `nodes` files
//! the old one left (`docs/colony.md`). Cells are adopted in an order that never lets a pid
//! stand for a process by itself: the main is recovered first, by pid, start time and cgroup id,
//! and only then is the cell adopted with it.
use crate::effects::CellOps;
use crate::route::Owner;
use crate::state::{CellLine, NodeLine};
use crate::syslog::Sev;
use qinit_cell::{CellId, Failure, Phase};
use qinit_colony::{Counters, Restored, RestoredNode, SavedTerminal};
use qinit_db::{Model, Ready, Route};
use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::OwnedFd;

/// What colony may ask of the process table. A trait so the host tests can answer for pids that
/// do not exist.
pub trait Procs {
    /// A pidfd for `pid`, if such a process exists now.
    fn pidfd(&self, pid: i32) -> Option<OwnedFd>;
    /// Field 22 of `/proc/<pid>/stat`.
    fn start_time(&self, pid: i32) -> Option<u64>;
    /// The cgroup id of the process behind `pidfd`.
    fn cgroup_id(&self, pidfd: &OwnedFd) -> Option<u64>;
}

/// The real process table.
pub struct RealProcs;

impl Procs for RealProcs {
    fn pidfd(&self, pid: i32) -> Option<OwnedFd> {
        qinit_sys::proc::pidfd_open(pid).ok()
    }

    fn start_time(&self, pid: i32) -> Option<u64> {
        crate::state::start_time(pid)
    }

    fn cgroup_id(&self, pidfd: &OwnedFd) -> Option<u64> {
        qinit_sys::proc::pidfd_cgroup_id(pidfd).ok()
    }
}

/// A cell adopted for a node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adopted {
    pub id: CellId,
    pub owner: Owner,
    pub name: String,
}

/// What re-adoption decided.
#[derive(Debug, Default)]
pub struct Plan {
    /// The node table to restore: adopted nodes and the saved state of the rest.
    pub restored: Vec<RestoredNode>,
    /// Adopted nodes to stop and start again (M6): a readiness source or a pipe that died with
    /// the old colony.
    pub restart: Vec<u32>,
    /// Adopted nodes whose main exited while colony was away (M7): colony reports the exit
    /// itself, since a cell adopted without a main never does.
    pub exited: Vec<u32>,
    /// Cells to stop and remove: instances, and cells of nodes the database no longer has.
    pub clear: Vec<CellId>,
    /// The first instance id that no cell in the map uses.
    pub next_instance: u32,
    /// Every adopted node cell, for the routing table.
    pub adopted: Vec<Adopted>,
    /// What to log.
    pub notes: Vec<(Sev, String)>,
}

/// The node indices that a pipe route touches: loggers and their producers.
fn pipe_nodes(model: &Model) -> BTreeSet<u32> {
    let mut set = BTreeSet::new();
    for (i, n) in model.nodes.iter().enumerate() {
        let ix = u32::try_from(i).unwrap_or(u32::MAX);
        for r in [n.output, n.errors].into_iter().flatten() {
            if let Some(Route::Pipe(logger)) = model.routes.get(r as usize) {
                set.insert(*logger);
                set.insert(ix);
            }
        }
    }
    set
}

/// The id of an instance cell name (`<frame>#<id>` or `~<name>#<id>`).
fn instance_id(name: &str) -> Option<u32> {
    name.rsplit_once('#')?.1.parse().ok()
}

/// Recovers the main of `line`, or says why not: the pidfd, the start time and the cgroup id must
/// all be the recorded ones.
fn recover_main(line: &CellLine, procs: &impl Procs) -> Option<OwnedFd> {
    if line.pid <= 0 {
        return None;
    }
    // The pidfd first: from here on the process is named by it, whatever happens to the pid.
    let fd = procs.pidfd(line.pid)?;
    if procs.start_time(line.pid)? != line.start_time {
        return None;
    }
    if procs.cgroup_id(&fd)? != line.cgroup_id {
        return None;
    }
    Some(fd)
}

/// One entry per node: the file's state, with the adopted cell's phase where there is one.
fn restored_entries(
    saved: &BTreeMap<&str, &NodeLine>,
    by_name: &BTreeMap<&str, u32>,
    cell_of: &BTreeMap<u32, Restored>,
) -> Vec<RestoredNode> {
    let mut entries: BTreeMap<u32, RestoredNode> = BTreeMap::new();
    for (name, line) in saved {
        if let Some(&ix) = by_name.get(name) {
            let phase = cell_of.get(&ix).copied().unwrap_or(match line.terminal {
                None => Restored::Off,
                Some(SavedTerminal::Done) => Restored::Done,
                Some(SavedTerminal::Quarantined(r)) => Restored::Quarantined(r),
            });
            entries.insert(
                ix,
                RestoredNode {
                    node: ix,
                    wanted: line.wanted,
                    phase,
                    counters: line.counters,
                },
            );
        }
    }
    for (&ix, &phase) in cell_of {
        entries.entry(ix).or_insert(RestoredNode {
            node: ix,
            wanted: true,
            phase,
            counters: Counters::default(),
        });
    }
    entries.into_values().collect()
}

/// Adopts the cells of `cells` through `ops` and decides what becomes of each (spec §8.2, steps 1
/// to 3), and what to restore for the nodes that have no cell.
pub fn plan(
    cells: &[CellLine],
    nodes: Option<&[NodeLine]>,
    model: &Model,
    ops: &mut impl CellOps,
    procs: &impl Procs,
    _now_ms: u64,
) -> Plan {
    let by_name: BTreeMap<&str, u32> = model
        .nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (n.name.as_str(), u32::try_from(i).unwrap_or(u32::MAX)))
        .collect();
    let piped = pipe_nodes(model);
    let saved: BTreeMap<&str, &NodeLine> = nodes
        .unwrap_or_default()
        .iter()
        .map(|n| (n.name.as_str(), n))
        .collect();
    let mut out = Plan {
        next_instance: 1,
        ..Plan::default()
    };
    let mut cell_of: BTreeMap<u32, Restored> = BTreeMap::new();

    for line in cells {
        if let Some(id) = instance_id(&line.name) {
            out.next_instance = out.next_instance.max(id.saturating_add(1));
        }
        let node = if line.name.contains('#') {
            None
        } else {
            by_name.get(line.name.as_str()).copied()
        };
        // A cell to clear is adopted without a main; a node's gets its main first.
        let main = node.and_then(|_| recover_main(line, procs));
        let had_main = main.is_some();
        let id = match ops.adopt(&line.name, line.cgroup_id, main) {
            Ok(id) => id,
            Err(e) => {
                out.notes.push((
                    Sev::Err,
                    format!("cannot adopt the cell {}: {e}", line.name),
                ));
                continue;
            }
        };
        if matches!(
            ops.phase(id),
            Some(Phase::Failed(Failure::IdMismatch)) | None
        ) {
            out.notes.push((
                Sev::Err,
                format!(
                    "the cell {} is not the one colony recorded (its cgroup id differs or it is gone): left alone",
                    line.name
                ),
            ));
            // Only the table slot goes back; the directory is not ours to touch.
            let _ = ops.remove(id);
            continue;
        }
        let Some(ix) = node else {
            out.notes.push((
                Sev::Info,
                format!("the cell {} belongs to nothing now: stopping it", line.name),
            ));
            out.clear.push(id);
            continue;
        };
        out.adopted.push(Adopted {
            id,
            owner: Owner::Node(ix),
            name: line.name.clone(),
        });
        let piped = piped.contains(&ix);
        let exit_ready = model
            .nodes
            .get(ix as usize)
            .is_some_and(|n| matches!(n.ready, Ready::Exit));
        let (phase, restart, exited) = match (line.ready, had_main) {
            (true, true) => (Restored::Ready, piped, false),
            (true, false) => (Restored::Ready, piped, true),
            (false, true) if exit_ready => (Restored::Starting, piped, false),
            (false, _) => (Restored::Starting, true, false),
        };
        if restart {
            out.restart.push(ix);
        }
        if exited {
            out.exited.push(ix);
        }
        cell_of.insert(ix, phase);
    }

    out.restored = restored_entries(&saved, &by_name, &cell_of);
    out
}
