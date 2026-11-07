// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Re-adoption after a colony restart: what the new colony makes of the `cells` and `nodes`
//! entries the old one left in queen's store (`docs/colony.md`). Queen held each cell's directory
//! and main pidfd, so nothing is recovered by pid: a descriptor names its process for good. A
//! main is adopted only if its pidfd says it runs and its cgroup id is the recorded one; one
//! that exited has its status read from the pidfd.
use crate::effects::CellOps;
use crate::route::Owner;
use crate::state::{CellLine, NodeLine};
use crate::store::Store;
use crate::syslog::Sev;
use qinit_cell::{CellId, Error as CellError, Failure, Phase};
use qinit_colony::{Counters, Restored, RestoredNode, SavedTerminal};
use qinit_db::{Model, Ready, Route};
use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::{AsRawFd, OwnedFd};

/// What a main's pidfd says about it now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MainNow {
    /// It runs, or has exited and not been reaped yet: its pid.
    Alive(i32),
    /// It exited and was reaped, with this wait status.
    Exited(i32),
    /// Nothing is left of it.
    Gone,
}

/// What colony may ask of the process table. A trait so the host tests can answer for pidfds
/// that name no process.
pub trait Procs {
    /// What the process behind `pidfd` is doing.
    fn main_now(&self, pidfd: &OwnedFd) -> MainNow;
    /// The cgroup id of the process behind `pidfd`.
    fn cgroup_id(&self, pidfd: &OwnedFd) -> Option<u64>;
}

/// The real process table.
pub struct RealProcs;

impl Procs for RealProcs {
    fn main_now(&self, pidfd: &OwnedFd) -> MainNow {
        if let Ok(qinit_sys::proc::PidfdExit::Exited(status)) = qinit_sys::proc::pidfd_exit(pidfd) {
            return MainNow::Exited(status);
        }
        std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))
            .ok()
            .and_then(|info| qinit_cell::text::parse_fdinfo_pid(&info))
            .map_or(MainNow::Gone, MainNow::Alive)
    }

    fn cgroup_id(&self, pidfd: &OwnedFd) -> Option<u64> {
        qinit_sys::proc::pidfd_cgroup_id(pidfd).ok()
    }
}

/// The descriptors queen handed over, each to be taken once.
pub trait Held {
    fn take(&mut self, key: u64) -> Option<OwnedFd>;
}

impl Held for Store {
    fn take(&mut self, key: u64) -> Option<OwnedFd> {
        Store::take(self, key)
    }
}

/// A cell adopted for a node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adopted {
    pub id: CellId,
    pub owner: Owner,
    pub name: String,
    /// The store keys the cell is held under; `main_key` is 0 when no main was adopted.
    pub dir_key: u64,
    pub main_key: u64,
}

/// What re-adoption decided.
#[derive(Debug, Default)]
pub struct Plan {
    /// The node table to restore: adopted nodes and the saved state of the rest.
    pub restored: Vec<RestoredNode>,
    /// Adopted nodes to stop and start again (M6): a readiness source or a pipe that died with
    /// the old colony.
    pub restart: Vec<u32>,
    /// Adopted nodes whose main exited while colony was away, with the status the kernel recorded
    /// (`None` when it is unknown): colony reports the exit itself, since a cell adopted without
    /// a main never does.
    pub exited: Vec<(u32, Option<i32>)>,
    /// Keys queen holds that the state does not name after all (a main not adopted, a cell not
    /// kept): to be forgotten once the state is saved.
    pub dropped: Vec<u64>,
    /// Cells to stop and remove: instances, and cells of nodes the database no longer has.
    pub clear: Vec<CellId>,
    /// The first instance id that no cell in the map uses.
    pub next_instance: u32,
    /// Every adopted node cell, for the routing table.
    pub adopted: Vec<Adopted>,
    /// What to log.
    pub notes: Vec<(Sev, String)>,
}

/// The node indices whose logger pipe was not held: loggers and their producers.
fn unheld_pipe_nodes(model: &Model, held: &BTreeSet<String>) -> BTreeSet<u32> {
    let mut set = BTreeSet::new();
    for (i, n) in model.nodes.iter().enumerate() {
        let ix = u32::try_from(i).unwrap_or(u32::MAX);
        for r in [n.output, n.errors].into_iter().flatten() {
            if let Some(Route::Pipe(logger)) = model.routes.get(r as usize)
                && let Some(l) = model.nodes.get(*logger as usize)
                && !held.contains(&l.name)
            {
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

/// One entry per node: the file's state, with the adopted cell's phase where there is one.
fn restored_entries(
    saved: &BTreeMap<&str, &NodeLine>,
    by_name: &BTreeMap<&str, u32>,
    cell_of: &BTreeMap<u32, (Restored, Option<i32>)>,
) -> Vec<RestoredNode> {
    let mut entries: BTreeMap<u32, RestoredNode> = BTreeMap::new();
    for (name, line) in saved {
        if let Some(&ix) = by_name.get(name) {
            let (phase, pid) = cell_of.get(&ix).copied().unwrap_or(match line.terminal {
                None => (Restored::Off, None),
                Some(SavedTerminal::Done) => (Restored::Done, None),
                Some(SavedTerminal::Quarantined(r)) => (Restored::Quarantined(r), None),
            });
            entries.insert(
                ix,
                RestoredNode {
                    node: ix,
                    wanted: line.wanted,
                    phase,
                    pid,
                    counters: line.counters,
                },
            );
        }
    }
    for (&ix, &(phase, pid)) in cell_of {
        entries.entry(ix).or_insert(RestoredNode {
            node: ix,
            wanted: true,
            phase,
            pid,
            counters: Counters::default(),
        });
    }
    entries.into_values().collect()
}

/// What became of a cell's main, as far as adoption can tell.
#[derive(Clone, Copy)]
enum Main {
    Alive(i32),
    Exited(i32),
    Gone,
}

/// Adopts the cells of `cells` through `ops` from the descriptors in `held`, and decides what
/// becomes of each (spec §8.2, steps 1 to 3), and what to restore for the nodes that have no
/// cell. `pipes` names the logger pipes that were held: their nodes need no restart.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // one pass over the cells, as the spec reads
pub fn plan(
    cells: &[CellLine],
    nodes: Option<&[NodeLine]>,
    pipes: &BTreeSet<String>,
    model: &Model,
    held: &mut impl Held,
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
    let unheld = unheld_pipe_nodes(model, pipes);
    let saved: BTreeMap<&str, &NodeLine> = nodes
        .unwrap_or_default()
        .iter()
        .map(|n| (n.name.as_str(), n))
        .collect();
    let mut out = Plan {
        next_instance: 1,
        ..Plan::default()
    };
    let mut cell_of: BTreeMap<u32, (Restored, Option<i32>)> = BTreeMap::new();

    for line in cells {
        if let Some(id) = instance_id(&line.name) {
            out.next_instance = out.next_instance.max(id.saturating_add(1));
        }
        let node = if line.name.contains('#') {
            None
        } else {
            by_name.get(line.name.as_str()).copied()
        };
        let Some(dir) = held.take(line.dir_key) else {
            out.notes.push((
                Sev::Err,
                format!(
                    "the cell {} has no directory descriptor held: dropped",
                    line.name
                ),
            ));
            continue;
        };
        // A node's main is looked at through its pidfd: it runs here, or it does not.
        let main_fd = node
            .filter(|_| line.main_key != 0)
            .and_then(|_| held.take(line.main_key));
        let (main_fd, mut now) = match main_fd {
            Some(fd) => match procs.main_now(&fd) {
                MainNow::Alive(pid) if procs.cgroup_id(&fd) == Some(line.cgroup_id) => {
                    (Some(fd), Main::Alive(pid))
                }
                MainNow::Exited(status) => (None, Main::Exited(status)),
                _ => (None, Main::Gone),
            },
            None => (None, Main::Gone),
        };
        // A main reaped between the look and the adoption is an exit: adopt without it.
        let retry_dir = dir.try_clone().ok();
        let first = ops.adopt_held(
            &line.name,
            line.cgroup_id,
            dir,
            main_fd.as_ref().and_then(|f| f.try_clone().ok()),
        );
        let id = match (first, &main_fd, retry_dir) {
            (Err(CellError::Sys(qinit_sys::Errno(libc::ESRCH))), Some(fd), Some(dir)) => {
                now = match procs.main_now(fd) {
                    MainNow::Exited(status) => Main::Exited(status),
                    _ => Main::Gone,
                };
                ops.adopt_held(&line.name, line.cgroup_id, dir, None)
            }
            (r, _, _) => r,
        };
        let id = match id {
            Ok(id) => id,
            Err(e) => {
                out.notes.push((
                    Sev::Err,
                    format!("cannot adopt the cell {}: {e}", line.name),
                ));
                out.dropped.extend([line.dir_key, line.main_key]);
                continue;
            }
        };
        let had_main = matches!(now, Main::Alive(_));
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
            out.dropped.extend([line.dir_key, line.main_key]);
            continue;
        }
        let Some(ix) = node else {
            out.notes.push((
                Sev::Info,
                format!("the cell {} belongs to nothing now: stopping it", line.name),
            ));
            out.clear.push(id);
            out.dropped.extend([line.dir_key, line.main_key]);
            continue;
        };
        out.adopted.push(Adopted {
            id,
            owner: Owner::Node(ix),
            name: line.name.clone(),
            dir_key: line.dir_key,
            main_key: if had_main { line.main_key } else { 0 },
        });
        if !had_main {
            out.dropped.push(line.main_key);
        }
        let pipe_lost = unheld.contains(&ix);
        let exit_ready = model
            .nodes
            .get(ix as usize)
            .is_some_and(|n| matches!(n.ready, Ready::Exit));
        let (phase, restart, exited) = match (line.ready, now) {
            (true, Main::Alive(_)) => (Restored::Ready, pipe_lost, None),
            (true, Main::Exited(s)) => (Restored::Ready, pipe_lost, Some(Some(s))),
            (true, Main::Gone) => (Restored::Ready, pipe_lost, Some(None)),
            (false, Main::Alive(_)) if exit_ready => (Restored::Starting, pipe_lost, None),
            (false, Main::Exited(s)) if exit_ready => (Restored::Starting, false, Some(Some(s))),
            (false, _) => (Restored::Starting, true, None),
        };
        if restart {
            out.restart.push(ix);
        }
        if let Some(status) = exited {
            out.exited.push((ix, status));
        }
        let pid = match now {
            Main::Alive(pid) => Some(pid),
            _ => None,
        };
        cell_of.insert(ix, (phase, pid));
    }
    out.dropped.retain(|k| *k != 0);

    out.restored = restored_entries(&saved, &by_name, &cell_of);
    out
}
