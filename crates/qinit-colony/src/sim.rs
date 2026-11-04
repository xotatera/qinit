// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! A deterministic [`Effects`] for host tests: it records every call, answers from per-node
//! scripts, and runs on virtual time that only [`advance`] moves. No cgroup, process or clock is
//! touched, and nothing sleeps.

use crate::effects::{Effects, Errno, InstanceSpec, NodeSpec};
use crate::engine::{Colony, Notice, Outcome};
use crate::handle::WaitId;
use qinit_cell_core::{Failure, Report as CellPhase};
use qinit_colony_core::{StopMode, TimerKind};
use std::collections::{BTreeMap, HashMap, HashSet};

/// What a simulated node does once started.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Script {
    /// Milliseconds after the start until the ready line; `None` never.
    pub ready_after_ms: Option<u64>,
    /// Milliseconds after the start until the main process exits, and with what status.
    pub exit_after: Option<(u64, Option<i32>)>,
    /// The ready pipe closes without a ready line, this many milliseconds after the start.
    pub not_ready_after_ms: Option<u64>,
    /// The program does not exist: the spawn fails.
    pub spawn_fails: bool,
    /// The polite stop does nothing: the cell is empty only after the grace period.
    pub ignore_term: bool,
    /// The cell cannot be killed: the stop ends in a failed cell after the grace period.
    pub stop_fails: bool,
}

impl Default for Script {
    /// Ready at once, runs until stopped, stops at once.
    fn default() -> Self {
        Script {
            ready_after_ms: Some(0),
            exit_after: None,
            not_ready_after_ms: None,
            spawn_fails: false,
            ignore_term: false,
            stop_fails: false,
        }
    }
}

/// One call colony made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    Start(u32),
    Stop(u32, StopMode, u32),
    Release(u32),
    Watch(String),
    Arm(u32, TimerKind, u32),
    Cancel(u32, TimerKind),
    Signal(u32, i32),
    StartInstance(u32, String),
    StopInstance(u32, StopMode, u32),
    ReleaseInstance(u32),
    ArmWait(u64, u32),
    CancelWait(u64),
}

/// A timer kind as a map key.
fn timer_id(t: TimerKind) -> u8 {
    match t {
        TimerKind::StartTimeout => 0,
        TimerKind::Backoff => 1,
        TimerKind::Edge => 2,
    }
}

enum Due {
    Timer(u32, TimerKind),
    Cell(u32, CellPhase),
    Instance(u32, CellPhase),
    Wait(u64),
}

/// The simulation.
#[derive(Default)]
pub struct Sim {
    pub calls: Vec<Call>,
    /// Every start as `(node, virtual time in ms)`.
    pub starts: Vec<(u32, u64)>,
    /// The script of each node; a node without one runs the default.
    pub scripts: HashMap<u32, Script>,
    /// Paths that exist.
    pub paths: HashSet<String>,
    /// Starts of these nodes fail with ENOENT before spawning.
    pub fail_start: HashSet<u32>,
    /// `arm_wait` fails with errno 11: the effects layer cannot give a wait a deadline.
    pub fail_arm_wait: bool,
    /// What every instance does once started; a test sets it before it launches.
    pub instance_script: Script,
    /// Instance slots that have a cell.
    pub instance_cells: HashSet<u32>,
    /// The descriptors each started instance was given, by slot.
    pub instance_fds: HashMap<u32, Vec<std::os::fd::OwnedFd>>,
    /// Nodes that have a cell. A start that succeeds adds the node, `release` removes it; a
    /// test that adopts a node adds it by hand. `stop` of a node without one does nothing, as
    /// the cell layer refuses it.
    pub cells: HashSet<u32>,
    now: u64,
    seq: u64,
    due: BTreeMap<(u64, u64), Due>,
    /// Pending cell events of a node, so a stop can drop the stale ones.
    cell_events: HashMap<u32, Vec<(u64, u64)>>,
    instance_events: HashMap<u32, Vec<(u64, u64)>>,
    timers: HashMap<(u32, u8), (u64, u64)>,
    wait_timers: HashMap<u64, (u64, u64)>,
}

impl Sim {
    #[must_use]
    pub fn new() -> Sim {
        Sim::default()
    }

    /// Whether any timer or cell event is still due.
    #[must_use]
    pub fn pending(&self) -> bool {
        !self.due.is_empty()
    }

    /// The virtual time in milliseconds.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.now
    }

    fn schedule(&mut self, at: u64, what: Due) -> (u64, u64) {
        self.seq += 1;
        let key = (at, self.seq);
        self.due.insert(key, what);
        key
    }

    fn cell_event(&mut self, node: u32, at: u64, report: CellPhase) {
        let key = self.schedule(at, Due::Cell(node, report));
        self.cell_events.entry(node).or_default().push(key);
    }

    fn instance_event(&mut self, slot: u32, at: u64, report: CellPhase) {
        let key = self.schedule(at, Due::Instance(slot, report));
        self.instance_events.entry(slot).or_default().push(key);
    }

    fn drop_instance_events(&mut self, slot: u32) {
        for key in self.instance_events.remove(&slot).unwrap_or_default() {
            self.due.remove(&key);
        }
    }

    fn drop_cell_events(&mut self, node: u32) {
        for key in self.cell_events.remove(&node).unwrap_or_default() {
            self.due.remove(&key);
        }
    }

    /// The calls of `node`, in order.
    #[must_use]
    pub fn calls_of(&self, node: u32) -> Vec<Call> {
        self.calls
            .iter()
            .filter(|c| match c {
                Call::Start(n)
                | Call::Stop(n, _, _)
                | Call::Release(n)
                | Call::Arm(n, _, _)
                | Call::Cancel(n, _)
                | Call::Signal(n, _) => *n == node,
                Call::Watch(_)
                | Call::StartInstance(..)
                | Call::StopInstance(..)
                | Call::ReleaseInstance(_)
                | Call::ArmWait(..)
                | Call::CancelWait(_) => false,
            })
            .cloned()
            .collect()
    }
}

impl Effects for Sim {
    fn start(&mut self, node: u32, _spec: &NodeSpec) -> Result<i32, Errno> {
        self.calls.push(Call::Start(node));
        self.starts.push((node, self.now));
        self.drop_cell_events(node);
        let script = self.scripts.get(&node).cloned().unwrap_or_default();
        if script.spawn_fails || self.fail_start.contains(&node) {
            return Err(Errno(2));
        }
        self.cells.insert(node);
        let t = self.now;
        self.cell_event(node, t, CellPhase::Running);
        if let Some(ms) = script.ready_after_ms {
            self.cell_event(node, t + ms, CellPhase::Ready);
        }
        if let Some(ms) = script.not_ready_after_ms {
            self.cell_event(node, t + ms, CellPhase::NotReady);
        }
        if let Some((ms, status)) = script.exit_after {
            self.cell_event(node, t + ms, CellPhase::MainExited(status));
        }
        Ok(1000 + i32::try_from(node).unwrap_or(0))
    }

    fn start_instance(&mut self, slot: u32, spec: InstanceSpec) -> Result<i32, Errno> {
        self.calls
            .push(Call::StartInstance(slot, spec.name.clone()));
        self.drop_instance_events(slot);
        let script = self.instance_script.clone();
        if script.spawn_fails {
            return Err(Errno(2));
        }
        self.instance_cells.insert(slot);
        self.instance_fds
            .insert(slot, spec.fds.into_iter().flatten().collect());
        let t = self.now;
        self.instance_event(slot, t, CellPhase::Running);
        if let Some((ms, status)) = script.exit_after {
            self.instance_event(slot, t + ms, CellPhase::MainExited(status));
        }
        Ok(5000 + i32::try_from(slot).unwrap_or(0))
    }

    fn stop_instance(&mut self, slot: u32, mode: StopMode, grace_ms: u32) -> Result<(), Errno> {
        self.calls.push(Call::StopInstance(slot, mode, grace_ms));
        if !self.instance_cells.contains(&slot) {
            return Ok(());
        }
        self.drop_instance_events(slot);
        let t = self.now;
        let after = if self.instance_script.ignore_term {
            u64::from(grace_ms)
        } else {
            0
        };
        self.instance_event(slot, t + after, CellPhase::Empty);
        Ok(())
    }

    fn release_instance(&mut self, slot: u32) {
        self.calls.push(Call::ReleaseInstance(slot));
        self.instance_cells.remove(&slot);
        self.drop_instance_events(slot);
    }

    fn stop(&mut self, node: u32, mode: StopMode, grace_ms: u32) -> Result<(), Errno> {
        self.calls.push(Call::Stop(node, mode, grace_ms));
        if !self.cells.contains(&node) {
            return Ok(());
        }
        self.drop_cell_events(node);
        let script = self.scripts.get(&node).cloned().unwrap_or_default();
        let t = self.now;
        if script.stop_fails {
            self.cell_event(
                node,
                t + u64::from(grace_ms),
                CellPhase::Failed(Failure::Kill),
            );
        } else if script.ignore_term {
            self.cell_event(node, t + u64::from(grace_ms), CellPhase::Empty);
        } else {
            self.cell_event(node, t, CellPhase::Empty);
        }
        Ok(())
    }

    fn release(&mut self, node: u32) {
        self.calls.push(Call::Release(node));
        self.cells.remove(&node);
    }

    fn watch_path(&mut self, path: &str) -> Result<bool, Errno> {
        self.calls.push(Call::Watch(path.to_owned()));
        Ok(self.paths.contains(path))
    }

    fn arm(&mut self, node: u32, timer: TimerKind, ms: u32) -> Result<(), Errno> {
        self.calls.push(Call::Arm(node, timer, ms));
        if let Some(key) = self.timers.remove(&(node, timer_id(timer))) {
            self.due.remove(&key);
        }
        let key = self.schedule(self.now + u64::from(ms), Due::Timer(node, timer));
        self.timers.insert((node, timer_id(timer)), key);
        Ok(())
    }

    fn remap(&mut self, map: &[u32]) {
        // New index of each old node that survives.
        let new_of: HashMap<u32, u32> = map
            .iter()
            .enumerate()
            .filter(|(_, old)| **old != u32::MAX)
            .map(|(new, &old)| (old, u32::try_from(new).unwrap_or(u32::MAX)))
            .collect();
        let gone: Vec<(u64, u64)> = self
            .due
            .iter()
            .filter(|(_, what)| match what {
                Due::Timer(n, _) | Due::Cell(n, _) => !new_of.contains_key(n),
                Due::Instance(..) | Due::Wait(_) => false,
            })
            .map(|(k, _)| *k)
            .collect();
        for key in gone {
            self.due.remove(&key);
        }
        for what in self.due.values_mut() {
            match what {
                Due::Timer(n, _) | Due::Cell(n, _) => *n = new_of[n],
                Due::Instance(..) | Due::Wait(_) => {}
            }
        }
        let rekey = |n: &u32| new_of.get(n).copied();
        self.cells = self.cells.iter().filter_map(rekey).collect();
        self.fail_start = self.fail_start.iter().filter_map(rekey).collect();
        self.scripts = self
            .scripts
            .drain()
            .filter_map(|(n, s)| new_of.get(&n).map(|&m| (m, s)))
            .collect();
        self.cell_events = self
            .cell_events
            .drain()
            .filter_map(|(n, k)| new_of.get(&n).map(|&m| (m, k)))
            .collect();
        self.timers = self
            .timers
            .drain()
            .filter_map(|((n, t), k)| new_of.get(&n).map(|&m| ((m, t), k)))
            .collect();
    }

    fn arm_wait(&mut self, wait: u64, ms: u32) -> Result<(), Errno> {
        self.calls.push(Call::ArmWait(wait, ms));
        if self.fail_arm_wait {
            return Err(Errno(11));
        }
        let key = self.schedule(self.now + u64::from(ms), Due::Wait(wait));
        self.wait_timers.insert(wait, key);
        Ok(())
    }

    fn cancel_wait(&mut self, wait: u64) {
        self.calls.push(Call::CancelWait(wait));
        if let Some(key) = self.wait_timers.remove(&wait) {
            self.due.remove(&key);
        }
    }

    fn signal(&mut self, node: u32, sig: i32) -> Result<(), Errno> {
        self.calls.push(Call::Signal(node, sig));
        Ok(())
    }

    fn cancel(&mut self, node: u32, timer: TimerKind) -> Result<(), Errno> {
        self.calls.push(Call::Cancel(node, timer));
        if let Some(key) = self.timers.remove(&(node, timer_id(timer))) {
            self.due.remove(&key);
        }
        Ok(())
    }
}

/// Delivers the earliest timer or cell event due at or before `target` to `colony`, moving the
/// clock to its time. `None` when none is due.
pub fn deliver_next(colony: &mut Colony<Sim>, target: u64) -> Option<Outcome> {
    let key = colony
        .effects
        .due
        .range(..=(target, u64::MAX))
        .next()
        .map(|(k, _)| *k)?;
    let what = colony.effects.due.remove(&key)?;
    colony.effects.now = key.0;
    Some(match what {
        Due::Timer(node, timer) => {
            colony.effects.timers.remove(&(node, timer_id(timer)));
            colony.on_deadline(node, timer, key.0)
        }
        Due::Cell(node, report) => colony.on_cell(node, report, key.0),
        Due::Instance(slot, report) => colony.on_instance(slot, report, key.0),
        Due::Wait(id) => {
            colony.effects.wait_timers.remove(&id);
            colony.on_wait_deadline(WaitId(id), key.0)
        }
    })
}

/// As [`advance`], but returns everything the events produced: notices, errors and the replies
/// of parked waits.
pub fn advance_outcome(colony: &mut Colony<Sim>, ms: u64) -> Outcome {
    let target = colony.effects.now + ms;
    let mut all = Outcome::default();
    while let Some(out) = deliver_next(colony, target) {
        all.notices.extend(out.notices);
        all.errors.extend(out.errors);
        all.replies.extend(out.replies);
    }
    colony.effects.now = target;
    all
}

/// Moves virtual time forward by `ms`, delivering every timer and cell event that falls due, in
/// order, to `colony`. Returns the notices they produced.
pub fn advance(colony: &mut Colony<Sim>, ms: u64) -> Vec<Notice> {
    let target = colony.effects.now + ms;
    let mut notices = Vec::new();
    while let Some(out) = deliver_next(colony, target) {
        notices.extend(out.notices);
    }
    colony.effects.now = target;
    notices
}
