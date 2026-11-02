// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! A deterministic [`Effects`] for host tests: it records every call, answers from per-node
//! scripts, and runs on virtual time that only [`advance`] moves. No cgroup, process or clock is
//! touched, and nothing sleeps.

use crate::effects::{Effects, Errno, NodeSpec};
use crate::engine::{Colony, Notice};
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
    now: u64,
    seq: u64,
    due: BTreeMap<(u64, u64), Due>,
    /// Pending cell events of a node, so a stop can drop the stale ones.
    cell_events: HashMap<u32, Vec<(u64, u64)>>,
    timers: HashMap<(u32, u8), (u64, u64)>,
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
                | Call::Cancel(n, _) => *n == node,
                Call::Watch(_) => false,
            })
            .cloned()
            .collect()
    }
}

impl Effects for Sim {
    fn start(&mut self, node: u32, _spec: &NodeSpec) -> Result<(), Errno> {
        self.calls.push(Call::Start(node));
        self.starts.push((node, self.now));
        self.drop_cell_events(node);
        let script = self.scripts.get(&node).cloned().unwrap_or_default();
        if script.spawn_fails || self.fail_start.contains(&node) {
            return Err(Errno(2));
        }
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
        Ok(())
    }

    fn stop(&mut self, node: u32, mode: StopMode, grace_ms: u32) -> Result<(), Errno> {
        self.calls.push(Call::Stop(node, mode, grace_ms));
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

    fn cancel(&mut self, node: u32, timer: TimerKind) -> Result<(), Errno> {
        self.calls.push(Call::Cancel(node, timer));
        if let Some(key) = self.timers.remove(&(node, timer_id(timer))) {
            self.due.remove(&key);
        }
        Ok(())
    }
}

/// Moves virtual time forward by `ms`, delivering every timer and cell event that falls due, in
/// order, to `colony`. Returns the notices they produced.
pub fn advance(colony: &mut Colony<Sim>, ms: u64) -> Vec<Notice> {
    let target = colony.effects.now + ms;
    let mut notices = Vec::new();
    while let Some(key) = colony
        .effects
        .due
        .range(..=(target, u64::MAX))
        .next()
        .map(|(k, _)| *k)
    {
        let Some(what) = colony.effects.due.remove(&key) else {
            break;
        };
        colony.effects.now = key.0;
        let out = match what {
            Due::Timer(node, timer) => {
                colony.effects.timers.remove(&(node, timer_id(timer)));
                colony.on_deadline(node, timer, key.0)
            }
            Due::Cell(node, report) => colony.on_cell(node, report, key.0),
        };
        notices.extend(out.notices);
    }
    colony.effects.now = target;
    notices
}
