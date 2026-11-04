// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The runtime around the proved core: owns the tables, feeds the core one input at a time,
//! drains its actions into [`Effects`], and turns effect failures into inputs.

use crate::effects::{Effects, Errno, NodeSpec};
use crate::text;
use qinit_cell_core::{Failure, Report as CellPhase};
use qinit_colony_core::{
    Action, CellReport, Input, MAX_SLOTS, Meta, NodeState, Params, Report, Request, Slot,
    SlotState, State, StopMode, TimerKind, free_slot, next_action, off, params, step,
};
use qinit_db::{Model, ReadError, Target, open};
use std::collections::VecDeque;

/// Something that happened to a node, for the caller to log or show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    Node(u32, Report),
    /// An instance (by id) reached this state; `Exited` carries its wait status, -1 if unknown.
    Instance(u32, SlotState),
}

/// What went wrong, other than a node failing (that is a [`Notice`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bytes are not a valid database.
    Db(ReadError),
    /// A node index outside the database.
    UnknownNode(u32),
    /// A timer or watch effect failed.
    Effect(u32, Errno),
    /// The scheduler did not settle within its pass limit (a pathological graph; D30).
    Unconverged,
}

/// What one call produced: node notices and the errors that were not events.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub notices: Vec<Notice>,
    pub errors: Vec<Error>,
}

/// Colony: the compiled database, the node table and the scheduler's state.
pub struct Colony<E: Effects> {
    /// The effects, public so tests can drive a simulation.
    pub effects: E,
    pub(crate) db: Vec<u8>,
    pub(crate) model: Model,
    pub(crate) nodes: Vec<NodeState>,
    pub(crate) paths: Vec<bool>,
    late: Vec<bool>,
    pub(crate) meta: Meta,
    /// Per node, its path edges as `(path, global edge index)`.
    path_edges: Vec<Vec<(String, u32)>>,
    /// Per node, whether a cell exists for it: set by a start that succeeded (or an adoption),
    /// cleared when the cell is released.
    live: Vec<bool>,
    /// Per node, the pid of its main process, as the effects layer reported it at the start.
    pids: Vec<Option<i32>>,
    /// The instance slot pool (proved in the core) and what the runtime keeps per slot.
    pub(crate) slots: Vec<Slot>,
    pub(crate) insts: Vec<Option<crate::instance::Inst>>,
    /// The id the next launch gets.
    pub(crate) next_id: u32,
    /// The last `RING` instance exits, oldest first.
    pub(crate) ring: std::collections::VecDeque<crate::instance::Exit>,
}

/// The state of a worker colony found already running when it started.
fn adopted(p: Params, ready: bool, now: u64) -> NodeState {
    let base = NodeState {
        wanted: true,
        last_start_ms: now,
        ..off()
    };
    if ready {
        NodeState {
            state: State::Ready,
            ..base
        }
    } else if p.start_timeout_ms > 0 {
        NodeState {
            state: State::Starting,
            timer: Some(TimerKind::StartTimeout),
            emit_arm: Some((TimerKind::StartTimeout, p.start_timeout_ms)),
            ..base
        }
    } else {
        NodeState {
            state: State::Starting,
            ..base
        }
    }
}

/// The core's input for a cell's report, if it is one.
fn cell_report(r: CellPhase) -> Option<CellReport> {
    match r {
        CellPhase::Running => Some(CellReport::Spawned),
        CellPhase::Ready => Some(CellReport::Ready),
        CellPhase::NotReady => Some(CellReport::NotReady),
        CellPhase::MainExited(s) => Some(CellReport::MainExited(s)),
        CellPhase::Empty => Some(CellReport::Empty),
        CellPhase::Failed(Failure::Create | Failure::Spawn) => Some(CellReport::SpawnFailed),
        CellPhase::Failed(_) => Some(CellReport::CellFailed),
        CellPhase::Created | CellPhase::Removed | CellPhase::Refused => None,
    }
}

impl<E: Effects> Colony<E> {
    /// Loads a compiled database. `initial` lists workers already running when colony starts,
    /// as `(node, ready)`: colony re-adopts them instead of starting them again.
    ///
    /// # Errors
    /// `Error::Db` if `bytes` do not pass the proved validator, or `Error::UnknownNode` for an
    /// `initial` entry outside the database.
    pub fn load(
        bytes: Vec<u8>,
        initial: &[(u32, bool)],
        effects: E,
        now_ms: u64,
    ) -> Result<(Self, Outcome), Error> {
        let model = open(&bytes).map_err(Error::Db)?.decode();
        let n = model.nodes.len();
        let mut path_edges = Vec::with_capacity(n);
        let mut edge = 0u32;
        for node in &model.nodes {
            let mut here = Vec::new();
            for e in node.groups.iter().flat_map(|g| &g.edges) {
                if let Target::Path(p) = &e.target {
                    here.push((p.clone(), edge));
                }
                edge += 1;
            }
            path_edges.push(here);
        }
        let mut nodes = vec![off(); n];
        let mut live = vec![false; n];
        for &(node, ready) in initial {
            let i = node as usize;
            if i >= n {
                return Err(Error::UnknownNode(node));
            }
            nodes[i] = adopted(params(&bytes, i), ready, now_ms);
            live[i] = true;
        }
        let mut c = Colony {
            effects,
            nodes,
            paths: vec![false; edge as usize],
            late: vec![false; edge as usize],
            meta: qinit_colony_core::meta(),
            db: bytes,
            model,
            path_edges,
            pids: vec![None; n],
            live,
            slots: vec![free_slot(); MAX_SLOTS],
            insts: (0..MAX_SLOTS).map(|_| None).collect(),
            next_id: 1,
            ring: std::collections::VecDeque::new(),
        };
        let mut out = Outcome::default();
        let converged = qinit_colony_core::load_from(
            &c.db,
            &mut c.nodes,
            &c.paths,
            &mut c.late,
            &mut c.meta,
            now_ms,
        );
        if !converged {
            out.errors.push(Error::Unconverged);
        }
        let mut queue = VecDeque::new();
        // An adopted node never goes through `Off -> Waiting`, which is what asks for the watch;
        // without it a restart would wait for a path nobody reports.
        for &(node, _) in initial {
            if !c.path_edges[node as usize].is_empty() {
                c.perform(Action::WatchPath(node), &mut queue, &mut out);
            }
        }
        c.drain(&mut queue, &mut out);
        c.run_queue(&mut queue, now_ms, &mut out);
        Ok((c, out))
    }

    /// An administrator's request for `node`.
    pub fn request(&mut self, node: u32, req: Request, now_ms: u64) -> Outcome {
        self.input(node, Input::Request { node, req }, now_ms)
    }

    /// Starts the ordered shutdown of the whole graph.
    pub fn shutdown(&mut self, now_ms: u64) -> Outcome {
        let mut out = Outcome::default();
        let mut queue = VecDeque::from([Input::Shutdown]);
        self.run_queue(&mut queue, now_ms, &mut out);
        out
    }

    /// What a node's cell reported.
    pub fn on_cell(&mut self, node: u32, report: CellPhase, now_ms: u64) -> Outcome {
        let Some(r) = cell_report(report) else {
            return Outcome::default();
        };
        // The cell is gone (empty) or never came to be (create or spawn failed): free its slot.
        let gone = matches!(
            report,
            CellPhase::Empty | CellPhase::Failed(Failure::Create | Failure::Spawn)
        );
        if gone && self.known(node) && self.live[node as usize] {
            self.live[node as usize] = false;
            self.pids[node as usize] = None;
            self.effects.release(node);
        }
        self.input(node, Input::Cell { node, report: r }, now_ms)
    }

    /// A timer fired.
    pub fn on_deadline(&mut self, node: u32, timer: TimerKind, now_ms: u64) -> Outcome {
        self.input(node, Input::Deadline { node, timer }, now_ms)
    }

    /// A watched path appeared.
    pub fn on_path(&mut self, path: &str, now_ms: u64) -> Outcome {
        let mut out = Outcome::default();
        let mut queue: VecDeque<Input> = self
            .path_edges
            .iter()
            .flatten()
            .filter(|(p, _)| p == path)
            .map(|&(_, edge)| Input::PathAppeared { edge })
            .collect();
        self.run_queue(&mut queue, now_ms, &mut out);
        out
    }

    /// The state of a node.
    #[must_use]
    pub fn state(&self, node: u32) -> Option<State> {
        self.nodes.get(node as usize).map(|n| n.state)
    }

    /// The index of the node called `name`.
    #[must_use]
    pub fn node_index(&self, name: &str) -> Option<u32> {
        let i = self.model.nodes.iter().position(|n| n.name == name)?;
        u32::try_from(i).ok()
    }

    /// The pid of the node's main process, as the effects layer reported it at the start.
    #[must_use]
    pub fn pid(&self, node: u32) -> Option<i32> {
        self.pids.get(node as usize).copied().flatten()
    }

    /// The decoded database, for callers that want names.
    #[must_use]
    pub fn model(&self) -> &Model {
        &self.model
    }

    /// One line per node: name, state, since when.
    #[must_use]
    pub fn status(&self, now_ms: u64) -> String {
        text::status(&self.model, &self.nodes, now_ms)
    }

    fn known(&self, node: u32) -> bool {
        (node as usize) < self.nodes.len()
    }

    fn input(&mut self, node: u32, input: Input, now: u64) -> Outcome {
        let mut out = Outcome::default();
        if !self.known(node) {
            out.errors.push(Error::UnknownNode(node));
            return out;
        }
        let mut queue = VecDeque::from([input]);
        self.run_queue(&mut queue, now, &mut out);
        out
    }

    /// Feeds each queued input to the core and performs what it asks; effect failures that are
    /// events (a failed start or stop) join the queue.
    fn run_queue(&mut self, queue: &mut VecDeque<Input>, now: u64, out: &mut Outcome) {
        while let Some(input) = queue.pop_front() {
            let converged = step(
                &self.db,
                &mut self.nodes,
                &mut self.paths,
                &mut self.late,
                &mut self.meta,
                input,
                now,
            );
            if !converged {
                out.errors.push(Error::Unconverged);
            }
            self.drain(queue, out);
        }
    }

    fn drain(&mut self, queue: &mut VecDeque<Input>, out: &mut Outcome) {
        while let Some(action) = next_action(&self.db, &mut self.nodes, &mut self.meta) {
            self.perform(action, queue, out);
        }
    }

    pub(crate) fn spec(&self, node: u32) -> NodeSpec {
        let n = &self.model.nodes[node as usize];
        NodeSpec {
            name: n.name.clone(),
            kind: n.kind,
            exec: n.exec.clone(),
            ready: n.ready.clone(),
            stop: match n.stop.mode {
                qinit_db::StopMode::Main => StopMode::Main,
                qinit_db::StopMode::Cell => StopMode::Cell,
            },
            grace_ms: n.stop.grace_ms,
            start_timeout_ms: n.start_timeout_ms,
        }
    }

    fn perform(&mut self, action: Action, queue: &mut VecDeque<Input>, out: &mut Outcome) {
        match action {
            Action::Start(node) => {
                let spec = self.spec(node);
                if let Ok(pid) = self.effects.start(node, &spec) {
                    self.live[node as usize] = true;
                    self.pids[node as usize] = Some(pid);
                } else {
                    queue.push_back(Input::Cell {
                        node,
                        report: CellReport::SpawnFailed,
                    });
                }
            }
            Action::Stop(node, mode, grace) => {
                if !self.live[node as usize] {
                    // No cell (the start failed): there is nothing to stop, and the node is
                    // already as empty as it will get.
                    queue.push_back(Input::Cell {
                        node,
                        report: CellReport::Empty,
                    });
                } else if self.effects.stop(node, mode, grace).is_err() {
                    queue.push_back(Input::Cell {
                        node,
                        report: CellReport::CellFailed,
                    });
                }
            }
            Action::Arm(node, timer, ms) => {
                if let Err(e) = self.effects.arm(node, timer, ms) {
                    out.errors.push(Error::Effect(node, e));
                }
            }
            Action::Cancel(node, timer) => {
                if let Err(e) = self.effects.cancel(node, timer) {
                    out.errors.push(Error::Effect(node, e));
                }
            }
            Action::WatchPath(node) => {
                let watches = self.path_edges[node as usize].clone();
                for (path, edge) in watches {
                    match self.effects.watch_path(&path) {
                        Ok(true) => queue.push_back(Input::PathAppeared { edge }),
                        Ok(false) => {}
                        Err(e) => out.errors.push(Error::Effect(node, e)),
                    }
                }
            }
            Action::Signal(node, sig) => {
                let number = i32::try_from(sig).unwrap_or(i32::MAX);
                if let Err(e) = self.effects.signal(node, number) {
                    out.errors.push(Error::Effect(node, e));
                }
            }
            Action::Report(node, r) => out.notices.push(Notice::Node(node, r)),
        }
    }
}
