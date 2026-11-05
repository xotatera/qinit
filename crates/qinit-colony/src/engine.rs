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
    /// An instance (by id) wrote its readiness byte.
    InstanceReady(u32),
    /// A database refresh finished: the new database is live.
    Swapped,
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
    /// A saved node table breaks the scheduler's invariant for this database.
    Restore,
}

/// What one call produced: node notices and the errors that were not events.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub notices: Vec<Notice>,
    pub errors: Vec<Error>,
    /// Replies owed to parked waits that this call settled, answered or superseded.
    pub replies: Vec<(crate::handle::WaitId, crate::handle::OwnedRep)>,
    /// Replies to watchers (D37), in the order the notices were pushed. Unlike `replies` they
    /// do not end a wait; an entry with `ends` set is the watcher's last.
    pub stream: Vec<Stream>,
}

/// One reply on a watcher's stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stream {
    pub wait: crate::handle::WaitId,
    /// An `OwnedRep::Notice`, or `OwnedRep::Superseded` when a refresh removed the node.
    pub rep: crate::handle::OwnedRep,
    /// The stream is over: the watcher was forgotten and the connection is idle again.
    pub ends: bool,
}

/// What a watcher watches. A node by name, not by index: a swap renumbers nodes, and the
/// watcher follows the name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    All,
    Node(String),
    Instance(u32),
}

/// Colony: the compiled database, the node table and the scheduler's state.
pub struct Colony<E: Effects> {
    /// The effects, public so tests can drive a simulation.
    pub effects: E,
    pub(crate) db: Vec<u8>,
    pub(crate) model: Model,
    pub(crate) nodes: Vec<NodeState>,
    pub(crate) paths: Vec<bool>,
    pub(crate) late: Vec<bool>,
    pub(crate) meta: Meta,
    /// Per node, its path edges as `(path, global edge index)`.
    pub(crate) path_edges: Vec<Vec<(String, u32)>>,
    /// Per node, whether a cell exists for it: set by a start that succeeded (or an adoption),
    /// cleared when the cell is released.
    pub(crate) live: Vec<bool>,
    /// Per node, the pid of its main process, as the effects layer reported it at the start.
    pub(crate) pids: Vec<Option<i32>>,
    /// The instance slot pool (proved in the core) and what the runtime keeps per slot.
    pub(crate) slots: Vec<Slot>,
    pub(crate) insts: Vec<Option<crate::instance::Inst>>,
    /// The id the next launch gets.
    pub(crate) next_id: u32,
    /// The last `RING` instance exits, oldest first.
    pub(crate) ring: std::collections::VecDeque<crate::instance::Exit>,
    /// A database swap waiting for its first phase to finish.
    pub(crate) swap: Option<crate::swap::Swap>,
    /// Per node, how many times it was started since the database was loaded.
    pub(crate) starts: Vec<u32>,
    /// The waits parked for protocol requests.
    pub(crate) waits: Vec<crate::handle::WaitRec>,
    /// The mode of the shutdown in progress, if any.
    pub(crate) shutdown_mode: Option<crate::handle::ShutdownMode>,
    /// The nodes the last refresh restarts or signals, by name.
    pub(crate) refresh_set: Vec<String>,
    /// The watchers (D37): not state to keep across a restart, as their connections go with it.
    pub(crate) watchers: Vec<(crate::handle::WaitId, Scope)>,
}

/// The state of a worker colony found already running when it started.
pub(crate) fn adopted(p: Params, ready: bool, now: u64) -> NodeState {
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
        let mut c = Self::assemble(bytes, model, nodes, live, effects);
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

    /// A colony over the validated `bytes` and its `model`, with `nodes` as its table and `live`
    /// marking the nodes that have a cell; nothing is started or watched yet.
    pub(crate) fn assemble(
        bytes: Vec<u8>,
        model: Model,
        nodes: Vec<NodeState>,
        live: Vec<bool>,
        effects: E,
    ) -> Self {
        let n = model.nodes.len();
        let (path_edges, edge) = Self::path_edges_of(&model);
        Colony {
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
            swap: None,
            starts: vec![0; n],
            waits: Vec::new(),
            shutdown_mode: None,
            refresh_set: Vec::new(),
            watchers: Vec::new(),
        }
    }

    /// Per node, its path edges as `(path, global edge index)`, and the number of edges.
    pub(crate) fn path_edges_of(model: &Model) -> (Vec<Vec<(String, u32)>>, u32) {
        let mut path_edges = Vec::with_capacity(model.nodes.len());
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
        (path_edges, edge)
    }

    /// An administrator's request for `node`.
    pub fn request(&mut self, node: u32, req: Request, now_ms: u64) -> Outcome {
        self.input(node, Input::Request { node, req }, now_ms)
    }

    /// Starts the ordered shutdown of the whole graph: the instances first (nothing depends on
    /// them), then the nodes in reverse dependency order. Whoever asks, a protocol request or a
    /// signal, the instances stop.
    pub fn shutdown(&mut self, now_ms: u64) -> Outcome {
        // A swap still stopping nodes is abandoned: the shutdown stops the old graph.
        self.swap = None;
        let mut out = Outcome::default();
        for slot in 0..self.slots.len() {
            if self.insts[slot].is_some() && self.slots[slot].state != SlotState::Stopping {
                self.begin_instance_stop(slot, &mut out);
            }
        }
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

    /// How many watchers colony streams notices to (D37): every accepted `Watch` whose stream
    /// has not ended and whose connection has not closed.
    #[must_use]
    pub fn watchers(&self) -> usize {
        self.watchers.len()
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

    pub(crate) fn input(&mut self, node: u32, input: Input, now: u64) -> Outcome {
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
    pub(crate) fn run_queue(&mut self, queue: &mut VecDeque<Input>, now: u64, out: &mut Outcome) {
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
        self.after_event(now, out);
    }

    pub(crate) fn drain(&mut self, queue: &mut VecDeque<Input>, out: &mut Outcome) {
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
            memory_max_kib: n.memory_max_kib,
            pids_max: n.pids_max,
        }
    }

    pub(crate) fn perform(
        &mut self,
        action: Action,
        queue: &mut VecDeque<Input>,
        out: &mut Outcome,
    ) {
        match action {
            Action::Start(node) => {
                let spec = self.spec(node);
                if let Ok(pid) = self.effects.start(node, &spec, &self.model) {
                    self.live[node as usize] = true;
                    self.pids[node as usize] = Some(pid);
                    self.starts[node as usize] = self.starts[node as usize].saturating_add(1);
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
            Action::Report(node, r) => self.emit(out, Notice::Node(node, r)),
        }
    }

    /// Pushes `n` into `out`, and with it the stream reply of every watcher it concerns. This is
    /// the one place a notice enters an outcome: a node index in `n` names the model in place
    /// now, which a later swap would renumber.
    pub(crate) fn emit(&mut self, out: &mut Outcome, n: Notice) {
        if !self.watchers.is_empty() {
            let mut rep = None;
            let mut ended = Vec::new();
            for (wait, scope) in &self.watchers {
                let hit = match (scope, &n) {
                    (Scope::All, _) => true,
                    // `ShutdownComplete` rides node 0's report slot but is the colony's.
                    (Scope::Node(_), Notice::Node(_, Report::ShutdownComplete { .. })) => false,
                    (Scope::Node(name), Notice::Node(ix, _)) => self
                        .model
                        .nodes
                        .get(*ix as usize)
                        .is_some_and(|m| m.name == *name),
                    (Scope::Instance(id), Notice::Instance(x, _) | Notice::InstanceReady(x)) => {
                        id == x
                    }
                    _ => false,
                };
                if hit {
                    let ends = matches!(scope, Scope::Instance(_))
                        && matches!(n, Notice::Instance(_, SlotState::Exited(_)));
                    let rep = rep.get_or_insert_with(|| self.notice_rep(&n)).clone();
                    out.stream.push(Stream {
                        wait: *wait,
                        rep,
                        ends,
                    });
                    if ends {
                        ended.push(*wait);
                    }
                }
                if let (Scope::Node(name), Notice::Swapped) = (scope, &n)
                    && self.node_index(name).is_none()
                {
                    out.stream.push(Stream {
                        wait: *wait,
                        rep: crate::handle::OwnedRep::Superseded(crate::handle::state_word(
                            State::Off,
                        )),
                        ends: true,
                    });
                    ended.push(*wait);
                }
            }
            self.watchers.retain(|(w, _)| !ended.contains(w));
        }
        out.notices.push(n);
    }

    /// The words of an instance state on a stream: `(state, report, status)`, the state as
    /// `Status` shows it.
    pub(crate) fn instance_words(s: SlotState) -> (u32, u32, i32) {
        match s {
            SlotState::Starting | SlotState::Free => (2, 1, 0),
            SlotState::Running => (3, 2, 0),
            SlotState::Stopping => (5, 4, 0),
            SlotState::Exited(status) => (4, 5, status),
        }
    }

    /// The stream reply for `n` (spec 2026-11-05 §2.2), read against the model in place now.
    pub(crate) fn notice_rep(&self, n: &Notice) -> crate::handle::OwnedRep {
        use crate::handle::{OwnedRep, state_word};
        use qinit_wire::StateWord;
        let zero = StateWord {
            state: 0,
            detail: 0,
        };
        let frame = |id: u32| self.instance(id).map(|v| v.frame_name).unwrap_or_default();
        match *n {
            Notice::Node(_, Report::ShutdownComplete { still_populated }) => OwnedRep::Notice {
                kind: 3,
                name: String::new(),
                id: 0,
                state: zero,
                report: 0,
                status: i32::try_from(still_populated).unwrap_or(i32::MAX),
            },
            Notice::Node(ix, r) => {
                let (report, status) = match r {
                    Report::Started => (1, 0),
                    Report::Ready => (2, 0),
                    Report::Done => (3, 0),
                    Report::Stopped => (4, 0),
                    Report::Failed(s) => (5, s.unwrap_or(-1)),
                    Report::Quarantined(_) => (6, 0),
                    Report::Refused => (7, 0),
                    Report::Lost => (8, 0),
                    // Turned into a signal before it could reach a notice; and handled above.
                    Report::Reload | Report::ShutdownComplete { .. } => (0, 0),
                };
                OwnedRep::Notice {
                    kind: 0,
                    name: self
                        .model
                        .nodes
                        .get(ix as usize)
                        .map(|m| m.name.clone())
                        .unwrap_or_default(),
                    id: 0,
                    state: self
                        .nodes
                        .get(ix as usize)
                        .map_or(state_word(State::Off), |s| state_word(s.state)),
                    report,
                    status,
                }
            }
            Notice::Instance(id, s) => {
                let (state, report, status) = Self::instance_words(s);
                OwnedRep::Notice {
                    kind: 1,
                    name: frame(id),
                    id,
                    state: StateWord { state, detail: 0 },
                    report,
                    status,
                }
            }
            Notice::InstanceReady(id) => OwnedRep::Notice {
                kind: 1,
                name: frame(id),
                id,
                state: StateWord {
                    state: 3,
                    detail: 0,
                },
                report: 3,
                status: 0,
            },
            Notice::Swapped => OwnedRep::Notice {
                kind: 2,
                name: String::new(),
                id: 0,
                state: zero,
                report: 0,
                status: 0,
            },
        }
    }
}
