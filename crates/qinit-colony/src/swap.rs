// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The two-phase database swap (spec 2026-11-04 §6.2, M12). The scheduler only ever holds one
//! database, so a refresh first stops, under the old database and in its stop order, the nodes
//! that must not run into the new one: removed nodes, and changed nodes that have to restart.
//! When they are all released, phase 2 puts the new database in place in one step, carries the
//! table over (the proved `remap`), signals the nodes that only need their reload signal, and
//! starts what the new graph wants.

use crate::effects::Effects;
use crate::engine::{Colony, Notice, Outcome};
use qinit_colony_core::{
    Action, Input, Request, State, off, params, rebuild_late, reconcile, remap, slot_of,
};
use qinit_db::{Cred, Kind, Model, Node, ReadError, Route, Target, open};
use std::collections::VecDeque;

/// A map entry for a node that is new.
const NEW_NODE: u32 = u32::MAX;

/// Why a refresh was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapError {
    /// The database does not pass the proved validator; nothing changed.
    Invalid(ReadError),
    /// An earlier refresh is still stopping nodes.
    Busy,
    /// Colony is shutting down.
    ShuttingDown,
}

/// A refresh whose first phase is running.
#[derive(Debug)]
pub struct Swap {
    db: Vec<u8>,
    model: Model,
    /// New node index to old node index; `NEW_NODE` for a node that is new.
    map: Vec<u32>,
    /// Old nodes stopped in phase 1: released when it is over.
    waiting: Vec<u32>,
    /// Live instances (by id) of removed frames, stopped in phase 1.
    instances: Vec<u32>,
    /// Kept nodes sent their reload signal in phase 2.
    reload: Vec<String>,
    /// Changed nodes that were wanted: started again in phase 2.
    again: Vec<String>,
}

/// A route by what it names, not by index.
#[derive(Debug, PartialEq, Eq)]
enum RouteName {
    Path(String),
    Pipe(String),
}

/// A node with every index replaced by what it names, so two nodes of two databases compare.
#[derive(Debug, PartialEq, Eq)]
struct Canon {
    node: Node,
    cred: Option<Cred>,
    output: Option<RouteName>,
    errors: Option<RouteName>,
}

fn route_name(model: &Model, r: u32) -> RouteName {
    match &model.routes[r as usize] {
        Route::Path(p) => RouteName::Path(p.clone()),
        Route::Pipe(n) => RouteName::Pipe(model.nodes[*n as usize].name.clone()),
    }
}

fn canon(model: &Model, node: &Node) -> Canon {
    let mut n = node.clone();
    for e in n.groups.iter_mut().flat_map(|g| g.edges.iter_mut()) {
        if let Target::Node(t) = e.target {
            e.target = Target::Path(format!("\0node:{}", model.nodes[t as usize].name));
        }
    }
    n.cred = None;
    n.output = None;
    n.errors = None;
    Canon {
        cred: node.cred.map(|c| model.creds[c as usize].clone()),
        output: node.output.map(|r| route_name(model, r)),
        errors: node.errors.map(|r| route_name(model, r)),
        node: n,
    }
}

/// Whether everything that decides how a service is launched is the same.
fn launch_same(a: &Canon, b: &Canon) -> bool {
    let (x, y) = (&a.node, &b.node);
    x.kind == y.kind
        && x.exec == y.exec
        && x.ready == y.ready
        && a.cred == b.cred
        && a.output == b.output
        && a.errors == b.errors
        && x.env == y.env
        && x.cwd == y.cwd
        && x.umask == y.umask
        && x.rlimits == y.rlimits
        && x.memory_max_kib == y.memory_max_kib
        && x.pids_max == y.pids_max
        && x.instance_of == y.instance_of
}

/// The nodes `node` has a hard edge to: a sync edge of a `require_all` or `require_any` group.
fn hard_targets(node: &Node) -> Vec<u32> {
    node.groups
        .iter()
        .filter(|g| {
            matches!(
                g.kind,
                qinit_db::GroupKind::RequireAll | qinit_db::GroupKind::RequireAny
            )
        })
        .flat_map(|g| &g.edges)
        .filter(|e| e.mode == qinit_db::Mode::Sync)
        .filter_map(|e| match e.target {
            Target::Node(t) => Some(t),
            Target::Path(_) => None,
        })
        .collect()
}

impl<E: Effects> Colony<E> {
    /// Whether a refresh is stopping nodes (phase 1).
    #[must_use]
    pub fn swapping(&self) -> bool {
        self.swap.is_some()
    }

    fn active(&self, j: usize) -> bool {
        matches!(
            self.nodes[j].state,
            State::Starting | State::Ready | State::Stopping
        )
    }

    /// Replaces the database with `db`: validates it, stops what must stop, and swaps when
    /// that is done. The returned outcome carries `Notice::Swapped` when the swap completed
    /// before it returned; otherwise it completes in a later call and its outcome carries the
    /// notice.
    ///
    /// # Errors
    /// `ShuttingDown` during shutdown, `Busy` while an earlier refresh is stopping nodes,
    /// `Invalid` for a database the validator refuses (nothing changes).
    pub fn refresh(&mut self, db: Vec<u8>, now: u64) -> Result<Outcome, SwapError> {
        if self.meta.shutdown {
            return Err(SwapError::ShuttingDown);
        }
        if self.swap.is_some() {
            return Err(SwapError::Busy);
        }
        let model = open(&db).map_err(SwapError::Invalid)?.decode();
        if db == self.db {
            // Nothing was refreshed: an earlier refresh's set must not decide this wait.
            self.refresh_set.clear();
            return Ok(Outcome {
                notices: vec![Notice::Swapped],
                errors: Vec::new(),
                replies: Vec::new(),
            });
        }
        let mut sw = self.classify(db, model);
        self.close_over_hard_dependents(&mut sw);
        self.refresh_set = sw
            .again
            .iter()
            .cloned()
            .chain(sw.reload.iter().cloned())
            .collect();
        let mut out = Outcome::default();
        // Stop what must stop; the swap is stored only afterwards, so that a node released
        // at once does not finish it before the rest has been asked.
        for j in sw.waiting.clone() {
            let o = self.input(
                j,
                Input::Request {
                    node: j,
                    req: Request::Stop,
                },
                now,
            );
            out.notices.extend(o.notices);
            out.errors.extend(o.errors);
        }
        for id in sw.instances.clone() {
            if let Some(slot) = slot_of(&self.slots, id) {
                self.begin_instance_stop(slot, &mut out);
            }
        }
        self.swap = Some(sw);
        self.after_event(now, &mut out);
        Ok(out)
    }

    /// Sorts the old nodes into removed, unchanged, to reload and to restart.
    fn classify(&self, db: Vec<u8>, model: Model) -> Swap {
        let mut sw = Swap {
            map: vec![NEW_NODE; model.nodes.len()],
            waiting: Vec::new(),
            instances: Vec::new(),
            reload: Vec::new(),
            again: Vec::new(),
            db,
            model,
        };
        for (j, old) in self.model.nodes.iter().enumerate() {
            let j32 = u32::try_from(j).unwrap_or(NEW_NODE);
            let state = self.nodes[j].state;
            let wanted = self.nodes[j].wanted;
            let found = sw
                .model
                .nodes
                .binary_search_by(|n| n.name.as_str().cmp(&old.name));
            let Ok(i) = found else {
                if self.active(j) {
                    sw.waiting.push(j32);
                }
                for (slot, s) in self.slots.iter().enumerate() {
                    if s.frame == j32 && self.insts[slot].is_some() {
                        sw.instances.push(s.id);
                    }
                }
                continue;
            };
            sw.map[i] = j32;
            let new = &sw.model.nodes[i];
            let (before, after) = (canon(&self.model, old), canon(&sw.model, new));
            if before == after {
                continue;
            }
            let same_machine = params(&self.db, j) == params(&sw.db, i);
            if self.active(j) {
                let signal = state == State::Ready
                    && !self.nodes[j].to_stop
                    && same_machine
                    && launch_same(&before, &after)
                    && old.reload == new.reload
                    && new.reload.is_some();
                if signal {
                    sw.reload.push(old.name.clone());
                } else {
                    sw.waiting.push(j32);
                    if wanted {
                        sw.again.push(old.name.clone());
                    }
                }
            } else if !same_machine && wanted {
                sw.again.push(old.name.clone());
            }
        }
        sw
    }

    /// A node cannot stop while a hard dependent runs: every running node that hard-depends
    /// on one being stopped is stopped with it and started again afterwards.
    fn close_over_hard_dependents(&self, sw: &mut Swap) {
        loop {
            let mut grew = false;
            for (j, node) in self.model.nodes.iter().enumerate() {
                let j32 = u32::try_from(j).unwrap_or(NEW_NODE);
                if !self.active(j) || sw.waiting.contains(&j32) {
                    continue;
                }
                if hard_targets(node).iter().any(|t| sw.waiting.contains(t)) {
                    sw.waiting.push(j32);
                    sw.reload.retain(|n| *n != node.name);
                    let kept = sw.model.nodes.iter().any(|n| n.name == node.name);
                    let known = sw.again.contains(&node.name);
                    if kept && self.nodes[j].wanted && !known {
                        sw.again.push(node.name.clone());
                    }
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }
    }

    /// Phase 1 is over when every node it stopped holds no process any more. A cell that
    /// could not be killed leaves its node quarantined (`StopFailed`) or, for a forager, off;
    /// either way it is left behind, as in a shutdown, because a wait that never ends would
    /// break the rule that every wait is bounded.
    fn phase_1_done(&self, sw: &Swap) -> bool {
        sw.waiting.iter().all(|&j| !self.active(j as usize))
            && sw
                .instances
                .iter()
                .all(|&id| slot_of(&self.slots, id).is_none())
    }

    /// Called after every input and instance report: finishes the swap when phase 1 is over.
    pub(crate) fn after_event(&mut self, now: u64, out: &mut Outcome) {
        let done = match &self.swap {
            Some(sw) => self.phase_1_done(sw),
            None => false,
        };
        if done {
            self.finish_swap(now, out);
        }
        self.resolve_waits(out);
    }

    /// Phase 2: the new database goes live.
    fn finish_swap(&mut self, now: u64, out: &mut Outcome) {
        let Some(mut sw) = self.swap.take() else {
            return;
        };
        let kept = self.carry_over(&mut sw);
        let mut queue = VecDeque::new();
        for (i, &carried) in kept.iter().enumerate() {
            if carried
                && !self.path_edges[i].is_empty()
                && !matches!(self.nodes[i].state, State::Off)
            {
                let node = u32::try_from(i).unwrap_or(NEW_NODE);
                self.perform(Action::WatchPath(node), &mut queue, out);
            }
        }
        if !reconcile(
            &self.db,
            &mut self.nodes,
            &self.paths,
            &mut self.late,
            false,
            now,
        ) {
            out.errors.push(crate::engine::Error::Unconverged);
        }
        self.drain(&mut queue, out);
        self.run_queue(&mut queue, now, out);
        // What the new graph wants: the enabled nodes that are new, the changed nodes that were
        // wanted, and the signal for the nodes that only needed it.
        let mut asks: Vec<(u32, Request)> = Vec::new();
        for &i in &self.model.enabled {
            if sw.map[i as usize] == NEW_NODE {
                asks.push((i, self.start_request(i)));
            }
        }
        for name in &sw.again {
            if let Some(i) = self.node_index(name) {
                asks.push((i, self.start_request(i)));
            }
        }
        for name in &sw.reload {
            if let Some(i) = self.node_index(name) {
                asks.push((i, Request::Refresh));
            }
        }
        for (node, req) in asks {
            let o = self.input(node, Input::Request { node, req }, now);
            out.notices.extend(o.notices);
            out.errors.extend(o.errors);
        }
        out.notices.push(Notice::Swapped);
    }

    /// What starts node `i` of the new graph: a forager only runs, a worker or brood starts.
    fn start_request(&self, i: u32) -> Request {
        if self.model.nodes[i as usize].kind == Kind::Forager {
            Request::Run
        } else {
            Request::Start
        }
    }

    /// Puts the new database and the carried-over tables in place. Returns, per new node,
    /// whether its old entry was carried over (its machine reads the same words).
    fn carry_over(&mut self, sw: &mut Swap) -> Vec<bool> {
        let old_len = self.nodes.len();
        let new_len = sw.model.nodes.len();
        let mut table = vec![off(); new_len];
        remap(&self.db, &sw.db, &self.nodes, &sw.map, &mut table);
        let kept: Vec<bool> = (0..new_len)
            .map(|i| {
                let j = sw.map[i] as usize;
                j < old_len && params(&self.db, j) == params(&sw.db, i)
            })
            .collect();
        let back: Vec<u32> = (0..new_len)
            .map(|i| if kept[i] { sw.map[i] } else { NEW_NODE })
            .collect();
        self.effects.remap(&back);
        self.starts = (0..new_len)
            .map(|i| {
                if kept[i] {
                    self.starts[sw.map[i] as usize]
                } else {
                    0
                }
            })
            .collect();
        self.live = (0..new_len)
            .map(|i| kept[i] && self.live[sw.map[i] as usize])
            .collect();
        self.pids = (0..new_len)
            .map(|i| {
                if kept[i] {
                    self.pids[sw.map[i] as usize]
                } else {
                    None
                }
            })
            .collect();
        // Instances keep running under their old definition; only their frame's index moves.
        let mut frame_of = vec![NEW_NODE; old_len];
        for (i, &j) in sw.map.iter().enumerate() {
            if (j as usize) < old_len {
                frame_of[j as usize] = u32::try_from(i).unwrap_or(NEW_NODE);
            }
        }
        let moved = |frame: u32| frame_of.get(frame as usize).copied().unwrap_or(NEW_NODE);
        for (slot, rec) in self.insts.iter_mut().enumerate() {
            if let Some(rec) = rec {
                rec.frame = moved(rec.frame);
                self.slots[slot].frame = rec.frame;
            }
        }
        for e in &mut self.ring {
            e.frame = moved(e.frame);
        }
        self.db = std::mem::take(&mut sw.db);
        self.model = std::mem::take(&mut sw.model);
        self.nodes = table;
        let (path_edges, edges) = Self::path_edges_of(&self.model);
        self.path_edges = path_edges;
        self.paths = vec![false; edges as usize];
        self.late = vec![false; edges as usize];
        self.meta.cursor = 0;
        rebuild_late(&self.db, &self.nodes, &self.paths, &mut self.late);
        kept
    }
}
