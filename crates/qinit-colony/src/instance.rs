// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Forager instances (spec 2026-11-04 §6.3): one transient cell per launch, up to the cap the
//! frame declares. The slot pool and its bounds are proved in the core; this file owns what the
//! proof leaves to the runtime: ids, cell names, the pids, the exit status, and the ring of the
//! last exits.

use crate::effects::{Effects, Errno, InstanceSpec};
use crate::engine::{Colony, Notice, Outcome};
use qinit_cell_core::Report as CellPhase;
use qinit_colony_core::{SlotState, claim, deps_satisfied, live_of, release, set_state, slot_of};
use qinit_db::Kind;
use std::os::fd::OwnedFd;

/// Exits kept for `Status` by instance id.
pub const RING: usize = 256;

/// What the runtime keeps for a live slot.
#[derive(Debug)]
pub struct Inst {
    pub(crate) frame: u32,
    pub(crate) frame_name: String,
    pub(crate) id: u32,
    pub(crate) pid: Option<i32>,
    /// The wait status of the main process, once seen.
    pub(crate) status: Option<i32>,
}

/// One remembered exit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exit {
    /// The frame's node index; `u32::MAX` once a refresh removed the frame.
    pub frame: u32,
    pub frame_name: String,
    pub id: u32,
    /// The wait status; -1 when the main process's exit was not seen.
    pub status: i32,
}

/// What a caller of [`Colony::launch`] asks for.
#[derive(Debug)]
pub struct LaunchArgs {
    /// The forager frame's name.
    pub frame: String,
    /// Extra argv elements, at most the frame's `argv_tail`.
    pub argv_tail: Vec<String>,
    /// Environment additions, keys the frame lists.
    pub env_add: Vec<(String, String)>,
    /// stdin, stdout, stderr: only the roles the frame lists.
    pub fds: [Option<OwnedFd>; 3],
}

/// Why a launch or an instance stop was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchError {
    /// Colony is shutting down.
    ShuttingDown,
    /// No node, or no instance, by that name or id.
    UnknownNode,
    /// The node is not a forager with a launch table.
    NotLaunchable,
    /// A request outside the launch table: an env key, a descriptor role or too long a tail.
    Denied,
    /// The frame's dependencies are not satisfied.
    Unsatisfied,
    /// The frame has all its slots, or the pool is full.
    NoSlot,
    /// The effects layer could not create the cell.
    Spawn(Errno),
}

/// An instance as `Status` shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceView {
    /// The frame's node index; `u32::MAX` once a refresh removed the frame.
    pub frame: u32,
    pub frame_name: String,
    pub id: u32,
    pub state: SlotState,
    pub pid: Option<i32>,
}

/// The descriptor role bits, as the database stores them.
const ROLES: [u32; 3] = [qinit_db::FD_STDIN, qinit_db::FD_STDOUT, qinit_db::FD_STDERR];

impl<E: Effects> Colony<E> {
    /// Launches an instance of the forager `args.frame`.
    ///
    /// # Errors
    /// The refusals of [`LaunchError`], checked in this order: shutdown, unknown or not
    /// launchable frame, a request outside the launch table, unsatisfied dependencies, no free
    /// slot, and a cell the effects layer cannot create.
    pub fn launch(&mut self, args: LaunchArgs, now: u64) -> Result<(u32, Outcome), LaunchError> {
        if self.meta.shutdown {
            return Err(LaunchError::ShuttingDown);
        }
        let node = self
            .node_index(&args.frame)
            .ok_or(LaunchError::UnknownNode)?;
        let model_node = &self.model.nodes[node as usize];
        let launch = match (&model_node.launch, model_node.kind) {
            (Some(l), Kind::Forager) => l.clone(),
            _ => return Err(LaunchError::NotLaunchable),
        };
        let role_ok = args
            .fds
            .iter()
            .zip(ROLES)
            .all(|(fd, bit)| fd.is_none() || launch.fds & bit != 0);
        let keys_ok = args
            .env_add
            .iter()
            .all(|(k, _)| launch.env.iter().any(|allowed| allowed == k));
        if args.argv_tail.len() > launch.argv_tail as usize || !role_ok || !keys_ok {
            return Err(LaunchError::Denied);
        }
        if !deps_satisfied(&self.db, &self.nodes, &self.paths, node as usize, now) {
            return Err(LaunchError::Unsatisfied);
        }
        let id = self.next_id;
        let next = id.checked_add(1).ok_or(LaunchError::NoSlot)?;
        let slot =
            claim(&mut self.slots, node, launch.concurrency, id).ok_or(LaunchError::NoSlot)?;
        let name = format!("{}#{id}", args.frame);
        let frame_name = args.frame.clone();
        let spec = InstanceSpec {
            name,
            frame: node,
            node: self.spec(node),
            argv_tail: args.argv_tail,
            env_add: args.env_add,
            fds: args.fds,
        };
        let slot32 = u32::try_from(slot).unwrap_or(u32::MAX);
        match self.effects.start_instance(slot32, spec) {
            Ok(pid) => {
                self.next_id = next;
                self.insts[slot] = Some(Inst {
                    frame: node,
                    frame_name,
                    id,
                    pid: Some(pid),
                    status: None,
                });
                let out = Outcome {
                    notices: vec![Notice::Instance(id, SlotState::Starting)],
                    errors: Vec::new(),
                    replies: Vec::new(),
                };
                Ok((id, out))
            }
            Err(e) => {
                release(&mut self.slots, slot);
                self.effects.release_instance(slot32);
                Err(LaunchError::Spawn(e))
            }
        }
    }

    /// Stops the live instance `id`; its exit arrives through [`Colony::on_instance`].
    ///
    /// # Errors
    /// `UnknownNode` when no live instance has that id.
    pub fn stop_instance(&mut self, id: u32, _now: u64) -> Result<Outcome, LaunchError> {
        let slot = slot_of(&self.slots, id).ok_or(LaunchError::UnknownNode)?;
        let mut out = Outcome::default();
        if self.slots[slot].state != SlotState::Stopping {
            self.begin_instance_stop(slot, &mut out);
        }
        Ok(out)
    }

    /// Moves a live slot to `Stopping` and asks the effects layer to stop its cell.
    pub(crate) fn begin_instance_stop(&mut self, slot: usize, out: &mut Outcome) {
        let frame = self.slots[slot].frame;
        let id = self.slots[slot].id;
        set_state(&mut self.slots, slot, SlotState::Stopping);
        let spec = self.spec(frame);
        let slot32 = u32::try_from(slot).unwrap_or(u32::MAX);
        if let Err(e) = self.effects.stop_instance(slot32, spec.stop, spec.grace_ms) {
            out.errors.push(crate::engine::Error::Effect(frame, e));
        }
        out.notices.push(Notice::Instance(id, SlotState::Stopping));
    }

    /// What an instance's cell reported.
    pub fn on_instance(&mut self, slot: u32, report: CellPhase, now: u64) -> Outcome {
        let mut out = Outcome::default();
        let i = slot as usize;
        if i >= self.insts.len() || self.insts[i].is_none() {
            return out;
        }
        let id = self.slots[i].id;
        match report {
            CellPhase::Running => {
                if self.slots[i].state == SlotState::Starting {
                    set_state(&mut self.slots, i, SlotState::Running);
                    out.notices.push(Notice::Instance(id, SlotState::Running));
                }
            }
            CellPhase::MainExited(status) => {
                if let Some(rec) = self.insts[i].as_mut() {
                    rec.status = status;
                }
                if self.slots[i].state != SlotState::Stopping {
                    // The main process is gone: empty the cell of whatever it left behind.
                    self.begin_instance_stop(i, &mut out);
                }
            }
            CellPhase::Empty | CellPhase::Failed(_) => self.finish_instance(i, &mut out),
            CellPhase::Created
            | CellPhase::Ready
            | CellPhase::NotReady
            | CellPhase::Removed
            | CellPhase::Refused => {}
        }
        self.after_event(now, &mut out);
        out
    }

    /// The instance in `slot` is over: free the slot, release the cell, remember the exit.
    fn finish_instance(&mut self, slot: usize, out: &mut Outcome) {
        let Some(rec) = self.insts[slot].take() else {
            return;
        };
        release(&mut self.slots, slot);
        self.effects
            .release_instance(u32::try_from(slot).unwrap_or(u32::MAX));
        let status = rec.status.unwrap_or(-1);
        if self.ring.len() == RING {
            self.ring.pop_front();
        }
        self.ring.push_back(Exit {
            frame: rec.frame,
            frame_name: rec.frame_name,
            id: rec.id,
            status,
        });
        out.notices
            .push(Notice::Instance(rec.id, SlotState::Exited(status)));
    }

    /// The live instance `id`, or its remembered exit.
    #[must_use]
    pub fn instance(&self, id: u32) -> Option<InstanceView> {
        if let Some(slot) = slot_of(&self.slots, id) {
            let rec = self.insts[slot].as_ref()?;
            return Some(InstanceView {
                frame: rec.frame,
                frame_name: rec.frame_name.clone(),
                id,
                state: self.slots[slot].state,
                pid: rec.pid,
            });
        }
        self.ring.iter().find(|e| e.id == id).map(|e| InstanceView {
            frame: e.frame,
            frame_name: e.frame_name.clone(),
            id,
            state: SlotState::Exited(e.status),
            pid: None,
        })
    }

    /// Live instances of the frame node `frame`.
    #[must_use]
    pub fn live_instances(&self, frame: u32) -> u32 {
        live_of(&self.slots, frame)
    }
}
