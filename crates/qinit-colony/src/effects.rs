// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! What colony asks of the system. A real implementation (sub-project 7) drives cells, timers
//! and a path watcher; `Sim` records the calls and answers from scripts.

use qinit_colony_core::{StopMode, TimerKind};
use qinit_db::{Kind, Ready};
use std::os::fd::OwnedFd;

/// An errno, as the effect layer reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Errno(pub i32);

/// What a node's cell is started with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeSpec {
    /// The node's name; also the name of its cell.
    pub name: String,
    pub kind: Kind,
    /// The argv; the first element is the program.
    pub exec: Vec<String>,
    pub ready: Ready,
    pub stop: StopMode,
    pub grace_ms: u32,
    pub start_timeout_ms: u32,
}

/// What an instance's cell is started with: the launchable frame's node, plus what the caller
/// of the launch added.
#[derive(Debug)]
pub struct InstanceSpec {
    /// The cell's name, `<frame>#<id>`.
    pub name: String,
    /// The frame's node index in the database.
    pub frame: u32,
    /// The frame's spec: its argv is the frame's own, without the tail.
    pub node: NodeSpec,
    /// Extra argv elements, appended to the frame's.
    pub argv_tail: Vec<String>,
    /// Environment additions `(key, value)`, applied after the frame's own.
    pub env_add: Vec<(String, String)>,
    /// The descriptors the caller supplied: stdin, stdout, stderr.
    pub fds: [Option<OwnedFd>; 3],
}

/// Effects per node. Every error is an errno; colony turns a failed `start` into a spawn
/// failure of that node and a failed `stop` into a failed cell, and returns the other failures
/// to its caller after the batch.
#[allow(clippy::missing_errors_doc)] // each method's error is the errno of the operation its doc names
pub trait Effects {
    /// Creates the node's cell and starts its main process in it; returns that process's pid.
    fn start(&mut self, node: u32, spec: &NodeSpec) -> Result<i32, Errno>;
    /// Creates the cell of instance slot `slot` and starts its main process; returns the pid.
    fn start_instance(&mut self, slot: u32, spec: InstanceSpec) -> Result<i32, Errno>;
    /// Begins the stop of the instance in `slot`, as `stop` does for a node.
    fn stop_instance(&mut self, slot: u32, mode: StopMode, grace_ms: u32) -> Result<(), Errno>;
    /// The instance's cell is empty, or its creation failed: remove it. Called once per cell.
    fn release_instance(&mut self, slot: u32);
    /// Begins the polite stop of the node: `mode`, then the kill after `grace_ms`. Only called
    /// for a node with a cell: one whose `start` succeeded and that has not been released.
    fn stop(&mut self, node: u32, mode: StopMode, grace_ms: u32) -> Result<(), Errno>;
    /// The node's cell is empty, or its creation or spawn failed: remove it and free its slot.
    /// Called once per cell.
    fn release(&mut self, node: u32);
    /// Watches `path`; `Ok(true)` when it already exists.
    fn watch_path(&mut self, path: &str) -> Result<bool, Errno>;
    /// Arms the node's timer, replacing one of the same kind.
    fn arm(&mut self, node: u32, timer: TimerKind, ms: u32) -> Result<(), Errno>;
    /// Cancels the node's timer of that kind, if armed.
    fn cancel(&mut self, node: u32, timer: TimerKind) -> Result<(), Errno>;
    /// The node table was renumbered by a database swap: new node `i` was node `map[i]` before
    /// (`u32::MAX` for a node that is new). Everything the layer keeps per node index (cells,
    /// timers, pids) moves with it; nodes absent from `map` have none.
    fn remap(&mut self, map: &[u32]);
    /// Sends the node's main process the Linux signal `sig` (its reload signal).
    fn signal(&mut self, node: u32, sig: i32) -> Result<(), Errno>;
}
