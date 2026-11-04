// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! What colony asks of the system. A real implementation (sub-project 7) drives cells, timers
//! and a path watcher; `Sim` records the calls and answers from scripts.

use qinit_colony_core::{StopMode, TimerKind};
use qinit_db::{Kind, Ready};

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

/// Effects per node. Every error is an errno; colony turns a failed `start` into a spawn
/// failure of that node and a failed `stop` into a failed cell, and returns the other failures
/// to its caller after the batch.
#[allow(clippy::missing_errors_doc)] // each method's error is the errno of the operation its doc names
pub trait Effects {
    /// Creates the node's cell and starts its main process in it.
    fn start(&mut self, node: u32, spec: &NodeSpec) -> Result<(), Errno>;
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
    /// Sends the node's main process the Linux signal `sig` (its reload signal).
    fn signal(&mut self, node: u32, sig: i32) -> Result<(), Errno>;
}
