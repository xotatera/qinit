// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the engine asks of the system (plan P3). `Kernel` performs it; `Sim` records it.
use qinit_cell_core::{Handle, ReadyMode, Sig, Timer};
use qinit_cell_drive::Source;
use qinit_sys::Errno;
use std::ffi::{CStr, OsString};
use std::os::fd::{OwnedFd, RawFd};
use std::path::PathBuf;

/// A program to run as a cell's main process.
pub struct Command {
    pub path: PathBuf,
    pub argv: Vec<OsString>,
    pub env: Vec<OsString>,
    /// Descriptors the program receives, each at its target number; nothing else arrives.
    pub fds: Vec<(OwnedFd, RawFd)>,
    /// Where the readiness pipe arrives in `ReadyMode::Pipe`.
    pub ready_fd: RawFd,
}

/// A child a subreaper reaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reaped {
    /// A cell's main process, reaped through its pidfd.
    Main(u16, i32),
    /// An orphan re-parented to this process (or a child no cell tracks any more).
    Orphan(libc::pid_t, i32),
}

/// Effects per cell slot. Every error is an errno; the engine decides what it means.
// Each method's error is the errno of the system operation its doc names.
#[allow(clippy::missing_errors_doc)]
pub trait Effects {
    /// Makes cell directory `name`, opens it and its `cgroup.events`, and watches the latter.
    fn create(&mut self, slot: u16, name: &CStr) -> Result<(), Errno>;
    /// Opens existing cell `name` and watches it: its cgroup id and `populated`.
    fn open_existing(&mut self, slot: u16, name: &CStr) -> Result<(u64, bool), Errno>;
    /// `(populated, frozen)`.
    fn read_level(&mut self, slot: u16) -> Result<(bool, bool), Errno>;
    /// Starts `cmd` in the cell; watches its pidfd, its exec-error pipe and, in pipe mode, its
    /// readiness pipe. The returned handle names the main process.
    fn spawn(&mut self, slot: u16, cmd: Command, ready: ReadyMode) -> Result<Handle, Errno>;
    /// Tracks a main pidfd queen handed over.
    fn adopt_main(&mut self, slot: u16, pidfd: OwnedFd) -> Result<Handle, Errno>;
    fn signal_main(&mut self, slot: u16, main: Handle, sig: Sig) -> Result<(), Errno>;
    fn freeze(&mut self, slot: u16, on: bool) -> Result<(), Errno>;
    /// Signals every member whose pidfd's cgroup id is this cell's.
    fn signal_members(&mut self, slot: u16, sig: Sig) -> Result<(), Errno>;
    fn kill(&mut self, slot: u16) -> Result<(), Errno>;
    /// Stops watching the cell and removes its directory.
    fn remove(&mut self, slot: u16, name: &CStr) -> Result<(), Errno>;
    fn arm(&mut self, slot: u16, timer: Timer, ms: u32) -> Result<(), Errno>;
    fn cancel(&mut self, slot: u16, timer: Timer) -> Result<(), Errno>;
    /// Reads the readiness pipe; 0 is EOF.
    fn read_ready(&mut self, slot: u16, buf: &mut [u8]) -> Result<usize, Errno>;
    /// Reads the exec-error pipe: `None` when exec succeeded (EOF), the child's errno otherwise.
    fn read_exec_error(&mut self, slot: u16) -> Result<Option<Errno>, Errno>;
    /// Stops watching one source of a slot and drops its descriptor. For [`Source::Main`], a
    /// process that has not been reaped is still reaped (never left a zombie), only no cell
    /// hears of it.
    fn close(&mut self, slot: u16, source: Source);
    /// Drops everything of a slot (a main process not yet reaped is handled as by `close`).
    fn release(&mut self, slot: u16);
    /// Reaps every exited child (subreaper mode).
    fn reap_children(&mut self) -> Result<Vec<Reaped>, Errno>;
    /// The cell's cgroup id, once opened.
    fn cgroup_id(&self, slot: u16) -> Option<u64>;
}
