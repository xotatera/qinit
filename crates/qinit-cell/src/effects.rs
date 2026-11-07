// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the engine asks of the system. `Kernel` performs it; `Sim` records it.
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
    /// A cell's main process `(slot, pid, wait status)`, reaped through its pidfd.
    Main(u16, libc::pid_t, i32),
    /// An orphan re-parented to this process (or a child no cell tracks any more).
    Orphan(libc::pid_t, i32),
}

/// Effects per cell slot. Every error is an errno; the engine decides what it means.
#[allow(clippy::missing_errors_doc)] // each method's error is the errno of the operation its doc names
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
    /// child that has not been reaped is still reaped (never left a zombie) and reported
    /// through `take_reaped`.
    fn close(&mut self, slot: u16, source: Source);
    /// Drops everything of a slot (a main process not yet reaped is handled as by `close`).
    fn release(&mut self, slot: u16);
    /// Reaps every exited child (subreaper mode). Children reaped before an error are
    /// returned, and the error comes on the next call.
    fn reap_children(&mut self) -> Result<Vec<Reaped>, Errno>;
    /// `(pid, wait status)` of every child reaped outside `reap_children` that no cell
    /// tracks (a main let go by `close` or `release`), since the last call.
    fn take_reaped(&mut self) -> Vec<(libc::pid_t, i32)>;
    /// Writes `memory.max` (bytes) and `pids.max` into the cell directory; 0 skips that file.
    fn write_limits(
        &mut self,
        slot: u16,
        memory_max_bytes: u64,
        pids_max: u32,
    ) -> Result<(), Errno>;
    /// Signals the tracked main process by number through its pidfd; `ESRCH` when none is
    /// tracked or it is gone.
    fn signal_number(&mut self, slot: u16, sig: i32) -> Result<(), Errno>;
    /// A duplicate of the tracked main's pidfd; `ESRCH` when none is tracked.
    fn dup_main_pidfd(&mut self, slot: u16) -> Result<OwnedFd, Errno>;
    /// The cell's cgroup id, once opened.
    fn cgroup_id(&self, slot: u16) -> Option<u64>;
    /// The exit status the kernel recorded for the tracked main (`PIDFD_INFO_EXIT`, Linux 6.15):
    /// `Some` once the main has been reaped by anyone, `None` while it runs, has not been
    /// reaped yet, or none is tracked.
    fn main_status(&mut self, slot: u16) -> Option<i32>;
    /// Takes the tracked main out of the loop and keeps its pidfd, so a later `main_status`
    /// can still read it. The next `close(slot, Source::Main)` drops it.
    fn unwatch_main(&mut self, slot: u16);
    /// Hands over the cell's directory: the next `open_existing` for the slot uses it instead of
    /// opening the cell by name.
    fn hand_dir(&mut self, slot: u16, dir: OwnedFd);
    /// A duplicate of the cell's directory descriptor; `EBADF` when none is open.
    fn dup_dir(&mut self, slot: u16) -> Result<OwnedFd, Errno>;
}
