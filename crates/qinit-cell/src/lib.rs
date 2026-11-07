// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! `qinit-cell`: run process trees in root-owned cgroup v2 cells and take them down again
//! (spec 2026-10-27). [`Cells`] is the API; the engine steps `qinit-cell-core`'s machine per
//! cell and carries out its actions through [`effects::Effects`].
pub mod effects;
pub mod engine;
pub mod kernel;
pub mod sim;
pub mod text;

pub use effects::Command;
pub use engine::{CellId, Error, Notice};
pub use qinit_cell_core::{Failure, Phase, Polite, ReadyMode, Report};

use effects::Effects;
use engine::{Engine, ORPHANS};
use kernel::Kernel;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::Path;
use std::time::Duration;

/// The cells under one comb directory.
pub struct Cells {
    engine: Engine<Kernel>,
    pending_error: Option<Error>,
}

impl Cells {
    /// Opens comb `root`; refuses a kernel below the floor (Linux 6.15).
    ///
    /// # Errors
    ///
    /// [`Error::Floor`] below the floor; [`Error::Sys`] when the release, the comb or the loop
    /// cannot be had.
    pub fn open(root: &Path) -> Result<Cells, Error> {
        let release = qinit_sys::proc::kernel_release()?;
        text::kernel_supported(&release).map_err(Error::Floor)?;
        Ok(Cells {
            engine: Engine::new(Kernel::open(root)?),
            pending_error: None,
        })
    }

    /// Becomes a subreaper and reports every orphan it reaps (rollout stage 1).
    ///
    /// # Errors
    ///
    /// [`Error::Sys`] when the prctl or the SIGCHLD source fails.
    pub fn subreaper(&mut self) -> Result<(), Error> {
        qinit_sys::proc::set_child_subreaper()?;
        self.engine.effects.watch_children(ORPHANS)?;
        Ok(())
    }

    /// Every main spawned from now on starts with `RLIMIT_NOFILE` `limit` (soft, hard), not with
    /// this process's: for a caller that raised its own to hold more than its services should.
    pub fn child_nofile(&mut self, limit: (u64, u64)) {
        self.engine.effects.child_nofile(limit);
    }

    /// See [`Engine::create`].
    ///
    /// # Errors
    ///
    /// As [`Engine::create`].
    pub fn create(&mut self, name: &str) -> Result<CellId, Error> {
        self.engine.create(name)
    }

    /// See [`Engine::spawn`].
    ///
    /// # Errors
    ///
    /// As [`Engine::spawn`].
    pub fn spawn(&mut self, id: CellId, cmd: Command, ready: ReadyMode) -> Result<(), Error> {
        self.engine.spawn(id, cmd, ready)
    }

    /// See [`Engine::adopt`].
    ///
    /// # Errors
    ///
    /// As [`Engine::adopt`].
    pub fn adopt(
        &mut self,
        name: &str,
        expected_id: u64,
        main: Option<OwnedFd>,
    ) -> Result<CellId, Error> {
        self.engine.adopt(name, expected_id, main)
    }

    /// See [`Engine::adopt_held`].
    ///
    /// # Errors
    ///
    /// As [`Engine::adopt_held`].
    pub fn adopt_held(
        &mut self,
        name: &str,
        expected_id: u64,
        dir: OwnedFd,
        main: Option<OwnedFd>,
    ) -> Result<CellId, Error> {
        self.engine.adopt_held(name, expected_id, dir, main)
    }

    /// See [`Engine::dir_fd`].
    ///
    /// # Errors
    ///
    /// As [`Engine::dir_fd`].
    pub fn dir_fd(&mut self, id: CellId) -> Result<OwnedFd, Error> {
        self.engine.dir_fd(id)
    }

    /// See [`Engine::wait_for_status`]. Only a caller whose mains are reaped by a queen asks.
    pub fn wait_for_status(&mut self) {
        self.engine.wait_for_status();
    }

    /// See [`Engine::settle_status`].
    ///
    /// # Errors
    ///
    /// As [`Engine::settle_status`].
    pub fn settle_status(&mut self, id: CellId, give_up: bool) -> Result<bool, Error> {
        self.engine.settle_status(id, give_up)
    }

    /// See [`Engine::stop`].
    ///
    /// # Errors
    ///
    /// As [`Engine::stop`].
    pub fn stop(
        &mut self,
        id: CellId,
        polite: Polite,
        grace: Duration,
        kill: Duration,
    ) -> Result<(), Error> {
        self.engine.stop(id, polite, grace, kill)
    }

    /// See [`Engine::remove`].
    ///
    /// # Errors
    ///
    /// As [`Engine::remove`].
    pub fn remove(&mut self, id: CellId) -> Result<(), Error> {
        self.engine.remove(id)
    }

    /// See [`Engine::set_limits`].
    ///
    /// # Errors
    ///
    /// As [`Engine::set_limits`].
    pub fn set_limits(
        &mut self,
        id: CellId,
        memory_max_bytes: u64,
        pids_max: u32,
    ) -> Result<(), Error> {
        self.engine.set_limits(id, memory_max_bytes, pids_max)
    }

    /// See [`Engine::mark_ready`].
    ///
    /// # Errors
    ///
    /// As [`Engine::mark_ready`].
    pub fn mark_ready(&mut self, id: CellId) -> Result<(), Error> {
        self.engine.mark_ready(id)
    }

    /// See [`Engine::signal_main`].
    ///
    /// # Errors
    ///
    /// As [`Engine::signal_main`].
    pub fn signal_main(&mut self, id: CellId, sig: i32) -> Result<(), Error> {
        self.engine.signal_main(id, sig)
    }

    /// See [`Engine::main_pidfd`].
    ///
    /// # Errors
    ///
    /// As [`Engine::main_pidfd`].
    pub fn main_pidfd(&mut self, id: CellId) -> Result<OwnedFd, Error> {
        self.engine.main_pidfd(id)
    }

    /// The cells' own loop's epoll descriptor: readable while [`Cells::poll`] has something
    /// to do. A caller with its own loop registers this and calls `poll` when it fires.
    #[must_use]
    pub fn poll_fd(&self) -> BorrowedFd<'_> {
        self.engine.effects.poll_fd()
    }

    /// One non-blocking round of the cells' loop, then the notices pending (possibly none).
    /// An error the round hit after it produced notices is returned by the next call.
    ///
    /// # Errors
    ///
    /// [`Error::Sys`] when the loop or an effect failed.
    pub fn poll(&mut self) -> Result<Vec<Notice>, Error> {
        if let Some(error) = self.pending_error.take() {
            return Err(error);
        }
        let batch = self.engine.effects.poll()?;
        self.pending_error = self.engine.on_batch(&batch);
        let notices = self.engine.take_notices();
        if notices.is_empty()
            && let Some(error) = self.pending_error.take()
        {
            return Err(error);
        }
        Ok(notices)
    }

    #[must_use]
    pub fn cgroup_id(&self, id: CellId) -> Option<u64> {
        self.engine.effects.cgroup_id(id.0)
    }

    /// The cell's main process's pid while it is tracked: from the spawn (or the hand-over on
    /// adoption) until its exit is seen.
    #[must_use]
    pub fn main_pid(&self, id: CellId) -> Option<libc::pid_t> {
        self.engine.effects.main_pid(id.0)
    }

    #[must_use]
    pub fn phase(&self, id: CellId) -> Option<Phase> {
        self.engine.phase(id)
    }

    /// The next notices: those already pending, else those of the next loop wake-ups that
    /// bring any.
    ///
    /// # Errors
    ///
    /// [`Error::Sys`] when the loop or an effect failed (an empty loop is `EINVAL`).
    #[allow(clippy::should_implement_trait)] // fallible and blocking, so not an `Iterator`; the guest suites call it `next`
    pub fn next(&mut self) -> Result<Vec<Notice>, Error> {
        if let Some(error) = self.pending_error.take() {
            return Err(error);
        }
        loop {
            let notices = self.engine.take_notices();
            if !notices.is_empty() {
                return Ok(notices);
            }
            let batch = self.engine.effects.wait()?;
            self.pending_error = self.engine.on_batch(&batch);
            let notices = self.engine.take_notices();
            if !notices.is_empty() {
                return Ok(notices);
            }
            if let Some(error) = self.pending_error.take() {
                return Err(error);
            }
        }
    }

    /// Runs `hook` with each member's pid between reading `cgroup.procs` and verifying its pidfd.
    #[cfg(feature = "test-hooks")]
    pub fn set_between_hook(&mut self, hook: Box<dyn FnMut(libc::pid_t)>) {
        self.engine.effects.between = Some(hook);
    }
}
