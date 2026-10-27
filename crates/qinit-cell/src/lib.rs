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
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::Duration;

/// The cells under one comb directory.
pub struct Cells {
    engine: Engine<Kernel>,
    pending_error: Option<Error>,
}

impl Cells {
    /// Opens comb `root`; refuses a kernel below the floor (spec R9).
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
    // Fallible and blocking, so not an `Iterator`; the guest suites call it `next`.
    #[allow(clippy::should_implement_trait)]
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
