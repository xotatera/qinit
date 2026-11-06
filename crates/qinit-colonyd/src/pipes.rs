// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Logger pipes. For every node a pipe route names, colony holds one pipe, both ends, for as long
//! as that node is a logger in the database. A producer's request routes the write end as its
//! output or error stream, the logger's request routes the read end as its input. Colony never
//! reads or writes the pipe, so a restart of either side finds the same pipe and nothing in it is
//! lost. A refresh keeps the pipe of a logger that is still one, matched by name.
use qinit_db::{Model, Route};
use qinit_sys::Errno;
use std::collections::BTreeMap;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

/// The pipes colony holds.
#[derive(Debug, Default)]
pub struct Pipes {
    /// `(read end, write end)` by the logger's name.
    by_name: BTreeMap<String, (OwnedFd, OwnedFd)>,
    /// The logger's name by its node index in the database in force.
    names: BTreeMap<u32, String>,
}

impl Pipes {
    /// Makes the pipes of `model`'s loggers: a logger that already has one keeps it, one that is
    /// no longer a logger loses it (both ends closed), a new one gets a new pipe.
    ///
    /// # Errors
    ///
    /// The errno of creating a pipe; the loggers before it keep theirs.
    pub fn rebuild(&mut self, model: &Model) -> Result<(), Errno> {
        let mut names = BTreeMap::new();
        for route in &model.routes {
            if let Route::Pipe(logger) = route
                && let Some(node) = model.nodes.get(*logger as usize)
            {
                names.insert(*logger, node.name.clone());
            }
        }
        self.by_name
            .retain(|name, _| names.values().any(|n| n == name));
        self.names = names;
        for name in self.names.values() {
            if !self.by_name.contains_key(name) {
                let ends = qinit_sys::fd::pipe(libc::O_CLOEXEC)?;
                self.by_name.insert(name.clone(), ends);
            }
        }
        Ok(())
    }

    fn ends(&self, logger: u32) -> Option<&(OwnedFd, OwnedFd)> {
        self.by_name.get(self.names.get(&logger)?)
    }

    /// The write end of the pipe of the logger at node index `logger`.
    #[must_use]
    pub fn writer(&self, logger: u32) -> Option<BorrowedFd<'_>> {
        self.ends(logger).map(|(_, w)| w.as_fd())
    }

    /// The read end of the pipe of the logger at node index `logger`.
    #[must_use]
    pub fn reader(&self, logger: u32) -> Option<BorrowedFd<'_>> {
        self.ends(logger).map(|(r, _)| r.as_fd())
    }

    /// The node table was renumbered: new node `i` was node `map[i]` before (`u32::MAX` for a new
    /// node). A pipe follows its logger; one whose node is absent from `map` has no index until
    /// the next [`Pipes::rebuild`], which closes it if the logger is gone.
    pub fn remap(&mut self, map: &[u32]) {
        let old = std::mem::take(&mut self.names);
        for (was, name) in old {
            if let Some(now) = map.iter().position(|&m| m == was) {
                self.names
                    .insert(u32::try_from(now).unwrap_or(u32::MAX), name);
            }
        }
    }
}
