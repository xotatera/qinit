// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! A small driver for tests and the VM suite: a listener, the server, and a `qinit-event` loop.
//! The daemon (sub-project 7) has its own loop and calls the same server methods.

use crate::server::{ConnId, Limits, Server};
use qinit_colony::{Colony, Effects, Outcome, Peer};
use qinit_event::{Loop, Ready};
use qinit_ipc::accept;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::time::Duration;

/// The listener's token; connections use their own id (from 1).
const LISTENER: u64 = 0;
/// The token of the idle marker `pump` uses.
const IDLE: u64 = u64::MAX;
/// The token of the stop descriptor `serve_until` watches.
const STOP: u64 = u64::MAX - 1;

/// A server on a listening socket, driven one batch of events at a time.
pub struct Driver {
    pub server: Server,
    listener: OwnedFd,
    events: Loop,
    /// When set, every accepted connection is given this identity instead of its own.
    pub identity: Option<Peer>,
}

impl Driver {
    /// A driver for `listener`.
    ///
    /// # Errors
    /// The event loop's error when it cannot watch the listener.
    pub fn new(listener: OwnedFd, limits: Limits) -> Result<Driver, qinit_event::Error> {
        let mut events = Loop::new()?;
        events.add_fd(listener.as_fd(), LISTENER)?;
        Ok(Driver {
            server: Server::new(limits),
            listener,
            events,
            identity: None,
        })
    }

    fn batch<E: Effects>(
        &mut self,
        colony: &mut Colony<E>,
        now: u64,
        ready: Vec<Ready>,
    ) -> Result<bool, qinit_event::Error> {
        let mut idle = false;
        for r in ready {
            match r {
                Ready::Readable(LISTENER) => self.accept_one()?,
                Ready::Readable(token) => {
                    let closed = self.server.on_readable(ConnId(token), colony, now);
                    self.forget(&closed)?;
                }
                Ready::Hangup(token) => {
                    self.server.close(ConnId(token), colony);
                    self.forget(&[ConnId(token)])?;
                }
                Ready::Deadline(IDLE) => idle = true,
                _ => {}
            }
        }
        Ok(idle)
    }

    fn accept_one(&mut self) -> Result<(), qinit_event::Error> {
        let Ok(fd) = accept(self.listener.as_fd()) else {
            return Ok(());
        };
        let admitted = match self.identity {
            Some(peer) => self.server.accept_as(fd, peer),
            None => self.server.accept(fd),
        };
        if let Ok(id) = admitted
            && let Some(fd) = self.server.fd(id)
        {
            self.events.add_fd(fd, id.0)?;
        }
        Ok(())
    }

    /// Drops the closed connections from the loop. Their descriptors are already closed, which
    /// removed them from epoll; the loop forgets the token either way, so its error is ignored.
    #[allow(clippy::unnecessary_wraps)] // kept symmetric with the other steps of a batch
    fn forget(&mut self, closed: &[ConnId]) -> Result<(), qinit_event::Error> {
        for c in closed {
            let _ = self.events.remove(c.0);
        }
        Ok(())
    }

    /// Delivers the replies in `out` (from a timer or a cell event) to their connections.
    ///
    /// # Errors
    /// The event loop's error.
    pub fn deliver<E: Effects>(
        &mut self,
        out: &Outcome,
        colony: &mut Colony<E>,
    ) -> Result<(), qinit_event::Error> {
        let closed = self.server.on_outcome(out, colony);
        self.forget(&closed)
    }

    /// Serves everything that is ready now and returns when nothing is: a zero deadline marks
    /// the end of a round, and a round with nothing but the marker is the last. Nothing sleeps.
    ///
    /// # Errors
    /// The event loop's error.
    pub fn pump<E: Effects>(
        &mut self,
        colony: &mut Colony<E>,
        now: u64,
    ) -> Result<(), qinit_event::Error> {
        loop {
            self.events.add_deadline(Duration::ZERO, IDLE)?;
            let mut busy = false;
            loop {
                let ready = self.events.wait()?;
                busy |= ready.iter().any(|r| !matches!(r, Ready::Deadline(IDLE)));
                if self.batch(colony, now, ready)? {
                    break;
                }
            }
            if !busy {
                return Ok(());
            }
        }
    }

    /// Serves until `stop` becomes readable. After each wake-up `tick` gives the time and the
    /// outcome of whatever timers and cell events came due (a simulation moves its clock
    /// there; a real loop reads the clock and returns an empty outcome).
    ///
    /// # Errors
    /// The event loop's error.
    pub fn serve_until<E: Effects>(
        &mut self,
        colony: &mut Colony<E>,
        stop: BorrowedFd<'_>,
        mut tick: impl FnMut(&mut Colony<E>) -> (u64, Outcome),
    ) -> Result<(), qinit_event::Error> {
        self.events.add_fd(stop, STOP)?;
        let (mut now, first) = tick(colony);
        self.deliver(&first, colony)?;
        loop {
            let ready = self.events.wait()?;
            if ready
                .iter()
                .any(|r| matches!(r, Ready::Readable(STOP) | Ready::Hangup(STOP)))
            {
                self.events.remove(STOP)?;
                return Ok(());
            }
            self.batch(colony, now, ready)?;
            let (next, out) = tick(colony);
            now = next;
            self.deliver(&out, colony)?;
        }
    }
}
