// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Connections: limits, identity, framing and the dispatch into colony.

use qinit_colony::{Attached, Colony, Effects, Outcome, OwnedRep, Peer, WaitId};
use qinit_ipc::{PeerCred, Received, peer_cred, peer_pidfd, recv, send};
use qinit_proto_core::{DecodeError, MAX_MESSAGE, authorized};
use qinit_wire::{ErrorCode, Msg, Req, decode, op_of};
use std::collections::HashMap;
use std::io::Read;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

/// The most bytes of a database a refresh may pass: above the largest valid one (four tables at
/// their limits plus the string pool).
pub const MAX_DB_READ: usize = 8 * 1024 * 1024;

/// The wire number of a database that is larger than [`MAX_DB_READ`].
const REASON_TOO_LARGE: u32 = 19;

/// The wire number of a database that cannot be read.
const REASON_UNREADABLE: u32 = 20;

/// Connection limits (spec R5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Connections at once.
    pub total: usize,
    /// Connections at once of one user other than root.
    pub per_uid: usize,
    /// Bytes of one message.
    pub message: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            total: 64,
            per_uid: 4,
            message: MAX_MESSAGE,
        }
    }
}

/// A connection, as the server numbers it. The event loop uses it as the connection's token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnId(pub u64);

/// A connection refused at `accept`: a limit is reached or the peer's identity could not be
/// had. The server has already answered (when it could) and closed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

enum State {
    Idle,
    /// A reply is parked under this wait.
    Waiting(WaitId),
}

struct Conn {
    fd: OwnedFd,
    peer: Peer,
    /// Held for the connection's life: it names the process even after the pid is reused.
    _pidfd: Option<OwnedFd>,
    state: State,
}

/// The server: the accepted connections and the waits that belong to them.
pub struct Server {
    limits: Limits,
    conns: HashMap<ConnId, Conn>,
    waits: HashMap<WaitId, ConnId>,
    next_conn: u64,
    next_wait: u64,
    out: Box<[u8; MAX_MESSAGE]>,
}

/// A zeroed buffer of one whole message, on the heap.
fn message_buffer() -> Box<[u8; MAX_MESSAGE]> {
    vec![0u8; MAX_MESSAGE]
        .try_into()
        .unwrap_or_else(|_| unreachable!("the vector has exactly MAX_MESSAGE bytes"))
}

fn encode_error(code: ErrorCode, detail: u32) -> Option<Vec<u8>> {
    let mut buf = message_buffer();
    let n = OwnedRep::Error { code, detail }.encode(&mut buf).ok()?;
    Some(buf[..n].to_vec())
}

/// Reads the database a refresh passed: a regular file or a memfd, at most [`MAX_DB_READ`].
/// Anything else (a pipe that may never end) is refused unread.
fn read_database(fd: OwnedFd) -> Result<Vec<u8>, u32> {
    let file = std::fs::File::from(fd);
    let meta = file.metadata().map_err(|_| REASON_UNREADABLE)?;
    if !meta.file_type().is_file() {
        return Err(REASON_UNREADABLE);
    }
    if meta.len() > MAX_DB_READ as u64 {
        return Err(REASON_TOO_LARGE);
    }
    let mut bytes = Vec::new();
    let mut reader = file.take(MAX_DB_READ as u64 + 1);
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| REASON_UNREADABLE)?;
    if bytes.len() > MAX_DB_READ {
        return Err(REASON_TOO_LARGE);
    }
    Ok(bytes)
}

impl Server {
    /// A server with no connections.
    #[must_use]
    pub fn new(limits: Limits) -> Server {
        Server {
            limits,
            conns: HashMap::new(),
            waits: HashMap::new(),
            next_conn: 1,
            next_wait: 1,
            out: message_buffer(),
        }
    }

    /// The number of connections.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.conns.len()
    }

    /// The descriptor of a connection, for the event loop to watch.
    #[must_use]
    pub fn fd(&self, conn: ConnId) -> Option<BorrowedFd<'_>> {
        self.conns.get(&conn).map(|c| c.fd.as_fd())
    }

    /// Takes a connection the listener accepted: reads the peer's credentials and pidfd (a
    /// connection that gives neither is closed, spec R2) and applies the limits.
    ///
    /// # Errors
    /// [`Full`] when the connection was closed instead of kept.
    pub fn accept(&mut self, fd: OwnedFd) -> Result<ConnId, Full> {
        let Ok(PeerCred { pid, uid, gid }) = peer_cred(fd.as_fd()) else {
            return Err(Full);
        };
        let Ok(pidfd) = peer_pidfd(fd.as_fd()) else {
            return Err(Full);
        };
        self.admit(fd, Peer { uid, gid, pid }, Some(pidfd))
    }

    /// As [`Server::accept`], with the identity given instead of read: for tests that need a
    /// peer of another user.
    ///
    /// # Errors
    /// [`Full`] when a limit closed the connection.
    #[cfg(feature = "testing")]
    pub fn accept_as(&mut self, fd: OwnedFd, peer: Peer) -> Result<ConnId, Full> {
        self.admit(fd, peer, None)
    }

    fn admit(&mut self, fd: OwnedFd, peer: Peer, pidfd: Option<OwnedFd>) -> Result<ConnId, Full> {
        let same_user = self
            .conns
            .values()
            .filter(|c| c.peer.uid == peer.uid)
            .count();
        let over_user = peer.uid != 0 && same_user >= self.limits.per_uid;
        if self.conns.len() >= self.limits.total || over_user {
            if let Some(bytes) = encode_error(ErrorCode::Full, 0) {
                let _ = send(fd.as_fd(), &bytes, &[]);
            }
            return Err(Full);
        }
        let id = ConnId(self.next_conn);
        self.next_conn += 1;
        self.conns.insert(
            id,
            Conn {
                fd,
                peer,
                _pidfd: pidfd,
                state: State::Idle,
            },
        );
        Ok(id)
    }

    /// Sends `rep` on `conn`; `false` when it could not be sent.
    fn reply(&mut self, conn: ConnId, rep: &OwnedRep) -> bool {
        let Some(c) = self.conns.get(&conn) else {
            return false;
        };
        let Ok(n) = rep.encode(&mut self.out) else {
            return false;
        };
        send(c.fd.as_fd(), &self.out[..n], &[]).is_ok()
    }

    /// Answers a malformed or unwanted message with one error and closes the connection.
    fn refuse<E: Effects>(
        &mut self,
        conn: ConnId,
        code: ErrorCode,
        detail: u32,
        colony: &mut Colony<E>,
    ) {
        let _ = self.reply(conn, &OwnedRep::Error { code, detail });
        self.close(conn, colony);
    }

    /// Closes a connection: its parked wait is forgotten.
    pub fn close<E: Effects>(&mut self, conn: ConnId, colony: &mut Colony<E>) {
        if let Some(c) = self.conns.remove(&conn)
            && let State::Waiting(w) = c.state
        {
            self.waits.remove(&w);
            colony.drop_wait(w);
        }
    }

    /// The connection has something to read: serves one request. Returns the connections that
    /// were closed (the event loop forgets them).
    pub fn on_readable<E: Effects>(
        &mut self,
        conn: ConnId,
        colony: &mut Colony<E>,
        now: u64,
    ) -> Vec<ConnId> {
        let mut closed = Vec::new();
        let Some(c) = self.conns.get(&conn) else {
            return closed;
        };
        let mut buf = vec![0u8; self.limits.message];
        let Ok(got) = recv(c.fd.as_fd(), &mut buf) else {
            self.close(conn, colony);
            return vec![conn];
        };
        let Received {
            len,
            fds,
            truncated,
            ctrunc,
        } = got;
        closed.extend(self.serve(conn, &buf[..len], fds, (truncated, ctrunc), colony, now));
        if !self.conns.contains_key(&conn) && !closed.contains(&conn) {
            closed.push(conn);
        }
        closed
    }

    fn serve<E: Effects>(
        &mut self,
        conn: ConnId,
        bytes: &[u8],
        fds: Vec<OwnedFd>,
        (truncated, ctrunc): (bool, bool),
        colony: &mut Colony<E>,
        now: u64,
    ) -> Vec<ConnId> {
        if bytes.is_empty() && !truncated {
            // The peer closed.
            self.close(conn, colony);
            return Vec::new();
        }
        if truncated {
            self.refuse(
                conn,
                ErrorCode::BadRequest,
                DecodeError::Header as u32,
                colony,
            );
            return Vec::new();
        }
        if ctrunc {
            self.refuse(
                conn,
                ErrorCode::BadRequest,
                DecodeError::FdCount as u32,
                colony,
            );
            return Vec::new();
        }
        if matches!(
            self.conns.get(&conn).map(|c| &c.state),
            Some(State::Waiting(_))
        ) {
            // One request in flight (R3): the first one's effect stands.
            self.refuse(
                conn,
                ErrorCode::BadRequest,
                DecodeError::Consistency as u32,
                colony,
            );
            return Vec::new();
        }
        let msg = match decode(bytes, fds.len()) {
            Ok(m) => m,
            Err(DecodeError::Version) => {
                self.refuse(conn, ErrorCode::Version, 0, colony);
                return Vec::new();
            }
            Err(e) => {
                self.refuse(conn, ErrorCode::BadRequest, e as u32, colony);
                return Vec::new();
            }
        };
        let Msg::Req(req) = msg else {
            self.refuse(
                conn,
                ErrorCode::BadRequest,
                DecodeError::Type as u32,
                colony,
            );
            return Vec::new();
        };
        let Some(peer) = self.conns.get(&conn).map(|c| c.peer) else {
            return Vec::new();
        };
        self.dispatch(conn, peer, &req, fds, colony, now)
    }

    fn dispatch<E: Effects>(
        &mut self,
        conn: ConnId,
        peer: Peer,
        req: &Req<'_>,
        fds: Vec<OwnedFd>,
        colony: &mut Colony<E>,
        now: u64,
    ) -> Vec<ConnId> {
        let mut attached = Attached::default();
        match req {
            Req::Refresh { .. } => {
                // Only a peer that may refresh gets its descriptor read.
                if authorized(op_of(req), qinit_proto_core::PeerId { uid: peer.uid }) {
                    attached.database = fds.into_iter().next().map(read_database);
                }
            }
            _ => attached.fds = fds,
        }
        let wait = WaitId(self.next_wait);
        self.next_wait += 1;
        let handled = colony.handle(peer, req, attached, wait, now);
        let _ = self.reply(conn, &handled.reply);
        // A second reply is owed when the wait was parked, or when the same call already
        // settled it (it then goes out with the outcome below).
        let owed = handled.waiting || handled.outcome.replies.iter().any(|(w, _)| *w == wait);
        if owed && let Some(c) = self.conns.get_mut(&conn) {
            c.state = State::Waiting(wait);
            self.waits.insert(wait, conn);
        }
        self.on_outcome(&handled.outcome, colony)
    }

    /// Sends the replies colony owes to parked waits, and returns the connections that could
    /// not be written to (they are closed).
    pub fn on_outcome<E: Effects>(&mut self, out: &Outcome, colony: &mut Colony<E>) -> Vec<ConnId> {
        let mut closed = Vec::new();
        for (wait, rep) in &out.replies {
            let Some(conn) = self.waits.remove(wait) else {
                continue;
            };
            if let Some(c) = self.conns.get_mut(&conn) {
                c.state = State::Idle;
            }
            if !self.reply(conn, rep) {
                self.close(conn, colony);
                closed.push(conn);
            }
        }
        closed
    }
}
