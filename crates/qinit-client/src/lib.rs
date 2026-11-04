// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! `qinit-client`: a blocking client of the control protocol (`docs/control-protocol.md`). One
//! method per operation; each sends one request and reads the reply or replies that belong to
//! it. The client is a thin shell over the proved message format.
#![forbid(unsafe_code)]

use qinit_ipc::{connect_seqpacket, recv, send};
use qinit_launch::RequestSpec;
use qinit_proto_core::{DecodeError, MAX_MESSAGE};
use qinit_wire::{Msg, Rep, Req, decode, encode};
use std::ffi::CString;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::time::Duration;

pub use qinit_wire::{Action, ErrorCode, Mode, StateWord};

/// Where colony listens.
pub const SOCKET: &str = "/run/qinit/colony";

/// Why a call failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientError {
    /// A system call failed (errno).
    Io(i32),
    /// The server's message is not a message of the format.
    Protocol(DecodeError),
    /// The server refused the request, with its detail word.
    Server(ErrorCode, u32),
    /// The server closed the connection, or sent a reply that does not answer the request.
    Unexpected,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "{}", std::io::Error::from_raw_os_error(*e)),
            ClientError::Protocol(e) => write!(f, "protocol error: {e:?}"),
            ClientError::Server(code, detail) => write!(f, "refused: {code:?} ({detail})"),
            ClientError::Unexpected => write!(f, "unexpected reply or closed connection"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<qinit_ipc::Errno> for ClientError {
    fn from(e: qinit_ipc::Errno) -> Self {
        ClientError::Io(e.0)
    }
}

/// How long a request that can wait does wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// Reply on acceptance.
    Now,
    /// Reply again when the target state is reached, or after this long (1 ms to 10 min).
    Settled(Duration),
}

/// The longest wait the protocol allows, in milliseconds.
const MAX_WAIT_MS: u32 = 600_000;

impl Wait {
    fn words(self) -> (bool, u32) {
        match self {
            Wait::Now => (false, 0),
            Wait::Settled(d) => (
                true,
                // The protocol allows 1 ms to 10 min: a longer wait is clamped, a zero one raised.
                u32::try_from(d.as_millis())
                    .unwrap_or(u32::MAX)
                    .clamp(1, MAX_WAIT_MS),
            ),
        }
    }
}

/// A node's status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeInfo {
    pub name: String,
    /// 0 worker, 1 forager, 2 brood.
    pub kind: u32,
    pub state: StateWord,
    /// The first unsatisfied group of a waiting node and its first unsatisfied target.
    pub blocking: Option<(u32, String)>,
    pub backoff_ms: u32,
    pub since_ms: u64,
    pub restarts: u32,
    pub pid: Option<i32>,
}

/// An instance's status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceInfo {
    pub frame: String,
    pub id: u32,
    /// 2 starting, 3 running, 4 exited, 5 stopping.
    pub state: u32,
    pub status: Option<i32>,
    pub pid: Option<i32>,
}

/// What `status` returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Node(NodeInfo),
    Instance(InstanceInfo),
}

/// One line of the node list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub kind: u32,
    pub state: StateWord,
}

/// The final reply to a request that can wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Accepted; the request did not ask to wait.
    Accepted,
    /// The awaited state was reached.
    Settled(StateWord),
    /// The wait ended first; the request stays in effect.
    Pending(StateWord),
    /// Another request changed what the wait waited for.
    Superseded(StateWord),
}

/// What `launch` returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchOutcome {
    /// The instance ended with this wait status.
    Exited { id: u32, status: i32 },
    /// The wait ended first; read the instance with `status` on `<frame>#<id>`.
    Pending { id: u32, state: StateWord },
    /// The instance could not be started.
    Failed { step: u32, errno: u32 },
}

/// A launch the server started: the instance's id, and a pidfd of its main process when the
/// launch asked for one and the server could open it.
#[derive(Debug)]
pub struct Started {
    pub id: u32,
    pub pidfd: Option<OwnedFd>,
}

/// What `begin_launch` returns: the first reply of a launch.
#[derive(Debug)]
pub enum Begun {
    /// The instance runs; `finish` reads how it ends.
    Started(Started),
    /// The instance could not be started; nothing more comes.
    Failed { step: u32, errno: u32 },
}

/// What a launch adds to the frame's own definition.
#[derive(Default)]
pub struct LaunchArgs<'a> {
    pub argv_tail: &'a [&'a str],
    pub env: &'a [(&'a str, &'a str)],
    pub stdin: Option<BorrowedFd<'a>>,
    pub stdout: Option<BorrowedFd<'a>>,
    pub stderr: Option<BorrowedFd<'a>>,
}

/// What a `run` sets besides the request: the streams, the cell limits and how the instance
/// stops.
pub struct RunArgs<'a> {
    pub stdin: Option<BorrowedFd<'a>>,
    pub stdout: Option<BorrowedFd<'a>>,
    pub stderr: Option<BorrowedFd<'a>>,
    /// The cell's memory ceiling in KiB, 0 for none.
    pub memory_max_kib: u32,
    /// The cell's process ceiling, 0 for none.
    pub pids_max: u32,
    /// How the instance stops: the main process only, or the whole cell.
    pub stop_mode: StopMode,
    /// The grace before the kill, in milliseconds, at least 100.
    pub stop_grace_ms: u32,
}

impl Default for RunArgs<'_> {
    fn default() -> Self {
        RunArgs {
            stdin: None,
            stdout: None,
            stderr: None,
            memory_max_kib: 0,
            pids_max: 0,
            stop_mode: StopMode::Main,
            stop_grace_ms: 10_000,
        }
    }
}

/// How a launched instance is stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopMode {
    /// Signal the main process.
    Main,
    /// Signal every process of the cell.
    Cell,
}

/// A connection to colony.
pub struct Client {
    fd: OwnedFd,
    buf: Vec<u8>,
    out: Box<[u8; MAX_MESSAGE]>,
}

/// A reply, owned.
enum Reply {
    Error(ErrorCode, u32),
    Node(NodeInfo),
    Instance(InstanceInfo),
    Page(Vec<Entry>, Option<u32>),
    Accepted,
    Settled(StateWord),
    Pending(StateWord),
    Superseded(StateWord),
    Launched(u32),
    LaunchFailed(u32, u32),
    Exited(i32),
}

fn own(rep: Rep<'_>) -> Reply {
    match rep {
        Rep::Error { code, detail, .. } => Reply::Error(code, detail),
        Rep::NodeStatus(n) => Reply::Node(NodeInfo {
            name: n.name.to_owned(),
            kind: n.kind,
            state: n.state,
            blocking: n.blocking.map(|(g, t)| (g, t.to_owned())),
            backoff_ms: n.backoff_ms,
            since_ms: n.since_ms,
            restarts: n.restarts,
            pid: n.pid,
        }),
        Rep::InstanceStatus(i) => Reply::Instance(InstanceInfo {
            frame: i.frame.to_owned(),
            id: i.id,
            state: i.state,
            status: i.status,
            pid: i.pid,
        }),
        Rep::ListPage { entries, next } => Reply::Page(
            entries
                .iter()
                .map(|e| Entry {
                    name: e.name.to_owned(),
                    kind: e.kind,
                    state: e.state,
                })
                .collect(),
            next,
        ),
        Rep::Accepted => Reply::Accepted,
        Rep::Settled(s) => Reply::Settled(s),
        Rep::Pending(s) => Reply::Pending(s),
        Rep::Superseded(s) => Reply::Superseded(s),
        Rep::Launched { id } => Reply::Launched(id),
        Rep::LaunchFailed { step, errno } => Reply::LaunchFailed(step, errno),
        Rep::Exited { status } => Reply::Exited(status),
    }
}

impl Client {
    /// Connects to the server at `path` ([`SOCKET`] is where colony listens).
    ///
    /// # Errors
    /// The errno of the connection.
    pub fn connect(path: &Path) -> Result<Client, ClientError> {
        use std::os::unix::ffi::OsStrExt;
        let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| ClientError::Io(22))?;
        Ok(Client {
            fd: connect_seqpacket(&c)?,
            buf: vec![0u8; MAX_MESSAGE],
            out: vec![0u8; MAX_MESSAGE]
                .try_into()
                .map_err(|_| ClientError::Io(12))?,
        })
    }

    /// Sends one request with the descriptors it declares.
    fn ask(&mut self, req: Req<'_>, fds: &[BorrowedFd<'_>]) -> Result<(), ClientError> {
        let declared = u32::try_from(fds.len()).map_err(|_| ClientError::Io(22))?;
        let n = encode(&Msg::Req(req), declared, &mut self.out).map_err(|_| ClientError::Io(22))?;
        send(self.fd.as_fd(), &self.out[..n], fds)?;
        Ok(())
    }

    /// Reads the next reply and the descriptors that came with it; a server error is returned
    /// as an error.
    fn reply_with_fds(&mut self) -> Result<(Reply, Vec<OwnedFd>), ClientError> {
        let got = recv(self.fd.as_fd(), &mut self.buf)?;
        if got.len == 0 {
            return Err(ClientError::Unexpected);
        }
        match decode(&self.buf[..got.len], got.fds.len()).map_err(ClientError::Protocol)? {
            Msg::Rep(rep) => match own(rep) {
                Reply::Error(code, detail) => Err(ClientError::Server(code, detail)),
                other => Ok((other, got.fds)),
            },
            Msg::Req(_) => Err(ClientError::Unexpected),
        }
    }

    /// Reads the next reply, which carries no descriptor.
    fn reply(&mut self) -> Result<Reply, ClientError> {
        self.reply_with_fds().map(|(rep, _)| rep)
    }

    /// The status of a node, or of an instance (`<frame>#<id>`).
    ///
    /// # Errors
    /// [`ClientError`].
    pub fn status(&mut self, target: &str) -> Result<Status, ClientError> {
        self.ask(Req::Status { target }, &[])?;
        match self.reply()? {
            Reply::Node(n) => Ok(Status::Node(n)),
            Reply::Instance(i) => Ok(Status::Instance(i)),
            _ => Err(ClientError::Unexpected),
        }
    }

    /// Every node of `kind` (0 all, 1 workers, 2 foragers, 3 broods), following the cursors.
    ///
    /// # Errors
    /// [`ClientError`].
    pub fn list(&mut self, kind: u32) -> Result<Vec<Entry>, ClientError> {
        let mut all = Vec::new();
        let mut cursor = 0;
        loop {
            self.ask(Req::List { cursor, kind }, &[])?;
            let Reply::Page(entries, next) = self.reply()? else {
                return Err(ClientError::Unexpected);
            };
            all.extend(entries);
            match next {
                Some(n) => cursor = n,
                None => return Ok(all),
            }
        }
    }

    /// The reply to a request that can wait: the acceptance, then (settled) the final reply.
    fn waited(&mut self, wait: Wait) -> Result<Outcome, ClientError> {
        if !matches!(self.reply()?, Reply::Accepted) {
            return Err(ClientError::Unexpected);
        }
        if wait == Wait::Now {
            return Ok(Outcome::Accepted);
        }
        match self.reply()? {
            Reply::Settled(s) => Ok(Outcome::Settled(s)),
            Reply::Pending(s) => Ok(Outcome::Pending(s)),
            Reply::Superseded(s) => Ok(Outcome::Superseded(s)),
            _ => Err(ClientError::Unexpected),
        }
    }

    /// Does `action` to a node or an instance (root only).
    ///
    /// # Errors
    /// [`ClientError`]; `Server(Denied, _)` for a user other than root.
    pub fn change(
        &mut self,
        target: &str,
        action: Action,
        wait: Wait,
    ) -> Result<Outcome, ClientError> {
        let (settled, wait_ms) = wait.words();
        self.ask(
            Req::Change {
                target,
                action,
                settled,
                wait_ms,
            },
            &[],
        )?;
        self.waited(wait)
    }

    /// Launches an instance of the forager `frame` (root only) and waits for it to end for at
    /// most `wait`. No pidfd: see [`Client::begin_launch`].
    ///
    /// # Errors
    /// [`ClientError`].
    pub fn launch(
        &mut self,
        frame: &str,
        args: &LaunchArgs<'_>,
        wait: Duration,
    ) -> Result<LaunchOutcome, ClientError> {
        match self.begin_launch(frame, args, false, wait)? {
            Begun::Failed { step, errno } => Ok(LaunchOutcome::Failed { step, errno }),
            Begun::Started(Started { id, .. }) => self.finish(id),
        }
    }

    /// Sends a launch of the forager `frame` (root only) and reads its first reply. With
    /// `pidfd`, the reply to a started instance carries a pidfd of its main process when the
    /// server could open one; [`Client::finish`] then reads how the instance ends, within
    /// `wait`.
    ///
    /// # Errors
    /// [`ClientError`].
    pub fn begin_launch(
        &mut self,
        frame: &str,
        args: &LaunchArgs<'_>,
        pidfd: bool,
        wait: Duration,
    ) -> Result<Begun, ClientError> {
        let tail = args.argv_tail.join("\0");
        let env: Vec<String> = args.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let env = env.join("\0");
        let mut roles = 0u32;
        let mut fds: Vec<BorrowedFd<'_>> = Vec::new();
        for (bit, fd) in [(1, args.stdin), (2, args.stdout), (4, args.stderr)] {
            if let Some(fd) = fd {
                roles |= bit;
                fds.push(fd);
            }
        }
        let (_, wait_ms) = Wait::Settled(wait).words();
        self.ask(
            Req::Launch {
                frame,
                argv_tail: qinit_wire::StrList::new(tail.as_bytes()),
                env_add: qinit_wire::StrList::new(env.as_bytes()),
                fd_roles: roles,
                wait_ms,
                flags: u32::from(pidfd) * qinit_proto_core::FLAG_PIDFD,
            },
            &fds,
        )?;
        self.started()
    }

    /// Reads the reply to a launch or a run.
    fn started(&mut self) -> Result<Begun, ClientError> {
        match self.reply_with_fds()? {
            (Reply::Launched(id), mut got) => Ok(Begun::Started(Started {
                id,
                pidfd: if got.is_empty() {
                    None
                } else {
                    Some(got.remove(0))
                },
            })),
            (Reply::LaunchFailed(step, errno), _) => Ok(Begun::Failed { step, errno }),
            _ => Err(ClientError::Unexpected),
        }
    }

    /// Reads the end of the launch `id` that [`Client::begin_launch`] started.
    ///
    /// # Errors
    /// [`ClientError`].
    pub fn finish(&mut self, id: u32) -> Result<LaunchOutcome, ClientError> {
        match self.reply()? {
            Reply::Exited(status) => Ok(LaunchOutcome::Exited { id, status }),
            Reply::Pending(state) => Ok(LaunchOutcome::Pending { id, state }),
            _ => Err(ClientError::Unexpected),
        }
    }

    /// Launches `request` as an instance named `~<name>#<id>` (root only) and waits for it to
    /// end for at most `wait`. No pidfd: see [`Client::begin_run`].
    ///
    /// # Errors
    /// [`ClientError`]; `Server(Denied, clause)` when the policy refuses the request.
    pub fn run(
        &mut self,
        name: &str,
        request: &RequestSpec,
        args: &RunArgs<'_>,
        wait: Duration,
    ) -> Result<LaunchOutcome, ClientError> {
        match self.begin_run(name, request, args, false, wait)? {
            Begun::Failed { step, errno } => Ok(LaunchOutcome::Failed { step, errno }),
            Begun::Started(Started { id, .. }) => self.finish(id),
        }
    }

    /// Sends a `Run` of `request`: its bytes in a sealed memfd, sent first, then the streams of
    /// `args`. With `pidfd` the reply to a started instance carries a pidfd of its main
    /// process. [`Client::finish`] reads how the instance ends, within `wait`.
    ///
    /// # Errors
    /// [`ClientError`]; `Io(EINVAL)` for a request that does not encode.
    pub fn begin_run(
        &mut self,
        name: &str,
        request: &RequestSpec,
        args: &RunArgs<'_>,
        pidfd: bool,
        wait: Duration,
    ) -> Result<Begun, ClientError> {
        let bytes = request.bytes().map_err(|_| ClientError::Io(22))?;
        let memfd = qinit_ipc::memfd::sealed(c"qinit-run", &bytes)?;
        let mut roles = 0u32;
        let mut fds: Vec<BorrowedFd<'_>> = vec![memfd.as_fd()];
        for (bit, fd) in [(1, args.stdin), (2, args.stdout), (4, args.stderr)] {
            if let Some(fd) = fd {
                roles |= bit;
                fds.push(fd);
            }
        }
        let (_, wait_ms) = Wait::Settled(wait).words();
        self.ask(
            Req::Run {
                name,
                fd_roles: roles,
                flags: u32::from(pidfd) * qinit_proto_core::FLAG_PIDFD,
                memory_max_kib: args.memory_max_kib,
                pids_max: args.pids_max,
                stop_mode: u32::from(args.stop_mode == StopMode::Cell),
                stop_grace_ms: args.stop_grace_ms,
                wait_ms,
            },
            &fds,
        )?;
        self.started()
    }

    /// Swaps in the compiled database in `db` (a regular file or a memfd; root only).
    ///
    /// # Errors
    /// [`ClientError`]; `Server(Invalid, reason)` for a database the validator refuses.
    pub fn refresh(&mut self, db: BorrowedFd<'_>, wait: Wait) -> Result<Outcome, ClientError> {
        let (settled, wait_ms) = wait.words();
        self.ask(Req::Refresh { settled, wait_ms }, &[db])?;
        self.waited(wait)
    }

    /// Shuts the system down (root only).
    ///
    /// # Errors
    /// [`ClientError`].
    pub fn shutdown(&mut self, mode: Mode, wait: Wait) -> Result<Outcome, ClientError> {
        let (settled, wait_ms) = wait.words();
        self.ask(
            Req::Shutdown {
                mode,
                settled,
                wait_ms,
            },
            &[],
        )?;
        self.waited(wait)
    }
}
