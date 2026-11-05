// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Protocol requests against colony (spec 2026-11-04 §§4, 6.4): authorization, the dispatch to
//! the operations, and the waits that answer a request later. A wait is parked with a deadline
//! the caller chose; every outcome of colony resolves the waits it settles, and a request that
//! changes what a wait waits for answers it as superseded.

use crate::effects::Effects;
use crate::engine::{Colony, Error, Notice, Outcome};
use crate::instance::{LaunchArgs, LaunchError, RunArgs, RunError};
use crate::swap::SwapError;
use qinit_colony_core::{Reason, Report, Request, SlotState, State, Why, slot_of};
use qinit_db::ReadError;
use qinit_proto_core::{
    DecodeError, EncodeError, FLAG_PIDFD, FLAG_WAIT_READY, MAX_MESSAGE, PeerId, authorized,
};
use qinit_wire::{
    Action, Entries, ErrorCode, InstanceStatus, ListEntry, Mode, Msg, NodeStatus, Rep, Req,
    StateWord, encode, op_of,
};
use std::os::fd::OwnedFd;

/// Who is asking: the identity colony took at `accept`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
}

/// The id a parked request is answered under; the server allocates it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WaitId(pub u64);

/// What travelled with a request: the descriptors, and for a refresh the database the server
/// read from its descriptor (or the reason it could not: 19 too large, 20 unreadable).
#[derive(Debug, Default)]
pub struct Attached {
    pub fds: Vec<OwnedFd>,
    pub database: Option<Result<Vec<u8>, u32>>,
    /// For a `Run`: the launch request the server read from its sealed memfd, with the memfd
    /// itself, or the reason it could not (19 too large, 20 unreadable, 21 not fully sealed).
    pub request: Option<Result<(Vec<u8>, OwnedFd), u32>>,
}

/// What a shutdown ends in, once colony's part is done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShutdownMode {
    Poweroff,
    Reboot,
    Halt,
}

impl From<Mode> for ShutdownMode {
    fn from(m: Mode) -> Self {
        match m {
            Mode::Poweroff => ShutdownMode::Poweroff,
            Mode::Reboot => ShutdownMode::Reboot,
            Mode::Halt => ShutdownMode::Halt,
        }
    }
}

/// The words of a `Run` request.
struct RunWire<'a> {
    name: &'a str,
    fd_roles: u32,
    pidfd: bool,
    wait_ready: bool,
    memory_max_kib: u32,
    pids_max: u32,
    stop_mode: u32,
    stop_grace_ms: u32,
    wait_ms: u32,
}

/// A node as `Status` shows it. It carries state and nothing about how the service is run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStatusView {
    pub name: String,
    /// 0 worker, 1 forager, 2 brood.
    pub kind: u32,
    pub state: StateWord,
    /// The first unsatisfied group of a waiting node, and its first unsatisfied target.
    pub blocking: Option<(u32, String)>,
    pub backoff_ms: u32,
    pub since_ms: u64,
    pub restarts: u32,
    pub pid: Option<i32>,
}

/// An instance as `Status` shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceStatusView {
    pub frame: String,
    pub id: u32,
    /// 2 starting, 3 running, 4 exited, 5 stopping.
    pub state: u32,
    pub status: Option<i32>,
    pub pid: Option<i32>,
}

/// One line of a list page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryView {
    pub name: String,
    pub kind: u32,
    pub state: StateWord,
}

/// A reply, owned. [`OwnedRep::encode`] lays it out as a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnedRep {
    Error {
        code: ErrorCode,
        detail: u32,
    },
    NodeStatus(NodeStatusView),
    InstanceStatus(InstanceStatusView),
    ListPage {
        entries: Vec<EntryView>,
        next: Option<u32>,
    },
    Accepted,
    Settled(StateWord),
    Pending(StateWord),
    Superseded(StateWord),
    Launched {
        id: u32,
    },
    LaunchFailed {
        step: u32,
        errno: u32,
    },
    Exited {
        status: i32,
    },
}

impl OwnedRep {
    /// Encodes the reply with no descriptor and returns its length.
    ///
    /// # Errors
    /// As `qinit_wire::encode`.
    pub fn encode(&self, out: &mut [u8; MAX_MESSAGE]) -> Result<usize, EncodeError> {
        self.encode_with(0, out)
    }

    /// Encodes the reply declaring `fd_count` descriptors (a `Launched` reply may carry a
    /// pidfd) and returns its length.
    ///
    /// # Errors
    /// As `qinit_wire::encode`.
    pub fn encode_with(
        &self,
        fd_count: u32,
        out: &mut [u8; MAX_MESSAGE],
    ) -> Result<usize, EncodeError> {
        let list: Vec<ListEntry<'_>> = match self {
            OwnedRep::ListPage { entries, .. } => entries
                .iter()
                .map(|e| ListEntry {
                    name: &e.name,
                    kind: e.kind,
                    state: e.state,
                })
                .collect(),
            _ => Vec::new(),
        };
        let rep = match self {
            OwnedRep::Error { code, detail } => Rep::Error {
                code: *code,
                detail: *detail,
                version: qinit_proto_core::QCP_VERSION,
            },
            OwnedRep::NodeStatus(n) => Rep::NodeStatus(NodeStatus {
                name: &n.name,
                kind: n.kind,
                state: n.state,
                blocking: n.blocking.as_ref().map(|(g, t)| (*g, t.as_str())),
                backoff_ms: n.backoff_ms,
                since_ms: n.since_ms,
                restarts: n.restarts,
                pid: n.pid,
            }),
            OwnedRep::InstanceStatus(i) => Rep::InstanceStatus(InstanceStatus {
                frame: &i.frame,
                id: i.id,
                state: i.state,
                status: i.status,
                pid: i.pid,
            }),
            OwnedRep::ListPage { next, .. } => Rep::ListPage {
                entries: Entries::given(&list),
                next: *next,
            },
            OwnedRep::Accepted => Rep::Accepted,
            OwnedRep::Settled(s) => Rep::Settled(*s),
            OwnedRep::Pending(s) => Rep::Pending(*s),
            OwnedRep::Superseded(s) => Rep::Superseded(*s),
            OwnedRep::Launched { id } => Rep::Launched { id: *id },
            OwnedRep::LaunchFailed { step, errno } => Rep::LaunchFailed {
                step: *step,
                errno: *errno,
            },
            OwnedRep::Exited { status } => Rep::Exited { status: *status },
        };
        encode(&Msg::Rep(rep), fd_count, out)
    }
}

/// What [`Colony::handle`] returns: the reply to send now, whether another is parked under the
/// request's wait id, and everything the call set in motion (replies to other waits included).
#[derive(Debug)]
pub struct Handled {
    pub reply: OwnedRep,
    /// The descriptors that travel with `reply`: a pidfd with `Launched`, none otherwise.
    pub reply_fds: Vec<OwnedFd>,
    pub waiting: bool,
    pub outcome: Outcome,
}

/// A parked wait.
#[derive(Debug)]
pub(crate) struct WaitRec {
    id: WaitId,
    what: What,
}

#[derive(Debug)]
enum What {
    /// The node reaches a state that ends its start, restart, run or refresh.
    Up(String),
    /// The node stops.
    Down(String),
    /// The instance ends.
    Instance(u32),
    /// The instance writes its readiness byte, or ends first.
    InstanceReady(u32),
    /// The swap has happened and the nodes it touched have settled.
    Refresh { names: Vec<String>, swapped: bool },
    /// Colony's part of the shutdown is done.
    Shutdown,
}

/// The wire numbers of a node state and its detail word.
#[must_use]
pub fn state_word(s: State) -> StateWord {
    let (state, detail) = match s {
        State::Off => (0, 0),
        State::Waiting(Why::Deps) => (1, 0),
        State::Waiting(Why::Backoff) => (1, 1),
        State::Starting => (2, 0),
        State::Ready => (3, 0),
        State::Done => (4, 0),
        State::Stopping => (5, 0),
        State::Quarantined(Reason::Breaker) => (6, 0),
        State::Quarantined(Reason::Cascade) => (6, 1),
        State::Quarantined(Reason::StartTimeout) => (6, 2),
        State::Quarantined(Reason::StopFailed) => (6, 3),
    };
    StateWord { state, detail }
}

fn error(code: ErrorCode, detail: u32) -> OwnedRep {
    OwnedRep::Error { code, detail }
}

/// The wire number of a refusal of a database.
fn invalid_reason(e: ReadError) -> u32 {
    use qinit_db::DbError;
    match e {
        ReadError::Crc => 1,
        ReadError::Db(d) => match d {
            DbError::Header => 2,
            DbError::Version => 3,
            DbError::Length => 4,
            DbError::Table(_) => 5,
            DbError::Overlap => 6,
            DbError::Count(_) => 7,
            DbError::Pool { .. } => 8,
            DbError::Utf8 { .. } => 9,
            DbError::Index { .. } => 10,
            DbError::Enum { .. } => 11,
            DbError::Tiling { .. } => 12,
            DbError::Consistency { .. } => 13,
            DbError::Cycle => 14,
            DbError::HardParallel => 15,
            DbError::Closure => 16,
            DbError::Order => 17,
            DbError::Scratch => 18,
        },
    }
}

/// `<frame>#<id>`: the instance a target names, if it names one.
fn instance_target(target: &str) -> Option<(&str, Option<u32>)> {
    let (frame, id) = target.split_once('#')?;
    let canonical = !id.is_empty()
        && id.bytes().all(|b| b.is_ascii_digit())
        && (id.len() == 1 || !id.starts_with('0'));
    Some((frame, if canonical { id.parse().ok() } else { None }))
}

/// A notice that ends a start, restart, run or refresh of `node`: it is ready or done, it is
/// quarantined, or it failed and will not be tried again (`gave_up`: it is off).
fn ends_up(n: &Notice, node: u32, gave_up: bool) -> bool {
    match n {
        Notice::Node(x, Report::Ready | Report::Done | Report::Quarantined(_)) => *x == node,
        Notice::Node(x, Report::Failed(_)) => *x == node && gave_up,
        _ => false,
    }
}

impl<E: Effects> Colony<E> {
    /// The mode of the shutdown in progress, if there is one.
    #[must_use]
    pub fn shutdown_mode(&self) -> Option<ShutdownMode> {
        self.shutdown_mode
    }

    /// Serves one decoded request of `peer`. The reply to send now is `reply`; when `waiting`
    /// is set another is parked under `wait` and arrives in the `replies` of a later outcome.
    pub fn handle(
        &mut self,
        peer: Peer,
        req: &Req<'_>,
        attached: Attached,
        wait: WaitId,
        now: u64,
    ) -> Handled {
        let mut h = Handled {
            reply: OwnedRep::Accepted,
            reply_fds: Vec::new(),
            waiting: false,
            outcome: Outcome::default(),
        };
        let op = op_of(req);
        if !authorized(op, PeerId { uid: peer.uid }) {
            h.reply = error(ErrorCode::Denied, 0);
            return h;
        }
        let reading = matches!(
            op,
            qinit_proto_core::Op::Status | qinit_proto_core::Op::List
        );
        if self.shutdown_mode.is_some() && !reading && !matches!(req, Req::Shutdown { .. }) {
            h.reply = error(ErrorCode::ShuttingDown, 0);
            return h;
        }
        match *req {
            Req::Status { target } => h.reply = self.status_reply(target, now),
            // Served by the watcher table (a later task); until then a watch is refused.
            Req::Watch { .. } => h.reply = error(ErrorCode::BadRequest, 0),
            Req::List { cursor, kind } => {
                let (entries, next) = self.list(cursor, kind);
                h.reply = OwnedRep::ListPage { entries, next };
            }
            Req::Change {
                target,
                action,
                settled,
                wait_ms,
            } => self.change(
                target,
                action,
                settled.then_some(wait_ms),
                wait,
                now,
                &mut h,
            ),
            Req::Launch {
                frame,
                argv_tail,
                env_add,
                fd_roles,
                wait_ms,
                flags,
            } => {
                let argv: Vec<String> = argv_tail.iter().map(str::to_owned).collect();
                let env: Vec<(String, String)> = env_add
                    .iter()
                    .filter_map(|e| e.split_once('='))
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect();
                self.launch_request(
                    frame,
                    argv,
                    env,
                    (fd_roles, flags & FLAG_PIDFD != 0),
                    wait_ms,
                    attached,
                    wait,
                    now,
                    &mut h,
                );
            }
            Req::Run {
                name,
                fd_roles,
                flags,
                memory_max_kib,
                pids_max,
                stop_mode,
                stop_grace_ms,
                wait_ms,
            } => self.run_handler(
                &RunWire {
                    name,
                    fd_roles,
                    pidfd: flags & FLAG_PIDFD != 0,
                    wait_ready: flags & FLAG_WAIT_READY != 0,
                    memory_max_kib,
                    pids_max,
                    stop_mode,
                    stop_grace_ms,
                    wait_ms,
                },
                attached,
                wait,
                now,
                &mut h,
            ),
            Req::Refresh { settled, wait_ms } => {
                self.refresh_request(settled.then_some(wait_ms), attached, wait, now, &mut h);
            }
            Req::Shutdown {
                mode,
                settled,
                wait_ms,
            } => self.shutdown_request(mode.into(), settled.then_some(wait_ms), wait, now, &mut h),
        }
        h
    }

    fn status_reply(&self, target: &str, now: u64) -> OwnedRep {
        if let Some((frame, id)) = instance_target(target) {
            let view = id.and_then(|id| self.instance(id));
            return match view {
                Some(v) if v.frame_name == frame => {
                    let (state, status) = match v.state {
                        SlotState::Starting | SlotState::Free => (2, None),
                        SlotState::Running => (3, None),
                        SlotState::Stopping => (5, None),
                        SlotState::Exited(s) => (4, Some(s)),
                    };
                    OwnedRep::InstanceStatus(InstanceStatusView {
                        frame: v.frame_name,
                        id: v.id,
                        state,
                        status,
                        pid: v.pid,
                    })
                }
                _ => error(ErrorCode::UnknownNode, 0),
            };
        }
        match self.node_index(target) {
            Some(i) => OwnedRep::NodeStatus(self.node_status(i, now)),
            None => error(ErrorCode::UnknownNode, 0),
        }
    }

    /// Registers a wait with its deadline; one the effects layer could not arm ends at once.
    fn park(&mut self, id: WaitId, what: What, wait_ms: u32, h: &mut Handled) {
        let armed = self.effects.arm_wait(id.0, wait_ms);
        self.waits.push(WaitRec { id, what });
        if let Err(e) = armed {
            // A wait with no deadline would be unbounded: it ends now, as if the time were up.
            h.outcome.errors.push(Error::Effect(0, e));
            let expired = self.on_wait_deadline(id, 0);
            h.outcome.replies.extend(expired.replies);
            return;
        }
        h.waiting = true;
    }

    /// The wait is over at once: its reply goes out with the call's other replies.
    fn settle_now(h: &mut Handled, id: WaitId, rep: OwnedRep) {
        h.outcome.replies.push((id, rep));
    }

    /// Takes every wait on node `name` out of the table, timers still armed: the caller decides
    /// whether the request that supersedes them was accepted ([`Self::supersede`]) or refused
    /// ([`Self::restore`]).
    fn take_waits_on(&mut self, name: &str) -> Vec<WaitRec> {
        let (hit, keep) = std::mem::take(&mut self.waits)
            .into_iter()
            .partition(|w| matches!(&w.what, What::Up(n) | What::Down(n) if n == name));
        self.waits = keep;
        hit
    }

    /// Answers the taken waits as superseded, with the state `name` is in now.
    fn supersede(&mut self, name: &str, taken: Vec<WaitRec>, out: &mut Outcome) {
        let state = self
            .node_index(name)
            .and_then(|i| self.state(i))
            .map_or(state_word(State::Off), state_word);
        for w in taken {
            self.effects.cancel_wait(w.id.0);
            out.replies.push((w.id, OwnedRep::Superseded(state)));
        }
    }

    /// Puts taken waits back: the request was refused, so nothing changed under them.
    fn restore(&mut self, taken: Vec<WaitRec>) {
        self.waits.extend(taken);
    }

    fn change(
        &mut self,
        target: &str,
        action: Action,
        wait_ms: Option<u32>,
        wait: WaitId,
        now: u64,
        h: &mut Handled,
    ) {
        if let Some((frame, id)) = instance_target(target) {
            self.change_instance(frame, id, action, wait_ms, wait, now, h);
            return;
        }
        let Some(node) = self.node_index(target) else {
            h.reply = error(ErrorCode::UnknownNode, 0);
            return;
        };
        let name = target.to_owned();
        let taken = self.take_waits_on(&name);
        let was_ready =
            self.nodes[node as usize].state == State::Ready && !self.nodes[node as usize].to_stop;
        let req = match action {
            Action::Start => Request::Start,
            Action::Stop => Request::Stop,
            Action::Restart => Request::Restart,
            Action::Clear => Request::Clear,
            Action::Refresh => Request::Refresh,
            Action::Run => Request::Run,
        };
        let out = self.request(node, req, now);
        let refused = out.notices.contains(&Notice::Node(node, Report::Refused));
        let gave_up = self.nodes[node as usize].state == State::Off;
        let ended = out.notices.iter().any(|n| ends_up(n, node, gave_up));
        h.outcome.notices.extend(out.notices);
        h.outcome.errors.extend(out.errors);
        h.outcome.replies.extend(out.replies);
        let state = self.nodes[node as usize].state;
        if refused {
            self.restore(taken);
            h.reply = error(ErrorCode::NotNow, state_word(state).state);
            return;
        }
        self.supersede(&name, taken, &mut h.outcome);
        h.reply = OwnedRep::Accepted;
        let Some(ms) = wait_ms else {
            return;
        };
        let reloaded = action == Action::Refresh
            && was_ready
            && self.model.nodes[node as usize].reload.is_some()
            && state == State::Ready;
        let up_now = ended
            || reloaded
            || (action == Action::Start && matches!(state, State::Ready | State::Done))
            || action == Action::Clear;
        let down_now = Self::down_met(state);
        match action {
            Action::Stop if down_now => {
                Self::settle_now(h, wait, OwnedRep::Settled(state_word(state)));
            }
            Action::Stop => self.park(wait, What::Down(name), ms, h),
            _ if up_now => Self::settle_now(h, wait, OwnedRep::Settled(state_word(state))),
            _ => self.park(wait, What::Up(name), ms, h),
        }
    }

    fn down_met(state: State) -> bool {
        matches!(state, State::Off | State::Done | State::Quarantined(_))
    }

    #[allow(clippy::too_many_arguments)] // the pieces of one request, passed through
    fn change_instance(
        &mut self,
        frame: &str,
        id: Option<u32>,
        action: Action,
        wait_ms: Option<u32>,
        wait: WaitId,
        now: u64,
        h: &mut Handled,
    ) {
        if action != Action::Stop {
            // An instance accepts only `stop`.
            h.reply = error(ErrorCode::BadRequest, DecodeError::Consistency as u32);
            return;
        }
        let known = id.and_then(|id| self.instance(id).filter(|v| v.frame_name == frame));
        let Some(view) = known else {
            h.reply = error(ErrorCode::UnknownNode, 0);
            return;
        };
        match self.stop_instance(view.id, now) {
            Ok(out) => {
                h.outcome.notices.extend(out.notices);
                h.outcome.errors.extend(out.errors);
                h.reply = OwnedRep::Accepted;
                if let Some(ms) = wait_ms {
                    self.park(wait, What::Instance(view.id), ms, h);
                }
            }
            Err(_) => h.reply = error(ErrorCode::UnknownNode, 0),
        }
    }

    #[allow(clippy::too_many_arguments)] // the pieces of one request, passed through
    fn launch_request(
        &mut self,
        frame: &str,
        argv_tail: Vec<String>,
        env_add: Vec<(String, String)>,
        (fd_roles, pidfd): (u32, bool),
        wait_ms: u32,
        attached: Attached,
        wait: WaitId,
        now: u64,
        h: &mut Handled,
    ) {
        let mut fds: [Option<OwnedFd>; 3] = [None, None, None];
        let mut given = attached.fds.into_iter();
        for (slot, bit) in fds.iter_mut().zip([1u32, 2, 4]) {
            if fd_roles & bit != 0 {
                *slot = given.next();
            }
        }
        let args = LaunchArgs {
            frame: frame.to_owned(),
            argv_tail,
            env_add,
            fds,
        };
        match self.launch(args, now) {
            Ok((id, out)) => {
                h.outcome.notices.extend(out.notices);
                h.outcome.errors.extend(out.errors);
                h.reply = OwnedRep::Launched { id };
                if pidfd
                    && let Some(slot) = slot_of(&self.slots, id)
                    && let Ok(fd) = self
                        .effects
                        .instance_pidfd(u32::try_from(slot).unwrap_or(u32::MAX))
                {
                    h.reply_fds.push(fd);
                }
                self.park(wait, What::Instance(id), wait_ms, h);
            }
            Err(LaunchError::Spawn(e)) => {
                h.reply = OwnedRep::LaunchFailed {
                    step: 0,
                    errno: u32::try_from(e.0).unwrap_or(0),
                };
            }
            Err(e) => {
                let code = match e {
                    LaunchError::ShuttingDown => ErrorCode::ShuttingDown,
                    LaunchError::UnknownNode => ErrorCode::UnknownNode,
                    LaunchError::NotLaunchable => ErrorCode::NotLaunchable,
                    LaunchError::Denied => ErrorCode::Denied,
                    LaunchError::Unsatisfied => ErrorCode::Unsatisfied,
                    LaunchError::NoSlot | LaunchError::Spawn(_) => ErrorCode::NoSlot,
                };
                h.reply = error(code, 0);
            }
        }
    }

    fn run_handler(
        &mut self,
        w: &RunWire<'_>,
        attached: Attached,
        wait: WaitId,
        now: u64,
        h: &mut Handled,
    ) {
        let (request, request_fd) = match attached.request {
            Some(Ok(r)) => r,
            Some(Err(reason)) => {
                h.reply = error(ErrorCode::Invalid, reason);
                return;
            }
            None => {
                h.reply = error(ErrorCode::Invalid, 20);
                return;
            }
        };
        let mut fds: [Option<OwnedFd>; 3] = [None, None, None];
        let mut given = attached.fds.into_iter();
        for (slot, bit) in fds.iter_mut().zip([1u32, 2, 4]) {
            if w.fd_roles & bit != 0 {
                *slot = given.next();
            }
        }
        let args = RunArgs {
            name: w.name.to_owned(),
            request,
            request_fd,
            fds,
            memory_max_kib: w.memory_max_kib,
            pids_max: w.pids_max,
            stop: if w.stop_mode == 1 {
                qinit_colony_core::StopMode::Cell
            } else {
                qinit_colony_core::StopMode::Main
            },
            grace_ms: w.stop_grace_ms,
            wait_ready: w.wait_ready,
        };
        match self.run_request(args, now) {
            Ok((id, out)) => {
                h.outcome.notices.extend(out.notices);
                h.outcome.errors.extend(out.errors);
                h.reply = OwnedRep::Launched { id };
                if w.pidfd
                    && let Some(slot) = slot_of(&self.slots, id)
                    && let Ok(fd) = self
                        .effects
                        .instance_pidfd(u32::try_from(slot).unwrap_or(u32::MAX))
                {
                    h.reply_fds.push(fd);
                }
                let what = if w.wait_ready {
                    What::InstanceReady(id)
                } else {
                    What::Instance(id)
                };
                self.park(wait, what, w.wait_ms, h);
            }
            Err(RunError::Spawn(e)) => {
                h.reply = OwnedRep::LaunchFailed {
                    step: 0,
                    errno: u32::try_from(e.0).unwrap_or(0),
                };
            }
            Err(RunError::Invalid(d)) => h.reply = error(ErrorCode::Invalid, d),
            Err(RunError::Denied(d)) => h.reply = error(ErrorCode::Denied, d),
            Err(RunError::NoSlot) => h.reply = error(ErrorCode::NoSlot, 0),
            Err(RunError::ShuttingDown) => h.reply = error(ErrorCode::ShuttingDown, 0),
        }
    }

    fn refresh_request(
        &mut self,
        wait_ms: Option<u32>,
        attached: Attached,
        wait: WaitId,
        now: u64,
        h: &mut Handled,
    ) {
        let db = match attached.database {
            Some(Ok(bytes)) => bytes,
            Some(Err(reason)) => {
                h.reply = error(ErrorCode::Invalid, reason);
                return;
            }
            None => {
                h.reply = error(ErrorCode::Invalid, 20);
                return;
            }
        };
        match self.refresh(db, now) {
            Ok(out) => {
                let swapped = out.notices.contains(&Notice::Swapped);
                h.outcome.notices.extend(out.notices);
                h.outcome.errors.extend(out.errors);
                h.outcome.replies.extend(out.replies);
                h.reply = OwnedRep::Accepted;
                if let Some(ms) = wait_ms {
                    let names = self.refresh_set.clone();
                    let what = What::Refresh { names, swapped };
                    if self.refresh_met(&what) {
                        Self::settle_now(
                            h,
                            wait,
                            OwnedRep::Settled(StateWord {
                                state: 3,
                                detail: 0,
                            }),
                        );
                    } else {
                        self.park(wait, what, ms, h);
                    }
                }
            }
            Err(SwapError::Invalid(e)) => h.reply = error(ErrorCode::Invalid, invalid_reason(e)),
            Err(SwapError::Busy) => h.reply = error(ErrorCode::Busy, 0),
            Err(SwapError::ShuttingDown) => h.reply = error(ErrorCode::ShuttingDown, 0),
        }
    }

    fn shutdown_request(
        &mut self,
        mode: ShutdownMode,
        wait_ms: Option<u32>,
        wait: WaitId,
        now: u64,
        h: &mut Handled,
    ) {
        let first = self.shutdown_mode.is_none();
        self.shutdown_mode = Some(mode);
        if first {
            // Nothing waits for a node that is about to stop.
            for w in std::mem::take(&mut self.waits) {
                if matches!(w.what, What::Up(_) | What::Refresh { .. }) {
                    self.effects.cancel_wait(w.id.0);
                    h.outcome
                        .replies
                        .push((w.id, OwnedRep::Superseded(state_word(State::Stopping))));
                } else {
                    self.waits.push(w);
                }
            }
            // Instances first: nothing depends on them.
            for slot in 0..self.slots.len() {
                if self.insts[slot].is_some() && self.slots[slot].state != SlotState::Stopping {
                    self.begin_instance_stop(slot, &mut h.outcome);
                }
            }
            let out = self.shutdown(now);
            h.outcome.notices.extend(out.notices);
            h.outcome.errors.extend(out.errors);
            h.outcome.replies.extend(out.replies);
        }
        h.reply = OwnedRep::Accepted;
        if let Some(ms) = wait_ms {
            if self.shutdown_done() {
                Self::settle_now(h, wait, OwnedRep::Settled(state_word(State::Off)));
            } else {
                self.park(wait, What::Shutdown, ms, h);
            }
        }
    }

    fn shutdown_done(&self) -> bool {
        self.meta.reported && self.insts.iter().all(Option::is_none)
    }

    /// The swap has happened and the nodes it restarted or signalled have settled: ready or
    /// done, quarantined, or off and no longer wanted (failed).
    fn refresh_met(&self, what: &What) -> bool {
        let What::Refresh { names, swapped } = what else {
            return false;
        };
        *swapped
            && !self.swapping()
            && names.iter().all(|n| match self.node_index(n) {
                None => true,
                Some(i) => {
                    let ns = &self.nodes[i as usize];
                    matches!(ns.state, State::Ready | State::Done | State::Quarantined(_))
                        || (ns.state == State::Off && !ns.wanted)
                }
            })
    }

    /// Answers the waits this call's notices settled, and the waits whose node a refresh
    /// removed.
    pub(crate) fn resolve_waits(&mut self, out: &mut Outcome) {
        if self.waits.is_empty() {
            return;
        }
        let swapped = out.notices.contains(&Notice::Swapped);
        let mut keep = Vec::new();
        for mut w in std::mem::take(&mut self.waits) {
            let answer = self.answer(&mut w.what, &out.notices, swapped);
            if let Some(rep) = answer {
                self.effects.cancel_wait(w.id.0);
                out.replies.push((w.id, rep));
            } else {
                keep.push(w);
            }
        }
        self.waits = keep;
    }

    fn answer(&self, what: &mut What, notices: &[Notice], swapped: bool) -> Option<OwnedRep> {
        match what {
            What::Up(name) => match self.node_index(name) {
                None => Some(OwnedRep::Superseded(state_word(State::Off))),
                Some(i)
                    if notices
                        .iter()
                        .any(|n| ends_up(n, i, self.nodes[i as usize].state == State::Off)) =>
                {
                    Some(OwnedRep::Settled(state_word(self.nodes[i as usize].state)))
                }
                Some(_) => None,
            },
            What::Down(name) => match self.node_index(name) {
                None => Some(OwnedRep::Superseded(state_word(State::Off))),
                Some(i) => {
                    let s = self.nodes[i as usize].state;
                    Self::down_met(s).then(|| OwnedRep::Settled(state_word(s)))
                }
            },
            What::Instance(id) => notices.iter().find_map(|n| match n {
                Notice::Instance(x, SlotState::Exited(status)) if x == id => {
                    Some(OwnedRep::Exited { status: *status })
                }
                _ => None,
            }),
            // Whichever comes first, in the order the notices came.
            What::InstanceReady(id) => notices.iter().find_map(|n| match n {
                Notice::InstanceReady(x) if x == id => Some(OwnedRep::Settled(StateWord {
                    state: 3,
                    detail: 0,
                })),
                Notice::Instance(x, SlotState::Exited(status)) if x == id => {
                    Some(OwnedRep::Exited { status: *status })
                }
                _ => None,
            }),
            What::Refresh { swapped: done, .. } => {
                *done |= swapped;
                self.refresh_met(what)
                    .then_some(OwnedRep::Settled(StateWord {
                        state: 3,
                        detail: 0,
                    }))
            }
            What::Shutdown => self
                .shutdown_done()
                .then(|| OwnedRep::Settled(state_word(State::Off))),
        }
    }

    /// The wait's deadline passed: the request stays in effect, the caller is told where it
    /// stands.
    pub fn on_wait_deadline(&mut self, wait: WaitId, _now: u64) -> Outcome {
        let mut out = Outcome::default();
        let Some(pos) = self.waits.iter().position(|w| w.id == wait) else {
            return out;
        };
        let rec = self.waits.remove(pos);
        let state = match &rec.what {
            What::Up(n) | What::Down(n) => self.node_index(n).map_or(state_word(State::Off), |i| {
                state_word(self.nodes[i as usize].state)
            }),
            What::Instance(id) | What::InstanceReady(id) => self.instance(*id).map_or(
                StateWord {
                    state: 4,
                    detail: 0,
                },
                |v| match v.state {
                    SlotState::Starting | SlotState::Free => StateWord {
                        state: 2,
                        detail: 0,
                    },
                    // A running process that has not written its byte is still starting.
                    SlotState::Running if matches!(&rec.what, What::InstanceReady(_)) => {
                        StateWord {
                            state: 2,
                            detail: 0,
                        }
                    }
                    SlotState::Running => StateWord {
                        state: 3,
                        detail: 0,
                    },
                    SlotState::Stopping => StateWord {
                        state: 5,
                        detail: 0,
                    },
                    SlotState::Exited(_) => StateWord {
                        state: 4,
                        detail: 0,
                    },
                },
            ),
            What::Refresh { names, swapped } => {
                if *swapped {
                    names
                        .iter()
                        .filter_map(|n| self.node_index(n))
                        .map(|i| state_word(self.nodes[i as usize].state))
                        .find(|s| !matches!(s.state, 3 | 4 | 6))
                        .unwrap_or(StateWord {
                            state: 3,
                            detail: 0,
                        })
                } else {
                    state_word(State::Stopping)
                }
            }
            What::Shutdown => state_word(State::Stopping),
        };
        out.replies.push((wait, OwnedRep::Pending(state)));
        out
    }

    /// The connection that owned the wait is gone: forget the wait and its deadline.
    pub fn drop_wait(&mut self, wait: WaitId) {
        if let Some(pos) = self.waits.iter().position(|w| w.id == wait) {
            self.waits.remove(pos);
            self.effects.cancel_wait(wait.0);
        }
    }
}
