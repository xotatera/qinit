// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! `qinit-wire`: QCP1 messages as borrowed values over `qinit-proto-core`.
//!
//! Messages as borrowed values. A value is built from the accessors of an accepted message, so
//! every index and string reference below is in bounds; the strings are checked UTF-8 once more
//! by `core::str::from_utf8`, which cannot fail on an accepted message.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

#[allow(clippy::wildcard_imports)] // the layout constants, used throughout
use qinit_proto_core::*;

/// What a change asks of a node or an instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Start,
    Stop,
    Restart,
    Clear,
    Refresh,
    Run,
}

impl Action {
    /// The wire word of the action.
    #[must_use]
    pub fn word(self) -> u32 {
        match self {
            Action::Start => 0,
            Action::Stop => 1,
            Action::Restart => 2,
            Action::Clear => 3,
            Action::Refresh => 4,
            Action::Run => 5,
        }
    }

    /// The action a wire word names.
    #[must_use]
    pub fn from_word(w: u32) -> Option<Action> {
        Some(match w {
            0 => Action::Start,
            1 => Action::Stop,
            2 => Action::Restart,
            3 => Action::Clear,
            4 => Action::Refresh,
            5 => Action::Run,
            _ => return None,
        })
    }
}

/// What the machine does after the services stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Poweroff,
    Reboot,
    Halt,
}

impl Mode {
    /// The wire word of the mode.
    #[must_use]
    pub fn word(self) -> u32 {
        match self {
            Mode::Poweroff => 0,
            Mode::Reboot => 1,
            Mode::Halt => 2,
        }
    }

    /// The mode a wire word names.
    #[must_use]
    pub fn from_word(w: u32) -> Option<Mode> {
        Some(match w {
            0 => Mode::Poweroff,
            1 => Mode::Reboot,
            2 => Mode::Halt,
            _ => return None,
        })
    }
}

/// Why a request got an error reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    Version = 1,
    BadRequest = 2,
    Denied = 3,
    Full = 4,
    Busy = 5,
    ShuttingDown = 6,
    UnknownNode = 7,
    NotLaunchable = 8,
    Unsatisfied = 9,
    NoSlot = 10,
    NotNow = 11,
    Invalid = 12,
}

impl ErrorCode {
    /// The wire word of the code.
    #[must_use]
    pub fn word(self) -> u32 {
        self as u32
    }

    /// The code a wire word names.
    #[must_use]
    pub fn from_word(w: u32) -> Option<ErrorCode> {
        Some(match w {
            1 => ErrorCode::Version,
            2 => ErrorCode::BadRequest,
            3 => ErrorCode::Denied,
            4 => ErrorCode::Full,
            5 => ErrorCode::Busy,
            6 => ErrorCode::ShuttingDown,
            7 => ErrorCode::UnknownNode,
            8 => ErrorCode::NotLaunchable,
            9 => ErrorCode::Unsatisfied,
            10 => ErrorCode::NoSlot,
            11 => ErrorCode::NotNow,
            12 => ErrorCode::Invalid,
            _ => return None,
        })
    }
}

/// A state and the detail that goes with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateWord {
    /// 0 off, 1 waiting, 2 starting, 3 ready (running, for an instance), 4 done (exited), 5
    /// stopping, 6 quarantined.
    pub state: u32,
    /// Why a node waits or is quarantined; 0 otherwise.
    pub detail: u32,
}

/// A NUL-separated list of strings, as the message carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StrList<'a>(&'a [u8]);

impl<'a> StrList<'a> {
    /// The list whose elements are `bytes` joined by NUL.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> StrList<'a> {
        StrList(bytes)
    }

    /// The joined bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Whether the list has no element.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The elements. An element that is not UTF-8 reads as the empty string; a decoded message
    /// has none.
    pub fn iter(&self) -> impl Iterator<Item = &'a str> + use<'a> {
        let bytes = self.0;
        let parts = if bytes.is_empty() {
            None
        } else {
            Some(bytes.split(|b| *b == 0))
        };
        parts
            .into_iter()
            .flatten()
            .map(|p| core::str::from_utf8(p).unwrap_or(""))
    }
}

/// One entry of a list page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListEntry<'a> {
    pub name: &'a str,
    /// 0 worker, 1 forager, 2 brood.
    pub kind: u32,
    pub state: StateWord,
}

/// The entries of a list page: read from a message, or given for encoding.
#[derive(Clone, Copy, Debug)]
pub struct Entries<'a>(Source<'a>);

#[derive(Clone, Copy, Debug)]
enum Source<'a> {
    /// The entries of the accepted message `bytes`.
    Wire { bytes: &'a [u8], count: usize },
    /// Entries to encode.
    Given(&'a [ListEntry<'a>]),
}

impl<'a> Entries<'a> {
    /// The entries `list`, for encoding.
    #[must_use]
    pub fn given(list: &'a [ListEntry<'a>]) -> Entries<'a> {
        Entries(Source::Given(list))
    }

    /// How many entries.
    #[must_use]
    pub fn len(&self) -> usize {
        match self.0 {
            Source::Wire { count, .. } => count,
            Source::Given(e) => e.len(),
        }
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Entry `i`, if there is one.
    #[must_use]
    pub fn get(&self, i: usize) -> Option<ListEntry<'a>> {
        match self.0 {
            Source::Given(e) => e.get(i).copied(),
            Source::Wire { bytes, count } => {
                if i >= count {
                    return None;
                }
                let name = core::str::from_utf8(string(
                    bytes,
                    entry(bytes, i, EN_NAME_OFF),
                    entry(bytes, i, EN_NAME_LEN),
                ))
                .ok()?;
                Some(ListEntry {
                    name,
                    kind: entry(bytes, i, EN_KIND),
                    state: StateWord {
                        state: entry(bytes, i, EN_STATE),
                        detail: entry(bytes, i, EN_DETAIL),
                    },
                })
            }
        }
    }

    /// The entries in order.
    pub fn iter(&self) -> impl Iterator<Item = ListEntry<'a>> + use<'a> {
        let this = *self;
        (0..this.len()).filter_map(move |i| this.get(i))
    }
}

impl PartialEq for Entries<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().zip(other.iter()).all(|(a, b)| a == b)
    }
}

impl Eq for Entries<'_> {}

/// The status of a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeStatus<'a> {
    pub name: &'a str,
    /// 0 worker, 1 forager, 2 brood.
    pub kind: u32,
    pub state: StateWord,
    /// The first unsatisfied group and its first unsatisfied target.
    pub blocking: Option<(u32, &'a str)>,
    pub backoff_ms: u32,
    pub since_ms: u64,
    pub restarts: u32,
    pub pid: Option<i32>,
}

/// The status of an instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstanceStatus<'a> {
    pub frame: &'a str,
    pub id: u32,
    /// 2 starting, 3 running, 4 exited, 5 stopping.
    pub state: u32,
    /// The wait status, once the instance exited.
    pub status: Option<i32>,
    pub pid: Option<i32>,
}

/// A request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Req<'a> {
    Status {
        target: &'a str,
    },
    List {
        cursor: u32,
        kind: u32,
    },
    Change {
        target: &'a str,
        action: Action,
        settled: bool,
        wait_ms: u32,
    },
    Launch {
        frame: &'a str,
        argv_tail: StrList<'a>,
        env_add: StrList<'a>,
        fd_roles: u32,
        wait_ms: u32,
        /// `FLAG_PIDFD`: reply to `Launched` with a pidfd of the instance's main process.
        flags: u32,
    },
    Refresh {
        settled: bool,
        wait_ms: u32,
    },
    Shutdown {
        mode: Mode,
        settled: bool,
        wait_ms: u32,
    },
    /// Launch the whole request in the first descriptor (a sealed memfd).
    Run {
        /// The launch name, 1 to 95 bytes; the instance is `~<name>#<id>`.
        name: &'a str,
        fd_roles: u32,
        /// `FLAG_PIDFD`.
        flags: u32,
        memory_max_kib: u32,
        pids_max: u32,
        /// 0 main, 1 cell.
        stop_mode: u32,
        stop_grace_ms: u32,
        wait_ms: u32,
    },
}

/// A reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rep<'a> {
    Error {
        code: ErrorCode,
        detail: u32,
        version: u32,
    },
    NodeStatus(NodeStatus<'a>),
    InstanceStatus(InstanceStatus<'a>),
    ListPage {
        entries: Entries<'a>,
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

/// A message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Msg<'a> {
    Req(Req<'a>),
    Rep(Rep<'a>),
}

fn text(b: &[u8], off: u32, len: u32) -> Result<&str, DecodeError> {
    core::str::from_utf8(string(b, off, len)).map_err(|_| DecodeError::Pool)
}

fn flag(w: u32) -> bool {
    w == 1
}

/// The pid word as an option: 0 is none.
#[allow(clippy::cast_possible_wrap)] // the word carries a signed pid
fn pid(w: u32) -> Option<i32> {
    (w != 0).then_some(w as i32)
}

fn state(b: &[u8], w: usize) -> StateWord {
    StateWord {
        state: rec(b, w),
        detail: rec(b, w + 1),
    }
}

fn request(b: &[u8], t: u32) -> Result<Req<'_>, DecodeError> {
    let bad = DecodeError::Enum;
    Ok(match t {
        T_STATUS => Req::Status {
            target: text(b, rec(b, ST_TARGET_OFF), rec(b, ST_TARGET_LEN))?,
        },
        T_LIST => Req::List {
            cursor: rec(b, LI_CURSOR),
            kind: rec(b, LI_KIND),
        },
        T_CHANGE => Req::Change {
            target: text(b, rec(b, CH_TARGET_OFF), rec(b, CH_TARGET_LEN))?,
            action: Action::from_word(rec(b, CH_ACTION)).ok_or(bad)?,
            settled: flag(rec(b, CH_SETTLED)),
            wait_ms: rec(b, CH_WAIT_MS),
        },
        T_LAUNCH => Req::Launch {
            frame: text(b, rec(b, LA_FRAME_OFF), rec(b, LA_FRAME_LEN))?,
            argv_tail: StrList(string(b, rec(b, LA_ARGV_OFF), rec(b, LA_ARGV_LEN))),
            env_add: StrList(string(b, rec(b, LA_ENV_OFF), rec(b, LA_ENV_LEN))),
            fd_roles: rec(b, LA_FD_ROLES),
            wait_ms: rec(b, LA_WAIT_MS),
            flags: rec(b, LA_FLAGS),
        },
        T_REFRESH => Req::Refresh {
            settled: flag(rec(b, RF_SETTLED)),
            wait_ms: rec(b, RF_WAIT_MS),
        },
        T_RUN => Req::Run {
            name: text(b, rec(b, RU_NAME_OFF), rec(b, RU_NAME_LEN))?,
            fd_roles: rec(b, RU_FD_ROLES),
            flags: rec(b, RU_FLAGS),
            memory_max_kib: rec(b, RU_MEMORY_MAX_KIB),
            pids_max: rec(b, RU_PIDS_MAX),
            stop_mode: rec(b, RU_STOP_MODE),
            stop_grace_ms: rec(b, RU_STOP_GRACE_MS),
            wait_ms: rec(b, RU_WAIT_MS),
        },
        _ => Req::Shutdown {
            mode: Mode::from_word(rec(b, SH_MODE)).ok_or(bad)?,
            settled: flag(rec(b, SH_SETTLED)),
            wait_ms: rec(b, SH_WAIT_MS),
        },
    })
}

#[allow(clippy::cast_possible_wrap)] // the words carry signed values
fn reply(b: &[u8], t: u32) -> Result<Rep<'_>, DecodeError> {
    let bad = DecodeError::Enum;
    Ok(match t {
        T_ERROR => Rep::Error {
            code: ErrorCode::from_word(rec(b, ER_CODE)).ok_or(bad)?,
            detail: rec(b, ER_DETAIL),
            version: rec(b, ER_VERSION),
        },
        T_NODE_STATUS => {
            let group = rec(b, NS_GROUP);
            let blocking = if group == NONE {
                None
            } else {
                Some((
                    group,
                    text(b, rec(b, NS_TARGET_OFF), rec(b, NS_TARGET_LEN))?,
                ))
            };
            Rep::NodeStatus(NodeStatus {
                name: text(b, rec(b, NS_NAME_OFF), rec(b, NS_NAME_LEN))?,
                kind: rec(b, NS_KIND),
                state: StateWord {
                    state: rec(b, NS_STATE),
                    detail: rec(b, NS_DETAIL),
                },
                blocking,
                backoff_ms: rec(b, NS_BACKOFF_MS),
                since_ms: u64::from(rec(b, NS_SINCE_LO)) | (u64::from(rec(b, NS_SINCE_HI)) << 32),
                restarts: rec(b, NS_RESTARTS),
                pid: pid(rec(b, NS_PID)),
            })
        }
        T_INSTANCE_STATUS => Rep::InstanceStatus(InstanceStatus {
            frame: text(b, rec(b, IS_FRAME_OFF), rec(b, IS_FRAME_LEN))?,
            id: rec(b, IS_ID),
            state: rec(b, IS_STATE),
            status: flag(rec(b, IS_HAS_STATUS)).then_some(rec(b, IS_STATUS) as i32),
            pid: pid(rec(b, IS_PID)),
        }),
        T_LIST_PAGE => {
            let next = rec(b, LP_NEXT);
            Rep::ListPage {
                entries: Entries(Source::Wire {
                    bytes: b,
                    count: rec(b, LP_COUNT) as usize,
                }),
                next: (next != NONE).then_some(next),
            }
        }
        T_ACCEPTED => Rep::Accepted,
        T_SETTLED => Rep::Settled(state(b, SW_STATE)),
        T_PENDING => Rep::Pending(state(b, SW_STATE)),
        T_SUPERSEDED => Rep::Superseded(state(b, SW_STATE)),
        T_LAUNCHED => Rep::Launched { id: rec(b, LD_ID) },
        T_LAUNCH_FAILED => Rep::LaunchFailed {
            step: rec(b, LF_STEP),
            errno: rec(b, LF_ERRNO),
        },
        _ => Rep::Exited {
            status: rec(b, EX_STATUS) as i32,
        },
    })
}

/// Decodes `b`, which arrived with `received` descriptors, as a message.
///
/// # Errors
/// The first rule the message breaks (see [`check`]).
pub fn decode(b: &[u8], received: usize) -> Result<Msg<'_>, DecodeError> {
    check(b, received)?;
    let t = message_type(b);
    if t < 64 {
        Ok(Msg::Req(request(b, t)?))
    } else {
        Ok(Msg::Rep(reply(b, t)?))
    }
}

/// The operation a request asks for.
#[must_use]
pub fn op_of(r: &Req<'_>) -> Op {
    match r {
        Req::Status { .. } => Op::Status,
        Req::List { .. } => Op::List,
        Req::Change { .. } => Op::Change,
        Req::Launch { .. } => Op::Launch,
        Req::Refresh { .. } => Op::Refresh,
        Req::Shutdown { .. } => Op::Shutdown,
        Req::Run { .. } => Op::Run,
    }
}

/// The descriptors a message carries: one per role of a launch, one for a refresh, the request
/// and one per role for a run, none otherwise. A `Launched` reply carries none or a pidfd (see [`FLAG_PIDFD`]): this counts none.
#[must_use]
pub fn required_fds(m: &Msg<'_>) -> u32 {
    match m {
        Msg::Req(Req::Launch { fd_roles, .. }) => {
            (fd_roles & 1) + ((fd_roles >> 1) & 1) + ((fd_roles >> 2) & 1)
        }
        Msg::Req(Req::Refresh { .. }) => 1,
        Msg::Req(Req::Run { fd_roles, .. }) => {
            1 + (fd_roles & 1) + ((fd_roles >> 1) & 1) + ((fd_roles >> 2) & 1)
        }
        _ => 0,
    }
}

fn word_of(b: bool) -> u32 {
    u32::from(b)
}

/// The pieces of a record being collected.
struct Rec<'a> {
    pieces: [Piece<'a>; MAX_PIECES],
    n: usize,
}

impl<'a> Rec<'a> {
    fn new() -> Rec<'a> {
        Rec {
            pieces: [Piece::Word(0); MAX_PIECES],
            n: 0,
        }
    }

    fn push(&mut self, p: Piece<'a>) {
        if let Some(slot) = self.pieces.get_mut(self.n) {
            *slot = p;
        }
        self.n += 1;
    }

    fn w(&mut self, v: u32) -> &mut Self {
        self.push(Piece::Word(v));
        self
    }

    fn s(&mut self, v: &'a str) -> &mut Self {
        self.push(Piece::Str(v.as_bytes()));
        self
    }

    fn state(&mut self, v: StateWord) -> &mut Self {
        self.w(v.state).w(v.detail)
    }

    fn list(&mut self, v: StrList<'a>) -> &mut Self {
        self.push(Piece::Str(v.as_bytes()));
        self
    }
}

#[allow(clippy::cast_sign_loss)] // the words carry signed values
fn request_record<'a>(r: &Req<'a>, rec: &mut Rec<'a>) -> u32 {
    match *r {
        Req::Status { target } => {
            rec.s(target);
            T_STATUS
        }
        Req::List { cursor, kind } => {
            rec.w(cursor).w(kind);
            T_LIST
        }
        Req::Change {
            target,
            action,
            settled,
            wait_ms,
        } => {
            rec.s(target)
                .w(action.word())
                .w(word_of(settled))
                .w(wait_ms);
            T_CHANGE
        }
        Req::Launch {
            frame,
            argv_tail,
            env_add,
            fd_roles,
            wait_ms,
            flags,
        } => {
            rec.s(frame)
                .list(argv_tail)
                .list(env_add)
                .w(fd_roles)
                .w(wait_ms)
                .w(flags);
            T_LAUNCH
        }
        Req::Refresh { settled, wait_ms } => {
            rec.w(word_of(settled)).w(wait_ms);
            T_REFRESH
        }
        Req::Shutdown {
            mode,
            settled,
            wait_ms,
        } => {
            rec.w(mode.word()).w(word_of(settled)).w(wait_ms);
            T_SHUTDOWN
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
        } => {
            rec.s(name)
                .w(fd_roles)
                .w(flags)
                .w(memory_max_kib)
                .w(pids_max)
                .w(stop_mode)
                .w(stop_grace_ms)
                .w(wait_ms);
            T_RUN
        }
    }
}

#[allow(clippy::cast_sign_loss)] // the words carry signed values
fn reply_record<'a>(r: &Rep<'a>, rec: &mut Rec<'a>) -> u32 {
    match *r {
        Rep::Error {
            code,
            detail,
            version,
        } => {
            rec.w(code.word()).w(detail).w(version);
            T_ERROR
        }
        Rep::NodeStatus(n) => {
            let (group, target) = n.blocking.unwrap_or((NONE, ""));
            rec.s(n.name)
                .w(n.kind)
                .state(n.state)
                .w(group)
                .s(target)
                .w(n.backoff_ms)
                .w((n.since_ms & 0xffff_ffff) as u32)
                .w((n.since_ms >> 32) as u32)
                .w(n.restarts)
                .w(n.pid.map_or(0, |p| p as u32));
            T_NODE_STATUS
        }
        Rep::InstanceStatus(i) => {
            rec.s(i.frame)
                .w(i.id)
                .w(i.state)
                .w(word_of(i.status.is_some()))
                .w(i.status.map_or(0, |s| s as u32))
                .w(i.pid.map_or(0, |p| p as u32));
            T_INSTANCE_STATUS
        }
        Rep::ListPage { entries, next } => {
            rec.w(u32::try_from(entries.len()).unwrap_or(u32::MAX))
                .w(next.unwrap_or(NONE));
            T_LIST_PAGE
        }
        Rep::Accepted => T_ACCEPTED,
        Rep::Settled(s) => {
            rec.state(s);
            T_SETTLED
        }
        Rep::Pending(s) => {
            rec.state(s);
            T_PENDING
        }
        Rep::Superseded(s) => {
            rec.state(s);
            T_SUPERSEDED
        }
        Rep::Launched { id } => {
            rec.w(id);
            T_LAUNCHED
        }
        Rep::LaunchFailed { step, errno } => {
            rec.w(step).w(errno);
            T_LAUNCH_FAILED
        }
        Rep::Exited { status } => {
            rec.w(status as u32);
            T_EXITED
        }
    }
}

/// Encodes `m` into `out`, declaring `fd_count` descriptors, and returns its length. The bytes
/// are a message `qinit_proto_core::check` accepts.
///
/// # Errors
/// `TooLarge` when the message does not fit; `Invalid` for a value that breaks a rule of the
/// format, such as a name of 97 bytes, a list over its cap, a wait of zero when settled, or a
/// `fd_count` that is not the descriptors the message requires.
pub fn encode(
    m: &Msg<'_>,
    fd_count: u32,
    out: &mut [u8; MAX_MESSAGE],
) -> Result<usize, EncodeError> {
    let mut rec = Rec::new();
    let t = match m {
        Msg::Req(r) => request_record(r, &mut rec),
        Msg::Rep(r) => reply_record(r, &mut rec),
    };
    if rec.n > MAX_PIECES {
        return Err(EncodeError::Invalid);
    }
    let mut entries = [EntryIn {
        name: b"",
        kind: 0,
        state: 0,
        detail: 0,
    }; MAX_LIST_ENTRIES];
    let mut count = 0;
    if let Msg::Rep(Rep::ListPage { entries: given, .. }) = m {
        if given.len() > MAX_LIST_ENTRIES {
            return Err(EncodeError::Invalid);
        }
        for (slot, e) in entries.iter_mut().zip(given.iter()) {
            *slot = EntryIn {
                name: e.name.as_bytes(),
                kind: e.kind,
                state: e.state.state,
                detail: e.state.detail,
            };
            count += 1;
        }
    }
    encode_pieces(t, fd_count, &rec.pieces[..rec.n], &entries[..count], out)
}
