// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The state machine: one function takes the state and an input and returns the actions queen's
//! binary performs. Nothing here does I/O, allocates or ends the process: the only way out of the
//! loop is the `ExecZero` action, and no action is a `reboot(2)` that halts, powers off or
//! restarts the machine.
#[allow(clippy::wildcard_imports, unused_imports)]
// the specification is erased outside verification
use crate::record::*;
#[allow(clippy::wildcard_imports, unused_imports)]
// the specification is erased outside verification
use crate::store::*;
use vstd::prelude::*;

verus! {

/// Counted exits that fit the limit's window.
pub const MAX_EXITS: usize = 5;

/// Actions one step may return.
pub const MAX_ACTIONS: usize = 6;

/// The times that bound queen's patience.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The window the last five counted exits must not all fall in.
    pub window_ms: u64,
    /// How long rescue must run for a clean exit to count.
    pub rescue_min_ms: u64,
    /// How long colony has to end a shutdown before it is killed.
    pub shutdown_ms: u64,
    /// How long after the kill queen waits before it execs zero anyway.
    pub kill_wait_ms: u64,
    /// How long a running colony may go without an `Alive` record before it is killed; 0 for no
    /// watch.
    pub heartbeat_ms: u64,
}

/// The limits of the spec: five exits in 60 s, 10 s for rescue, 5 min and 5 s for a shutdown,
/// 30 s of silence from a running colony.
pub const LIMITS: Limits = Limits {
    window_ms: 60_000,
    rescue_min_ms: 10_000,
    shutdown_ms: 300_000,
    kill_wait_ms: 5_000,
    heartbeat_ms: 30_000,
};

/// How often a colony that runs under queen sends `Alive`.
pub const ALIVE_MS: u64 = 2_000;

/// The shortest heartbeat period worth setting: four beats fit in it.
pub const MIN_HEARTBEAT_MS: u64 = 8_000;

/// What queen is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Colony runs, or is about to be started.
    Running,
    /// The rescue program runs.
    Rescue,
    /// Nothing runs; queen reaps and waits for Ctrl-Alt-Del or `SIGPWR`.
    Hold,
    /// A shutdown has begun and the timer runs.
    Stopping,
    /// The timer fired and colony was killed.
    Killed,
}

/// Everything queen remembers besides the store table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]  // a state machine's flags, each independent
pub struct State {
    pub phase: Phase,
    /// A shutdown has begun, ever: sticky, and no colony starts once it is set.
    pub stopped: bool,
    /// Colony's pid, 0 for none.
    pub colony: i32,
    /// The rescue program's pid, 0 for none.
    pub rescue: i32,
    /// When rescue was started.
    pub rescue_start: u64,
    /// Times of the last counted exits, oldest first; the first `nexits` are used.
    pub exits: [u64; 5],
    pub nexits: usize,
    /// The mode the shutdown ends in.
    pub mode: Mode,
    /// The next store slot to hand to the attached colony.
    pub cursor: usize,
    /// How many `Held` records the attached colony has been sent.
    pub held_sent: u32,
    /// `HeldEnd` has been sent to the attached colony.
    pub handed_over: bool,
    /// A shutdown colony has not heard of yet.
    pub request: Option<Mode>,
    /// An orphan was reaped since the last `Reaped` record.
    pub reaped: bool,
    /// The last key a `Put` was refused for, 0 for none.
    pub refused: u64,
    /// Colony sent `Alive` in the heartbeat period now running.
    pub alive: bool,
    /// When that period began.
    pub period_start: u64,
}

/// A fixed event for the log; the binary formats it with its numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    ColonyStarted(i32),
    ColonyExited(i32),
    LimitTripped,
    RescueStarted(i32),
    RescueEnded(i32),
    Hold,
    Shutdown(Mode),
    ExecZero(Mode),
    ExecFailed,
    ChannelBad,
    /// A running colony sent nothing for a whole heartbeat period.
    ColonySilent,
    StoreFull(u64),
    SpawnFailed,
    CadIgnored,
}

/// What the outer layer tells the machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    /// Ctrl-Alt-Del (`SIGINT`).
    Cad,
    /// `SIGPWR`.
    Pwr,
    /// A reaped child.
    Child { pid: i32, status: i32 },
    /// A decoded record from colony, with the descriptor that came with it (-1 for none).
    Record(FromColony, i32),
    /// The channel gave something that does not decode.
    ChannelBad,
    /// Colony's end of the channel is gone.
    ChannelClosed,
    /// The timer fired.
    Timer,
    ColonySpawned(i32),
    ColonySpawnFailed,
    RescueSpawned(i32),
    RescueSpawnFailed,
    /// The exec of zero returned.
    ExecFailed,
}

/// What the machine asks the outer layer to do, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    SpawnColony,
    SpawnRescue,
    Kill(i32),
    ArmTimer(u64),
    CancelTimer,
    /// Exec zero. Returns only on failure, which comes back as `Input::ExecFailed`.
    ExecZero(Mode),
    /// `reboot(RB_ENABLE_CAD)`, the only `reboot` command besides turning it off at start.
    CadOn,
    /// Close this descriptor number.
    Close(i32),
    Log(Event),
}

/// The actions of one step, in order. No step produces more than four; a fifth would be dropped
/// and the property test asserts it never is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Actions {
    pub items: [Action; 6],
    pub len: usize,
    /// One of the actions is `SpawnColony`.
    pub spawn_colony: bool,
    /// One of the actions is `ExecZero`.
    pub exec_zero: bool,
    /// One of the actions is a `Kill`.
    pub kill: bool,
}

impl Actions {
    /// The `i`th action, or `None` past the end.
    #[must_use]
    pub fn get(&self, i: usize) -> (r: Option<Action>)
        requires
            self.len <= 6,
        ensures
            r is Some <==> i < self.len,
    {
        if i < self.len {
            Some(self.items[i])
        } else {
            None
        }
    }

    /// No actions.
    #[must_use]
    pub fn none() -> (r: Actions)
        ensures
            r.len == 0,
            !r.spawn_colony,
            !r.exec_zero,
            !r.kill,
    {
        Actions {
            items: [Action::CancelTimer;6],
            len: 0,
            spawn_colony: false,
            exec_zero: false,
            kill: false,
        }
    }
}

/// Appends `x` unless the list is full.
fn push(a: &mut Actions, x: Action)
    requires
        old(a).len <= MAX_ACTIONS,
    ensures
        final(a).len <= old(a).len + 1,
        old(a).len < MAX_ACTIONS ==> final(a).len == old(a).len + 1,
        final(a).spawn_colony == (old(a).spawn_colony || (x is SpawnColony && old(a).len < 6)),
        final(a).exec_zero == (old(a).exec_zero || (x is ExecZero && old(a).len < 6)),
        final(a).kill == (old(a).kill || (x is Kill && old(a).len < 6)),
{
    if a.len < MAX_ACTIONS {
        a.items[a.len] = x;
        a.len += 1;
        match x {
            Action::SpawnColony => {
                a.spawn_colony = true;
            },
            Action::ExecZero(_) => {
                a.exec_zero = true;
            },
            Action::Kill(_) => {
                a.kill = true;
            },
            _ => {},
        }
    }
}

/// Facts that hold of every state the machine reaches.
pub open spec fn inv(s: State) -> bool {
    &&& s.nexits <= MAX_EXITS
    &&& (s.phase == Phase::Running ==> !s.stopped)
    &&& (s.phase == Phase::Stopping || s.phase == Phase::Killed) ==> s.stopped
}

/// The state and actions of a machine that has just started: colony is to be spawned.
#[must_use]
pub fn initial() -> (r: (State, Actions))
    ensures
        inv(r.0),
        r.1.spawn_colony,
        !r.1.exec_zero,
{
    let s = State {
        phase: Phase::Running,
        stopped: false,
        colony: 0,
        rescue: 0,
        rescue_start: 0,
        exits: [0;5],
        nexits: 0,
        mode: Mode::Halt,
        cursor: 0,
        held_sent: 0,
        handed_over: false,
        request: None,
        reaped: false,
        refused: 0,
        alive: false,
        period_start: 0,
    };
    let mut a = Actions::none();
    push(&mut a, Action::SpawnColony);
    (s, a)
}

/// The exit code of a normal exit in a `waitpid` status; `None` for a signal.
#[must_use]
#[allow(clippy::verbose_bit_mask, clippy::cast_sign_loss, clippy::cast_possible_truncation)]  // masked to 8 bits first
pub fn exit_code(status: i32) -> Option<u8> {
    if status & 0x7f == 0 {
        Some(((status >> 8) & 0xff) as u8)
    } else {
        None
    }
}

/// The mode colony's exit code 0, 10 or 11 names.
fn code_mode(c: Option<u8>) -> (m: Option<Mode>)
    ensures
        match c {
            Some(0) => m == Some(Mode::Halt),
            Some(10) => m == Some(Mode::Poweroff),
            Some(11) => m == Some(Mode::Reboot),
            _ => m is None,
        },
{
    match c {
        Some(0) => Some(Mode::Halt),
        Some(10) => Some(Mode::Poweroff),
        Some(11) => Some(Mode::Reboot),
        _ => None,
    }
}

/// Starts the shutdown from `Running`: record the mode, switch Ctrl-Alt-Del on and arm the timer.
fn begin_shutdown(s: &mut State, a: &mut Actions, lim: &Limits, mode: Mode)
    requires
        old(a).len + 3 <= MAX_ACTIONS,
    ensures
        final(s).phase == Phase::Stopping,
        final(s).stopped,
        final(s).mode == mode,
        final(s).colony == old(s).colony,
        final(s).rescue == old(s).rescue,
        final(s).nexits == old(s).nexits,
        final(s).exits == old(s).exits,
        final(a).len <= old(a).len + 3,
        final(a).spawn_colony == old(a).spawn_colony,
        final(a).exec_zero == old(a).exec_zero,
        final(a).kill == old(a).kill,
{
    s.phase = Phase::Stopping;
    s.stopped = true;
    s.mode = mode;
    push(a, Action::Log(Event::Shutdown(mode)));
    push(a, Action::CadOn);
    push(a, Action::ArmTimer(lim.shutdown_ms));
}

/// Forgets the held `colony.db` and closes its descriptor, if one is held: the administrator has
/// had the machine in rescue, and the next colony must read the file they repaired, not the copy
/// that was in force when colony failed.
fn drop_held_db(table: &mut [Entry], a: &mut Actions)
    requires
        unique(old(table)@),
        old(a).len <= MAX_ACTIONS,
    ensures
        final(table)@.len() == old(table)@.len(),
        unique(final(table)@),
        final(a).len <= old(a).len + 1,
        final(a).spawn_colony == old(a).spawn_colony,
        final(a).exec_zero == old(a).exec_zero,
        final(a).kill == old(a).kill,
{
    #[allow(clippy::collapsible_if)]  // Verus has no let chains
    if let Some(f) = take(table, DB_KEY) {
        push(a, Action::Close(f));
    }
}

/// Runs the rescue program, unless one already runs.
fn spawn_rescue(s: &State, a: &mut Actions)
    requires
        old(a).len < MAX_ACTIONS,
    ensures
        final(a).len <= old(a).len + 1,
        final(a).spawn_colony == old(a).spawn_colony,
        final(a).exec_zero == old(a).exec_zero,
        final(a).kill == old(a).kill,
{
    if s.rescue == 0 {
        push(a, Action::SpawnRescue);
    }
}

/// Records a counted exit at `now`, from `Running`: restart, or trip the limit and run rescue.
fn counted(s: &mut State, a: &mut Actions, lim: &Limits, now: u64)
    requires
        inv(*old(s)),
        old(s).phase == Phase::Running,
        old(a).len + 2 <= MAX_ACTIONS,
    ensures
        inv(*final(s)),
        final(s).stopped == old(s).stopped,
        final(s).colony == old(s).colony,
        final(a).len <= old(a).len + 2,
        !old(a).spawn_colony && final(a).spawn_colony ==> final(s).phase == Phase::Running,
        final(a).spawn_colony && !old(a).spawn_colony && old(s).nexits == MAX_EXITS ==> old(
            s,
        ).exits[0] + lim.window_ms <= now,
        final(a).exec_zero == old(a).exec_zero,
        final(a).kill == old(a).kill,
{
    if s.nexits == MAX_EXITS && (now < s.exits[0] || now - s.exits[0] < lim.window_ms) {
        push(a, Action::Log(Event::LimitTripped));
        s.phase = Phase::Rescue;
        spawn_rescue(s, a);
    } else {
        if s.nexits == MAX_EXITS {
            let mut i: usize = 0;
            while i < MAX_EXITS - 1
                invariant
                    i <= MAX_EXITS - 1,
                    s.nexits == MAX_EXITS,
                    s.phase == Phase::Running,
                    s.stopped == old(s).stopped,
                    s.colony == old(s).colony,
                    s.exits.len() == 5,
                decreases MAX_EXITS - 1 - i,
            {
                s.exits[i] = s.exits[i + 1];
                i += 1;
            }
            s.exits[MAX_EXITS - 1] = now;
        } else {
            s.exits[s.nexits] = now;
            s.nexits += 1;
        }
        push(a, Action::SpawnColony);
    }
}

/// Runs zero in `mode`.
fn exec_zero(s: &mut State, a: &mut Actions, mode: Mode)
    requires
        old(a).len + 2 <= MAX_ACTIONS,
    ensures
        final(s).mode == mode,
        final(s).phase == old(s).phase,
        final(s).stopped == old(s).stopped,
        final(s).colony == old(s).colony,
        final(s).rescue == old(s).rescue,
        final(s).nexits == old(s).nexits,
        final(a).len <= old(a).len + 2,
        final(a).exec_zero,
        final(a).spawn_colony == old(a).spawn_colony,
        final(a).kill == old(a).kill,
{
    s.mode = mode;
    push(a, Action::Log(Event::ExecZero(mode)));
    push(a, Action::ExecZero(mode));
}

/// What a step does with `input` at `now_ms` (a monotonic reading): the state changes in place,
/// the store table too, and the actions come back in order.
///
/// The obligations of the spec's section 4 are the `ensures`: the function is total (no step
/// ends the process, and `Action` has no variant that does), a reaped colony or rescue pid is
/// cleared, nothing starts colony once a shutdown has begun, a restart with five counted exits
/// needs the oldest to be a window old, a shutdown ends within two timers, and the store keeps
/// each key once.
#[allow(clippy::too_many_lines)]  // one match over every input, as the table reads
pub fn step(s: &mut State, table: &mut [Entry], lim: &Limits, input: Input, now: u64) -> (a:
    Actions)
    requires
        inv(*old(s)),
        unique(old(table)@),
    ensures
        inv(*final(s)),
        unique(final(table)@),
        final(table)@.len() == old(table)@.len(),
        old(s).stopped ==> final(s).stopped && !a.spawn_colony,
        old(s).phase == Phase::Running && old(s).nexits == MAX_EXITS && a.spawn_colony ==> old(
            s,
        ).exits[0] + lim.window_ms <= now,
        (input is Timer && old(s).phase == Phase::Killed) ==> a.exec_zero,
        (input is Timer && old(s).phase == Phase::Stopping && old(s).colony != 0) ==> final(s).phase
            == Phase::Killed && !a.exec_zero,
        (input is Timer && old(s).phase == Phase::Stopping && old(s).colony == 0) ==> a.exec_zero,
        (input is ExecFailed) ==> final(s).phase == Phase::Rescue,
        (input is Timer && old(s).phase == Phase::Running && old(s).colony != 0 && lim.heartbeat_ms
            > 0 && old(s).period_start <= now && now - old(s).period_start + 1 >= lim.heartbeat_ms
            && !old(s).alive) ==> a.kill,
        (input is Timer && old(s).phase == Phase::Running && old(s).alive) ==> !a.kill,
        match input {
            Input::Child { pid, .. } => (pid != 0 && pid == old(s).colony && (old(s).phase
                == Phase::Stopping || old(s).phase == Phase::Killed) ==> a.exec_zero) && (pid != 0
                && pid == old(s).colony ==> final(s).colony == 0) && (pid != 0 && pid == old(
                s,
            ).rescue ==> final(s).rescue == 0 || pid == old(s).colony),
            _ => true,
        },
        a.len <= MAX_ACTIONS,
{
    let mut a = Actions::none();
    match input {
        Input::Cad => {
            match s.phase {
                Phase::Running => {
                    begin_shutdown(s, &mut a, lim, Mode::Reboot);
                    s.request = Some(Mode::Reboot);
                },
                Phase::Rescue => {
                    push(&mut a, Action::Log(Event::CadIgnored));
                },
                Phase::Hold => {
                    if s.stopped {
                        push(&mut a, Action::Log(Event::CadIgnored));
                    } else {
                        s.nexits = 0;
                        s.phase = Phase::Running;
                        drop_held_db(table, &mut a);
                        push(&mut a, Action::SpawnColony);
                    }
                },
                Phase::Stopping | Phase::Killed => {},
            }
        },
        Input::Pwr => {
            match s.phase {
                Phase::Running => {
                    begin_shutdown(s, &mut a, lim, Mode::Poweroff);
                    s.request = Some(Mode::Poweroff);
                },
                Phase::Rescue | Phase::Hold => {
                    s.stopped = true;
                    push(&mut a, Action::CadOn);
                    exec_zero(s, &mut a, Mode::Poweroff);
                },
                Phase::Stopping | Phase::Killed => {},
            }
        },
        Input::Child { pid, status } => {
            if pid != 0 && pid == s.colony {
                s.colony = 0;
                push(&mut a, Action::Log(Event::ColonyExited(status)));
                match s.phase {
                    Phase::Running => {
                        let c = exit_code(status);
                        match code_mode(c) {
                            Some(mode) => {
                                s.phase = Phase::Stopping;
                                s.stopped = true;
                                push(&mut a, Action::CadOn);
                                exec_zero(s, &mut a, mode);
                            },
                            None => {
                                if c == Some(2) || c == Some(3) {
                                    s.phase = Phase::Rescue;
                                    spawn_rescue(s, &mut a);
                                } else {
                                    counted(s, &mut a, lim, now);
                                }
                            },
                        }
                    },
                    Phase::Stopping | Phase::Killed => {
                        let mode = match code_mode(exit_code(status)) {
                            Some(m) => m,
                            None => s.mode,
                        };
                        push(&mut a, Action::CancelTimer);
                        exec_zero(s, &mut a, mode);
                    },
                    Phase::Rescue | Phase::Hold => {},
                }
            } else if pid != 0 && pid == s.rescue {
                s.rescue = 0;
                push(&mut a, Action::Log(Event::RescueEnded(status)));
                if matches!(s.phase, Phase::Rescue) {
                    let clean = exit_code(status) == Some(0) && now >= s.rescue_start && now
                        - s.rescue_start >= lim.rescue_min_ms && !s.stopped;
                    if clean {
                        s.nexits = 0;
                        s.phase = Phase::Running;
                        drop_held_db(table, &mut a);
                        push(&mut a, Action::SpawnColony);
                    } else {
                        s.phase = Phase::Hold;
                        push(&mut a, Action::Log(Event::Hold));
                    }
                }
            }
        },
        Input::Record(r, fd) => {
            match r {
                FromColony::Put { key } => {
                    if key == 0 {
                        if fd >= 0 {
                            push(&mut a, Action::Close(fd));
                        }
                    } else {
                        match put(table, key, fd) {
                            Put::Stored => {},
                            Put::Replaced(old) => {
                                push(&mut a, Action::Close(old));
                            },
                            Put::Full => {
                                push(&mut a, Action::Close(fd));
                                push(&mut a, Action::Log(Event::StoreFull(key)));
                                s.refused = key;
                            },
                        }
                    }
                },
                FromColony::Drop { key } => {
                    #[allow(clippy::collapsible_if)]  // Verus has no let chains
                    if key != 0 {
                        if let Some(f) = take(table, key) {
                            push(&mut a, Action::Close(f));
                        }
                    }
                },
                FromColony::Alive => {
                    s.alive = true;
                },
                FromColony::Shutdown { mode } => {
                    match s.phase {
                        Phase::Running => {
                            begin_shutdown(s, &mut a, lim, mode);
                        },
                        Phase::Stopping | Phase::Killed => {
                            s.mode = mode;
                        },
                        Phase::Rescue | Phase::Hold => {},
                    }
                },
            }
        },
        Input::ChannelBad => {
            if matches!(s.phase, Phase::Running | Phase::Stopping) {
                push(&mut a, Action::Log(Event::ChannelBad));
                if s.colony != 0 {
                    push(&mut a, Action::Kill(s.colony));
                }
            }
        },
        Input::ChannelClosed => {},
        Input::Timer => {
            match s.phase {
                Phase::Stopping => {
                    if s.colony != 0 {
                        s.phase = Phase::Killed;
                        push(&mut a, Action::Kill(s.colony));
                        push(&mut a, Action::ArmTimer(lim.kill_wait_ms));
                    } else {
                        // Nothing is left to kill or to wait for: the bound ends the shutdown.
                        let mode = s.mode;
                        exec_zero(s, &mut a, mode);
                    }
                },
                Phase::Killed => {
                    let mode = s.mode;
                    exec_zero(s, &mut a, mode);
                },
                Phase::Running => {
                    // The heartbeat: a whole period without a word from colony kills it; one
                    // with a word starts the next. A timer read before the period is over is
                    // the stale one of a colony that was replaced in the same turn.
                    if s.colony != 0 && lim.heartbeat_ms > 0 && now >= s.period_start && now
                        - s.period_start >= lim.heartbeat_ms - 1 {
                        if s.alive {
                            s.alive = false;
                            s.period_start = now;
                            push(&mut a, Action::ArmTimer(lim.heartbeat_ms));
                        } else {
                            push(&mut a, Action::Log(Event::ColonySilent));
                            push(&mut a, Action::Kill(s.colony));
                        }
                    }
                },
                Phase::Rescue | Phase::Hold => {},
            }
        },
        Input::ColonySpawned(pid) => {
            s.colony = pid;
            s.cursor = 0;
            s.held_sent = 0;
            s.handed_over = false;
            s.reaped = false;
            s.refused = 0;
            s.alive = false;
            s.period_start = now;
            push(&mut a, Action::Log(Event::ColonyStarted(pid)));
            if matches!(s.phase, Phase::Running) && lim.heartbeat_ms > 0 {
                push(&mut a, Action::ArmTimer(lim.heartbeat_ms));
            }
        },
        Input::ColonySpawnFailed => {
            push(&mut a, Action::Log(Event::SpawnFailed));
            if matches!(s.phase, Phase::Running) {
                counted(s, &mut a, lim, now);
            }
        },
        Input::RescueSpawned(pid) => {
            s.rescue = pid;
            s.rescue_start = now;
            push(&mut a, Action::Log(Event::RescueStarted(pid)));
        },
        Input::RescueSpawnFailed => {
            push(&mut a, Action::Log(Event::SpawnFailed));
            if matches!(s.phase, Phase::Rescue) {
                s.phase = Phase::Hold;
                push(&mut a, Action::Log(Event::Hold));
            }
        },
        Input::ExecFailed => {
            push(&mut a, Action::Log(Event::ExecFailed));
            s.phase = Phase::Rescue;
            spawn_rescue(s, &mut a);
        },
    }
    a
}

/// The next record queen owes the attached colony, with the descriptor that goes with it (-1 for
/// none): the store entry by entry, then `HeldEnd`, then a pending request, the `Reaped` wake and
/// a refusal. Nothing while no colony is attached. [`record_sent`] moves past it.
#[must_use]
pub fn next_record(s: &State, table: &[Entry]) -> (r: Option<(ToColony, i32)>) {
    if s.colony == 0 {
        return None;
    }
    if !s.handed_over {
        match next_held(table, s.cursor) {
            Some((_, e)) => Some((ToColony::Held { key: e.key }, e.fd)),
            None => Some((ToColony::HeldEnd { count: s.held_sent }, -1)),
        }
    } else if let Some(mode) = s.request {
        Some((ToColony::Request { mode }, -1))
    } else if s.reaped {
        Some((ToColony::Reaped, -1))
    } else if s.refused != 0 {
        Some((ToColony::Refused { key: s.refused }, -1))
    } else {
        None
    }
}

/// Marks the record [`next_record`] returned as sent.
#[allow(clippy::implicit_saturating_add)]  // Verus has no saturating_add
pub fn record_sent(s: &mut State, table: &[Entry])
    requires
        inv(*old(s)),
    ensures
        inv(*final(s)),
{
    if s.colony == 0 {
        return;
    }
    if !s.handed_over {
        match next_held(table, s.cursor) {
            Some((i, _)) => {
                if i < usize::MAX {
                    s.cursor = i + 1;
                }
                if s.held_sent < u32::MAX {
                    s.held_sent += 1;
                }
            },
            None => {
                s.handed_over = true;
            },
        }
    } else if s.request.is_some() {
        s.request = None;
    } else if s.reaped {
        s.reaped = false;
    } else if s.refused != 0 {
        s.refused = 0;
    }
}

/// An orphan was reaped: the next `Reaped` record will say so.
pub fn orphan_reaped(s: &mut State)
    requires
        inv(*old(s)),
    ensures
        inv(*final(s)),
{
    s.reaped = true;
}

} // verus!
