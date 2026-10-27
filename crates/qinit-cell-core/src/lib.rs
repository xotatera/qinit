// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! `qinit-cell-core`: the cell machine (spec 2026-10-27 §5.2), proved by Verus
//! (`proof:qinit-cell-core`). One machine per cell over fixed-size `Copy` data: requests and
//! kernel results come in as [`Event`]s, at most four [`Action`]s go out. Process and fd
//! identities are [`Handle`]s the drive maps to real pidfds. `step`'s postcondition `good` is
//! the spec's six obligations; `inv` holds between steps.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use vstd::prelude::*;

verus! {

/// The drive's name for a process (its pidfd).
pub type Handle = u32;

/// How a stop asks politely first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Polite {
    /// TERM to the main process through its pidfd.
    Main,
    /// Freeze the cell, TERM every member through a verified pidfd, thaw.
    Cell,
}

/// What counts as ready.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadyMode {
    /// A newline on the readiness pipe.
    Pipe,
    /// The main process exits with status 0.
    Exit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sig {
    Term,
    Kill,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timer {
    Grace,
    Kill,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Create,
    Spawn,
    IdMismatch,
    /// Still populated after the kill deadline (a process in uninterruptible sleep).
    Stuck,
    Remove,
}

/// The tracked main process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Main {
    None,
    /// `Spawn` was emitted; the exec result (`Spawned` or `SpawnFailed`) has not arrived.
    Pending,
    Live(Handle),
    /// Reaped, with its wait status.
    Reaped(i32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopStep {
    Freezing,
    Signalling,
    Thawing,
    Waiting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Absent,
    Creating,
    Created,
    Adopting,
    Starting,
    Running,
    /// The main process is gone; the cell is still populated.
    Exited,
    Stopping(StopStep),
    Killing,
    Empty,
    Removing,
    Removed,
    Failed(Failure),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    pub phase: Phase,
    pub main: Main,
    pub ready: ReadyMode,
    /// `populated` as last read from `cgroup.events`.
    pub populated: bool,
    /// `frozen` as last read.
    pub frozen: bool,
    /// A freeze this machine asked for and has not thawed yet.
    pub freeze_held: bool,
    /// The armed deadline, if any.
    pub armed: Option<Timer>,
    /// The kill deadline of the current stop.
    pub kill_ms: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Create,
    Spawn(ReadyMode),
    /// Adopt an existing cell; the main pidfd queen handed over, if any.
    Adopt(Option<Handle>),
    Stop { polite: Polite, grace_ms: u32, kill_ms: u32 },
    Remove,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Request(Request),
    Created,
    CreateFailed,
    /// The exec was confirmed; the main process's handle.
    Spawned(Handle),
    SpawnFailed,
    ReadyLine,
    ReadyClosed,
    /// The main process was reaped, with its wait status.
    MainExited(i32),
    /// `cgroup.events` re-read after a notification.
    Level { populated: bool, frozen: bool },
    /// Every member got the polite signal.
    Signalled,
    AdoptChecked { id_matches: bool, populated: bool },
    Deadline(Timer),
    Removed,
    RemoveFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Report {
    Created,
    Ready,
    /// The readiness pipe closed without a newline; the caller decides.
    NotReady,
    Running,
    MainExited(i32),
    Empty,
    Removed,
    Failed(Failure),
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    CreateDir,
    Spawn,
    CheckAdopt,
    Arm(Timer, u32),
    Cancel(Timer),
    SignalMain(Handle, Sig),
    Freeze,
    SignalMembers(Sig),
    Thaw,
    Kill,
    RemoveDir,
    Report(Report),
}

/// At most four actions per step, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Actions {
    pub a: Option<Action>,
    pub b: Option<Action>,
    pub c: Option<Action>,
    pub d: Option<Action>,
}

pub open spec fn emits(acts: Actions, x: Action) -> bool {
    acts.a == Some(x) || acts.b == Some(x) || acts.c == Some(x) || acts.d == Some(x)
}

/// Whether a slot holds an action that reaches processes: a signal, a freeze or a kill.
pub open spec fn reaches(o: Option<Action>) -> bool {
    match o {
        Some(Action::SignalMain(_, _)) => true,
        Some(Action::Freeze) => true,
        Some(Action::SignalMembers(_)) => true,
        Some(Action::Kill) => true,
        _ => false,
    }
}

pub open spec fn emits_reaching(acts: Actions) -> bool {
    reaches(acts.a) || reaches(acts.b) || reaches(acts.c) || reaches(acts.d)
}

/// Removed and Failed end the machine: no event moves them except `Remove` from Failed.
pub open spec fn terminal(p: Phase) -> bool {
    p is Removed || p is Failed
}

/// Obligation 6: the event a phase without an armed deadline waits for exists.
pub open spec fn awaits(c: Cell) -> bool {
    match c.phase {
        // The answer to the effect issued on entry (`entered`): Created / CreateFailed,
        // AdoptChecked, Removed / RemoveFailed.
        Phase::Creating | Phase::Adopting | Phase::Removing => true,
        // The caller's next request; entry was reported to the caller (`entered`).
        Phase::Absent | Phase::Created | Phase::Empty => true,
        // Spawned / SpawnFailed while the spawn is outstanding, then the live pidfd's exit.
        Phase::Starting => c.main is Pending || c.main is Live,
        // The live pidfd's exit, or the level change that reports `populated 0`.
        Phase::Running | Phase::Exited => c.main is Live || c.populated,
        // Only an armed deadline moves these.
        Phase::Stopping(_) | Phase::Killing => false,
        Phase::Removed | Phase::Failed(_) => false,
    }
}

/// The phases of a cell that was empty; none of them reaches processes.
pub open spec fn after_empty(p: Phase) -> bool {
    p is Empty || p is Removing || p is Removed || p == Phase::Failed(Failure::Remove)
}

/// What holds between steps.
pub open spec fn inv(c: Cell) -> bool {
    &&& (c.freeze_held <==> (c.phase == Phase::Stopping(StopStep::Freezing) || c.phase
        == Phase::Stopping(StopStep::Signalling)))
    &&& (c.phase is Stopping ==> c.armed == Some(Timer::Grace))
    &&& (c.phase is Killing ==> c.armed == Some(Timer::Kill))
    &&& (!(c.phase is Stopping) && !(c.phase is Killing)
        ==> c.armed is None)
    // Nothing is spawned or adopted before `Spawn` or `Adopt`.
    &&& (c.phase is Absent || c.phase is Creating || c.phase is Created
        ==> c.main is None)
    // Exited means the main process was reaped.
    &&& (c.phase is Exited
        ==> c.main is Reaped)
    // Adoption never has a spawn outstanding.
    &&& (c.phase is Adopting ==> c.main
        != Main::Pending)
    // A cell starts with its spawn outstanding; Running never has one.
    &&& (c.phase is Starting ==> c.main is Pending || c.main is Live)
    &&& (c.phase is Running ==> c.main
        != Main::Pending)
    // Obligation 4: empty is honest: no live main process, no outstanding spawn.
    &&& (c.phase is Empty ==> (c.main is None || c.main is Reaped)
        && !c.populated)
    // Obligation 6: no stuck state.
    &&& (!terminal(c.phase) ==> c.armed is Some || awaits(c))
}

/// Obligation 4: the level that makes a cell empty was observed: the event's own reading, or
/// the last one recorded.
pub open spec fn observed_empty(c: Cell, e: Event) -> bool {
    match e {
        Event::Level { populated, .. } => !populated,
        Event::AdoptChecked { populated, .. } => !populated,
        _ => !c.populated,
    }
}

/// Obligation 4: every level read is recorded (an empty cell ignores late readings).
pub open spec fn records_level(c: Cell, e: Event, n: Cell) -> bool {
    match e {
        Event::Level { populated, .. } => c.phase is Empty || n.populated == populated,
        _ => true,
    }
}

/// Obligation 3: the main process goes None -> Pending (spawn requested) -> Live(h) (exec
/// confirmed) or None (exec failed); None -> Live(h) (handed over on adoption); Live(h) ->
/// Reaped(status) (its exit observed), and never back.
pub open spec fn main_moves(c: Cell, e: Event, n: Cell) -> bool {
    match c.main {
        Main::Reaped(_) => n.main == c.main,
        Main::Live(_) => match e {
            Event::MainExited(status) => n.main == Main::Reaped(status),
            _ => n.main == c.main,
        },
        Main::Pending => match e {
            Event::Spawned(h) => n.main == Main::Live(h),
            Event::SpawnFailed => n.main is None,
            _ => n.main is Pending,
        },
        Main::None => n.main is None || match e {
            Event::Request(Request::Spawn(_)) => n.main is Pending,
            Event::Request(Request::Adopt(Some(h))) => n.main == Main::Live(h),
            _ => false,
        },
    }
}

/// Obligation 6: entering a phase that waits for an effect's answer issues that effect, and
/// entering one that waits for the caller (or ends the machine) reports it.
pub open spec fn entered(c: Cell, r: (Cell, Actions)) -> bool {
    let (p, q) = (c.phase, r.0.phase);
    &&& (q is Creating && !(p is Creating) ==> emits(r.1, Action::CreateDir))
    &&& (q is Adopting && !(p is Adopting) ==> emits(r.1, Action::CheckAdopt))
    &&& (q is Starting && !(p is Starting) ==> emits(r.1, Action::Spawn))
    &&& (q is Removing && !(p is Removing) ==> emits(r.1, Action::RemoveDir))
    &&& (q is Created && !(p is Created) ==> emits(r.1, Action::Report(Report::Created)))
    &&& (q is Empty && !(p is Empty) ==> emits(r.1, Action::Report(Report::Empty)))
    &&& (forall|f: Failure|
        q == Phase::Failed(f) && p != q ==> emits(r.1, Action::Report(Report::Failed(f))))
}

/// The spec's obligations (2026-10-27 §5.2) for one step from `c` on `e` to `r`.
pub open spec fn good(c: Cell, e: Event, r: (Cell, Actions)) -> bool {
    &&& inv(
        r.0,
    )
    // 1. Escalation: the grace deadline while stopping always kills.
    &&& (c.phase is Stopping && e == Event::Deadline(Timer::Grace) ==> emits(
        r.1,
        Action::Kill,
    ))
    // 2. No freeze leak: a freeze is held until a thaw is emitted.
    &&& (emits(r.1, Action::Freeze) ==> r.0.freeze_held)
    &&& (c.freeze_held && !r.0.freeze_held ==> emits(
        r.1,
        Action::Thaw,
    ))
    // 3. No pid reuse: the main process is signalled only through its live handle, which
    // stops being live once its exit is observed.
    &&& (forall|h: Handle, s: Sig|
        emits(r.1, Action::SignalMain(h, s)) ==> c.main == Main::Live(h) && r.0.main == Main::Live(
            h,
        ))
    &&& main_moves(
        c,
        e,
        r.0,
    )
    // 4. Empty is honest: entered only on an observed empty level, with no live main process
    // (`inv`); every level read is recorded.
    &&& (!(c.phase is Empty) && r.0.phase is Empty ==> observed_empty(c, e))
    &&& records_level(
        c,
        e,
        r.0,
    )
    // 5. Nothing reaches processes once the cell was empty.
    &&& (after_empty(c.phase) ==> after_empty(r.0.phase) && !emits_reaching(
        r.1,
    ))
    // 6. No stuck state: every non-terminal state has an awaited event or an armed deadline
    // (`inv`, `entered`); the kill deadline ends in Failed, never in a loop.
    &&& entered(c, r)
    &&& (c.phase is Killing && e == Event::Deadline(Timer::Kill) ==> r.0.phase == Phase::Failed(
        Failure::Stuck,
    ))
    // Deadlines are cancelled when their state is left (unless the deadline itself fired).
    &&& (forall|t: Timer|
        c.armed == Some(t) && r.0.armed != Some(t) && e != Event::Deadline(t) ==> emits(
            r.1,
            Action::Cancel(t),
        ))
}

fn none() -> (r: Actions)
    ensures
        r == (Actions { a: None, b: None, c: None, d: None }),
{
    Actions { a: None, b: None, c: None, d: None }
}

fn one(x: Action) -> (r: Actions)
    ensures
        r == (Actions { a: Some(x), b: None, c: None, d: None }),
{
    Actions { a: Some(x), b: None, c: None, d: None }
}

fn two(x: Action, y: Action) -> (r: Actions)
    ensures
        r == (Actions { a: Some(x), b: Some(y), c: None, d: None }),
{
    Actions { a: Some(x), b: Some(y), c: None, d: None }
}

fn three(x: Action, y: Action, z: Action) -> (r: Actions)
    ensures
        r == (Actions { a: Some(x), b: Some(y), c: Some(z), d: None }),
{
    Actions { a: Some(x), b: Some(y), c: Some(z), d: None }
}

fn refused() -> (r: Actions)
    ensures
        r == (Actions { a: Some(Action::Report(Report::Refused)), b: None, c: None, d: None }),
{
    one(Action::Report(Report::Refused))
}

/// A new, absent cell.
#[must_use]
pub fn absent() -> (c: Cell)
    ensures
        inv(c),
        c.phase == Phase::Absent,
{
    Cell {
        phase: Phase::Absent,
        main: Main::None,
        ready: ReadyMode::Pipe,
        populated: false,
        frozen: false,
        freeze_held: false,
        armed: None,
        kill_ms: 0,
    }
}

/// The cell goes empty: cancel the armed deadline, thaw a held freeze, report.
#[allow(unused_variables)]  // `e` appears only in the contract, which a plain build erases
fn to_empty(c: Cell, e: Ghost<Event>, main: Main) -> (r: (Cell, Actions))
    requires
        inv(c),
        main is None || main is Reaped,
        !after_empty(c.phase),
        observed_empty(c, e@),
        main_moves(c, e@, Cell { main, ..c }),
        !(c.phase is Stopping && e@ == Event::Deadline(Timer::Grace)),
        !(c.phase is Killing && e@ == Event::Deadline(Timer::Kill)),
    ensures
        good(c, e@, r),
        r.0.phase == Phase::Empty,
        r.0.main == main,
{
    let n = Cell {
        phase: Phase::Empty,
        main,
        populated: false,
        freeze_held: false,
        armed: None,
        ..c
    };
    let empty = Action::Report(Report::Empty);
    let acts = match c.armed {
        Some(t) => if c.freeze_held {
            three(Action::Cancel(t), Action::Thaw, empty)
        } else {
            two(Action::Cancel(t), empty)
        },
        None => if c.freeze_held {
            two(Action::Thaw, empty)
        } else {
            one(empty)
        },
    };
    (n, acts)
}

fn request(c: Cell, q: Request) -> (r: (Cell, Actions))
    requires
        inv(c),
    ensures
        good(c, Event::Request(q), r),
{
    match q {
        Request::Create => match c.phase {
            Phase::Absent => (Cell { phase: Phase::Creating, ..c }, one(Action::CreateDir)),
            _ => (c, refused()),
        },
        Request::Spawn(mode) => match c.phase {
            Phase::Created => (
                Cell { phase: Phase::Starting, ready: mode, main: Main::Pending, ..c },
                one(Action::Spawn),
            ),
            _ => (c, refused()),
        },
        Request::Adopt(h) => match c.phase {
            Phase::Absent => {
                let main = match h {
                    Some(x) => Main::Live(x),
                    None => Main::None,
                };
                (Cell { phase: Phase::Adopting, main, ..c }, one(Action::CheckAdopt))
            },
            _ => (c, refused()),
        },
        Request::Stop { polite, grace_ms, kill_ms } => match c.phase {
            Phase::Starting | Phase::Running | Phase::Exited => match (polite, c.main) {
                (Polite::Main, Main::Live(h)) => (
                    Cell {
                        phase: Phase::Stopping(StopStep::Waiting),
                        armed: Some(Timer::Grace),
                        kill_ms,
                        ..c
                    },
                    two(Action::SignalMain(h, Sig::Term), Action::Arm(Timer::Grace, grace_ms)),
                ),
                _ => (
                    Cell {
                        phase: Phase::Stopping(StopStep::Freezing),
                        freeze_held: true,
                        armed: Some(Timer::Grace),
                        kill_ms,
                        ..c
                    },
                    two(Action::Freeze, Action::Arm(Timer::Grace, grace_ms)),
                ),
            },
            Phase::Created => if c.populated {
                (c, refused())
            } else {
                (Cell { phase: Phase::Empty, ..c }, one(Action::Report(Report::Empty)))
            },
            Phase::Empty => (c, one(Action::Report(Report::Empty))),
            _ => (c, none()),
        },
        Request::Remove => match c.phase {
            Phase::Created | Phase::Empty | Phase::Failed(_) => (
                Cell { phase: Phase::Removing, ..c },
                one(Action::RemoveDir),
            ),
            _ => (c, refused()),
        },
    }
}

fn main_exited(c: Cell, status: i32) -> (r: (Cell, Actions))
    requires
        inv(c),
    ensures
        good(c, Event::MainExited(status), r),
{
    match c.main {
        Main::Live(_) => {
            let reaped = Main::Reaped(status);
            let exited = Action::Report(Report::MainExited(status));
            match c.phase {
                Phase::Starting => {
                    let by_exit = match c.ready {
                        ReadyMode::Exit => status == 0,
                        ReadyMode::Pipe => false,
                    };
                    let first = if by_exit {
                        Action::Report(Report::Ready)
                    } else {
                        exited
                    };
                    if c.populated {
                        let phase = if by_exit {
                            Phase::Running
                        } else {
                            Phase::Exited
                        };
                        (Cell { phase, main: reaped, ..c }, one(first))
                    } else {
                        (
                            Cell { phase: Phase::Empty, main: reaped, ..c },
                            two(first, Action::Report(Report::Empty)),
                        )
                    }
                },
                Phase::Running => if c.populated {
                    (Cell { phase: Phase::Exited, main: reaped, ..c }, one(exited))
                } else {
                    (
                        Cell { phase: Phase::Empty, main: reaped, ..c },
                        two(exited, Action::Report(Report::Empty)),
                    )
                },
                Phase::Stopping(_) | Phase::Killing => if c.populated {
                    (Cell { main: reaped, ..c }, none())
                } else {
                    to_empty(c, Ghost(Event::MainExited(status)), reaped)
                },
                _ => (Cell { main: reaped, ..c }, none()),
            }
        },
        _ => (c, none()),
    }
}

fn level(c: Cell, populated: bool, frozen: bool) -> (r: (Cell, Actions))
    requires
        inv(c),
    ensures
        good(c, Event::Level { populated, frozen }, r),
{
    // The main process can no longer keep the cell alive: reaped, or never tracked (adopted
    // without a pidfd). An outstanding spawn may still leave an unreaped main process.
    let gone = match c.main {
        Main::Reaped(_) | Main::None => true,
        Main::Pending | Main::Live(_) => false,
    };
    let n = Cell { populated, frozen, ..c };
    match c.phase {
        Phase::Starting | Phase::Running | Phase::Exited | Phase::Stopping(_) | Phase::Killing => {
            if !populated && gone {
                to_empty(c, Ghost(Event::Level { populated, frozen }), c.main)
            } else {
                match c.phase {
                    Phase::Stopping(StopStep::Freezing) => if frozen {
                        (
                            Cell { phase: Phase::Stopping(StopStep::Signalling), ..n },
                            one(Action::SignalMembers(Sig::Term)),
                        )
                    } else {
                        (n, none())
                    },
                    Phase::Stopping(StopStep::Thawing) => if frozen {
                        (n, none())
                    } else {
                        (Cell { phase: Phase::Stopping(StopStep::Waiting), ..n }, none())
                    },
                    _ => (n, none()),
                }
            }
        },
        Phase::Empty => (c, none()),
        _ => (n, none()),
    }
}

fn deadline(c: Cell, t: Timer) -> (r: (Cell, Actions))
    requires
        inv(c),
    ensures
        good(c, Event::Deadline(t), r),
{
    match (c.phase, t) {
        (Phase::Stopping(_), Timer::Grace) => {
            let n = Cell {
                phase: Phase::Killing,
                freeze_held: false,
                armed: Some(Timer::Kill),
                ..c
            };
            let arm = Action::Arm(Timer::Kill, c.kill_ms);
            if c.freeze_held {
                (n, three(Action::Thaw, Action::Kill, arm))
            } else {
                (n, two(Action::Kill, arm))
            }
        },
        (Phase::Killing, Timer::Kill) => (
            Cell { phase: Phase::Failed(Failure::Stuck), armed: None, ..c },
            one(Action::Report(Report::Failed(Failure::Stuck))),
        ),
        _ => (c, none()),
    }
}

fn adopt_checked(c: Cell, id_matches: bool, populated: bool) -> (r: (Cell, Actions))
    requires
        inv(c),
    ensures
        good(c, Event::AdoptChecked { id_matches, populated }, r),
{
    match c.phase {
        Phase::Adopting => {
            let live = matches!(c.main, Main::Live(_));
            if !id_matches {
                (
                    Cell { phase: Phase::Failed(Failure::IdMismatch), ..c },
                    one(Action::Report(Report::Failed(Failure::IdMismatch))),
                )
            } else if populated || live {
                (
                    Cell { phase: Phase::Running, populated, ..c },
                    one(Action::Report(Report::Running)),
                )
            } else {
                (
                    Cell { phase: Phase::Empty, populated: false, ..c },
                    one(Action::Report(Report::Empty)),
                )
            }
        },
        _ => (c, none()),
    }
}

/// The exec failed, possibly after a stop began: end the start or stop (cancel its deadline,
/// thaw a held freeze) and fail; later phases only forget the outstanding spawn.
fn spawn_failed(c: Cell) -> (r: (Cell, Actions))
    requires
        inv(c),
    ensures
        good(c, Event::SpawnFailed, r),
{
    let failed = Action::Report(Report::Failed(Failure::Spawn));
    let n = Cell {
        phase: Phase::Failed(Failure::Spawn),
        main: Main::None,
        freeze_held: false,
        armed: None,
        ..c
    };
    match (c.phase, c.main) {
        (Phase::Starting | Phase::Stopping(_) | Phase::Killing, Main::Pending) => match c.armed {
            Some(t) => if c.freeze_held {
                (n, three(Action::Cancel(t), Action::Thaw, failed))
            } else {
                (n, two(Action::Cancel(t), failed))
            },
            // Unarmed means Starting (`inv`): no freeze is held.
            None => (n, one(failed)),
        },
        (_, Main::Pending) => (Cell { main: Main::None, ..c }, none()),
        _ => (c, none()),
    }
}

/// One step of the machine.
#[must_use]
pub fn step(c: Cell, e: Event) -> (r: (Cell, Actions))
    requires
        inv(c),
    ensures
        good(c, e, r),
{
    match e {
        Event::Request(q) => request(c, q),
        Event::Created => match c.phase {
            Phase::Creating => (
                Cell { phase: Phase::Created, ..c },
                one(Action::Report(Report::Created)),
            ),
            _ => (c, none()),
        },
        Event::CreateFailed => match c.phase {
            Phase::Creating => (
                Cell { phase: Phase::Failed(Failure::Create), ..c },
                one(Action::Report(Report::Failed(Failure::Create))),
            ),
            _ => (c, none()),
        },
        // A stop may come before the exec is confirmed: the handle is still recorded.
        Event::Spawned(h) => match c.main {
            Main::Pending => (Cell { main: Main::Live(h), populated: true, ..c }, none()),
            _ => (c, none()),
        },
        Event::SpawnFailed => spawn_failed(c),
        Event::ReadyLine => match (c.phase, c.ready, c.main) {
            (Phase::Starting, ReadyMode::Pipe, Main::Live(_)) => (
                Cell { phase: Phase::Running, ..c },
                one(Action::Report(Report::Ready)),
            ),
            _ => (c, none()),
        },
        Event::ReadyClosed => match (c.phase, c.ready) {
            (Phase::Starting, ReadyMode::Pipe) => (c, one(Action::Report(Report::NotReady))),
            _ => (c, none()),
        },
        Event::MainExited(status) => main_exited(c, status),
        Event::Level { populated, frozen } => level(c, populated, frozen),
        Event::Signalled => match c.phase {
            Phase::Stopping(StopStep::Signalling) => (
                Cell { phase: Phase::Stopping(StopStep::Thawing), freeze_held: false, ..c },
                one(Action::Thaw),
            ),
            _ => (c, none()),
        },
        Event::AdoptChecked { id_matches, populated } => adopt_checked(c, id_matches, populated),
        Event::Deadline(t) => deadline(c, t),
        Event::Removed => match c.phase {
            Phase::Removing => (
                Cell { phase: Phase::Removed, ..c },
                one(Action::Report(Report::Removed)),
            ),
            _ => (c, none()),
        },
        Event::RemoveFailed => match c.phase {
            Phase::Removing => (
                Cell { phase: Phase::Failed(Failure::Remove), ..c },
                one(Action::Report(Report::Failed(Failure::Remove))),
            ),
            _ => (c, none()),
        },
    }
}

} // verus!

impl Actions {
    /// The four slots in order (`None` past the last action).
    #[must_use]
    pub fn items(&self) -> [Option<Action>; 4] {
        [self.a, self.b, self.c, self.d]
    }
}
