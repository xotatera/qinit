// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The engine: a table of cells, each stepped by `qinit-cell-core` and routed by
//! `qinit-cell-drive`; actions are carried out through [`Effects`], and their immediate
//! results come back as events in the same delivery.
use crate::effects::{Command, Effects, Reaped};
use crate::text::{ReadyBuf, valid_name};
use qinit_cell_core::{
    Action, Cell, Event, Failure, Handle, Main, Phase, Polite, ReadyMode, Report, Request,
    STATUS_UNKNOWN, absent, step,
};
use qinit_cell_drive::{CAPACITY, Source, first_free, route, source_timer};
use qinit_event::{Ready, Token};
use qinit_sys::Errno;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::fd::OwnedFd;
use std::time::Duration;

/// The loop token of the subreaper's SIGCHLD source; never a cell's (`route` gives `None`).
pub const ORPHANS: Token = u64::MAX;

/// A cell's place in the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CellId(pub u16);

/// What the engine tells its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Notice {
    Cell(CellId, Report),
    Orphan { pid: libc::pid_t, status: i32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The table holds [`CAPACITY`] cells.
    Full,
    BadName(String),
    NoSuchCell(u16),
    /// The running kernel is below the floor (spec R9).
    Floor(String),
    Sys(Errno),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Full => write!(f, "the cell table is full ({CAPACITY} cells)"),
            Error::BadName(n) => write!(
                f,
                "{n:?} is not a cell name: 1 to 64 of [A-Za-z0-9._-], not . or .."
            ),
            Error::NoSuchCell(s) => write!(f, "no cell in slot {s}"),
            Error::Floor(m) => write!(f, "{m}"),
            Error::Sys(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<Errno> for Error {
    fn from(e: Errno) -> Error {
        Error::Sys(e)
    }
}

struct Entry {
    name: CString,
    cell: Cell,
    ready: ReadyBuf,
    mode: ReadyMode,
    expected_id: u64,
    command: Option<Command>,
    /// The handle `spawn` returned while its exec result is outstanding; given to the machine
    /// once exec is confirmed.
    pending_main: Option<Handle>,
}

impl Entry {
    fn new(name: &str) -> Result<Entry, Error> {
        Ok(Entry {
            name: CString::new(name).map_err(|_| Error::BadName(name.to_string()))?,
            cell: absent(),
            ready: ReadyBuf::new(),
            mode: ReadyMode::Pipe,
            expected_id: 0,
            command: None,
            pending_main: None,
        })
    }
}

fn ms(d: Duration) -> u32 {
    u32::try_from(d.as_millis()).unwrap_or(u32::MAX)
}

pub struct Engine<E: Effects> {
    pub effects: E,
    /// Exactly [`CAPACITY`] long, so `first_free` finds no slot in a full table.
    slots: Vec<Option<Entry>>,
    notices: Vec<Notice>,
}

impl<E: Effects> Engine<E> {
    pub fn new(effects: E) -> Engine<E> {
        Engine {
            effects,
            slots: (0..CAPACITY).map(|_| None).collect(),
            notices: Vec::new(),
        }
    }

    fn entry(&mut self, slot: u16) -> Result<&mut Entry, Error> {
        self.slots
            .get_mut(usize::from(slot))
            .and_then(Option::as_mut)
            .ok_or(Error::NoSuchCell(slot))
    }

    fn has(&self, slot: u16) -> bool {
        self.slots
            .get(usize::from(slot))
            .is_some_and(Option::is_some)
    }

    fn place(&mut self, name: &str) -> Result<u16, Error> {
        if !valid_name(name) {
            return Err(Error::BadName(name.to_string()));
        }
        let used: Vec<bool> = self.slots.iter().map(Option::is_some).collect();
        let i = first_free(&used).ok_or(Error::Full)?;
        let slot = u16::try_from(i).map_err(|_| Error::Full)?;
        self.slots[i] = Some(Entry::new(name)?);
        Ok(slot)
    }

    /// Frees a slot and everything the effects hold for it.
    fn free(&mut self, slot: u16) {
        self.effects.release(slot);
        if let Some(s) = self.slots.get_mut(usize::from(slot)) {
            *s = None;
        }
    }

    /// Creates cell `name`; its reports follow as notices.
    ///
    /// # Errors
    ///
    /// [`Error::BadName`], [`Error::Full`], or [`Error::Sys`] when an effect failed.
    pub fn create(&mut self, name: &str) -> Result<CellId, Error> {
        let slot = self.place(name)?;
        self.deliver(slot, Event::Request(Request::Create))?;
        Ok(CellId(slot))
    }

    /// Starts `cmd` in a created cell (the machine refuses it otherwise; the command and its
    /// descriptors are dropped then).
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchCell`], or [`Error::Sys`] when an effect failed.
    pub fn spawn(&mut self, id: CellId, cmd: Command, ready: ReadyMode) -> Result<(), Error> {
        let e = self.entry(id.0)?;
        e.command = Some(cmd);
        e.mode = ready;
        let r = self.deliver(id.0, Event::Request(Request::Spawn(ready)));
        if let Ok(e) = self.entry(id.0) {
            e.command = None;
        }
        r
    }

    /// Adopts existing cell `name`, recorded with cgroup id `expected_id`, with the main
    /// pidfd queen handed over, if any.
    ///
    /// # Errors
    ///
    /// [`Error::BadName`], [`Error::Full`], or [`Error::Sys`] when an effect failed (a
    /// refused hand-over frees the slot again).
    pub fn adopt(
        &mut self,
        name: &str,
        expected_id: u64,
        main: Option<OwnedFd>,
    ) -> Result<CellId, Error> {
        let slot = self.place(name)?;
        self.entry(slot)?.expected_id = expected_id;
        let handle = match main.map(|fd| self.effects.adopt_main(slot, fd)) {
            Some(Ok(h)) => Some(h),
            Some(Err(e)) => {
                self.free(slot);
                return Err(e.into());
            }
            None => None,
        };
        self.deliver(slot, Event::Request(Request::Adopt(handle)))?;
        Ok(CellId(slot))
    }

    /// Stops a cell: `polite` first, the kill after `grace`, given up after `kill`.
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchCell`], or [`Error::Sys`] when an effect failed.
    pub fn stop(
        &mut self,
        id: CellId,
        polite: Polite,
        grace: Duration,
        kill: Duration,
    ) -> Result<(), Error> {
        self.deliver(
            id.0,
            Event::Request(Request::Stop {
                polite,
                grace_ms: ms(grace),
                kill_ms: ms(kill),
            }),
        )
    }

    /// Removes a created, empty or failed cell; `Removed` frees its slot.
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchCell`], or [`Error::Sys`] when an effect failed.
    pub fn remove(&mut self, id: CellId) -> Result<(), Error> {
        // A mismatched directory belongs to somebody else. Release only our tracking;
        // never execute the machine's RemoveDir effect against that directory.
        if self.phase(id) == Some(Phase::Failed(Failure::IdMismatch)) {
            self.free(id.0);
            self.notices.push(Notice::Cell(id, Report::Removed));
            return Ok(());
        }
        self.deliver(id.0, Event::Request(Request::Remove))
    }

    #[must_use]
    pub fn phase(&self, id: CellId) -> Option<Phase> {
        self.slots
            .get(usize::from(id.0))
            .and_then(Option::as_ref)
            .map(|e| e.cell.phase)
    }

    /// Every notice so far, with the children the effects reaped outside any cell as
    /// orphans (spec §5.3: never dropped).
    pub fn take_notices(&mut self) -> Vec<Notice> {
        for (pid, status) in self.effects.take_reaped() {
            self.notices.push(Notice::Orphan { pid, status });
        }
        std::mem::take(&mut self.notices)
    }

    /// Feeds one loop result to the cell it concerns; results for no cell are ignored.
    ///
    /// # Errors
    ///
    /// [`Error::Sys`] when an effect failed.
    pub fn on_ready(&mut self, r: &Ready) -> Result<(), Error> {
        match *r {
            Ready::Signal(ORPHANS, _) => {
                for c in self.effects.reap_children()? {
                    match c {
                        Reaped::Main(slot, _, status) if self.has(slot) => {
                            self.main_exited(slot, status)?;
                        }
                        // A main whose cell is gone is an orphan like any other.
                        Reaped::Main(_, pid, status) | Reaped::Orphan(pid, status) => {
                            self.notices.push(Notice::Orphan { pid, status });
                        }
                    }
                }
            }
            Ready::Readable(t) | Ready::Hangup(t) => match route(t) {
                Some((slot, Source::Ready)) if self.has(slot) => self.on_ready_pipe(slot)?,
                Some((slot, Source::ExecError)) if self.has(slot) => self.on_exec(slot)?,
                // A handed-over main is watched without reaping: readable once it exits.
                Some((slot, Source::Main)) if self.has(slot) => {
                    self.effects.close(slot, Source::Main);
                    self.main_exited(slot, STATUS_UNKNOWN)?;
                }
                _ => {}
            },
            Ready::Priority(t) | Ready::Inotify(t, _) => {
                if let Some((slot, Source::Events)) = route(t)
                    && self.has(slot)
                {
                    let (populated, frozen) = self.effects.read_level(slot)?;
                    self.deliver(slot, Event::Level { populated, frozen })?;
                }
            }
            Ready::Exited(t, status) => {
                if let Some((slot, Source::Main)) = route(t)
                    && self.has(slot)
                {
                    self.main_exited(slot, status)?;
                }
            }
            Ready::Deadline(t) => {
                if let Some((slot, s)) = route(t)
                    && let Some(timer) = source_timer(s)
                    && self.has(slot)
                {
                    self.deliver(slot, Event::Deadline(timer))?;
                }
            }
            Ready::Signal(..) => {}
        }
        Ok(())
    }

    fn on_ready_pipe(&mut self, slot: u16) -> Result<(), Error> {
        let mut buf = [0u8; 256];
        let n = self.effects.read_ready(slot, &mut buf)?;
        if n == 0 {
            // Both pipes close on exec failure; epoll may report readiness EOF first.
            self.on_exec(slot)?;
            if !self.has(slot) {
                return Ok(());
            }
            self.effects.close(slot, Source::Ready);
            if self.entry(slot)?.cell.phase == Phase::Starting && self.entry(slot)?.ready.at_eof() {
                self.deliver(slot, Event::ReadyClosed)?;
            }
        } else if self.entry(slot)?.ready.push(&buf[..n]) {
            self.deliver(slot, Event::ReadyLine)?;
        }
        Ok(())
    }

    /// The main process exited. The loop reports exits first in a batch, so a quick child's
    /// exit can come before its exec result: that is settled first (the child is gone, so its
    /// end of the exec pipe is closed and the read cannot block), and the machine sees
    /// `Spawned` or `SpawnFailed` before the exit, never an exit it would drop.
    fn main_exited(&mut self, slot: u16, status: i32) -> Result<(), Error> {
        self.on_exec(slot)?;
        if self.has(slot) {
            self.deliver(slot, Event::MainExited(status))?;
        }
        Ok(())
    }

    /// Settles an outstanding exec result; nothing once it is settled (a later report of the
    /// closed pipe in the same batch).
    fn on_exec(&mut self, slot: u16) -> Result<(), Error> {
        let Some(h) = self.entry(slot)?.pending_main.take() else {
            return Ok(());
        };
        let failed = self.effects.read_exec_error(slot)?;
        self.effects.close(slot, Source::ExecError);
        match failed {
            None => self.spawned(slot, h),
            Some(_) => self.deliver(slot, Event::SpawnFailed),
        }
    }

    /// Delivers a confirmed exec. A result that arrives after the cell failed (or while it is
    /// removed) records a live main nothing will act on: its pidfd is released at once, and
    /// the process is still reaped (`Effects::close`).
    fn spawned(&mut self, slot: u16, h: Handle) -> Result<(), Error> {
        self.deliver(slot, Event::Spawned(h))?;
        let Some(e) = self.slots.get(usize::from(slot)).and_then(Option::as_ref) else {
            return Ok(());
        };
        if matches!(e.cell.phase, Phase::Removing | Phase::Failed(_))
            && e.cell.main == Main::Live(h)
        {
            self.effects.close(slot, Source::Main);
        }
        Ok(())
    }

    /// Steps the cell with `first` and every event its actions produce at once.
    fn deliver(&mut self, slot: u16, first: Event) -> Result<(), Error> {
        let mut queue = VecDeque::from([first]);
        let mut release = false;
        while let Some(e) = queue.pop_front() {
            let entry = self.entry(slot)?;
            let (next, acts) = step(entry.cell, e);
            entry.cell = next;
            // An effect that fails returns its error at once: the step's later actions are not
            // carried out, and the machine keeps the state it stepped to.
            for a in acts.items().into_iter().flatten() {
                queue.extend(self.act(slot, a, &mut release)?);
            }
        }
        if release {
            self.free(slot);
        }
        Ok(())
    }

    /// Carries out one action; the events it produces at once.
    fn act(&mut self, slot: u16, a: Action, release: &mut bool) -> Result<Vec<Event>, Error> {
        let id = CellId(slot);
        Ok(match a {
            Action::CreateDir => {
                let name = self.entry(slot)?.name.clone();
                // A directory whose level cannot be read is a failed create: the caller can
                // still remove it.
                match self
                    .effects
                    .create(slot, &name)
                    .and_then(|()| self.effects.read_level(slot))
                {
                    Ok((populated, frozen)) => {
                        vec![Event::Created, Event::Level { populated, frozen }]
                    }
                    Err(_) => vec![Event::CreateFailed],
                }
            }
            Action::Spawn => {
                let e = self.entry(slot)?;
                let (cmd, mode) = (e.command.take(), e.mode);
                match cmd.map(|c| self.effects.spawn(slot, c, mode)) {
                    Some(Ok(h)) => {
                        self.entry(slot)?.pending_main = Some(h);
                        Vec::new()
                    }
                    Some(Err(_)) | None => vec![Event::SpawnFailed],
                }
            }
            Action::CheckAdopt => {
                let e = self.entry(slot)?;
                let (name, expected) = (e.name.clone(), e.expected_id);
                // A cell that cannot be opened counts as a mismatch: it is not the one recorded.
                match self.effects.open_existing(slot, &name) {
                    Ok((cg, populated)) => vec![Event::AdoptChecked {
                        id_matches: cg == expected,
                        populated,
                    }],
                    Err(_) => vec![Event::AdoptChecked {
                        id_matches: false,
                        populated: false,
                    }],
                }
            }
            Action::Arm(t, ms) => {
                self.effects.arm(slot, t, ms)?;
                Vec::new()
            }
            Action::Cancel(t) => {
                self.effects.cancel(slot, t)?;
                Vec::new()
            }
            Action::SignalMain(h, sig) => {
                self.effects.signal_main(slot, h, sig)?;
                Vec::new()
            }
            Action::Freeze => {
                self.effects.freeze(slot, true)?;
                Vec::new()
            }
            Action::Thaw => {
                self.effects.freeze(slot, false)?;
                Vec::new()
            }
            Action::SignalMembers(sig) => {
                self.effects.signal_members(slot, sig)?;
                vec![Event::Signalled]
            }
            Action::Kill => {
                self.effects.kill(slot)?;
                Vec::new()
            }
            Action::RemoveDir => {
                let name = self.entry(slot)?.name.clone();
                match self.effects.remove(slot, &name) {
                    Ok(()) | Err(Errno(libc::ENOENT)) => vec![Event::Removed],
                    Err(_) => vec![Event::RemoveFailed],
                }
            }
            Action::Report(r) => {
                self.notices.push(Notice::Cell(id, r));
                if r == Report::Removed {
                    *release = true;
                }
                Vec::new()
            }
        })
    }
}
