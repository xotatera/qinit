// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Queen's turn: one wake-up, one pass over the channel, the signals, the reap, the timer, and
//! the records owed to colony. [`Io`] is everything that touches the system, so the turn can be
//! driven by a fake. Nothing in a turn calls `exit`.
use crate::kmsg;
use crate::quiet::Quiet;
use qinit_queen_core::machine::{
    Action, Actions, Event, Input, Limits, State, initial, next_record, orphan_reaped, record_sent,
    step,
};
use qinit_queen_core::store::{CAPACITY, Entry, FREE};
use qinit_queen_core::{FromColony, Mode, decode_from_colony, encode_to_colony};
use qinit_sys::Errno;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};

/// Descriptor numbers queen can hold: `RLIMIT_NOFILE` is set to this.
pub const NOFILE: usize = 65_536;

/// What `Io::recv` found on colony's channel.
pub enum Recv {
    /// Nothing more until colony sends again.
    Empty,
    /// Colony's end is gone. Reported once; `recv` says `Empty` after.
    Closed,
    Message(Message),
}

/// One message from colony.
pub struct Message {
    pub bytes: [u8; 32],
    pub len: usize,
    pub fds: Vec<OwnedFd>,
    /// The message or its descriptors did not fit.
    pub truncated: bool,
}

/// What `Io::send` did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sent {
    Ok,
    /// The socket is full: wait for it to be writable.
    Again,
    /// There is no channel, or it is broken.
    Gone,
}

/// Everything queen's turn asks of the system.
pub trait Io {
    /// A monotonic reading, in milliseconds.
    fn now_ms(&mut self) -> u64;
    /// Starts colony with a fresh channel, dropping the old one. Returns its pid.
    ///
    /// # Errors
    /// The errno of the step that failed.
    fn spawn_colony(&mut self) -> Result<i32, Errno>;
    /// Starts the rescue program. Returns its pid.
    ///
    /// # Errors
    /// The errno of the step that failed.
    fn spawn_rescue(&mut self) -> Result<i32, Errno>;
    /// Execs zero in `mode`; returns only on failure, with the errno.
    fn exec_zero(&mut self, mode: Mode) -> Errno;
    fn kill(&mut self, pid: i32);
    fn cad_on(&mut self);
    /// Arms the timer for `ms` from now, or disarms it.
    fn arm(&mut self, ms: Option<u64>);
    fn log(&mut self, line: &[u8]);
    /// One reaped child, `None` when none is left.
    fn reap(&mut self) -> Option<(i32, i32)>;
    fn recv(&mut self) -> Recv;
    fn send(&mut self, record: &[u8; 16], fd: Option<BorrowedFd<'_>>) -> Sent;
    /// Asks for a wake-up when the channel can be written to (or stops asking).
    fn want_writable(&mut self, on: bool);
}

/// What woke queen.
pub struct Wake<'a> {
    /// Signal numbers read from the signalfd.
    pub signals: &'a [u32],
    pub channel: bool,
    pub timer: bool,
    pub writable: bool,
}

/// The owners of the descriptors the store names, by descriptor number. The machine's table
/// holds numbers; this holds the descriptors, so closing is a drop and sending borrows.
pub struct Descriptors {
    slots: Vec<Option<OwnedFd>>,
}

impl Descriptors {
    #[must_use]
    pub fn new() -> Descriptors {
        Descriptors {
            slots: std::iter::repeat_with(|| None).take(NOFILE).collect(),
        }
    }

    /// Takes ownership of `fd`; its number, or the descriptor back when no slot has that number.
    ///
    /// # Errors
    /// The descriptor itself, when its number is `NOFILE` or more.
    pub fn hold(&mut self, fd: OwnedFd) -> Result<i32, OwnedFd> {
        let n = fd.as_raw_fd();
        match usize::try_from(n).ok().and_then(|i| self.slots.get_mut(i)) {
            Some(slot) => {
                *slot = Some(fd);
                Ok(n)
            }
            None => Err(fd),
        }
    }

    /// Closes the descriptor with number `n`, if held.
    pub fn close(&mut self, n: i32) {
        if let Some(slot) = usize::try_from(n).ok().and_then(|i| self.slots.get_mut(i)) {
            *slot = None;
        }
    }

    #[must_use]
    pub fn get(&self, n: i32) -> Option<BorrowedFd<'_>> {
        let slot = self.slots.get(usize::try_from(n).ok()?)?;
        slot.as_ref().map(std::os::fd::AsFd::as_fd)
    }
}

impl Default for Descriptors {
    fn default() -> Descriptors {
        Descriptors::new()
    }
}

/// Queen: the machine, its table, the descriptors, and the system it acts on.
pub struct Queen<I: Io> {
    io: I,
    s: State,
    table: Vec<Entry>,
    desc: Descriptors,
    quiet: Quiet,
    lim: Limits,
}

impl<I: Io> Queen<I> {
    /// Starts the machine and performs its first actions: colony is spawned.
    pub fn new(io: I, lim: Limits) -> Queen<I> {
        let (s, a) = initial();
        let mut q = Queen {
            io,
            s,
            table: vec![FREE; CAPACITY],
            desc: Descriptors::new(),
            quiet: Quiet::new(),
            lim,
        };
        q.perform(&a);
        // Colony waits for the hand-over before it does anything: it must not wait for the
        // first wake-up to get it.
        q.send_pending();
        q
    }

    pub fn io(&mut self) -> &mut I {
        &mut self.io
    }

    #[must_use]
    pub fn state(&self) -> &State {
        &self.s
    }

    #[must_use]
    pub fn table(&self) -> &[Entry] {
        &self.table
    }

    #[must_use]
    pub fn descriptors(&self) -> &Descriptors {
        &self.desc
    }

    /// One wake-up. In this order: what colony queued, the signals, the reap, the timer, and
    /// then the records owed to colony. Records first, so a `Put` queued before a death is in
    /// the store before the reap restarts colony.
    ///
    /// # Panics
    /// With the `testing` feature, on `SIGUSR1`, on purpose.
    pub fn turn(&mut self, ready: &Wake<'_>) {
        self.read_channel();
        let mut sigchld = false;
        for &signo in ready.signals {
            match i32::try_from(signo).unwrap_or(0) {
                libc::SIGCHLD => sigchld = true,
                libc::SIGINT => self.feed(Input::Cad),
                libc::SIGPWR => self.feed(Input::Pwr),
                #[cfg(feature = "testing")]
                libc::SIGUSR1 => panic!("queen test panic"),
                #[cfg(feature = "testing")]
                libc::SIGUSR2 => {
                    let _ = qinit_sys::proc::kill_thread_self(libc::SIGSEGV);
                }
                _ => {
                    let now = self.io.now_ms();
                    if self.quiet.log(signo, now) {
                        let mut buf = [0u8; 128];
                        let n = kmsg::format_signal(signo, &mut buf);
                        self.io.log(&buf[..n]);
                    }
                }
            }
        }
        if sigchld {
            self.reap_all();
        }
        if ready.timer {
            self.feed(Input::Timer);
        }
        self.send_pending();
    }

    /// Everything colony has queued, one input each.
    fn read_channel(&mut self) {
        loop {
            match self.io.recv() {
                Recv::Empty => return,
                Recv::Closed => {
                    self.feed(Input::ChannelClosed);
                    return;
                }
                Recv::Message(m) => {
                    let input = self.decode(m);
                    self.feed(input);
                }
            }
        }
    }

    /// A message as an input: a record, or `ChannelBad` with its descriptors closed.
    fn decode(&mut self, mut m: Message) -> Input {
        if m.truncated || m.len > m.bytes.len() {
            return Input::ChannelBad;
        }
        match decode_from_colony(&m.bytes[..m.len], m.fds.len()) {
            None => Input::ChannelBad,
            Some(r @ FromColony::Put { .. }) => match m.fds.pop().map(|f| self.desc.hold(f)) {
                Some(Ok(n)) => Input::Record(r, n),
                _ => Input::ChannelBad,
            },
            Some(r) => Input::Record(r, -1),
        }
    }

    /// Reaps until nothing is left (a coalesced `SIGCHLD` stands for any number of exits).
    fn reap_all(&mut self) {
        let (mut orphans, mut last) = (0u32, 0i32);
        while let Some((pid, status)) = self.io.reap() {
            let colony = pid != 0 && pid == self.s.colony;
            if colony {
                // Whatever the dying colony queued last is in the store before it restarts.
                self.read_channel();
            }
            let rescue = pid != 0 && pid == self.s.rescue;
            if !(colony || rescue) {
                orphan_reaped(&mut self.s);
                orphans += 1;
                last = pid;
            }
            self.feed(Input::Child { pid, status });
        }
        if orphans > 0 {
            let mut buf = [0u8; 128];
            let n = kmsg::format_orphans(orphans, last, &mut buf);
            self.io.log(&buf[..n]);
        }
    }

    /// Sends colony what it is owed until the socket is full.
    fn send_pending(&mut self) {
        loop {
            let Some((rec, fd)) = next_record(&self.s, &self.table) else {
                self.io.want_writable(false);
                return;
            };
            let bytes = encode_to_colony(rec);
            let held = if fd >= 0 { self.desc.get(fd) } else { None };
            if fd >= 0 && held.is_none() {
                // The store names a descriptor queen does not hold: nothing to send.
                record_sent(&mut self.s, &self.table);
                continue;
            }
            match self.io.send(&bytes, held) {
                Sent::Ok => record_sent(&mut self.s, &self.table),
                Sent::Again => {
                    self.io.want_writable(true);
                    return;
                }
                Sent::Gone => return,
            }
        }
    }

    /// Steps the machine and performs what it asks.
    fn feed(&mut self, input: Input) {
        let now = self.io.now_ms();
        let a = step(&mut self.s, &mut self.table, &self.lim, input, now);
        self.perform(&a);
    }

    fn perform(&mut self, a: &Actions) {
        for i in 0..a.len {
            let Some(action) = a.get(i) else { return };
            match action {
                Action::SpawnColony => match self.io.spawn_colony() {
                    Ok(pid) => self.feed(Input::ColonySpawned(pid)),
                    Err(_) => self.feed(Input::ColonySpawnFailed),
                },
                Action::SpawnRescue => match self.io.spawn_rescue() {
                    Ok(pid) => self.feed(Input::RescueSpawned(pid)),
                    Err(_) => self.feed(Input::RescueSpawnFailed),
                },
                Action::Kill(pid) => self.io.kill(pid),
                Action::ArmTimer(ms) => self.io.arm(Some(ms)),
                Action::CancelTimer => self.io.arm(None),
                Action::ExecZero(mode) => {
                    let _ = self.io.exec_zero(mode);
                    self.feed(Input::ExecFailed);
                    return;
                }
                Action::CadOn => self.io.cad_on(),
                Action::Close(n) => self.desc.close(n),
                Action::Log(ev) => self.log(&ev),
            }
        }
    }

    fn log(&mut self, ev: &Event) {
        let mut buf = [0u8; 128];
        let n = kmsg::format(ev, &mut buf);
        self.io.log(&buf[..n]);
    }
}
