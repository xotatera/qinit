// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The loop: one `qinit-event` loop for the control socket, the cells, the timers, the paths and
//! the signals. Each wake-up reads the clock once and handles every ready source with it; every
//! outcome colony returns goes to the server (replies), to syslog (notices and errors) and, when a
//! refresh swapped the database or a shutdown completed, to the work that follows. See
//! `docs/colony.md`.
use crate::args::Args;
use crate::deadlines::Key;
use crate::effects::{CellOps, Heard, PathEvent, RealEffects, WatchLoss, status_owner};
use crate::exit;
use crate::notes::describe;
use crate::readopt::{self, Plan, Procs, RealProcs};
use crate::route::Owner;
use crate::state::{
    CellLine, NodeLine, PipeLine, format_cells, format_nodes, parse_cells, parse_nodes,
};
use crate::store::{KEY_CELLS, KEY_DB, KEY_NODES, Store};
use crate::syslog::{Sev, Syslog};
use qinit_cell::{CellId, Report as CellReport};
use qinit_colony::{
    Colony, Error, Notice, Outcome, Report, Request, Restored, ShutdownMode, TimerKind, WaitId,
};
use qinit_event::{Loop, Ready, Token};
use qinit_ipc::{accept, listen_seqpacket};
use qinit_proto::{ConnId, Limits, Server};
use qinit_queen_core::ToColony;
use std::collections::BTreeSet;
use std::ffi::CString;
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::time::Duration;

/// The control listener's token; connections use their own id (from 1).
const LISTENER: Token = 0;
/// How long the listener stays out of the loop after it could not accept.
pub const LISTENER_RETRY_MS: u64 = 100;
/// First token above every connection id.
const BASE: Token = 1 << 40;
/// The cell layer's own epoll descriptor.
const CELLS: Token = BASE;
/// The one timer.
const TIMER: Token = BASE | 1;
/// The signalfd.
const SIGNALS: Token = BASE | 2;
/// The path watcher's inotify set.
const INOTIFY: Token = BASE | 3;
/// The channel to queen.
const QUEEN: Token = BASE | 4;

/// How long a handed-over main's status is waited for after it exited.
pub const STATUS_WAIT_MS: u64 = 1_000;

/// How long a leftover cell is given to stop before it is killed.
const CLEAR_GRACE: Duration = Duration::from_secs(5);

/// Where colony's own messages go when syslog is not there: the kernel log.
pub const KMSG: &str = "/dev/kmsg";

/// Whether the cgroup `own` (as `/proc/self/cgroup` names it, such as `/18/session`) is the
/// directory `comb` or below it. A comb outside `/sys/fs/cgroup` cannot be compared and is not
/// reported as containing us.
#[must_use]
pub fn inside_comb(own: &str, comb: &Path) -> bool {
    let Ok(rel) = comb.strip_prefix("/sys/fs/cgroup") else {
        return false;
    };
    Path::new(own.trim_start_matches('/')).starts_with(rel)
}

/// The monotonic clock in milliseconds.
fn now_ms() -> u64 {
    qinit_sys::timer::now_monotonic_ns() / 1_000_000
}

/// Queen's name for a mode, as colony's.
fn shutdown_mode(m: qinit_queen_core::Mode) -> ShutdownMode {
    match m {
        qinit_queen_core::Mode::Halt => ShutdownMode::Halt,
        qinit_queen_core::Mode::Poweroff => ShutdownMode::Poweroff,
        qinit_queen_core::Mode::Reboot => ShutdownMode::Reboot,
    }
}

/// The exit status a completed shutdown ends in.
fn exit_of(mode: Option<ShutdownMode>) -> u8 {
    match mode {
        Some(ShutdownMode::Poweroff) => exit::POWEROFF,
        Some(ShutdownMode::Reboot) => exit::REBOOT,
        Some(ShutdownMode::Halt) | None => exit::HALT,
    }
}

/// The running daemon.
pub struct Daemon<C: CellOps> {
    pub colony: Colony<RealEffects<C>>,
    server: Server,
    listener: OwnedFd,
    log: Syslog,
    socket: std::path::PathBuf,
    /// The text last saved under each state key.
    last_nodes: Option<String>,
    last_cells: Option<String>,
    cells_dirty: bool,
    now_ms: u64,
    /// The exit status once the daemon is done; `shutdown_done` says whether the graph is down.
    exit: Option<u8>,
    shutdown_done: bool,
    /// The status a completed shutdown ends in, held until the cells it left are gone.
    exit_after: Option<u8>,
    /// Outcomes whose replies are not yet delivered (see [`Daemon::settle`]).
    owed: Vec<Outcome>,
    /// Cells whose handed-over main exited and whose status is awaited.
    status_pending: BTreeSet<CellId>,
}

impl<C: CellOps> Daemon<C> {
    /// Brings the daemon up over `cells`, as [`Daemon::boot_with`] does with the real process
    /// table.
    ///
    /// # Errors
    ///
    /// As [`Daemon::boot_with`].
    pub fn boot(
        cells: C,
        args: &Args,
        bytes: &[u8],
        store: Store,
        log: Syslog,
    ) -> Result<Daemon<C>, u8> {
        Self::boot_with(cells, args, bytes, store, log, &RealProcs)
    }

    /// Brings the daemon up over `cells`: the loop and its sources, the logger pipes, the
    /// database, whatever an earlier colony left in the comb (adopted from the descriptors queen
    /// held, spec §8), the control socket and the saved state. `bytes` is the database of
    /// `--db`; the copy queen held, if it loads, takes its place. Refusals are returned as the
    /// exit status and logged.
    ///
    /// # Errors
    ///
    /// `exit::DATABASE` for a database the validator refuses, `exit::STARTUP` for anything else
    /// that stops it from serving.
    #[allow(clippy::too_many_lines)] // one start-up sequence, in the order the spec gives it
    pub fn boot_with(
        cells: C,
        args: &Args,
        bytes: &[u8],
        mut store: Store,
        mut log: Syslog,
        procs: &impl Procs,
    ) -> Result<Daemon<C>, u8> {
        // What the earlier colony left in queen's store: an entry that does not parse is as
        // good as none.
        let text = |store: &mut Store, key: u64| {
            store
                .load(key)
                .map(|b| String::from_utf8(b).map_err(|_| "not text".to_owned()))
        };
        let left = match text(&mut store, KEY_CELLS).map(|t| t.and_then(|t| parse_cells(&t))) {
            Some(Ok(lines)) => Some(lines),
            Some(Err(why)) => {
                log.log(Sev::Err, &format!("the saved cell map is refused: {why}"));
                None
            }
            None => None,
        };
        let saved_db = store.load(KEY_DB).filter(|b| qinit_db::open(b).is_ok());
        let from_state = saved_db.is_some();
        let chosen = saved_db.unwrap_or_else(|| bytes.to_vec());
        if left.is_some() && !from_state {
            log.log(
                Sev::Err,
                "no usable saved database copy: starting from --db, saved node state ignored",
            );
        }
        let refuse = |log: &mut Syslog, code: u8, why: String| {
            log.log(Sev::Err, &why);
            eprintln!("colony: {why}");
            code
        };
        let model = match qinit_db::open(&chosen) {
            Ok(db) => db.decode(),
            Err(e) => {
                return Err(refuse(
                    &mut log,
                    exit::DATABASE,
                    format!("the database is refused: {e:?}"),
                ));
            }
        };
        let mut events =
            Loop::new().map_err(|e| refuse(&mut log, exit::STARTUP, format!("loop: {e}")))?;
        let signals = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP];
        events
            .add_signal(&signals, SIGNALS)
            .and_then(|()| events.add_timer(TIMER))
            .map_err(|e| refuse(&mut log, exit::STARTUP, format!("loop: {e}")))?;
        if let Some(fd) = cells.poll_fd() {
            events
                .add_fd(fd, CELLS)
                .map_err(|e| refuse(&mut log, exit::STARTUP, format!("loop: {e}")))?;
        }
        let mut effects = RealEffects::new(
            cells,
            args.overseer.clone(),
            args.comb.clone(),
            events,
            INOTIFY,
        )
        .map_err(|e| refuse(&mut log, exit::STARTUP, format!("path watcher: {e}")))?;
        effects.store = store;
        if let Some(link) = effects.store.link() {
            // Queen reaps a handed-over main's parent's orphans: its status is awaited.
            effects
                .events
                .add_fd(link, QUEEN)
                .map_err(|e| refuse(&mut log, exit::STARTUP, format!("loop: {e}")))?;
            effects.cells.wait_for_status();
        }
        // The node state and the logger pipes the earlier colony left, if its database is the
        // one in force.
        let (saved_nodes, saved_pipes) = if from_state {
            match text(&mut effects.store, KEY_NODES).map(|t| t.and_then(|t| parse_nodes(&t))) {
                Some(Ok((nodes, pipes))) => (Some(nodes), pipes),
                Some(Err(why)) => {
                    log.log(Sev::Err, &format!("the saved node state is refused: {why}"));
                    (None, Vec::new())
                }
                None => (None, Vec::new()),
            }
        } else {
            (None, Vec::new())
        };
        let mut seeded = Vec::new();
        for p in &saved_pipes {
            let ends = (effects.store.take(p.read), effects.store.take(p.write));
            if let (Some(r), Some(w)) = ends {
                effects.pipes.seed(&p.logger, r, w);
                seeded.push(p.clone());
            } else {
                effects.retire(p.read);
                effects.retire(p.write);
            }
        }
        // Before the first start: a producer needs its logger's pipe.
        effects
            .pipes
            .rebuild(&model)
            .map_err(|e| refuse(&mut log, exit::STARTUP, format!("logger pipes: {e}")))?;
        let mut held_pipes = BTreeSet::new();
        for p in seeded {
            if effects.pipes.entries().any(|(n, _, _)| n == p.logger) {
                effects.adopt_pipe(&p.logger, (p.read, p.write));
                held_pipes.insert(p.logger);
            } else {
                effects.retire(p.read);
                effects.retire(p.write);
            }
        }
        // Before anything is started: a socket that cannot be had must not leave services
        // running that no colony tracks. Clients that connect meanwhile wait in its backlog.
        let listener = bind(&args.socket).map_err(|e| {
            refuse(
                &mut log,
                exit::STARTUP,
                format!("control socket {}: {e}", args.socket.display()),
            )
        })?;
        effects
            .events
            .add_fd(listener.as_fd(), LISTENER)
            .map_err(|e| refuse(&mut log, exit::STARTUP, format!("loop: {e}")))?;
        let now = now_ms();
        effects.now_ms = now;
        if effects.store.link().is_none() {
            // Without queen nothing is held to re-adopt a cell from: what an earlier colony left
            // in the comb stays, one line each.
            if let Ok(dir) = std::fs::read_dir(&args.comb) {
                let mut names: Vec<String> = dir
                    .flatten()
                    .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect();
                names.sort();
                for name in names {
                    log.log(
                        Sev::Info,
                        &format!(
                            "the cell {name} was found in the comb: left alone (without queen nothing is re-adopted)"
                        ),
                    );
                }
            }
        }

        let mut plan = Plan::default();
        let (colony, first) = if let Some(lines) = &left {
            plan = readopt::plan(
                lines,
                saved_nodes.as_deref(),
                &held_pipes,
                &model,
                &mut effects.store,
                &mut effects.cells,
                procs,
                now,
            );
            for (sev, text) in &plan.notes {
                log.log(*sev, text);
            }
            for a in &plan.adopted {
                effects.adopt_cell(a.id, a.owner, &a.name, (a.dir_key, a.main_key));
            }
            for key in &plan.dropped {
                effects.retire(*key);
            }
            for id in &plan.clear {
                if let Err(e) = effects.clear_cell(*id, CLEAR_GRACE) {
                    log.log(
                        Sev::Err,
                        &format!("cannot stop a leftover cell: errno {}", e.0),
                    );
                }
            }
            match Colony::<RealEffects<C>>::validate_restore(&chosen, &plan.restored, now) {
                Ok(()) => Colony::restore(chosen.clone(), &plan.restored, effects, now),
                Err(e) => {
                    // A state file from disk is input: one that breaks the scheduler's
                    // invariant is refused whole, and only the cells are adopted.
                    log.log(
                        Sev::Err,
                        &format!(
                            "the saved node state is refused ({e:?}): adopting the cells only"
                        ),
                    );
                    let initial: Vec<(u32, bool)> = plan
                        .restored
                        .iter()
                        .filter_map(|r| match r.phase {
                            Restored::Ready => Some((r.node, true)),
                            Restored::Starting => Some((r.node, false)),
                            _ => None,
                        })
                        .collect();
                    Colony::load(chosen.clone(), &initial, effects, now)
                }
            }
        } else {
            Colony::load(chosen.clone(), &[], effects, now)
        }
        .map_err(|e| {
            refuse(
                &mut log,
                exit::DATABASE,
                format!("the database is refused: {e:?}"),
            )
        })?;

        let mut d = Daemon {
            colony,
            server: Server::new(Limits::default()),
            listener,
            log,
            socket: args.socket.clone(),
            last_nodes: None,
            last_cells: None,
            cells_dirty: true,
            now_ms: now,
            exit: None,
            shutdown_done: false,
            exit_after: None,
            owed: Vec::new(),
            status_pending: BTreeSet::new(),
        };
        d.colony.effects.ready = plan
            .restored
            .iter()
            .filter(|r| r.phase == Restored::Ready)
            .map(|r| Owner::Node(r.node))
            .collect();
        d.colony.effects.store.save(KEY_DB, &chosen);
        d.colony.effects.store.forget_unclaimed();
        d.say(
            Sev::Info,
            &format!(
                "started with {} nodes, {} cells adopted",
                d.colony.model().nodes.len(),
                plan.adopted.len()
            ),
        );
        d.settle(first, true);
        // The exits and restarts adoption calls for come after the table is restored and before
        // the notices the adoption held are delivered: an exit, then the empty cell it leaves.
        for (node, status) in &plan.exited {
            let out = d.colony.adopted_exit(*node, *status, now);
            d.settle(out, true);
        }
        for node in &plan.restart {
            let out = d.colony.request(*node, Request::Restart, now);
            d.settle(out, true);
        }
        if plan.next_instance > 1 {
            d.colony.seed_instance_ids(plan.next_instance);
        }
        d.after_wakeup();
        Ok(d)
    }

    fn say(&mut self, sev: Sev, text: &str) {
        self.log.log(sev, text);
    }

    /// The listener could not accept (`errno`). A connection that went away before it was
    /// accepted costs nothing; anything else (out of descriptors above all) would wake the loop
    /// again at once for as long as it lasts, so the listener leaves the loop and comes back
    /// after [`LISTENER_RETRY_MS`], with one error line.
    pub fn listener_failed(&mut self, errno: i32) {
        if matches!(
            errno,
            libc::EAGAIN | libc::EINTR | libc::ECONNABORTED | libc::EPROTO
        ) {
            return;
        }
        let why = std::io::Error::from_raw_os_error(errno);
        self.say(
            Sev::Err,
            &format!(
                "accept on the control socket failed ({why}): paused for {LISTENER_RETRY_MS} ms"
            ),
        );
        let _ = self.colony.effects.events.remove(LISTENER);
        self.colony.effects.deadlines.arm(
            crate::deadlines::Key::Listener,
            self.now_ms + LISTENER_RETRY_MS,
        );
    }

    /// Puts the paused listener back into the loop.
    fn resume_listener(&mut self) {
        if let Err(e) = self
            .colony
            .effects
            .events
            .add_fd(self.listener.as_fd(), LISTENER)
        {
            self.say(Sev::Err, &format!("loop: {e}"));
            self.exit = Some(exit::LOOP);
        }
    }

    /// Takes an accepted connection into the server and the loop.
    fn accept_conn(&mut self, fd: OwnedFd) {
        let admitted = self.server.accept(fd);
        self.admit(admitted);
    }

    /// As the daemon takes a connection, with the identity given instead of read from the socket.
    #[cfg(feature = "testing")]
    pub fn accept_as(&mut self, fd: OwnedFd, peer: qinit_colony::Peer) {
        let admitted = self.server.accept_as(fd, peer);
        self.admit(admitted);
    }

    fn admit(&mut self, admitted: Result<ConnId, qinit_proto::Full>) {
        if let Ok(id) = admitted
            && let Some(fd) = self.server.fd(id)
            && let Err(e) = self.colony.effects.events.add_fd(fd, id.0)
        {
            self.say(Sev::Err, &format!("loop: {e}"));
            self.server.close(id, &mut self.colony);
        }
    }

    /// Drops closed connections from the loop (their descriptors are closed already).
    fn forget(&mut self, closed: &[ConnId]) {
        for c in closed {
            let _ = self.colony.effects.events.remove(c.0);
        }
    }

    /// What an outcome of colony means for everyone: notices to syslog, errors to syslog, the work
    /// a swap or a completed shutdown calls for, and, when `deliver` (a request's own outcome has
    /// been delivered by the server already), the replies it owes parked waits and watchers.
    ///
    /// The replies are held until the end of the wake-up, after the log and the state files: a
    /// client that has seen a change can rely on its log line and on the saved state being there.
    fn settle(&mut self, out: Outcome, deliver: bool) {
        for e in &out.errors {
            self.say(Sev::Err, &describe_error(e));
        }
        for n in &out.notices {
            let view = match *n {
                Notice::Instance(id, _) | Notice::InstanceReady(id) => self.colony.instance(id),
                _ => None,
            };
            if let Some((sev, line)) = describe(self.colony.model(), view.as_ref(), n) {
                self.say(sev, &line);
            }
            match *n {
                Notice::Swapped => self.swapped(),
                Notice::Node(_, Report::ShutdownComplete { .. }) => {
                    // The graph is down. Instances are not part of it: their cells are waited
                    // for before the daemon leaves, so that it leaves an empty comb.
                    self.shutdown_done = true;
                    self.exit_after = Some(exit_of(self.colony.shutdown_mode()));
                }
                _ => {}
            }
        }
        if deliver {
            self.owed.push(out);
        }
    }

    /// A refresh finished: the database now in force is the one a restart must start from, and
    /// the logger pipes follow the new set of loggers.
    fn swapped(&mut self) {
        let db = self.colony.db().to_vec();
        self.colony.effects.store.save(KEY_DB, &db);
        let model = self.colony.model().clone();
        if let Err(e) = self.colony.effects.pipes.rebuild(&model) {
            self.say(Sev::Err, &format!("logger pipes after a refresh: {e}"));
        }
        self.cells_dirty = true;
    }

    /// Gives colony every cell report collected so far, until there are none: a report can
    /// make colony act, which can make the cells report.
    fn pump_cells(&mut self) {
        loop {
            let heard = match self.colony.effects.drain_notices() {
                Ok(h) => h,
                Err(e) => {
                    self.say(Sev::Err, &format!("cells: {e:?}"));
                    return;
                }
            };
            if heard.cells.is_empty()
                && heard.orphans.is_empty()
                && heard.strays.is_empty()
                && heard.status_pending.is_empty()
            {
                return;
            }
            self.on_heard(heard);
        }
    }

    /// A launch's status pipe is readable: a failure record is logged, end of file is a launch
    /// that reached its `execve`.
    fn on_status(&mut self, owner: Owner) {
        if let Some(f) = self.colony.effects.take_launch_record(owner) {
            let why = std::io::Error::from_raw_os_error(f.errno);
            self.say(
                Sev::Err,
                &format!("{}: launch failed at {}: {why}", f.name, f.step),
            );
        }
    }

    fn on_heard(&mut self, heard: Heard) {
        for id in heard.status_pending {
            self.status_pending.insert(id);
            self.colony
                .effects
                .deadlines
                .arm(Key::Status(id), self.now_ms + STATUS_WAIT_MS);
        }
        for (id, report) in heard.strays {
            match report {
                CellReport::Empty => self.colony.effects.remove_cleared(id),
                CellReport::Failed(why) => self.say(
                    Sev::Err,
                    &format!("a leftover cell could not be cleared: {why:?}"),
                ),
                _ => {}
            }
        }
        for (pid, status) in heard.orphans {
            self.say(
                Sev::Debug,
                &format!(
                    "orphan {pid} ({})",
                    crate::notes::status_words(Some(status))
                ),
            );
        }
        for (owner, report) in heard.cells {
            if let CellReport::Failed(_) = report {
                self.colony.effects.failed.insert(owner);
            }
            match report {
                CellReport::Ready => {
                    self.cells_dirty |= self.colony.effects.ready.insert(owner);
                }
                CellReport::MainExited(_)
                | CellReport::Empty
                | CellReport::NotReady
                | CellReport::Failed(_) => {
                    self.cells_dirty |= self.colony.effects.ready.remove(&owner);
                }
                _ => {}
            }
            if !matches!(report, CellReport::Created | CellReport::Running) {
                // Ready, gone or failed: what waited for its readiness is past caring.
                self.colony.effects.end_readiness_watch(owner);
            }
            let out = match owner {
                Owner::Node(n) => self.colony.on_cell(n, report, self.now_ms),
                Owner::Instance(slot) => self.colony.on_instance(slot, report, self.now_ms),
            };
            self.settle(out, true);
        }
    }

    fn on_timer(&mut self) {
        for key in self.colony.effects.deadlines.due(self.now_ms) {
            let out = match key {
                crate::deadlines::Key::Node(n, kind) => {
                    self.colony.on_deadline(n, kind, self.now_ms)
                }
                crate::deadlines::Key::Wait(w) => {
                    self.colony.on_wait_deadline(WaitId(w), self.now_ms)
                }
                crate::deadlines::Key::Listener => {
                    self.resume_listener();
                    continue;
                }
                crate::deadlines::Key::Status(id) => {
                    self.settle_status(id, true);
                    continue;
                }
            };
            self.settle(out, true);
        }
    }

    /// Asks the cell layer for the status of a pending main; a delivered one ends the wait.
    fn settle_status(&mut self, id: CellId, give_up: bool) {
        match self.colony.effects.cells.settle_status(id, give_up) {
            Ok(true) => {
                self.status_pending.remove(&id);
                self.colony.effects.deadlines.cancel(Key::Status(id));
            }
            Ok(false) => {}
            Err(e) => self.say(Sev::Err, &format!("a main's status: {e}")),
        }
    }

    /// Queen has something for colony: a reap (statuses may be readable now), a refusal, a
    /// request. A channel that fails is dropped, and colony serves on without queen.
    fn on_queen(&mut self) {
        loop {
            match self.colony.effects.store.next() {
                Ok(None) => return,
                Ok(Some(ToColony::Reaped)) => {
                    let pending: Vec<CellId> = self.status_pending.iter().copied().collect();
                    for id in pending {
                        self.settle_status(id, false);
                    }
                }
                Ok(Some(ToColony::Refused { key })) => self.say(
                    Sev::Err,
                    &format!("queen's store is full: the descriptor for key {key} was refused"),
                ),
                Ok(Some(ToColony::Request { mode })) => {
                    self.say(
                        Sev::Info,
                        &format!("queen asks for a shutdown ending in {mode:?}"),
                    );
                    let out = self
                        .colony
                        .request_shutdown(shutdown_mode(mode), self.now_ms);
                    self.settle(out, true);
                }
                Ok(Some(_)) => {}
                Err(why) => {
                    self.say(Sev::Err, &format!("{why}: state is no longer saved"));
                    let _ = self.colony.effects.events.remove(QUEEN);
                    self.colony.effects.store.detach();
                    return;
                }
            }
        }
    }

    fn on_signal(&mut self, signo: u32) {
        match i32::try_from(signo).unwrap_or(0) {
            libc::SIGTERM | libc::SIGINT => {
                self.say(Sev::Info, "shutting down on a signal");
                let out = self.colony.shutdown(self.now_ms);
                self.settle(out, true);
            }
            _ => self.say(
                Sev::Info,
                "SIGHUP ignored: a new database comes through a refresh",
            ),
        }
    }

    fn on_inotify(&mut self, evs: &[(i32, u32, std::ffi::OsString)]) {
        for ev in self.colony.effects.on_inotify(evs) {
            match ev {
                PathEvent::Path(p) => {
                    let out = self.colony.on_path(&p, self.now_ms);
                    self.settle(out, true);
                }
                PathEvent::Ready(owner) => self.mark_ready(owner),
            }
        }
    }

    /// What a node's readiness waited for has appeared: its cell is ready.
    fn mark_ready(&mut self, owner: Owner) {
        let Some(id) = self.colony.effects.routes.cell(owner) else {
            return;
        };
        // A cell that left `Starting` meanwhile (it exited, was stopped) refuses nothing and
        // reports nothing: the mark is simply late.
        let _ = self.colony.effects.cells.mark_ready(id);
    }

    fn on_ready(&mut self, r: Ready) {
        match r {
            Ready::Readable(LISTENER) => match accept(self.listener.as_fd()) {
                Ok(fd) => self.accept_conn(fd),
                Err(e) => self.listener_failed(e.0),
            },
            Ready::Readable(CELLS | TIMER) | Ready::Deadline(TIMER) => {
                // The cells are drained after every wake-up; the timer is checked below.
            }
            Ready::Readable(t) if t < BASE => {
                let served = self
                    .server
                    .on_readable(ConnId(t), &mut self.colony, self.now_ms);
                self.forget(&served.closed);
                self.settle(served.outcome, false);
            }
            Ready::Hangup(t) if t < BASE => {
                self.server.close(ConnId(t), &mut self.colony);
                self.forget(&[ConnId(t)]);
            }
            Ready::Readable(t) | Ready::Hangup(t) if status_owner(t).is_some() => {
                if let Some(owner) = status_owner(t) {
                    self.on_status(owner);
                }
            }
            Ready::Readable(QUEEN) | Ready::Hangup(QUEEN) => self.on_queen(),
            Ready::Signal(SIGNALS, signo) => self.on_signal(signo),
            Ready::InotifySet(INOTIFY, evs) => self.on_inotify(&evs),
            _ => {}
        }
    }

    /// What follows every wake-up: due deadlines, cell reports, state files, the timer.
    fn after_wakeup(&mut self) {
        self.on_timer();
        self.pump_cells();
        self.report_faults();
        self.persist();
        self.flush_replies();
        self.rearm();
    }

    /// What the effects could not return an error for (a removal that failed, a poll that did):
    /// logged as errors.
    fn report_faults(&mut self) {
        for fault in std::mem::take(&mut self.colony.effects.faults) {
            self.say(Sev::Err, &fault);
        }
        for (loss, why) in self.colony.effects.watch_faults() {
            let line = match loss {
                WatchLoss::Readiness(n) => {
                    let name = self
                        .colony
                        .model()
                        .nodes
                        .get(n as usize)
                        .map(|x| x.name.as_str());
                    format!(
                        "{}: readiness watch lost ({why}); the node ends on its start timeout",
                        name.unwrap_or("a node")
                    )
                }
                WatchLoss::Path(p) => format!("path watch for {p} lost ({why}): it is not seen"),
            };
            self.say(Sev::Err, &line);
        }
    }

    /// Saves the state whose content changed, in queen's store: the descriptors first (a state
    /// must never name a key queen does not hold), then the text that names them, then the
    /// forgetting of the keys the new text no longer names.
    fn persist(&mut self) {
        self.colony.effects.sync_store();
        let nodes: Vec<NodeLine> = self
            .colony
            .saved()
            .into_iter()
            .map(|(name, wanted, terminal, counters)| NodeLine {
                name,
                wanted,
                terminal,
                counters,
            })
            .collect();
        let pipes: Vec<PipeLine> = self.colony.effects.pipe_lines();
        let text = format_nodes(&nodes, &pipes);
        if self.last_nodes.as_ref() != Some(&text) {
            self.colony.effects.store.save(KEY_NODES, text.as_bytes());
            self.last_nodes = Some(text);
        }
        if self.cells_dirty || self.colony.effects.dirty {
            let lines: Vec<CellLine> = self.colony.effects.cell_lines();
            self.colony.effects.dirty = false;
            self.cells_dirty = false;
            let text = format_cells(&lines);
            if self.last_cells.as_ref() != Some(&text) {
                self.colony.effects.store.save(KEY_CELLS, text.as_bytes());
                self.last_cells = Some(text);
            }
        }
        self.colony.effects.forget_retired();
        while let Some(line) = self.colony.effects.store.warnings() {
            self.say(Sev::Err, &line);
        }
    }

    /// Sets the one timer to the earliest deadline.
    fn rearm(&mut self) {
        let after = self
            .colony
            .effects
            .deadlines
            .next()
            .map(|at| Duration::from_millis(at.saturating_sub(self.now_ms)));
        if let Err(e) = self.colony.effects.events.set_timer(TIMER, after) {
            self.say(Sev::Err, &format!("the timer refused: {e}"));
            self.exit = Some(exit::LOOP);
        }
    }

    /// Handles one wake-up's ready sources with one reading of the clock. `Some(code)` once the
    /// daemon is done.
    pub fn turn(&mut self, ready: Vec<Ready>) -> Option<u8> {
        self.now_ms = now_ms();
        self.colony.effects.now_ms = self.now_ms;
        for r in ready {
            self.on_ready(r);
        }
        self.after_wakeup();
        if self.exit.is_none()
            && let Some(code) = self.exit_after
            && self.cells_are_gone()
        {
            self.exit = Some(code);
        }
        self.exit
    }

    /// Delivers the replies held during this wake-up.
    fn flush_replies(&mut self) {
        for out in std::mem::take(&mut self.owed) {
            let closed = self.server.on_outcome(&out, &mut self.colony);
            self.forget(&closed);
        }
    }

    /// Whether every cell colony made is removed, bar the ones that failed (a cell the cell layer
    /// gave up on stays where it is, and the daemon cannot wait for it).
    fn cells_are_gone(&self) -> bool {
        let effects = &self.colony.effects;
        effects
            .routes
            .cells()
            .all(|(_, owner)| effects.failed.contains(&owner))
            && !effects.is_clearing()
    }

    /// Handles everything that is ready now, without waiting, until nothing is.
    pub fn pump(&mut self) -> Option<u8> {
        loop {
            let Ok(ready) = self.colony.effects.events.poll() else {
                return Some(exit::LOOP);
            };
            if ready.is_empty() {
                return self.exit;
            }
            if let Some(code) = self.turn(ready) {
                return Some(code);
            }
        }
    }

    /// Waits for the next wake-up and handles it.
    ///
    /// # Errors
    ///
    /// The loop's error.
    pub fn serve_once(&mut self) -> Result<Option<u8>, qinit_event::Error> {
        let ready = self.colony.effects.events.wait()?;
        Ok(self.turn(ready))
    }

    /// Ends the daemon with `code`. A completed shutdown leaves nothing behind: queen forgets
    /// what it held for colony, and the socket file goes. A loop failure leaves them, and the workers, for the next colony.
    pub fn finish(mut self, code: u8) -> u8 {
        if self.shutdown_done {
            self.colony.effects.store.clear();
            let _ = std::fs::remove_file(&self.socket);
        }
        code
    }

    /// Serves until the graph is down or the loop fails; the exit status.
    pub fn serve(mut self) -> u8 {
        loop {
            match self.serve_once() {
                Ok(Some(code)) => return self.finish(code),
                Ok(None) => {}
                Err(e) => {
                    self.say(Sev::Err, &format!("the loop failed: {e}"));
                    return self.finish(exit::LOOP);
                }
            }
        }
    }
}

fn describe_error(e: &Error) -> String {
    match e {
        Error::Effect(node, errno) => format!("effect for node {node} failed: errno {}", errno.0),
        other => format!("{other:?}"),
    }
}

/// Binds the control socket (mode 0666: authorization is the server's, not the file's), after
/// removing a stale file: the path belongs to colony.
fn bind(path: &Path) -> Result<OwnedFd, String> {
    let _ = std::fs::remove_file(path);
    let c = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|e| e.to_string())?;
    let fd = listen_seqpacket(&c, 128).map_err(|e| format!("errno {}", e.0))?;
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o666))
        .map_err(|e| e.to_string())?;
    Ok(fd)
}

/// The timer kinds, for callers that name them.
pub const START_TIMEOUT: TimerKind = TimerKind::StartTimeout;
