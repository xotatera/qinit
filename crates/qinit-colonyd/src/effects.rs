// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The real [`qinit_colony::Effects`]: cells under the comb, their limits, the overseer that
//! launches each service, the deadline queue and the path watcher. See `docs/colony.md`.
//!
//! The launch of a node, in order: the request is built and sealed (nothing to undo yet); the
//! cell is created; limits are written; the readiness watch is set; the overseer is spawned into
//! the cell with the request at fd 3, the status pipe's write end at fd 4 and the readiness
//! pipe's at fd 5. Any failure after the cell exists removes it again.
use crate::deadlines::{Deadlines, Key};
use crate::route::{Owner, Routes};
use crate::watch::{Want, Watcher};
use qinit_cell::effects::Command;
use qinit_cell::{CellId, Error as CellError, Notice, Phase, Polite, ReadyMode, Report};
use qinit_colony::{Effects, Errno, InstanceSpec, NodeSpec, StopMode, TimerKind};
use qinit_db::{Model, Ready};
use qinit_event::{Loop, Token};
use qinit_overseer::request::{RequestSpec, Routed, from_instance, from_model};
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::os::fd::{OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Where the launch request arrives in the overseer.
pub const REQUEST_FD: RawFd = 3;
/// Where the failure record's write end arrives.
pub const STATUS_FD: RawFd = 4;
/// Where the readiness pipe's write end arrives.
pub const READY_FD: RawFd = 5;

/// A watcher id for the readiness of node `n`.
const READY_TAG: u64 = 1 << 32;
/// A watcher id for a dependency path.
const PATH_TAG: u64 = 2 << 32;

/// The calls on the cell layer the effects make: [`qinit_cell::Cells`] in the daemon, a fake in
/// the host tests.
#[allow(clippy::missing_errors_doc)] // each call's error is the one of the `Cells` call it names
pub trait CellOps {
    fn create(&mut self, name: &str) -> Result<CellId, CellError>;
    fn set_limits(
        &mut self,
        id: CellId,
        memory_max_bytes: u64,
        pids_max: u32,
    ) -> Result<(), CellError>;
    fn spawn(&mut self, id: CellId, cmd: Command, ready: ReadyMode) -> Result<(), CellError>;
    fn phase(&self, id: CellId) -> Option<Phase>;
    fn stop(
        &mut self,
        id: CellId,
        polite: Polite,
        grace: Duration,
        kill: Duration,
    ) -> Result<(), CellError>;
    fn remove(&mut self, id: CellId) -> Result<(), CellError>;
    fn mark_ready(&mut self, id: CellId) -> Result<(), CellError>;
    fn signal_main(&mut self, id: CellId, sig: i32) -> Result<(), CellError>;
    fn main_pidfd(&mut self, id: CellId) -> Result<OwnedFd, CellError>;
    fn main_pid(&self, id: CellId) -> Option<libc::pid_t>;
    fn cgroup_id(&self, id: CellId) -> Option<u64>;
    fn adopt(
        &mut self,
        name: &str,
        expected_id: u64,
        main: Option<OwnedFd>,
    ) -> Result<CellId, CellError>;
    fn poll(&mut self) -> Result<Vec<Notice>, CellError>;
}

impl CellOps for qinit_cell::Cells {
    fn create(&mut self, name: &str) -> Result<CellId, CellError> {
        qinit_cell::Cells::create(self, name)
    }
    fn set_limits(&mut self, id: CellId, memory: u64, pids: u32) -> Result<(), CellError> {
        qinit_cell::Cells::set_limits(self, id, memory, pids)
    }
    fn spawn(&mut self, id: CellId, cmd: Command, ready: ReadyMode) -> Result<(), CellError> {
        qinit_cell::Cells::spawn(self, id, cmd, ready)
    }
    fn phase(&self, id: CellId) -> Option<Phase> {
        qinit_cell::Cells::phase(self, id)
    }
    fn stop(
        &mut self,
        id: CellId,
        polite: Polite,
        grace: Duration,
        kill: Duration,
    ) -> Result<(), CellError> {
        qinit_cell::Cells::stop(self, id, polite, grace, kill)
    }
    fn remove(&mut self, id: CellId) -> Result<(), CellError> {
        qinit_cell::Cells::remove(self, id)
    }
    fn mark_ready(&mut self, id: CellId) -> Result<(), CellError> {
        qinit_cell::Cells::mark_ready(self, id)
    }
    fn signal_main(&mut self, id: CellId, sig: i32) -> Result<(), CellError> {
        qinit_cell::Cells::signal_main(self, id, sig)
    }
    fn main_pidfd(&mut self, id: CellId) -> Result<OwnedFd, CellError> {
        qinit_cell::Cells::main_pidfd(self, id)
    }
    fn main_pid(&self, id: CellId) -> Option<libc::pid_t> {
        qinit_cell::Cells::main_pid(self, id)
    }
    fn cgroup_id(&self, id: CellId) -> Option<u64> {
        qinit_cell::Cells::cgroup_id(self, id)
    }
    fn adopt(
        &mut self,
        name: &str,
        expected_id: u64,
        main: Option<OwnedFd>,
    ) -> Result<CellId, CellError> {
        qinit_cell::Cells::adopt(self, name, expected_id, main)
    }
    fn poll(&mut self) -> Result<Vec<Notice>, CellError> {
        qinit_cell::Cells::poll(self)
    }
}

/// What a path watch found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathEvent {
    /// A dependency path appeared.
    Path(String),
    /// What a node's readiness waits for appeared.
    Ready(Owner),
}

/// The cell notices collected so far, already routed to their owners.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Heard {
    pub cells: Vec<(Owner, Report)>,
    /// `(pid, wait status)` of children nobody tracks.
    pub orphans: Vec<(libc::pid_t, i32)>,
}

/// The seconds `deadline_ms` of a launch request: the start timeout capped at 30 s, 30 s when the
/// start timeout is none.
#[must_use]
pub fn deadline_ms(start_timeout_ms: u32) -> u32 {
    const CAP: u32 = 30_000;
    if start_timeout_ms == 0 {
        CAP
    } else {
        start_timeout_ms.min(CAP)
    }
}

fn errno_of(e: &CellError) -> Errno {
    Errno(match e {
        CellError::Sys(q) => q.0,
        CellError::Full => libc::ENOSPC,
        CellError::BadName(_) => libc::EINVAL,
        CellError::NoSuchCell(_) => libc::ENOENT,
        CellError::Floor(_) => libc::ENOSYS,
    })
}

fn sys(e: qinit_sys::Errno) -> Errno {
    Errno(e.0)
}

/// The effects colony runs on.
pub struct RealEffects<C: CellOps> {
    pub cells: C,
    pub routes: Routes,
    pub deadlines: Deadlines,
    pub watcher: Watcher,
    /// The daemon's event loop: the watcher's inotify set lives in it.
    pub events: Loop,
    /// The read end of each launch's status pipe, until the launch ends.
    pub status: HashMap<Owner, OwnedFd>,
    /// The cell map changed: the state files need rewriting.
    pub dirty: bool,
    /// The loop's clock, `CLOCK_MONOTONIC` milliseconds, as of this wake-up.
    pub now_ms: u64,
    /// Things that went wrong in calls that cannot return an error (`release`), for the log.
    pub faults: Vec<String>,
    overseer: PathBuf,
    comb: PathBuf,
    /// Notices collected out of turn (while a failed cell was being cleaned up), routed.
    inbox: Heard,
    path_ids: BTreeMap<String, u64>,
    path_names: BTreeMap<u64, String>,
}

impl<C: CellOps> RealEffects<C> {
    /// Effects over `cells`, launching through `overseer`, with cell directories under `comb`.
    /// The path watcher is registered in `events` under `inotify_token`.
    ///
    /// # Errors
    ///
    /// The errno of creating the inotify set.
    pub fn new(
        cells: C,
        overseer: PathBuf,
        comb: PathBuf,
        mut events: Loop,
        inotify_token: Token,
    ) -> Result<Self, qinit_sys::Errno> {
        let watcher = Watcher::new(&mut events, inotify_token)?;
        Ok(RealEffects {
            cells,
            routes: Routes::default(),
            deadlines: Deadlines::default(),
            watcher,
            events,
            status: HashMap::new(),
            dirty: false,
            now_ms: 0,
            faults: Vec::new(),
            overseer,
            comb,
            inbox: Heard::default(),
            path_ids: BTreeMap::new(),
            path_names: BTreeMap::new(),
        })
    }

    /// Routes `notices` to their owners as of now and adds them to the inbox.
    fn collect(&mut self, notices: Vec<Notice>) {
        for n in notices {
            match n {
                Notice::Cell(id, report) => {
                    if let Some(owner) = self.routes.owner(id) {
                        self.inbox.cells.push((owner, report));
                    }
                }
                Notice::Orphan { pid, status } => self.inbox.orphans.push((pid, status)),
            }
        }
    }

    /// One non-blocking round of the cells, then everything collected: notices already routed
    /// to their owners, orphans apart.
    ///
    /// # Errors
    ///
    /// The cell layer's error from the round.
    pub fn drain_notices(&mut self) -> Result<Heard, Errno> {
        let notices = self.cells.poll().map_err(|e| errno_of(&e))?;
        self.collect(notices);
        Ok(std::mem::take(&mut self.inbox))
    }

    /// What the events of the inotify set mean: dependency paths that appeared and readiness
    /// watches that were satisfied. Each readiness watch ends with its report.
    pub fn on_inotify(&mut self, evs: &[(i32, u32, OsString)]) -> Vec<PathEvent> {
        let ids = self.watcher.on_events(&mut self.events, evs);
        let mut out = Vec::new();
        for id in ids {
            match id & !0xFFFF_FFFF {
                READY_TAG => {
                    let node = u32::try_from(id & 0xFFFF_FFFF).unwrap_or(u32::MAX);
                    out.push(PathEvent::Ready(Owner::Node(node)));
                }
                PATH_TAG => {
                    if let Some(path) = self.path_names.get(&id) {
                        out.push(PathEvent::Path(path.clone()));
                    }
                }
                _ => {}
            }
        }
        out
    }

    /// Reads whatever the inotify set has ready now (not blocking) and says what it means. For
    /// hosts that do not run the daemon's loop.
    ///
    /// # Errors
    ///
    /// The errno of the loop.
    pub fn take_path_events(&mut self) -> Result<Vec<PathEvent>, Errno> {
        let mut out = Vec::new();
        loop {
            let batch = self.events.poll().map_err(|e| match e {
                qinit_event::Error::Sys { errno, .. } => sys(errno),
                _ => Errno(libc::EINVAL),
            })?;
            if batch.is_empty() {
                return Ok(out);
            }
            for r in batch {
                if let qinit_event::Ready::InotifySet(t, evs) = r
                    && t == self.watcher.token()
                {
                    out.extend(self.on_inotify(&evs));
                }
            }
        }
    }

    /// Removes a cell that must not live on and settles its notices now, while its slot still
    /// means it: a later cell in the same slot must not hear them.
    fn discard(&mut self, id: CellId, owner: Owner) {
        if let Err(e) = self.cells.remove(id) {
            self.faults.push(format!(
                "removing the cell of {owner:?}: {}",
                errno_of(&e).0
            ));
        }
        match self.cells.poll() {
            Ok(notices) => self.collect(notices),
            Err(e) => self
                .faults
                .push(format!("polling after a removal: {}", errno_of(&e).0)),
        }
        self.routes.unbind(id);
        self.status.remove(&owner);
        self.watcher
            .remove(&mut self.events, READY_TAG | owner_node(owner));
        self.dirty = true;
    }

    /// The launch of a node.
    fn launch_node(&mut self, node: u32, spec: &NodeSpec, model: &Model) -> Result<i32, Errno> {
        let n = model.nodes.get(node as usize).ok_or(Errno(libc::ENOENT))?;
        let routed = Routed {
            stdin: None,
            stdout: None,
            stderr: None,
            ready: matches!(n.ready, Ready::Pipe).then_some(READY_FD.unsigned_abs()),
        };
        let request = from_model(n, model, &routed, deadline_ms(spec.start_timeout_ms))
            .map_err(|_| Errno(libc::EINVAL))?;
        let (mode, watch) = match &n.ready {
            Ready::Pipe => (ReadyMode::Pipe, None),
            Ready::Exit => (ReadyMode::Exit, None),
            Ready::Socket(p) => (ReadyMode::External, Some((p.clone(), Want::CreatedSocket))),
            Ready::Path(p) => (ReadyMode::External, Some((p.clone(), Want::Created))),
        };
        self.run_plan(Plan {
            owner: Owner::Node(node),
            name: spec.name.clone(),
            memory_max_kib: spec.memory_max_kib,
            pids_max: spec.pids_max,
            mode,
            watch,
            request: Request::Build(Box::new(request)),
            fds: Vec::new(),
            ready_fd: READY_FD,
        })
    }

    /// The launch of an instance: a frame's, built here, or a `Run`'s, whose request is the
    /// caller's own sealed file.
    fn launch_instance(
        &mut self,
        slot: u32,
        spec: InstanceSpec,
        model: &Model,
    ) -> Result<i32, Errno> {
        let [stdin, stdout, stderr] = spec.fds;
        let plan = if let Some(fd) = spec.request {
            // The request names its own descriptor numbers: 5, 6 and 7 for stdin, stdout and
            // stderr; the readiness pipe goes where it says.
            let fds = [(stdin, 5), (stdout, 6), (stderr, 7)]
                .into_iter()
                .filter_map(|(f, n)| f.map(|f| (f, n)))
                .collect();
            let wait = spec.ready_fd.is_some();
            Plan {
                owner: Owner::Instance(slot),
                name: spec.name,
                memory_max_kib: spec.memory_max_kib,
                pids_max: spec.pids_max,
                mode: if wait {
                    ReadyMode::Pipe
                } else {
                    ReadyMode::Exit
                },
                watch: None,
                request: Request::Sealed(fd),
                fds,
                ready_fd: spec
                    .ready_fd
                    .and_then(|n| RawFd::try_from(n).ok())
                    .unwrap_or(READY_FD),
            }
        } else {
            let n = model
                .nodes
                .get(spec.frame as usize)
                .ok_or(Errno(libc::ENOENT))?;
            // The caller's descriptors follow the readiness pipe: 6 upward, in the order stdin,
            // stdout, stderr, as many as were sent.
            let mut fds = Vec::new();
            let mut number = READY_FD + 1;
            let mut place = |fd: Option<OwnedFd>| {
                fd.map(|fd| {
                    fds.push((fd, number));
                    number += 1;
                    number.unsigned_abs() - 1
                })
            };
            let routed = Routed {
                stdin: place(stdin),
                stdout: place(stdout),
                stderr: place(stderr),
                ready: matches!(n.ready, Ready::Pipe).then_some(READY_FD.unsigned_abs()),
            };
            let request = from_instance(
                n,
                model,
                &routed,
                &spec.argv_tail,
                &spec.env_add,
                deadline_ms(spec.node.start_timeout_ms),
            )
            .map_err(|_| Errno(libc::EINVAL))?;
            Plan {
                owner: Owner::Instance(slot),
                name: spec.name,
                memory_max_kib: spec.memory_max_kib,
                pids_max: spec.pids_max,
                mode: if matches!(n.ready, Ready::Pipe) {
                    ReadyMode::Pipe
                } else {
                    ReadyMode::Exit
                },
                watch: None,
                request: Request::Build(Box::new(request)),
                fds,
                ready_fd: READY_FD,
            }
        };
        self.run_plan(plan)
    }

    /// Creates the cell and launches into it; any failure after the cell exists removes it.
    fn run_plan(&mut self, plan: Plan) -> Result<i32, Errno> {
        let owner = plan.owner;
        let request_fd = match plan.request {
            Request::Sealed(fd) => fd,
            Request::Build(spec) => {
                let bytes = spec.bytes().map_err(|_| Errno(libc::E2BIG))?;
                qinit_ipc::memfd::sealed(c"qinit-launch", &bytes).map_err(|e| Errno(e.0))?
            }
        };
        let (status_r, status_w) = qinit_sys::fd::pipe(libc::O_CLOEXEC).map_err(sys)?;

        let id = self.cells.create(&plan.name).map_err(|e| errno_of(&e))?;
        self.routes.bind(id, owner);
        self.dirty = true;
        if matches!(self.cells.phase(id), Some(Phase::Failed(_)) | None) {
            // The directory could not be made; the cell layer reports that later, without an
            // errno. Colony hears of it through this return, so the notice is muted.
            self.routes.mute(id);
            let errno = if self.comb.join(&plan.name).exists() {
                libc::EEXIST
            } else {
                libc::EIO
            };
            self.discard(id, owner);
            return Err(Errno(errno));
        }
        let launched = Launched {
            id,
            owner,
            memory_max_kib: plan.memory_max_kib,
            pids_max: plan.pids_max,
            mode: plan.mode,
            watch: plan.watch,
            request_fd,
            fds: plan.fds,
            ready_fd: plan.ready_fd,
            status_w,
            status_r,
        };
        let outcome = self.finish_launch(launched);
        if outcome.is_err() {
            self.routes.mute(id);
            self.discard(id, owner);
        }
        outcome
    }

    fn finish_launch(&mut self, l: Launched) -> Result<i32, Errno> {
        self.cells
            .set_limits(l.id, u64::from(l.memory_max_kib) * 1024, l.pids_max)
            .map_err(|e| errno_of(&e))?;
        if let Some((path, want)) = l.watch {
            // Before the spawn: what the service makes at once must not be missed.
            let key = READY_TAG | owner_node(l.owner);
            self.watcher
                .add(&mut self.events, key, Path::new(&path), want)
                .map_err(sys)?;
        }
        let mut fds = vec![(l.request_fd, REQUEST_FD), (l.status_w, STATUS_FD)];
        fds.extend(l.fds);
        let cmd = Command {
            path: self.overseer.clone(),
            argv: vec![OsString::from("overseer")],
            env: Vec::new(),
            fds,
            ready_fd: l.ready_fd,
        };
        self.cells
            .spawn(l.id, cmd, l.mode)
            .map_err(|e| errno_of(&e))?;
        // The cell layer reports a spawn it could not make as a failed cell, not as an error.
        let pid = match (self.cells.phase(l.id), self.cells.main_pid(l.id)) {
            (Some(Phase::Failed(_)) | None, _) | (_, None) => return Err(Errno(libc::EIO)),
            (_, Some(pid)) => pid,
        };
        self.status.insert(l.owner, l.status_r);
        Ok(pid)
    }

    fn stop_owner(&mut self, owner: Owner, mode: StopMode, grace_ms: u32) -> Result<(), Errno> {
        let id = self.routes.cell(owner).ok_or(Errno(libc::ENOENT))?;
        // The readiness watch ends with the stop.
        self.watcher
            .remove(&mut self.events, READY_TAG | owner_node(owner));
        // A cell adopted without its main has no process to signal politely.
        let polite = match mode {
            StopMode::Main if self.cells.main_pid(id).is_some() => Polite::Main,
            _ => Polite::Cell,
        };
        let grace = Duration::from_millis(u64::from(grace_ms));
        self.cells
            .stop(id, polite, grace, grace)
            .map_err(|e| errno_of(&e))
    }
}

/// Where a launch request comes from.
enum Request {
    /// A request value to encode and seal.
    Build(Box<RequestSpec>),
    /// The caller's own sealed file, handed on as it is.
    Sealed(OwnedFd),
}

/// Everything one launch needs, before its cell exists.
struct Plan {
    owner: Owner,
    name: String,
    memory_max_kib: u32,
    pids_max: u32,
    mode: ReadyMode,
    watch: Option<(String, Want)>,
    request: Request,
    /// The descriptors routed in beside the request, the status pipe and the readiness pipe.
    fds: Vec<(OwnedFd, RawFd)>,
    ready_fd: RawFd,
}

/// A [`Plan`] whose cell exists.
struct Launched {
    id: CellId,
    owner: Owner,
    memory_max_kib: u32,
    pids_max: u32,
    mode: ReadyMode,
    watch: Option<(String, Want)>,
    request_fd: OwnedFd,
    fds: Vec<(OwnedFd, RawFd)>,
    ready_fd: RawFd,
    status_w: OwnedFd,
    status_r: OwnedFd,
}

fn owner_node(owner: Owner) -> u64 {
    match owner {
        Owner::Node(n) | Owner::Instance(n) => u64::from(n),
    }
}

impl<C: CellOps> Effects for RealEffects<C> {
    fn start(&mut self, node: u32, spec: &NodeSpec, model: &Model) -> Result<i32, Errno> {
        self.launch_node(node, spec, model)
    }

    fn start_instance(
        &mut self,
        slot: u32,
        spec: InstanceSpec,
        model: &Model,
    ) -> Result<i32, Errno> {
        self.launch_instance(slot, spec, model)
    }

    fn instance_pidfd(&mut self, slot: u32) -> Result<OwnedFd, Errno> {
        let id = self
            .routes
            .cell(Owner::Instance(slot))
            .ok_or(Errno(libc::ENOENT))?;
        self.cells.main_pidfd(id).map_err(|e| errno_of(&e))
    }

    fn stop_instance(&mut self, slot: u32, mode: StopMode, grace_ms: u32) -> Result<(), Errno> {
        self.stop_owner(Owner::Instance(slot), mode, grace_ms)
    }

    fn release_instance(&mut self, slot: u32) {
        let owner = Owner::Instance(slot);
        if let Some(id) = self.routes.cell(owner) {
            self.discard(id, owner);
        }
    }

    fn stop(&mut self, node: u32, mode: StopMode, grace_ms: u32) -> Result<(), Errno> {
        self.stop_owner(Owner::Node(node), mode, grace_ms)
    }

    fn release(&mut self, node: u32) {
        let owner = Owner::Node(node);
        let Some(id) = self.routes.cell(owner) else {
            return;
        };
        self.discard(id, owner);
    }

    fn watch_path(&mut self, path: &str) -> Result<bool, Errno> {
        let id = if let Some(&id) = self.path_ids.get(path) {
            id
        } else {
            let id = PATH_TAG | u64::try_from(self.path_ids.len()).unwrap_or(0);
            self.path_ids.insert(path.to_owned(), id);
            self.path_names.insert(id, path.to_owned());
            id
        };
        self.watcher
            .add(&mut self.events, id, Path::new(path), Want::Exists)
            .map_err(sys)
    }

    fn arm(&mut self, node: u32, timer: TimerKind, ms: u32) -> Result<(), Errno> {
        self.deadlines
            .arm(Key::Node(node, timer), self.now_ms + u64::from(ms));
        Ok(())
    }

    fn cancel(&mut self, node: u32, timer: TimerKind) -> Result<(), Errno> {
        self.deadlines.cancel(Key::Node(node, timer));
        Ok(())
    }

    fn remap(&mut self, map: &[u32]) {
        self.routes.remap(map);
        self.deadlines.remap(map);
        let old: Vec<(Owner, OwnedFd)> = self.status.drain().collect();
        for (owner, fd) in old {
            match owner {
                Owner::Instance(_) => {
                    self.status.insert(owner, fd);
                }
                Owner::Node(was) => {
                    if let Some(now) = map.iter().position(|&m| m == was) {
                        let now = u32::try_from(now).unwrap_or(u32::MAX);
                        self.status.insert(Owner::Node(now), fd);
                    }
                }
            }
        }
        // Readiness watches (tagged by node) follow their node; dependency paths are by name.
        let find = |was: u64| {
            map.iter()
                .position(|&m| u64::from(m) == was)
                .map(|now| u64::try_from(now).unwrap_or(u64::MAX))
        };
        self.watcher.remap(&mut self.events, |id| {
            if id & !0xFFFF_FFFF == READY_TAG {
                find(id & 0xFFFF_FFFF).map(|now| READY_TAG | now)
            } else {
                Some(id)
            }
        });
        self.dirty = true;
    }

    fn arm_wait(&mut self, wait: u64, ms: u32) -> Result<(), Errno> {
        self.deadlines
            .arm(Key::Wait(wait), self.now_ms + u64::from(ms));
        Ok(())
    }

    fn cancel_wait(&mut self, wait: u64) {
        self.deadlines.cancel(Key::Wait(wait));
    }

    fn signal(&mut self, node: u32, sig: i32) -> Result<(), Errno> {
        let id = self
            .routes
            .cell(Owner::Node(node))
            .ok_or(Errno(libc::ENOENT))?;
        self.cells.signal_main(id, sig).map_err(|e| errno_of(&e))
    }
}
