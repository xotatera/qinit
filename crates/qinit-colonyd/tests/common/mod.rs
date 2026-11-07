// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! A fake cell layer and small models for the effects tests.
#![allow(dead_code)] // each test binary uses a different part

use qinit_cell::effects::Command;
use qinit_cell::{CellId, Error, Notice, Phase, Polite, ReadyMode};
use qinit_colonyd::effects::CellOps;
use qinit_db::{
    Cred, Kind, Model, Node, Ready, Restart, RestartPolicy, Seccomp, Securebits, Stop, StopMode,
    UserMap,
};
use std::collections::{BTreeMap, HashMap};
use std::os::fd::{OwnedFd, RawFd};
use std::time::Duration;

/// What the effects asked of the cells, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    Create(String),
    SetLimits(u16, u64, u32),
    Spawn(u16, ReadyMode),
    Stop(u16, Polite, Duration, Duration),
    Remove(u16),
    MarkReady(u16),
    Signal(u16, i32),
    Poll,
    /// `(name, expected cgroup id, a main was handed over)`.
    Adopt(String, u64, bool),
}

/// How a scripted adoption ends.
#[derive(Clone, Copy, Debug)]
pub struct Adopt {
    /// The cell's cgroup id is not the recorded one (or its directory is gone).
    pub mismatch: bool,
    /// The cell still has processes.
    pub populated: bool,
}

impl Default for Adopt {
    fn default() -> Adopt {
        Adopt {
            mismatch: false,
            populated: true,
        }
    }
}

/// What a spawn was given.
pub struct Spawned {
    pub path: std::path::PathBuf,
    pub argv: Vec<std::ffi::OsString>,
    pub fds: Vec<(OwnedFd, RawFd)>,
    pub ready_fd: RawFd,
}

#[derive(Default)]
pub struct FakeCells {
    pub calls: Vec<Call>,
    pub phases: HashMap<u16, Phase>,
    pub mains: HashMap<u16, i32>,
    pub spawned: Vec<Spawned>,
    /// The next `create` leaves the cell in `Failed(Create)` and queues that notice.
    pub create_fails: bool,
    pub limits_fail: Option<i32>,
    /// Notices the next `poll` returns.
    pub pending: Vec<Notice>,
    /// Runs inside `spawn`, before it returns (a service that acts at once).
    pub on_spawn: Option<Box<dyn FnMut()>>,
    /// How each adoption by cell name ends; the default is a populated cell with the right id.
    pub adopt_script: HashMap<String, Adopt>,
    next: u16,
}

impl CellOps for FakeCells {
    fn create(&mut self, name: &str) -> Result<CellId, Error> {
        self.calls.push(Call::Create(name.to_owned()));
        let id = self.next;
        self.next += 1;
        if self.create_fails {
            self.create_fails = false;
            self.phases
                .insert(id, Phase::Failed(qinit_cell::Failure::Create));
            self.pending.push(Notice::Cell(
                CellId(id),
                qinit_cell::Report::Failed(qinit_cell::Failure::Create),
            ));
        } else {
            self.phases.insert(id, Phase::Created);
        }
        Ok(CellId(id))
    }

    fn set_limits(&mut self, id: CellId, memory: u64, pids: u32) -> Result<(), Error> {
        self.calls.push(Call::SetLimits(id.0, memory, pids));
        match self.limits_fail {
            Some(e) => Err(Error::Sys(qinit_sys::Errno(e))),
            None => Ok(()),
        }
    }

    fn spawn(&mut self, id: CellId, cmd: Command, ready: ReadyMode) -> Result<(), Error> {
        self.calls.push(Call::Spawn(id.0, ready));
        self.phases.insert(id.0, Phase::Starting);
        self.mains.insert(id.0, 4000 + i32::from(id.0));
        self.spawned.push(Spawned {
            path: cmd.path,
            argv: cmd.argv,
            fds: cmd.fds,
            ready_fd: cmd.ready_fd,
        });
        if let Some(f) = self.on_spawn.as_mut() {
            f();
        }
        Ok(())
    }

    fn phase(&self, id: CellId) -> Option<Phase> {
        self.phases.get(&id.0).copied()
    }

    fn stop(
        &mut self,
        id: CellId,
        polite: Polite,
        grace: Duration,
        kill: Duration,
    ) -> Result<(), Error> {
        self.calls.push(Call::Stop(id.0, polite, grace, kill));
        Ok(())
    }

    fn remove(&mut self, id: CellId) -> Result<(), Error> {
        self.calls.push(Call::Remove(id.0));
        self.phases.remove(&id.0);
        self.mains.remove(&id.0);
        Ok(())
    }

    fn mark_ready(&mut self, id: CellId) -> Result<(), Error> {
        self.calls.push(Call::MarkReady(id.0));
        Ok(())
    }

    fn signal_main(&mut self, id: CellId, sig: i32) -> Result<(), Error> {
        self.calls.push(Call::Signal(id.0, sig));
        Ok(())
    }

    fn main_pidfd(&mut self, id: CellId) -> Result<OwnedFd, Error> {
        if !self.mains.contains_key(&id.0) {
            return Err(Error::Sys(qinit_sys::Errno(libc::ESRCH)));
        }
        std::fs::File::open("/dev/null")
            .map(OwnedFd::from)
            .map_err(|_| Error::Sys(qinit_sys::Errno(libc::EIO)))
    }

    fn main_pid(&self, id: CellId) -> Option<i32> {
        self.mains.get(&id.0).copied()
    }

    fn cgroup_id(&self, id: CellId) -> Option<u64> {
        self.phases
            .contains_key(&id.0)
            .then_some(900 + u64::from(id.0))
    }

    fn adopt(
        &mut self,
        name: &str,
        expected_id: u64,
        main: Option<OwnedFd>,
    ) -> Result<CellId, Error> {
        self.calls
            .push(Call::Adopt(name.to_owned(), expected_id, main.is_some()));
        let id = self.next;
        self.next += 1;
        let how = self.adopt_script.get(name).copied().unwrap_or_default();
        let (phase, report) = if how.mismatch {
            (
                Phase::Failed(qinit_cell::Failure::IdMismatch),
                qinit_cell::Report::Failed(qinit_cell::Failure::IdMismatch),
            )
        } else if how.populated || main.is_some() {
            (Phase::Running, qinit_cell::Report::Running)
        } else {
            (Phase::Empty, qinit_cell::Report::Empty)
        };
        self.phases.insert(id, phase);
        if main.is_some() {
            self.mains.insert(id, 5000 + i32::from(id));
        }
        self.pending.push(Notice::Cell(CellId(id), report));
        Ok(CellId(id))
    }

    fn poll(&mut self) -> Result<Vec<Notice>, Error> {
        self.calls.push(Call::Poll);
        Ok(std::mem::take(&mut self.pending))
    }
}

pub fn svc() -> Cred {
    Cred {
        user: "svc".into(),
        caps: 0,
        securebits: Securebits::None,
        nnp: true,
        ns: 0,
        seccomp: Seccomp::None,
        paths: Vec::new(),
        user_map: UserMap::Own,
        inside_uid: 0,
        inside_gid: 0,
    }
}

/// A worker called `name` with a pipe readiness and no limits.
pub fn worker(name: &str) -> Node {
    Node {
        kind: Kind::Worker,
        name: name.to_owned(),
        exec: vec![format!("/bin/{name}"), "-v".to_owned()],
        ready: Ready::Pipe,
        restart: Restart {
            policy: RestartPolicy::Never,
            max: 0,
            window_ms: 0,
            delay_ms: 1000,
        },
        stop: Stop {
            mode: StopMode::Main,
            grace_ms: 10_000,
        },
        start_timeout_ms: 90_000,
        output: None,
        errors: None,
        cred: Some(0),
        groups: Vec::new(),
        memory_max_kib: 0,
        pids_max: 0,
        instance_of: None,
        env: Vec::new(),
        cwd: "/".into(),
        umask: 0o027,
        rlimits: [None; 16],
        reload: None,
        launch: None,
    }
}

pub fn model(nodes: Vec<Node>) -> Model {
    Model {
        nodes,
        creds: vec![svc()],
        ..Model::default()
    }
}

/// The spec colony would hand the effects for node `i` of `m`.
pub fn spec_of(m: &Model, i: usize) -> qinit_colony::NodeSpec {
    let n = &m.nodes[i];
    qinit_colony::NodeSpec {
        name: n.name.clone(),
        kind: n.kind,
        exec: n.exec.clone(),
        ready: n.ready.clone(),
        stop: match n.stop.mode {
            StopMode::Main => qinit_colony::StopMode::Main,
            StopMode::Cell => qinit_colony::StopMode::Cell,
        },
        grace_ms: n.stop.grace_ms,
        start_timeout_ms: n.start_timeout_ms,
        memory_max_kib: n.memory_max_kib,
        pids_max: n.pids_max,
    }
}

/// A temporary directory removed when it goes out of scope.
pub struct Tmp(pub std::path::PathBuf);

impl Tmp {
    pub fn new(tag: &str) -> Tmp {
        let d = std::env::temp_dir().join(format!("qinit-fx-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Tmp(d)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The database bytes for `frames` (inline TOML) with `enable` as the roots, compiled by the real
/// frame compiler.
pub fn database(frames: &str, enable: &[&str]) -> Vec<u8> {
    use qinit_frames::compile::{CompileInput, compile};
    use qinit_frames::layers::LayerInput;
    let tmp = Tmp::new(&format!(
        "db-{}",
        std::thread::current()
            .name()
            .unwrap_or("t")
            .replace("::", "-")
    ));
    let vendor = tmp.0.join("vendor");
    std::fs::create_dir_all(&vendor).unwrap();
    std::fs::write(vendor.join("frames.toml"), frames).unwrap();
    let list: Vec<String> = enable.iter().map(|e| format!("\"{e}\"")).collect();
    std::fs::write(
        vendor.join("enable.toml"),
        format!("enable = [{}]\n", list.join(", ")),
    )
    .unwrap();
    let input = CompileInput {
        layers: vec![LayerInput {
            name: "vendor".to_owned(),
            dir: vendor,
        }],
        policy: None,
    };
    compile(&input).expect("the frames compile").bytes
}

/// Queen's side of the channel, for the tests: it holds what colony puts, as queen would, and
/// hands it to a new colony.
pub struct FakeQueen {
    pub peer: OwnedFd,
    pub held: BTreeMap<u64, OwnedFd>,
    /// The modes colony announced.
    pub shutdowns: Vec<qinit_queen_core::Mode>,
}

impl FakeQueen {
    /// A queen and the colony end of its channel.
    pub fn new() -> (FakeQueen, OwnedFd) {
        let (peer, link) = qinit_ipc::seqpacket_pair().unwrap();
        qinit_sys::fd::set_nonblocking(&peer).unwrap();
        (
            FakeQueen {
                peer,
                held: BTreeMap::new(),
                shutdowns: Vec::new(),
            },
            link,
        )
    }

    /// Sends colony `rec`, with `fd` when given.
    pub fn send(&self, rec: qinit_queen_core::ToColony, fd: Option<std::os::fd::BorrowedFd<'_>>) {
        let bytes = qinit_queen_core::encode_to_colony(rec);
        let fds: Vec<_> = fd.into_iter().collect();
        qinit_ipc::send(std::os::fd::AsFd::as_fd(&self.peer), &bytes, &fds).unwrap();
    }

    /// Applies everything colony has sent so far.
    pub fn pump(&mut self) {
        use qinit_queen_core::{FromColony, decode_from_colony};
        loop {
            let mut buf = [0u8; 32];
            let r = match qinit_ipc::recv(std::os::fd::AsFd::as_fd(&self.peer), &mut buf) {
                Ok(r) => r,
                Err(qinit_ipc::Errno(libc::EAGAIN)) => return,
                Err(e) => panic!("{e:?}"),
            };
            if r.len == 0 && r.fds.is_empty() {
                return;
            }
            let mut fds = r.fds;
            match decode_from_colony(&buf[..r.len], fds.len()).expect("a well-formed record") {
                FromColony::Put { key } => {
                    self.held.insert(key, fds.pop().unwrap());
                }
                FromColony::Drop { key } => {
                    self.held.remove(&key);
                }
                FromColony::Shutdown { mode } => self.shutdowns.push(mode),
            }
        }
    }

    /// A new colony's end: queen sends what it holds, then `HeldEnd`, as it does at a spawn.
    pub fn reattach(&mut self) -> qinit_colonyd::store::Store {
        use qinit_queen_core::ToColony;
        self.pump();
        let (peer, link) = qinit_ipc::seqpacket_pair().unwrap();
        qinit_sys::fd::set_nonblocking(&peer).unwrap();
        self.peer = peer;
        for (&key, fd) in &self.held {
            let bytes = qinit_queen_core::encode_to_colony(ToColony::Held { key });
            qinit_ipc::send(
                std::os::fd::AsFd::as_fd(&self.peer),
                &bytes,
                &[std::os::fd::AsFd::as_fd(fd)],
            )
            .unwrap();
        }
        self.send(
            ToColony::HeldEnd {
                count: u32::try_from(self.held.len()).unwrap(),
            },
            None,
        );
        qinit_colonyd::store::Store::attach(link).unwrap()
    }
}
