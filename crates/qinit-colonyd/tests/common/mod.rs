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
use std::collections::HashMap;
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
        _expected_id: u64,
        _main: Option<OwnedFd>,
    ) -> Result<CellId, Error> {
        self.create(name)
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
