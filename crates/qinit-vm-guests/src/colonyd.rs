// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The colony program as a real process in a guest: a site (a directory with the database, the
//! run directory and a syslog receiver), the models the suites run, and the waits that tell a
//! guest case when colony is ready for its next step. Nothing here sleeps: a wait is an event
//! (the socket appearing, a settled reply, a notice, the process ending) with a hang guard.
use crate::{COMB, HANG_GUARD, HELPER_FLAG, e};
use qinit_client::Client;
use qinit_db::{
    Cred, Edge, Group, GroupKind, Kind, Mode, Model, Node, Ready, Restart, RestartOn,
    RestartPolicy, Seccomp, Securebits, Stop, StopMode, Target, UserMap,
};
use qinit_event::{Loop, Ready as LoopReady};
use std::os::fd::AsFd;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

/// Where the initrd puts the colony program.
pub const COLONY: &str = "/colony";

/// One colony and the directory it lives in.
pub struct Site {
    pub dir: PathBuf,
    pub run: PathBuf,
    pub db: PathBuf,
    pub syslog: PathBuf,
    pub console: PathBuf,
    log: UnixDatagram,
    child: Option<Child>,
}

/// Makes the site `tag` under `/tmp`, with a syslog receiver bound in it, and gives the comb
/// the controllers colony hands on to its cells.
pub fn site(tag: &str) -> Result<Site, String> {
    // The root cgroup may hand its children the controllers; colony does the same for the comb.
    e(std::fs::write(
        "/sys/fs/cgroup/cgroup.subtree_control",
        "+memory +pids",
    ))?;
    let dir = PathBuf::from("/tmp").join(tag);
    let _ = std::fs::remove_dir_all(&dir);
    e(std::fs::create_dir_all(&dir))?;
    let syslog = dir.join("log");
    let log = e(UnixDatagram::bind(&syslog))?;
    e(log.set_nonblocking(true))?;
    let console = dir.join("console");
    e(std::fs::write(&console, b""))?;
    Ok(Site {
        run: dir.join("run"),
        db: dir.join("colony.db"),
        syslog,
        console,
        dir,
        log,
        child: None,
    })
}

impl Site {
    /// Writes `model` as the database `--db` names.
    pub fn write_db(&self, model: &Model) -> Result<(), String> {
        let bytes = qinit_db::write(model).map_err(|x| format!("write the database: {x:?}"))?;
        e(std::fs::write(&self.db, bytes))
    }

    /// The control socket.
    #[must_use]
    pub fn socket(&self) -> PathBuf {
        self.run.join("colony")
    }

    /// Starts colony over the test comb.
    pub fn start(&mut self) -> Result<(), String> {
        let child = e(Command::new(COLONY)
            .arg("--db")
            .arg(&self.db)
            .arg("--comb")
            .arg(COMB)
            .arg("--run")
            .arg(&self.run)
            .arg("--socket")
            .arg(self.socket())
            .arg("--overseer")
            .arg(crate::OVERSEER)
            .arg("--syslog")
            .arg(&self.syslog)
            .arg("--console")
            .arg(&self.console)
            .spawn())?;
        self.child = Some(child);
        Ok(())
    }

    fn pid(&self) -> Result<libc::pid_t, String> {
        let child = self.child.as_ref().ok_or("colony was not started")?;
        e(libc::pid_t::try_from(child.id()))
    }

    /// Waits for the control socket and connects: an event wait on the run directory, ending
    /// early if colony exits.
    pub fn client(&mut self) -> Result<Client, String> {
        let pidfd = e(qinit_sys::proc::pidfd_open(self.pid()?))?;
        let mut l = e(Loop::new())?;
        e(std::fs::create_dir_all(&self.run))?;
        e(l.add_inotify(&self.run, libc::IN_CREATE | libc::IN_ATTRIB, 1))?;
        e(l.add_fd(pidfd.as_fd(), 3))?;
        e(l.add_deadline(HANG_GUARD, 2))?;
        loop {
            if let Ok(c) = Client::connect(&self.socket()) {
                return Ok(c);
            }
            for r in e(l.wait())? {
                match r {
                    LoopReady::Deadline(2) => return Err("colony never listened".into()),
                    LoopReady::Readable(3) | LoopReady::Hangup(3) => {
                        let code = self.wait_exit()?;
                        return Err(format!("colony exited with {code} before it listened"));
                    }
                    _ => {}
                }
            }
        }
    }

    /// Everything colony has sent to syslog so far.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut buf = [0u8; 1024];
        while let Ok(n) = self.log.recv(&mut buf) {
            out.push(String::from_utf8_lossy(&buf[..n]).into_owned());
        }
        out
    }

    /// Sends colony `sig`.
    pub fn signal(&self, sig: libc::c_int) -> Result<(), String> {
        e(qinit_sys::proc::kill(self.pid()?, sig))
    }

    /// Waits for colony to exit and returns its exit code (128 + signal when killed).
    pub fn wait_exit(&mut self) -> Result<i32, String> {
        let pid = self.pid()?;
        let pidfd = e(qinit_sys::proc::pidfd_open(pid))?;
        let ms = i32::try_from(HANG_GUARD.as_millis()).unwrap_or(i32::MAX);
        if !e(qinit_ipc::poll_readable(pidfd.as_fd(), ms))? {
            return Err("colony did not exit".into());
        }
        let status = e(self.child.as_mut().ok_or("colony was not started")?.wait())?;
        self.child = None;
        Ok(status.code().unwrap_or_else(|| {
            128 + std::os::unix::process::ExitStatusExt::signal(&status).unwrap_or(0)
        }))
    }

    /// SIGTERM, then the exit code.
    pub fn terminate(&mut self) -> Result<i32, String> {
        self.signal(libc::SIGTERM)?;
        self.wait_exit()
    }
}

/// Fails unless the comb holds no cell (a clean shutdown leaves none).
pub fn comb_is_empty() -> Result<(), String> {
    // A cgroup directory lists its interface files too: only the sub-directories are cells.
    let left: Vec<String> = e(std::fs::read_dir(COMB))?
        .filter_map(Result::ok)
        .filter(|d| d.file_type().is_ok_and(|t| t.is_dir()))
        .map(|d| d.file_name().to_string_lossy().into_owned())
        .collect();
    if left.is_empty() {
        Ok(())
    } else {
        Err(format!("cells left in the comb: {left:?}"))
    }
}

/// The credential every node runs under: root, nothing else.
#[must_use]
pub fn cred() -> Cred {
    Cred {
        user: "root".into(),
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

/// A node with every default: a worker that never restarts, ready by pipe.
#[must_use]
pub fn node(name: &str, kind: Kind) -> Node {
    Node {
        kind,
        name: name.to_owned(),
        exec: Vec::new(),
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
        start_timeout_ms: 60_000,
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

/// A worker running the guest's helper `role` with `args`, ready by the pipe the helper writes.
#[must_use]
pub fn worker(name: &str, role: &str, args: &[&str]) -> Node {
    let mut exec = vec!["/init".to_owned(), HELPER_FLAG.to_owned(), role.to_owned()];
    exec.extend(args.iter().map(ToString::to_string));
    Node {
        exec,
        ..node(name, Kind::Worker)
    }
}

/// A brood: no process, ready when what it requires is.
#[must_use]
pub fn brood(name: &str) -> Node {
    Node {
        ready: Ready::Exit,
        start_timeout_ms: 0,
        cred: None,
        ..node(name, Kind::Brood)
    }
}

/// `n` requires every node of `targets` (by index), each by a synchronous edge.
#[must_use]
pub fn requires(mut n: Node, targets: &[u32]) -> Node {
    n.groups.push(Group {
        kind: GroupKind::RequireAll,
        edges: targets
            .iter()
            .map(|&t| Edge {
                target: Target::Node(t),
                mode: Mode::Sync,
                deadline_ms: 0,
                restart_on: RestartOn::Error,
                stop_parallel: false,
                cascade: false,
            })
            .collect(),
    });
    n
}

/// A database of `nodes` (in name order) with `enabled` nodes by index.
#[must_use]
pub fn model(nodes: Vec<Node>, enabled: &[u32]) -> Model {
    Model {
        nodes,
        creds: vec![cred()],
        routes: Vec::new(),
        enabled: enabled.to_vec(),
        presyslog: Vec::new(),
        policy: None,
    }
}

/// The read of a file in a cell's directory, trimmed.
pub fn cell_file(cell: &str, file: &str) -> Result<String, String> {
    let text = e(std::fs::read_to_string(
        Path::new(COMB).join(cell).join(file),
    ))?;
    Ok(text.trim().to_owned())
}
