// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The colony program as a real process in a guest: a site (a directory with the database, the
//! run directory and a syslog receiver), the models the suites run, and the waits that tell a
//! guest case when colony is ready for its next step. Nothing here sleeps: a wait is an event
//! (the socket appearing, a settled reply, a notice, the process ending) with a hang guard.
use crate::{COMB, HANG_GUARD, HELPER_FLAG, e};
use qinit_client::{Action, Client, Event, Next, Outcome, Report, Scope, Status, Wait};
use qinit_db::{
    Cred, Edge, Group, GroupKind, Kind, Mode, Model, Node, Ready, Restart, RestartOn,
    RestartPolicy, Seccomp, Securebits, Stop, StopMode, Target, UserMap,
};
use qinit_event::{Loop, Ready as LoopReady};
use std::collections::HashMap;
use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Condvar, Mutex, OnceLock};

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
    pid: Option<libc::pid_t>,
}

/// The exit statuses of the guest's own children, reaped by one thread: the guest's init is the
/// parent of everything a killed colony leaves behind, and a zombie keeps its cell populated.
struct Reaper {
    statuses: Mutex<HashMap<libc::pid_t, i32>>,
    exited: Condvar,
    /// Written to when children may have appeared while the thread waited for some.
    wake: OwnedFd,
}

static REAPER: OnceLock<Reaper> = OnceLock::new();

fn reaper() -> Result<&'static Reaper, String> {
    if let Some(r) = REAPER.get() {
        return Ok(r);
    }
    let (wake_r, wake_w) = e(qinit_sys::fd::pipe(libc::O_CLOEXEC))?;
    let r = REAPER.get_or_init(|| Reaper {
        statuses: Mutex::new(HashMap::new()),
        exited: Condvar::new(),
        wake: wake_w,
    });
    std::thread::spawn(move || {
        let mut wake = std::fs::File::from(wake_r);
        loop {
            if let Ok(Some((pid, status))) = qinit_sys::proc::wait_any() {
                if let Ok(mut m) = r.statuses.lock() {
                    m.insert(pid, status);
                }
                r.exited.notify_all();
            } else {
                // No children for now: block until a colony is started or killed.
                let mut byte = [0u8; 1];
                if wake.read_exact(&mut byte).is_err() {
                    return;
                }
            }
        }
    });
    Ok(r)
}

impl Reaper {
    fn poke(&self) {
        let _ = qinit_sys::fd::write_all(self.wake.as_fd(), b"x");
    }
}

/// Makes the site `tag` under `/tmp`, with a syslog receiver bound in it, and gives the comb
/// the controllers colony hands on to its cells.
pub fn site(tag: &str) -> Result<Site, String> {
    reaper()?;
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
        pid: None,
    })
}

impl Drop for Site {
    /// A case that ended early leaves nothing running: colony is killed and the comb emptied, so
    /// the next case starts clean.
    fn drop(&mut self) {
        if let Some(pid) = self.pid.take() {
            let _ = qinit_sys::proc::kill(pid, libc::SIGKILL);
            if let Some(r) = REAPER.get() {
                r.poke();
            }
        }
        clear_comb();
    }
}

/// Kills every cell of the comb and removes it, best effort.
pub fn clear_comb() {
    let Ok(entries) = std::fs::read_dir(COMB) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let path = entry.path();
        let _ = std::fs::write(path.join("cgroup.kill"), b"1");
        let name = entry.file_name().to_string_lossy().into_owned();
        let _ = await_unpopulated(&name);
        let _ = std::fs::remove_dir(&path);
    }
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

    /// Starts colony over the test comb (again, after a kill: the run directory, with its saved
    /// state, and the comb, with its cells, are as the last colony left them).
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
        self.pid = Some(e(libc::pid_t::try_from(child.id()))?);
        // The reaper owns the child's exit status; std's handle is not waited on.
        std::mem::forget(child);
        reaper()?.poke();
        Ok(())
    }

    fn pid(&self) -> Result<libc::pid_t, String> {
        self.pid.ok_or_else(|| "colony was not started".to_owned())
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
        let r = reaper()?;
        let mut seen = r.statuses.lock().map_err(|x| x.to_string())?;
        let status = loop {
            if let Some(s) = seen.remove(&pid) {
                break s;
            }
            let (next, timeout) = r
                .exited
                .wait_timeout(seen, HANG_GUARD)
                .map_err(|x| x.to_string())?;
            seen = next;
            if timeout.timed_out() && !seen.contains_key(&pid) {
                return Err("colony did not exit".into());
            }
        };
        drop(seen);
        self.pid = None;
        Ok(if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            128 + libc::WTERMSIG(status)
        })
    }

    /// Waits until the lines colony has sent to syslog (every one since the last drain, plus
    /// those that come) satisfy `want`; returns them. An event wait on the syslog socket.
    pub fn await_log(&self, want: impl Fn(&[String]) -> bool) -> Result<Vec<String>, String> {
        let ms = i32::try_from(HANG_GUARD.as_millis()).unwrap_or(i32::MAX);
        let mut seen = self.lines();
        while !want(&seen) {
            if !e(qinit_ipc::poll_readable(self.log.as_fd(), ms))? {
                return Err(format!("the log never showed it: {seen:?}"));
            }
            seen.extend(self.lines());
        }
        Ok(seen)
    }

    /// SIGTERM, then the exit code.
    pub fn terminate(&mut self) -> Result<i32, String> {
        self.signal(libc::SIGTERM)?;
        self.wait_exit()
    }

    /// SIGKILL: colony dies where it stands, and what it ran runs on. The orphans are the
    /// guest's to reap.
    pub fn kill_hard(&mut self) -> Result<(), String> {
        self.signal(libc::SIGKILL)?;
        let code = self.wait_exit()?;
        reaper()?.poke();
        if code == 128 + libc::SIGKILL {
            Ok(())
        } else {
            Err(format!("colony ended with {code}, not by SIGKILL"))
        }
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

/// Starts colony on `model` in a new site and connects.
pub fn up(tag: &str, model: &Model) -> Result<(Site, Client), String> {
    let mut s = site(tag)?;
    s.write_db(model)?;
    s.start()?;
    let c = s.client()?;
    Ok((s, c))
}

/// Waits until `target` has settled after a start request (a parked reply, not a poll) and
/// returns its state word's state.
pub fn settled(c: &mut Client, target: &str) -> Result<u32, String> {
    match e(c.change(target, Action::Start, Wait::Settled(HANG_GUARD)))? {
        Outcome::Settled(w) => Ok(w.state),
        other => Err(format!("{target} did not settle: {other:?}")),
    }
}

/// A node's status.
pub fn info(c: &mut Client, name: &str) -> Result<qinit_client::NodeInfo, String> {
    match e(c.status(name))? {
        Status::Node(n) => Ok(n),
        other @ Status::Instance(_) => Err(format!("{name} is not a node: {other:?}")),
    }
}

/// What a watch of one node saw on its way to a state.
pub struct Seen {
    pub detail: u32,
    pub reports: Vec<Report>,
}

/// Watches `name` on a new connection until it is in `want` (the watch starts with the state it
/// is in now, so a state already reached counts).
pub fn await_state(s: &mut Site, name: &str, want: u32) -> Result<Seen, String> {
    let c = s.client()?;
    let mut w = e(c.watch(Scope::Target(name)))?;
    let mut reports = Vec::new();
    loop {
        match e(w.next(Some(HANG_GUARD)))? {
            Next::Event(Event::Node { state, report, .. }) => {
                reports.push(report);
                if state.state == want {
                    return Ok(Seen {
                        detail: state.detail,
                        reports,
                    });
                }
            }
            Next::Event(_) => {}
            Next::Timeout => return Err(format!("{name} never reached state {want}: {reports:?}")),
            Next::Ended(w) => return Err(format!("the watch of {name} ended in {w:?}")),
        }
    }
}

/// The cgroup path of process `pid`.
pub fn cgroup_of(pid: i32) -> Result<String, String> {
    Ok(e(std::fs::read_to_string(format!("/proc/{pid}/cgroup")))?
        .trim()
        .to_owned())
}

/// The processes of `cell`, sorted.
pub fn procs_of(cell: &str) -> Result<Vec<i32>, String> {
    let text = e(std::fs::read_to_string(
        Path::new(COMB).join(cell).join("cgroup.procs"),
    ))?;
    let mut pids: Vec<i32> = text.lines().filter_map(|l| l.trim().parse().ok()).collect();
    pids.sort_unstable();
    Ok(pids)
}

/// Waits until `file` has at least `n` lines (an inotify wait on its directory).
pub fn await_lines(file: &Path, n: usize) -> Result<Vec<String>, String> {
    let mut l = e(Loop::new())?;
    let dir = file.parent().ok_or("a file without a directory")?;
    e(l.add_inotify(
        dir,
        libc::IN_MODIFY | libc::IN_CREATE | libc::IN_CLOSE_WRITE,
        1,
    ))?;
    e(l.add_deadline(HANG_GUARD, 2))?;
    loop {
        let text = std::fs::read_to_string(file).unwrap_or_default();
        let lines: Vec<String> = text.lines().map(str::to_owned).collect();
        if lines.len() >= n {
            return Ok(lines);
        }
        for r in e(l.wait())? {
            if matches!(r, LoopReady::Deadline(2)) {
                return Err(format!("{} never had {n} lines: {lines:?}", file.display()));
            }
        }
    }
}

/// Waits until the process behind `pidfd` has exited.
pub fn await_exit(pidfd: &OwnedFd) -> Result<(), String> {
    let ms = i32::try_from(HANG_GUARD.as_millis()).unwrap_or(i32::MAX);
    if e(qinit_ipc::poll_readable(pidfd.as_fd(), ms))? {
        Ok(())
    } else {
        Err("a process did not exit".into())
    }
}

/// Waits until `cell` has no process (`cgroup.events` `populated 0`), a priority-notification
/// wait on the file itself.
pub fn await_unpopulated(cell: &str) -> Result<(), String> {
    let events = e(std::fs::File::open(
        Path::new(COMB).join(cell).join("cgroup.events"),
    ))?;
    let mut l = e(Loop::new())?;
    e(l.add_priority(events.as_fd(), 1))?;
    e(l.add_deadline(HANG_GUARD, 2))?;
    loop {
        let (populated, _) = crate::read_events(events.as_fd())?;
        if !populated {
            return Ok(());
        }
        for r in e(l.wait())? {
            if matches!(r, LoopReady::Deadline(2)) {
                return Err(format!("{cell} is still populated"));
            }
        }
    }
}

/// Whether `pid` still runs: a zombie is dead (it has left its cgroup, and only waits to be
/// reaped).
#[must_use]
pub fn alive(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().next().map(str::to_owned))
            .is_some_and(|state| state != "Z" && state != "X")
    })
}

/// Waits until the directory of `cell` is gone from the comb (an inotify wait on the comb).
pub fn await_cell_gone(cell: &str) -> Result<(), String> {
    let mut l = e(Loop::new())?;
    e(l.add_inotify(Path::new(COMB), libc::IN_DELETE | libc::IN_MOVED_FROM, 1))?;
    e(l.add_deadline(HANG_GUARD, 2))?;
    let dir = Path::new(COMB).join(cell);
    loop {
        if !dir.exists() {
            return Ok(());
        }
        for r in e(l.wait())? {
            if matches!(r, LoopReady::Deadline(2)) {
                return Err(format!("{cell} is still in the comb"));
            }
        }
    }
}
