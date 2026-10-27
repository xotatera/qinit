// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The real [`Effects`]: cells under a comb directory, spawned with `clone3` into their cgroup,
//! watched through `qinit-event`.
use crate::effects::{Command, Effects, Reaped};
use crate::text::{parse_events, parse_fdinfo_pid, parse_procs};
use qinit_cell_core::{Handle, ReadyMode, Sig, Timer};
use qinit_cell_drive::{CAPACITY, Source, route, timer_source, token};
use qinit_event::{Loop, Ready, Token};
use qinit_sys::{Errno, cgroup, event, fd, proc, spawn};
use std::ffi::{CStr, OsStr, OsString};
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How `cgroup.events` changes are watched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Watch {
    Priority,
    Inotify,
}

/// What the `probe` suite found on the pinned kernel (Task 5; `notes/2026-10-27-probe-results.md`).
pub const EVENTS_WATCH: Watch = Watch::Priority;

/// First loop token of a stray: a child process no cell tracks any more. Far above every cell
/// token (`route` gives `None`) and below [`crate::engine::ORPHANS`].
const STRAYS: Token = 1 << 62;

/// A cell's main process.
struct Tracked {
    pid: libc::pid_t,
    pidfd: OwnedFd,
    /// Spawned here, so this process reaps it (the loop through the pidfd, or
    /// `reap_children`). A main handed over on adoption is watched without reaping: it need
    /// not be this process's child.
    child: bool,
}

#[derive(Default)]
struct Slot {
    dir: Option<OwnedFd>,
    events: Option<OwnedFd>,
    id: u64,
    /// The main process until it is reaped or its exit is seen.
    main: Option<Tracked>,
    ready: Option<OwnedFd>,
    exec_err: Option<OwnedFd>,
}

const SOURCES: [Source; 6] = [
    Source::Main,
    Source::Ready,
    Source::ExecError,
    Source::Events,
    Source::Grace,
    Source::Kill,
];

fn lp(e: qinit_event::Error) -> Errno {
    match e {
        qinit_event::Error::Sys { errno, .. } => errno,
        qinit_event::Error::DuplicateToken(_) => Errno(libc::EEXIST),
        qinit_event::Error::Empty => Errno(libc::EINVAL),
    }
}

fn signo(s: Sig) -> libc::c_int {
    match s {
        Sig::Term => libc::SIGTERM,
        Sig::Kill => libc::SIGKILL,
    }
}

pub struct Kernel {
    comb: OwnedFd,
    comb_path: PathBuf,
    l: Loop,
    slots: Vec<Slot>,
    /// Children no cell tracks any more that had not exited when they were let go: the loop
    /// watches each under its own token and reaps it.
    strays: Vec<(Token, libc::pid_t)>,
    next_stray: Token,
    /// Such children the loop refused to watch: tried at every wake-up (D9).
    unwatched: Vec<(libc::pid_t, OwnedFd)>,
    /// `(pid, wait status)` of every child reaped here that no cell tracks, until
    /// `take_reaped` hands them to the engine (spec §5.3: never dropped).
    reaped: Vec<(libc::pid_t, i32)>,
    /// An error `reap_children` hit after it had reaped some children: returned next time.
    reap_error: Option<Errno>,
    #[cfg(feature = "test-hooks")]
    pub(crate) between: Option<Box<dyn FnMut(libc::pid_t)>>,
}

impl Kernel {
    /// Cells will live directly under `comb` (a cgroup2 directory this process may write).
    ///
    /// # Errors
    ///
    /// The errno of opening `comb` or creating the loop.
    pub fn open(comb: &Path) -> Result<Kernel, Errno> {
        Ok(Kernel {
            comb: cgroup::open_dir(comb)?,
            comb_path: comb.to_path_buf(),
            l: Loop::new().map_err(lp)?,
            slots: (0..CAPACITY).map(|_| Slot::default()).collect(),
            strays: Vec::new(),
            next_stray: STRAYS,
            unwatched: Vec::new(),
            reaped: Vec::new(),
            reap_error: None,
            #[cfg(feature = "test-hooks")]
            between: None,
        })
    }

    /// The tracked main process's pid, until it is reaped or its exit is seen.
    #[must_use]
    pub fn main_pid(&self, slot: u16) -> Option<libc::pid_t> {
        self.slots
            .get(usize::from(slot))
            .and_then(|s| s.main.as_ref())
            .map(|m| m.pid)
    }

    /// Reports SIGCHLD under `token` (subreaper mode).
    ///
    /// # Errors
    ///
    /// The errno of the signal mask, the signalfd or its registration.
    pub fn watch_children(&mut self, token: Token) -> Result<(), Errno> {
        self.l.add_signal(&[libc::SIGCHLD], token).map_err(lp)
    }

    /// The next loop results. Exits the loop reaped are taken off the books here: a slot's
    /// main process is forgotten (its pid may be reused from now on); a stray's exit goes to
    /// [`Effects::take_reaped`] instead of the results.
    ///
    /// # Errors
    ///
    /// The loop's errno.
    pub fn wait(&mut self) -> Result<Vec<Ready>, Errno> {
        let mut out = self.l.wait().map_err(lp)?;
        out.retain(|r| match *r {
            Ready::Exited(t, status) => self.reaped_by_loop(t, status),
            _ => true,
        });
        let unwatched = std::mem::take(&mut self.unwatched);
        for (pid, pidfd) in unwatched {
            match proc::reap_pidfd(&pidfd) {
                Ok(Some(status)) => self.reaped.push((pid, status)),
                Ok(None) => self.unwatched.push((pid, pidfd)),
                // Reaped elsewhere (by `reap_children`, which reported it).
                Err(_) => {}
            }
        }
        Ok(out)
    }

    /// Whether an exit the loop reaped goes on to the engine as it is.
    fn reaped_by_loop(&mut self, t: Token, status: i32) -> bool {
        if let Some(k) = self.strays.iter().position(|&(s, _)| s == t) {
            let (_, pid) = self.strays.swap_remove(k);
            self.reaped.push((pid, status));
            return false;
        }
        if let Some((slot, Source::Main)) = route(t)
            && let Ok(s) = self.slot(slot)
        {
            s.main = None;
        }
        true
    }

    /// Lets a process go that no cell tracks any more, without leaving a zombie or losing its
    /// status: a child that has exited is reaped now, one still running is watched as a stray
    /// until it does (each reported through `take_reaped`). A process that is not this one's
    /// child (a handed-over main) has nothing to reap.
    fn abandon(&mut self, pid: libc::pid_t, pidfd: OwnedFd) {
        match proc::reap_pidfd(&pidfd) {
            Ok(Some(status)) => self.reaped.push((pid, status)),
            Ok(None) => {
                let t = self.next_stray;
                self.next_stray += 1;
                if self.l.add_pidfd(pidfd.as_fd(), t).is_ok() {
                    self.strays.push((t, pid));
                } else {
                    self.unwatched.push((pid, pidfd));
                }
            }
            Err(_) => {}
        }
    }

    /// One exited child for `reap_children`: reaped, and its report.
    fn reap_one(&mut self, pid: libc::pid_t, status: i32) -> Result<Option<Reaped>, Errno> {
        let tracked = self
            .slots
            .iter()
            .position(|s| s.main.as_ref().is_some_and(|m| m.child && m.pid == pid));
        if let Some(slot) = tracked.and_then(|i| u16::try_from(i).ok()) {
            // The loop's copy goes first, so the loop never reaps it as well.
            let _ = self.l.remove(token(slot, Source::Main));
            let Some(m) = self.slot(slot)?.main.take() else {
                return Ok(None);
            };
            return Ok(proc::reap_pidfd(&m.pidfd)?.map(|_| Reaped::Main(slot, pid, status)));
        }
        if let Some(k) = self.strays.iter().position(|&(_, p)| p == pid) {
            let (t, _) = self.strays.swap_remove(k);
            let _ = self.l.remove(t);
        }
        self.unwatched.retain(|(p, _)| *p != pid);
        Ok(proc::reap_pid(pid)?.map(|_| Reaped::Orphan(pid, status)))
    }

    fn slot(&mut self, slot: u16) -> Result<&mut Slot, Errno> {
        self.slots
            .get_mut(usize::from(slot))
            .ok_or(Errno(libc::EINVAL))
    }

    fn dir(&self, slot: u16) -> Result<BorrowedFd<'_>, Errno> {
        self.slots
            .get(usize::from(slot))
            .and_then(|s| s.dir.as_ref())
            .map(AsFd::as_fd)
            .ok_or(Errno(libc::EBADF))
    }

    /// Opens `name`'s directory and `cgroup.events` and watches the latter.
    fn watch(&mut self, slot: u16, name: &CStr) -> Result<(), Errno> {
        let dir = cgroup::open_dir_at(&self.comb, name)?;
        let events = cgroup::open_file_at(&dir, c"cgroup.events", libc::O_RDONLY)?;
        let id = cgroup::inode(&dir)?;
        let t = token(slot, Source::Events);
        match EVENTS_WATCH {
            Watch::Priority => self.l.add_priority(events.as_fd(), t).map_err(lp)?,
            Watch::Inotify => {
                let path = self
                    .comb_path
                    .join(OsStr::from_bytes(name.to_bytes()))
                    .join("cgroup.events");
                self.l.add_inotify(&path, libc::IN_MODIFY, t).map_err(lp)?;
            }
        }
        let s = self.slot(slot)?;
        s.dir = Some(dir);
        s.events = Some(events);
        s.id = id;
        Ok(())
    }

    /// Watches a spawned child's exec-error pipe, pidfd and readiness pipe.
    fn watch_spawn(
        &mut self,
        slot: u16,
        err_r: &OwnedFd,
        pidfd: &OwnedFd,
        ready: Option<&OwnedFd>,
    ) -> Result<(), Errno> {
        self.l
            .add_fd(err_r.as_fd(), token(slot, Source::ExecError))
            .map_err(lp)?;
        self.l
            .add_pidfd(pidfd.as_fd(), token(slot, Source::Main))
            .map_err(lp)?;
        if let Some(r) = ready {
            self.l
                .add_fd(r.as_fd(), token(slot, Source::Ready))
                .map_err(lp)?;
        }
        Ok(())
    }
}

impl Effects for Kernel {
    fn create(&mut self, slot: u16, name: &CStr) -> Result<(), Errno> {
        cgroup::mkdir_at(&self.comb, name, 0o755)?;
        self.watch(slot, name)
    }

    fn open_existing(&mut self, slot: u16, name: &CStr) -> Result<(u64, bool), Errno> {
        self.watch(slot, name)?;
        let (populated, _) = self.read_level(slot)?;
        Ok((self.slot(slot)?.id, populated))
    }

    fn read_level(&mut self, slot: u16) -> Result<(bool, bool), Errno> {
        let events = self.slot(slot)?.events.as_ref().ok_or(Errno(libc::EBADF))?;
        let mut buf = [0u8; 128];
        let n = cgroup::read_from_start(events, &mut buf)?;
        parse_events(&buf[..n]).ok_or(Errno(libc::EPROTO))
    }

    fn spawn(&mut self, slot: u16, cmd: Command, ready: ReadyMode) -> Result<Handle, Errno> {
        let (err_r, err_w) = fd::pipe(libc::O_CLOEXEC)?;
        let pipe = match ready {
            ReadyMode::Pipe => Some(fd::pipe(libc::O_CLOEXEC)?),
            ReadyMode::Exit => None,
        };
        let mut routes: Vec<(BorrowedFd<'_>, RawFd)> =
            cmd.fds.iter().map(|(f, n)| (f.as_fd(), *n)).collect();
        if let Some((_, w)) = &pipe {
            routes.push((w.as_fd(), cmd.ready_fd));
        }
        let argv: Vec<&OsStr> = cmd.argv.iter().map(OsString::as_os_str).collect();
        let env: Vec<&OsStr> = cmd.env.iter().map(OsString::as_os_str).collect();
        let prepared = spawn::Prepared::new(&cmd.path, &argv, &env, &routes)?;
        let (pid, pidfd) = spawn::spawn(&prepared, Some(self.dir(slot)?), err_w.as_fd())?;
        drop(prepared);
        drop(routes);
        drop(err_w);
        let ready_r = pipe.map(|(r, w)| {
            drop(w);
            r
        });
        if let Err(e) = self.watch_spawn(slot, &err_r, &pidfd, ready_r.as_ref()) {
            // Unwatched, the child would run unsupervised: it is killed and let go.
            for s in [Source::ExecError, Source::Main, Source::Ready] {
                let _ = self.l.remove(token(slot, s));
            }
            let _ = proc::pidfd_signal(&pidfd, libc::SIGKILL);
            self.abandon(pid, pidfd);
            return Err(e);
        }
        let s = self.slot(slot)?;
        s.exec_err = Some(err_r);
        s.main = Some(Tracked {
            pid,
            pidfd,
            child: true,
        });
        s.ready = ready_r;
        Ok(u32::from(slot))
    }

    fn adopt_main(&mut self, slot: u16, pidfd: OwnedFd) -> Result<Handle, Errno> {
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))
            .map_err(|_| Errno(libc::EBADF))?;
        let pid = parse_fdinfo_pid(&info).ok_or(Errno(libc::ESRCH))?;
        // Readable once it exits, and never reaped here: a handed-over main need not be this
        // process's child, and its status is unknown (D8).
        self.l
            .add_fd(pidfd.as_fd(), token(slot, Source::Main))
            .map_err(lp)?;
        self.slot(slot)?.main = Some(Tracked {
            pid,
            pidfd,
            child: false,
        });
        Ok(u32::from(slot))
    }

    fn signal_main(&mut self, slot: u16, main: Handle, sig: Sig) -> Result<(), Errno> {
        if main != u32::from(slot) {
            return Err(Errno(libc::EINVAL));
        }
        // A process already reaped or gone is not an error: its exit is on its way to the
        // machine.
        match &self.slot(slot)?.main {
            Some(m) => proc::pidfd_signal(&m.pidfd, signo(sig)).map(|_| ()),
            None => Ok(()),
        }
    }

    fn freeze(&mut self, slot: u16, on: bool) -> Result<(), Errno> {
        cgroup::write_file_at(
            self.dir(slot)?,
            c"cgroup.freeze",
            if on { b"1" } else { b"0" },
        )
    }

    fn signal_members(&mut self, slot: u16, sig: Sig) -> Result<(), Errno> {
        let procs = cgroup::open_file_at(self.dir(slot)?, c"cgroup.procs", libc::O_RDONLY)?;
        let mut text = Vec::new();
        std::fs::File::from(procs)
            .read_to_end(&mut text)
            .map_err(|_| Errno(libc::EIO))?;
        let pids = parse_procs(&text).map_err(|_| Errno(libc::EPROTO))?;
        let id = self.slot(slot)?.id;
        for pid in pids {
            let pidfd = match proc::pidfd_open(pid) {
                Ok(p) => p,
                Err(Errno(libc::ESRCH)) => continue,
                Err(e) => return Err(e),
            };
            #[cfg(feature = "test-hooks")]
            if let Some(hook) = self.between.as_mut() {
                hook(pid);
            }
            // The pid may have been reused by a process outside the cell between the read and
            // the open: only a pidfd whose cgroup id is this cell's is signalled.
            match proc::pidfd_cgroup_id(&pidfd) {
                Ok(cg) if cg == id => {
                    // A member that exits before the signal (ESRCH) is skipped: `Ok(false)`.
                    proc::pidfd_signal(&pidfd, signo(sig))?;
                }
                Ok(_) | Err(Errno(libc::ESRCH)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn kill(&mut self, slot: u16) -> Result<(), Errno> {
        cgroup::write_file_at(self.dir(slot)?, c"cgroup.kill", b"1")
    }

    fn remove(&mut self, slot: u16, name: &CStr) -> Result<(), Errno> {
        let _ = self.l.remove(token(slot, Source::Events));
        let s = self.slot(slot)?;
        s.events = None;
        s.dir = None;
        cgroup::rmdir_at(&self.comb, name)
    }

    fn arm(&mut self, slot: u16, timer: Timer, ms: u32) -> Result<(), Errno> {
        self.l
            .add_deadline(
                Duration::from_millis(ms.into()),
                token(slot, timer_source(timer)),
            )
            .map_err(lp)
    }

    fn cancel(&mut self, slot: u16, timer: Timer) -> Result<(), Errno> {
        self.l.remove(token(slot, timer_source(timer))).map_err(lp)
    }

    fn read_ready(&mut self, slot: u16, buf: &mut [u8]) -> Result<usize, Errno> {
        let r = self.slot(slot)?.ready.as_ref().ok_or(Errno(libc::EBADF))?;
        event::read(r, buf)
    }

    fn read_exec_error(&mut self, slot: u16) -> Result<Option<Errno>, Errno> {
        let r = self
            .slot(slot)?
            .exec_err
            .as_ref()
            .ok_or(Errno(libc::EBADF))?;
        let mut b = [0u8; 4];
        match event::read(r, &mut b)? {
            0 => Ok(None),
            4 => Ok(Some(Errno(i32::from_ne_bytes(b)))),
            _ => Ok(Some(Errno(libc::EIO))),
        }
    }

    fn close(&mut self, slot: u16, source: Source) {
        let _ = self.l.remove(token(slot, source));
        let Ok(s) = self.slot(slot) else {
            return;
        };
        match source {
            Source::Ready => s.ready = None,
            Source::ExecError => s.exec_err = None,
            Source::Main => {
                if let Some(m) = s.main.take() {
                    self.abandon(m.pid, m.pidfd);
                }
            }
            Source::Events | Source::Grace | Source::Kill => {}
        }
    }

    fn release(&mut self, slot: u16) {
        for s in SOURCES {
            let _ = self.l.remove(token(slot, s));
        }
        let Ok(s) = self.slot(slot) else {
            return;
        };
        if let Some(m) = std::mem::take(s).main {
            self.abandon(m.pid, m.pidfd);
        }
    }

    fn reap_children(&mut self) -> Result<Vec<Reaped>, Errno> {
        if let Some(e) = self.reap_error.take() {
            return Err(e);
        }
        let mut out = Vec::new();
        let result = loop {
            match proc::peek_any() {
                Ok(Some((pid, status))) => match self.reap_one(pid, status) {
                    Ok(Some(r)) => out.push(r),
                    // A child the peek saw exited but no wait reaped: stop rather than spin.
                    Ok(None) => break Ok(()),
                    Err(e) => break Err(e),
                },
                Ok(None) => break Ok(()),
                Err(e) => break Err(e),
            }
        };
        // Children already reaped are reported; the error waits for the next call.
        match result {
            Err(e) if out.is_empty() => Err(e),
            Err(e) => {
                self.reap_error = Some(e);
                Ok(out)
            }
            Ok(()) => Ok(out),
        }
    }

    fn take_reaped(&mut self) -> Vec<(libc::pid_t, i32)> {
        std::mem::take(&mut self.reaped)
    }

    fn cgroup_id(&self, slot: u16) -> Option<u64> {
        self.slots
            .get(usize::from(slot))
            .filter(|s| s.dir.is_some())
            .map(|s| s.id)
    }
}
