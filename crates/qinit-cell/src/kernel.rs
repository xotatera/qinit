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

#[derive(Default)]
struct Slot {
    dir: Option<OwnedFd>,
    events: Option<OwnedFd>,
    id: u64,
    /// The main process until it is reaped (by the loop, or by `reap_children`).
    main: Option<(libc::pid_t, OwnedFd)>,
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
    /// watches each under its own token and reaps it; their exits never reach the engine.
    strays: Vec<(Token, libc::pid_t)>,
    next_stray: Token,
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
            #[cfg(feature = "test-hooks")]
            between: None,
        })
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
    /// main process is forgotten (its pid may be reused from now on), a stray is dropped and
    /// not reported.
    ///
    /// # Errors
    ///
    /// The loop's errno.
    pub fn wait(&mut self) -> Result<Vec<Ready>, Errno> {
        let mut out = self.l.wait().map_err(lp)?;
        out.retain(|r| match *r {
            Ready::Exited(t, _) => self.reaped_by_loop(t),
            _ => true,
        });
        Ok(out)
    }

    /// Whether an exit the loop reaped is reported.
    fn reaped_by_loop(&mut self, t: Token) -> bool {
        if let Some(k) = self.strays.iter().position(|&(s, _)| s == t) {
            self.strays.swap_remove(k);
            return false;
        }
        if let Some((slot, Source::Main)) = route(t)
            && let Ok(s) = self.slot(slot)
        {
            s.main = None;
        }
        true
    }

    /// Lets a child go that no cell tracks any more, without leaving a zombie: reaped now if
    /// it has exited, else watched as a stray until it does. A process that is not this one's
    /// child (an adopted main) has nothing to reap.
    fn abandon(&mut self, pid: libc::pid_t, pidfd: &OwnedFd) {
        if !matches!(proc::reap_pidfd(pidfd), Ok(None)) {
            return;
        }
        let t = self.next_stray;
        self.next_stray += 1;
        // Should the loop refuse, a subreaper still reaps it as an orphan.
        if self.l.add_pidfd(pidfd.as_fd(), t).is_ok() {
            self.strays.push((t, pid));
        }
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
            self.abandon(pid, &pidfd);
            return Err(e);
        }
        let s = self.slot(slot)?;
        s.exec_err = Some(err_r);
        s.main = Some((pid, pidfd));
        s.ready = ready_r;
        Ok(u32::from(slot))
    }

    fn adopt_main(&mut self, slot: u16, pidfd: OwnedFd) -> Result<Handle, Errno> {
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))
            .map_err(|_| Errno(libc::EBADF))?;
        let pid = parse_fdinfo_pid(&info).ok_or(Errno(libc::ESRCH))?;
        self.l
            .add_pidfd(pidfd.as_fd(), token(slot, Source::Main))
            .map_err(lp)?;
        self.slot(slot)?.main = Some((pid, pidfd));
        Ok(u32::from(slot))
    }

    fn signal_main(&mut self, slot: u16, main: Handle, sig: Sig) -> Result<(), Errno> {
        if main != u32::from(slot) {
            return Err(Errno(libc::EINVAL));
        }
        // A process already reaped or gone is not an error: its exit is on its way to the
        // machine.
        match &self.slot(slot)?.main {
            Some((_, pidfd)) => proc::pidfd_signal(pidfd, signo(sig)).map(|_| ()),
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
                if let Some((pid, pidfd)) = s.main.take() {
                    self.abandon(pid, &pidfd);
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
        if let Some((pid, pidfd)) = std::mem::take(s).main {
            self.abandon(pid, &pidfd);
        }
    }

    fn reap_children(&mut self) -> Result<Vec<Reaped>, Errno> {
        let mut out = Vec::new();
        while let Some((pid, status)) = proc::peek_any()? {
            let tracked = self
                .slots
                .iter()
                .position(|s| s.main.as_ref().is_some_and(|(p, _)| *p == pid));
            let reaped = if let Some(slot) = tracked.and_then(|i| u16::try_from(i).ok()) {
                // The loop's copy goes first, so the loop never reaps it as well.
                let _ = self.l.remove(token(slot, Source::Main));
                let main = self.slot(slot)?.main.take();
                out.push(Reaped::Main(slot, status));
                match main {
                    Some((_, pidfd)) => proc::reap_pidfd(&pidfd)?,
                    None => None,
                }
            } else {
                if let Some(k) = self.strays.iter().position(|&(_, p)| p == pid) {
                    let (t, _) = self.strays.swap_remove(k);
                    let _ = self.l.remove(t);
                }
                out.push(Reaped::Orphan(pid, status));
                proc::reap_pid(pid)?
            };
            // A child the peek saw exited but no wait reaped: stop rather than spin on it.
            if reaped.is_none() {
                break;
            }
        }
        Ok(out)
    }

    fn cgroup_id(&self, slot: u16) -> Option<u64> {
        self.slots
            .get(usize::from(slot))
            .filter(|s| s.dir.is_some())
            .map(|s| s.id)
    }
}
