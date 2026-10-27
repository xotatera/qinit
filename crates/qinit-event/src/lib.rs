// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! `qinit-event`: the driver half of the four layers (spec 2026-10-27 §5.3). One epoll loop
//! turns fd readiness, priority notifications (`cgroup.events`), process exit by pidfd,
//! timerfd deadlines, signals and inotify into [`Ready`] values. Nothing waits by sleeping.
//! Seeded from alloy's `common-event`.
use qinit_sys::{Errno, event};
use std::collections::HashMap;
use std::ffi::OsString;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::time::Duration;

pub use qinit_event_core::{Token, next_event};

/// What happened to a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ready {
    /// The fd has data (or EOF to read).
    Readable(Token),
    /// The peer closed and nothing is left to read.
    Hangup(Token),
    /// A priority notification: for `cgroup.events`, the file changed; re-read it.
    Priority(Token),
    /// The process behind a pidfd exited; its wait status. The source is removed and the
    /// process reaped.
    Exited(Token, i32),
    /// The deadline passed. The source is removed.
    Deadline(Token),
    Signal(Token, u32),
    /// `(mask, name)` of each inotify event.
    Inotify(Token, Vec<(u32, OsString)>),
}

/// Why the loop failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Sys {
        what: &'static str,
        errno: Errno,
    },
    DuplicateToken(Token),
    /// `wait` with no source registered: an error, never a hang.
    Empty,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Sys { what, errno } => write!(f, "{what}: {errno}"),
            Error::DuplicateToken(t) => write!(f, "token {t} is already registered"),
            Error::Empty => write!(f, "wait on an empty loop"),
        }
    }
}

impl std::error::Error for Error {}

fn sys<T>(r: qinit_sys::Result<T>, what: &'static str) -> Result<T, Error> {
    r.map_err(|errno| Error::Sys { what, errno })
}

/// Exit code of a wait status (`128 + signal` when killed).
#[must_use]
pub fn exit_code(raw: i32) -> i32 {
    if libc::WIFEXITED(raw) {
        libc::WEXITSTATUS(raw)
    } else {
        128 + libc::WTERMSIG(raw)
    }
}

/// A registered source; owned fds are held open until the source is removed.
enum Source {
    Fd,
    Priority,
    /// The loop's own duplicate of the caller's pidfd: the caller keeps its pidfd for
    /// signalling, and this crate forbids `unsafe`, so it cannot borrow a raw number.
    Pidfd(OwnedFd),
    Deadline {
        _timer: OwnedFd,
    },
    Signal(OwnedFd),
    Inotify(OwnedFd),
}

/// An epoll loop. Sources are level-triggered; one-shot sources (deadlines, pidfds) remove
/// themselves when they report.
pub struct Loop {
    ep: OwnedFd,
    sources: HashMap<Token, (RawFd, Source)>,
}

const IN: u32 = libc::EPOLLIN as u32;

impl Loop {
    /// An empty loop.
    ///
    /// # Errors
    ///
    /// [`Error::Sys`] when `epoll_create1` fails.
    pub fn new() -> Result<Loop, Error> {
        Ok(Loop {
            ep: sys(event::epoll(), "epoll_create1")?,
            sources: HashMap::new(),
        })
    }

    fn register(&mut self, fd: RawFd, events: u32, token: Token, src: Source) -> Result<(), Error> {
        if self.sources.contains_key(&token) {
            return Err(Error::DuplicateToken(token));
        }
        sys(
            event::epoll_add(&self.ep, fd, events, token),
            "epoll_ctl add",
        )?;
        self.sources.insert(token, (fd, src));
        Ok(())
    }

    /// Reports `Readable` while `fd` has data, `Hangup` once the peer closed and nothing is left.
    ///
    /// # Errors
    ///
    /// [`Error::DuplicateToken`] when `token` is registered; [`Error::Sys`] when the kernel
    /// refuses the registration.
    pub fn add_fd(&mut self, fd: BorrowedFd<'_>, token: Token) -> Result<(), Error> {
        let events = (libc::EPOLLIN | libc::EPOLLRDHUP) as u32;
        self.register(fd.as_raw_fd(), events, token, Source::Fd)
    }

    /// Reports `Priority` while `fd` has a priority notification (kernfs files such as
    /// `cgroup.events` raise `EPOLLPRI` and `EPOLLERR` on change until re-read).
    ///
    /// # Errors
    ///
    /// [`Error::DuplicateToken`] when `token` is registered; [`Error::Sys`] when the kernel
    /// refuses the registration.
    pub fn add_priority(&mut self, fd: BorrowedFd<'_>, token: Token) -> Result<(), Error> {
        let events = (libc::EPOLLPRI | libc::EPOLLERR) as u32;
        self.register(fd.as_raw_fd(), events, token, Source::Priority)
    }

    /// Reports `Exited` once the process behind `pidfd` (a child of this process) exits, and
    /// reaps it; the caller must not reap it as well.
    ///
    /// # Errors
    ///
    /// [`Error::DuplicateToken`] when `token` is registered; [`Error::Sys`] when the kernel
    /// refuses the duplicate or the registration.
    pub fn add_pidfd(&mut self, pidfd: BorrowedFd<'_>, token: Token) -> Result<(), Error> {
        let dup = sys(qinit_sys::fd::dup_above(pidfd, 0), "dup a pidfd")?;
        let raw = dup.as_raw_fd();
        self.register(raw, IN, token, Source::Pidfd(dup))
    }

    /// Reports `Deadline` once, `after` from now (monotonic clock).
    ///
    /// # Errors
    ///
    /// [`Error::DuplicateToken`] when `token` is registered; [`Error::Sys`] when the kernel
    /// refuses the timerfd or the registration.
    pub fn add_deadline(&mut self, after: Duration, token: Token) -> Result<(), Error> {
        let t = sys(event::timer(after), "timerfd")?;
        let raw = t.as_raw_fd();
        self.register(raw, IN, token, Source::Deadline { _timer: t })
    }

    /// Blocks `signals` in the calling thread and reports each as `Signal`. Call it before
    /// other threads start if the signal is process-directed.
    ///
    /// # Errors
    ///
    /// [`Error::DuplicateToken`] when `token` is registered; [`Error::Sys`] when the kernel
    /// refuses the signal mask, the signalfd or the registration.
    pub fn add_signal(&mut self, signals: &[libc::c_int], token: Token) -> Result<(), Error> {
        let f = sys(event::signalfd_blocking(signals), "signalfd")?;
        let raw = f.as_raw_fd();
        self.register(raw, IN, token, Source::Signal(f))
    }

    /// Reports `Inotify` for events in `mask` on `path`.
    ///
    /// # Errors
    ///
    /// [`Error::DuplicateToken`] when `token` is registered; [`Error::Sys`] when the kernel
    /// refuses the inotify instance, the watch or the registration.
    pub fn add_inotify(&mut self, path: &Path, mask: u32, token: Token) -> Result<(), Error> {
        let f = sys(event::inotify(path, mask), "inotify_add_watch")?;
        let raw = f.as_raw_fd();
        self.register(raw, IN, token, Source::Inotify(f))
    }

    /// Stops reporting `token`; owned fds are closed.
    ///
    /// # Errors
    ///
    /// [`Error::Sys`] when `epoll_ctl` refuses the removal; the source is gone either way.
    pub fn remove(&mut self, token: Token) -> Result<(), Error> {
        let Some((fd, _src)) = self.sources.remove(&token) else {
            return Ok(());
        };
        // The fd is still open here (owned fds are dropped after this call).
        sys(event::epoll_del(&self.ep, fd), "epoll_ctl del")
    }

    /// Waits for the next events. `Exited` entries come first: the process is already reaped,
    /// so nothing else in the batch may be acted on as if it still ran.
    ///
    /// # Errors
    ///
    /// [`Error::Empty`] with no source registered; [`Error::Sys`] when `epoll_wait` fails or a
    /// pidfd cannot be reaped (that source is removed first).
    pub fn wait(&mut self) -> Result<Vec<Ready>, Error> {
        if self.sources.is_empty() {
            return Err(Error::Empty);
        }
        let mut evs = [libc::epoll_event { events: 0, u64: 0 }; 16];
        let n = sys(event::epoll_wait(&self.ep, &mut evs), "epoll_wait")?;
        let mut out = Vec::new();
        for ev in &evs[..n] {
            let (token, bits) = (ev.u64, ev.events);
            let Some((_, src)) = self.sources.get(&token) else {
                continue;
            };
            match src {
                Source::Fd => {
                    if bits & IN != 0 {
                        out.push(Ready::Readable(token));
                    } else if bits & (libc::EPOLLHUP | libc::EPOLLRDHUP | libc::EPOLLERR) as u32
                        != 0
                    {
                        out.push(Ready::Hangup(token));
                    }
                }
                Source::Priority => out.push(Ready::Priority(token)),
                Source::Pidfd(pidfd) => match qinit_sys::proc::reap_pidfd(pidfd) {
                    Ok(Some(status)) => {
                        self.remove(token)?;
                        out.push(Ready::Exited(token, status));
                    }
                    Ok(None) => {}
                    Err(errno) => {
                        self.remove(token)?;
                        return Err(Error::Sys {
                            what: "waitid P_PIDFD",
                            errno,
                        });
                    }
                },
                Source::Deadline { .. } => {
                    self.remove(token)?;
                    out.push(Ready::Deadline(token));
                }
                Source::Signal(f) => {
                    while let Some(signo) = event::read_signal(f) {
                        out.push(Ready::Signal(token, signo));
                    }
                }
                Source::Inotify(f) => {
                    let evs = read_inotify(f);
                    if !evs.is_empty() {
                        out.push(Ready::Inotify(token, evs));
                    }
                }
            }
        }
        out.sort_by_key(|r| !matches!(r, Ready::Exited(..)));
        Ok(out)
    }
}

impl Drop for Loop {
    fn drop(&mut self) {
        let tokens: Vec<Token> = self.sources.keys().copied().collect();
        for t in tokens {
            let _ = self.remove(t);
        }
    }
}

fn read_inotify(fd: &OwnedFd) -> Vec<(u32, OsString)> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 4096];
    while let Ok(n @ 1..) = event::read(fd, &mut buf) {
        out.extend(parse_inotify(&buf[..n]));
    }
    out
}

/// The `(mask, name)` of each complete `inotify_event` in `buf` (a truncated event ends the
/// parse).
#[must_use]
pub fn parse_inotify(buf: &[u8]) -> Vec<(u32, OsString)> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while let Some((mask, name, next)) = next_event(buf, off) {
        let name = &buf[name];
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        out.push((mask, OsString::from_vec(name[..end].to_vec())));
        off = next;
    }
    out
}
