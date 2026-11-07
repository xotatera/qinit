// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The system behind [`Io`]: one epoll instance over a signalfd, a timerfd and colony's channel.
use crate::run::{Io, Message, Recv, Sent};
use crate::spawn;
use qinit_ipc::{recv, send_nowait, seqpacket_pair};
use qinit_queen_core::Mode;
use qinit_sys::spawn::{Session, exec_in_place};
use qinit_sys::{Errno, event, fd, proc, signal, timer};
use std::ffi::{CString, OsStr, OsString};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::time::Duration;

/// Epoll tokens.
pub const SIGNALS: u64 = 1;
pub const TIMER: u64 = 2;
pub const CHANNEL: u64 = 3;

/// The descriptors and settings queen works with.
pub struct RealIo {
    pub ep: OwnedFd,
    pub sigfd: OwnedFd,
    pub timerfd: OwnedFd,
    /// `/dev/kmsg`, or the console when that would not open.
    pub log_fd: OwnedFd,
    /// The console children get on 0, 1 and 2.
    pub console: OwnedFd,
    channel: Option<OwnedFd>,
    writable: bool,
    env: Vec<OsString>,
}

impl RealIo {
    #[must_use]
    pub fn new(
        ep: OwnedFd,
        sigfd: OwnedFd,
        timerfd: OwnedFd,
        log_fd: OwnedFd,
        console: OwnedFd,
    ) -> RealIo {
        let env = std::env::vars_os()
            .map(|(k, v)| {
                let mut kv = k;
                kv.push("=");
                kv.push(v);
                kv
            })
            .collect();
        RealIo {
            ep,
            sigfd,
            timerfd,
            log_fd,
            console,
            channel: None,
            writable: false,
            env,
        }
    }

    /// The raw descriptor of colony's channel, for the loop's wake-up flags.
    #[must_use]
    pub fn channel_fd(&self) -> Option<i32> {
        self.channel.as_ref().map(AsRawFd::as_raw_fd)
    }

    fn env(&self) -> Vec<&OsStr> {
        self.env.iter().map(OsString::as_os_str).collect()
    }

    fn events(on: bool) -> u32 {
        let mut e = libc::EPOLLIN as u32;
        if on {
            e |= libc::EPOLLOUT as u32;
        }
        e
    }

    /// Drops the channel and its registration.
    fn drop_channel(&mut self) {
        if let Some(c) = self.channel.take() {
            let _ = event::epoll_del(&self.ep, c.as_raw_fd());
        }
        self.writable = false;
    }
}

impl Io for RealIo {
    fn now_ms(&mut self) -> u64 {
        timer::now_monotonic_ns() / 1_000_000
    }

    fn spawn_colony(&mut self) -> Result<i32, Errno> {
        let (mine, theirs) = seqpacket_pair().map_err(|e| Errno(e.0))?;
        fd::set_nonblocking(&mine)?;
        let env = self.env();
        let pid = spawn::start(
            spawn::COLONY,
            &spawn::colony_argv(),
            &env,
            self.console.as_fd(),
            Some(theirs.as_fd()),
            Session::New,
        )?;
        drop(theirs);
        self.drop_channel();
        // A channel that cannot be watched is a colony that cannot be heard.
        event::epoll_add(&self.ep, mine.as_raw_fd(), Self::events(false), CHANNEL)?;
        self.channel = Some(mine);
        Ok(pid)
    }

    fn spawn_rescue(&mut self) -> Result<i32, Errno> {
        let env = self.env();
        spawn::start(
            spawn::RESCUE,
            &["rescue"],
            &env,
            self.console.as_fd(),
            None,
            Session::Console,
        )
    }

    fn exec_zero(&mut self, mode: Mode) -> Errno {
        let (Ok(path), Ok(argv), Ok(env)) = (
            CString::new(spawn::ZERO),
            spawn::zero_argv(mode)
                .iter()
                .map(|a| CString::new(*a))
                .collect::<Result<Vec<_>, _>>(),
            self.env
                .iter()
                .map(|e| CString::new(e.as_bytes()))
                .collect::<Result<Vec<_>, _>>(),
        ) else {
            return Errno(libc::EINVAL);
        };
        let argv: Vec<&std::ffi::CStr> = argv.iter().map(CString::as_c_str).collect();
        let env: Vec<&std::ffi::CStr> = env.iter().map(CString::as_c_str).collect();
        // Zero starts with every signal unblocked; a failed exec blocks them again.
        let _ = signal::unblock_all();
        let e = exec_in_place(&path, &argv, &env);
        let _ = signal::block_all_but_fatal();
        e
    }

    fn kill(&mut self, pid: i32) {
        let _ = proc::kill(pid, libc::SIGKILL);
    }

    fn cad_on(&mut self) {
        let _ = proc::cad_on();
    }

    fn arm(&mut self, ms: Option<u64>) {
        let _ = event::timer_set(&self.timerfd, ms.map(Duration::from_millis));
    }

    fn log(&mut self, line: &[u8]) {
        let _ = fd::write_all(self.log_fd.as_fd(), line);
    }

    fn reap(&mut self) -> Option<(i32, i32)> {
        proc::reap_any().ok().flatten()
    }

    fn recv(&mut self) -> Recv {
        let Some(chan) = self.channel.as_ref() else {
            return Recv::Empty;
        };
        let mut bytes = [0u8; 32];
        match recv(chan.as_fd(), &mut bytes) {
            Err(qinit_ipc::Errno(libc::EAGAIN)) => Recv::Empty,
            Err(_) => {
                self.drop_channel();
                Recv::Closed
            }
            Ok(r) if r.len == 0 && r.fds.is_empty() && !r.truncated => {
                self.drop_channel();
                Recv::Closed
            }
            Ok(r) => Recv::Message(Message {
                bytes,
                len: r.len,
                fds: r.fds,
                truncated: r.truncated || r.ctrunc,
            }),
        }
    }

    fn send(&mut self, record: &[u8; 16], held: Option<BorrowedFd<'_>>) -> Sent {
        let Some(chan) = self.channel.as_ref() else {
            return Sent::Gone;
        };
        let fds: Vec<BorrowedFd<'_>> = held.into_iter().collect();
        match send_nowait(chan.as_fd(), record, &fds) {
            Ok(()) => Sent::Ok,
            Err(qinit_ipc::Errno(libc::EAGAIN)) => Sent::Again,
            Err(_) => Sent::Gone,
        }
    }

    fn want_writable(&mut self, on: bool) {
        if on == self.writable {
            return;
        }
        let Some(chan) = self.channel.as_ref() else {
            return;
        };
        let n = chan.as_raw_fd();
        let _ = event::epoll_del(&self.ep, n);
        if event::epoll_add(&self.ep, n, Self::events(on), CHANNEL).is_ok() {
            self.writable = on;
        }
    }
}
