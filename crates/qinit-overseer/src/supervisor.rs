// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The supervisor of a pid-namespace launch (spec §3, M2): the process that stays behind while
//! its child goes on. It holds no capability, forwards the termination signals, reaps, and
//! relays the child's status. A pid-namespace launch has two: one outside, one as the init.
use crate::identity::Identity;
use crate::status::Status;
use qinit_sys::cred::{
    cap_last, capbset_drop, capset, set_dumpable, set_no_new_privs, setgroups, setresgid, setresuid,
};
use qinit_sys::event::{epoll, epoll_add, epoll_wait, read_signal, signalfd_blocking};
use qinit_sys::timer::Alarm;
use qinit_sys::{Errno, Result, fd, proc, signal};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

/// The signals forwarded to the child.
const FORWARDED: [libc::c_int; 6] = [
    libc::SIGTERM,
    libc::SIGINT,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGUSR1,
    libc::SIGUSR2,
];

/// Drops everything but the right to signal the child: the supervisor's uid is the service's.
fn drop_privileges(id: &Identity) -> Result<()> {
    setgroups(&id.groups)?;
    setresgid(id.gid)?;
    for cap in 0..=cap_last()? {
        match capbset_drop(cap) {
            // A kernel that does not know the capability has nothing to drop.
            Ok(()) | Err(Errno(libc::EINVAL)) => {}
            Err(e) => return Err(e),
        }
    }
    setresuid(id.uid)?;
    capset(0, 0, 0)?;
    set_dumpable(false)?;
    set_no_new_privs()
}

/// Ends this process the way the child ended: its exit code, or its signal re-raised. With
/// `decode`, an exit code of `128 + n` (`n` a signal number) counts as death by signal `n`:
/// the init of a pid namespace cannot raise a default-action signal on itself, so it exits
/// with the shell's code and the supervisor outside turns that back into the signal.
fn relay(wait_status: i32, decode: bool) -> ! {
    let mut sig = wait_status & 0x7f;
    if sig == 0 {
        let code = (wait_status >> 8) & 0xff;
        match death_signal(code) {
            Some(n) if decode => sig = n,
            _ => proc::exit_now(code),
        }
    }
    // The dispositions were never changed and the mask is lifted, so the kill ends this
    // process; a namespace init-like process that ignores it falls back to the shell's code.
    let _ = signal::unblock_all();
    let _ = proc::kill(proc::pid(), sig);
    proc::exit_now(128 + sig)
}

/// The signal that an exit code of `128 + n` stands for, when `n` is one whose default action
/// ends the process. The stopping signals (`SIGSTOP`, `SIGTSTP`, `SIGTTIN`, `SIGTTOU`) are
/// left out: raising one on the supervisor would stop it instead of ending it, and colony
/// would see a stopped process rather than the exit.
#[must_use]
pub fn death_signal(code: i32) -> Option<i32> {
    match code - 128 {
        libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU => None,
        n @ 1..=31 => Some(n),
        _ => None,
    }
}

fn watch(child: libc::pid_t, decode: bool) -> Result<()> {
    let sigs: Vec<libc::c_int> = FORWARDED.iter().copied().chain([libc::SIGCHLD]).collect();
    let sfd = signalfd_blocking(&sigs)?;
    let ep = epoll()?;
    epoll_add(&ep, sfd.as_raw_fd(), libc::EPOLLIN as u32, 0)?;
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
    loop {
        // Drain the signals first and reap after: a child that ends once it has been looked
        // at leaves its SIGCHLD pending, so the wait below returns. Reaping first would let
        // the drain swallow the one SIGCHLD of an exit that came in between.
        while let Some(sig) = read_signal(&sfd) {
            match libc::c_int::try_from(sig) {
                Ok(sig) if FORWARDED.contains(&sig) => {
                    let _ = proc::kill(child, sig);
                }
                _ => {}
            }
        }
        if let Some(status) = proc::reap_pid(child)? {
            relay(status, decode);
        }
        // What the child orphaned (the init of a pid namespace inherits it) is reaped too.
        while proc::reap_any()?.is_some() {}
        epoll_wait(&ep, &mut events)?;
    }
}

/// Becomes the supervisor of `child`. `status` is this process's copy of the status pipe: it
/// carries the failure record of `step` (the plan's `Fork`) when the supervisor cannot drop
/// its privileges, and is closed once they are dropped, so that EOF on it is the child's exec
/// and nothing else. Every other inherited descriptor is closed at once: they are the
/// parent's, and holding them would keep its pipes from ever reaching EOF: the standard streams
/// and the readiness pipe are open by now, because the outputs are opened before the fork, and
/// they belong to the service. `alarm`, the outside supervisor's deadline timer, is deleted: the
/// service has its own, armed again after the fork. `decode`: see [`relay`].
pub fn supervise(
    child: libc::pid_t,
    id: &Identity,
    status: OwnedFd,
    step: u32,
    decode: bool,
    alarm: Option<Alarm>,
) -> ! {
    if let Some(a) = alarm {
        let _ = a.delete();
    }
    let _ = fd::close_range(0, 3);
    let _ = fd::close_from(5);
    if let Err(e) = drop_privileges(id) {
        let _ = proc::kill(child, libc::SIGKILL);
        Status { step, errno: e.0 }.write(status.as_fd());
        proc::exit_now(127);
    }
    drop(status);
    let _ = fd::close_from(0);
    let _ = watch(child, decode);
    let _ = proc::kill(child, libc::SIGKILL);
    proc::exit_now(127)
}
