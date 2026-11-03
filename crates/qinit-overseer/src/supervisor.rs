// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The supervisor of a pid-namespace launch (spec §3, M2): the process that stays behind while
//! its child goes on. It holds no capability, forwards the termination signals, reaps, and
//! relays the child's status. A pid-namespace launch has two: one outside, one as the init.
use crate::identity::Identity;
use qinit_sys::cred::{
    CAP_LAST, capbset_drop, capset, set_dumpable, set_no_new_privs, setgroups, setresgid, setresuid,
};
use qinit_sys::event::{epoll, epoll_add, epoll_wait, read_signal, signalfd_blocking};
use qinit_sys::{Errno, Result, proc, signal};
use std::os::fd::{AsRawFd, OwnedFd};

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
    for cap in 0..=CAP_LAST {
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
        match code - 128 {
            n @ 1..=31 if decode => sig = n,
            _ => proc::exit_now(code),
        }
    }
    // The dispositions were never changed and the mask is lifted, so the kill ends this
    // process; a namespace init-like process that ignores it falls back to the shell's code.
    let _ = signal::unblock_all();
    let _ = proc::kill(proc::pid(), sig);
    proc::exit_now(128 + sig)
}

fn watch(child: libc::pid_t, decode: bool) -> Result<()> {
    let sigs: Vec<libc::c_int> = FORWARDED.iter().copied().chain([libc::SIGCHLD]).collect();
    let sfd = signalfd_blocking(&sigs)?;
    let ep = epoll()?;
    epoll_add(&ep, sfd.as_raw_fd(), libc::EPOLLIN as u32, 0)?;
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
    loop {
        // SIGCHLD is queued only once blocked, so look before every wait.
        if let Some(status) = proc::reap_pid(child)? {
            relay(status, decode);
        }
        // What the child orphaned (the init of a pid namespace inherits it) is reaped too.
        while proc::reap_any()?.is_some() {}
        while let Some(sig) = read_signal(&sfd) {
            match libc::c_int::try_from(sig) {
                Ok(sig) if FORWARDED.contains(&sig) => {
                    let _ = proc::kill(child, sig);
                }
                _ => {}
            }
        }
        epoll_wait(&ep, &mut events)?;
    }
}

/// Becomes the supervisor of `child`. `status` is this process's copy of the status pipe,
/// closed at once so that EOF on it is the child's exec and nothing else. `decode`: see
/// [`relay`].
pub fn supervise(child: libc::pid_t, id: &Identity, status: OwnedFd, decode: bool) -> ! {
    drop(status);
    if drop_privileges(id).is_err() {
        let _ = proc::kill(child, libc::SIGKILL);
        proc::exit_now(127);
    }
    let _ = watch(child, decode);
    let _ = proc::kill(child, libc::SIGKILL);
    proc::exit_now(127)
}
