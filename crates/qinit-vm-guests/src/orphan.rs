// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! An orphan on demand, for the guests whose PID 1 reaps: a grandchild that waits for a byte,
//! whose parent has already gone, so it is re-parented to PID 1.
use crate::e;
use crate::queened::spin_until;
use qinit_sys::proc::PidfdExit;
use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};

/// The orphan: its pidfd and the pipe that lets it go.
pub struct Orphan {
    pub pid: i32,
    pidfd: OwnedFd,
    go: OwnedFd,
}

/// Starts an orphan and waits until it exists.
pub fn start() -> Result<Orphan, String> {
    let (pid_r, pid_w) = e(qinit_sys::fd::pipe(libc::O_CLOEXEC))?;
    let (go_r, go_w) = e(qinit_sys::fd::pipe(libc::O_CLOEXEC))?;
    let a = e(qinit_sys::proc::fork())?;
    if a == 0 {
        // The first child: starts the orphan and leaves at once.
        match qinit_sys::proc::fork() {
            Ok(0) => {
                let me = std::process::id().to_ne_bytes();
                let _ = qinit_sys::fd::write_all(pid_w.as_fd(), &me);
                let _ = qinit_sys::fd::read_byte(go_r.as_fd());
                qinit_sys::proc::exit_now(0)
            }
            _ => qinit_sys::proc::exit_now(0),
        }
    }
    drop((pid_w, go_r));
    e(qinit_sys::proc::wait_pid(a))?;
    let mut buf = [0u8; 4];
    std::fs::File::from(pid_r)
        .read_exact(&mut buf)
        .map_err(|x| x.to_string())?;
    let pid = i32::from_ne_bytes(buf);
    let pidfd = e(qinit_sys::proc::pidfd_open(pid))?;
    Ok(Orphan {
        pid,
        pidfd,
        go: go_w,
    })
}

impl Orphan {
    /// Lets the orphan exit and waits until it has.
    pub fn exit(&self) -> Result<(), String> {
        e(qinit_sys::fd::write_all(self.go.as_fd(), b"x"))?;
        let ms = i32::try_from(crate::HANG_GUARD.as_millis()).unwrap_or(i32::MAX);
        if e(qinit_ipc::poll_readable(self.pidfd.as_fd(), ms))? {
            Ok(())
        } else {
            Err("the orphan never exited".into())
        }
    }

    /// Whether the orphan is a zombie nobody has reaped.
    pub fn is_zombie(&self) -> Result<bool, String> {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", self.pid))
            .map_err(|x| x.to_string())?;
        Ok(stat
            .rsplit(')')
            .next()
            .is_some_and(|r| r.trim().starts_with('Z')))
    }

    /// Waits until PID 1 has reaped the orphan: the kernel records its status then.
    pub fn await_reaped(&self) -> Result<(), String> {
        spin_until("the orphan reaped", || {
            matches!(
                qinit_sys::proc::pidfd_exit(&self.pidfd),
                Ok(PidfdExit::Exited(_))
            )
            .then_some(())
        })
    }
}
