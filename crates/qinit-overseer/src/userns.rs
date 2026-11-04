// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The user namespace (sandbox design §3, §4 step 8). Only a process in the host user
//! namespace with `CAP_SETUID` and `CAP_SETGID` there may map ids other than its own, so a
//! forked map writer, which stays behind in the host namespace as real root, writes the maps of
//! the process that unshares.
#![allow(clippy::missing_errors_doc)] // each function returns the errno of what failed
use crate::identity::Identity;
use qinit_sys::{Errno, Result, fd, ns, proc};
use std::fmt::Write as _;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

/// A directory descriptor of the host's `/proc/self`, opened before the view hides `/proc`: the
/// writer reaches the maps of the process through it.
pub fn proc_self() -> Result<OwnedFd> {
    fd::open_cloexec(c"/proc/self", libc::O_PATH | libc::O_DIRECTORY, 0)
}

/// Writes `text` to `name` below the `/proc/self` descriptor `dir`.
fn put(dir: BorrowedFd<'_>, name: &std::ffi::CStr, text: &str) -> Result<()> {
    let file = fd::openat_cloexec(dir, name, libc::O_WRONLY)?;
    fd::write_all(file.as_fd(), text.as_bytes())
}

/// The bodies of `gid_map` and `uid_map`, in that order. An own map maps the one inside id the
/// service runs as onto the outside user and group; a range map maps inside 0 onto them and
/// inside `1..=count` onto the user's subordinate ranges, so any inside id up to `count` is
/// mapped.
pub fn map_text(id: &Identity, range: bool, inside: (u32, u32)) -> Result<(String, String)> {
    if !range {
        return Ok((
            format!("{} {} 1\n", inside.1, id.gid),
            format!("{} {} 1\n", inside.0, id.uid),
        ));
    }
    let (Some((gf, gc)), Some((uf, uc))) = (id.subgid, id.subuid) else {
        return Err(Errno(libc::EINVAL));
    };
    let mut gids = format!("0 {} 1\n", id.gid);
    let mut uids = format!("0 {} 1\n", id.uid);
    let _ = writeln!(gids, "1 {gf} {gc}");
    let _ = writeln!(uids, "1 {uf} {uc}");
    Ok((gids, uids))
}

/// The map writer's work: `setgroups`, `gid_map`, `uid_map`. An own map denies `setgroups`, a
/// range map allows it.
fn write_maps(dir: BorrowedFd<'_>, maps: &(String, String), range: bool) -> Result<()> {
    put(dir, c"setgroups", if range { "allow" } else { "deny" })?;
    put(dir, c"gid_map", &maps.0)?;
    put(dir, c"uid_map", &maps.1)
}

/// The writer process: waits for the go byte, writes the maps and exits with 0, or with the
/// errno of what failed.
fn writer(dir: BorrowedFd<'_>, maps: &(String, String), range: bool, go: BorrowedFd<'_>) -> ! {
    let code = match fd::read_byte(go) {
        Ok(Some(_)) => match write_maps(dir, maps, range) {
            Ok(()) => 0,
            Err(Errno(e)) => e.clamp(1, 255),
        },
        _ => libc::ECANCELED,
    };
    proc::exit_now(code)
}

/// Unshares a user namespace with the maps of `id` for a service that runs as the `inside` user and
/// group id (see [`map_text`]): forks the writer, `unshare`s, lets the writer go, and fails
/// unless it exited 0. `dir` is [`proc_self`].
pub fn enter(dir: &OwnedFd, id: &Identity, range: bool, inside: (u32, u32)) -> Result<()> {
    let maps = map_text(id, range, inside)?;
    let (go_r, go_w) = fd::pipe(libc::O_CLOEXEC)?;
    let pid = proc::fork()?;
    if pid == 0 {
        drop(go_w);
        writer(dir.as_fd(), &maps, range, go_r.as_fd());
    }
    drop(go_r);
    let unshared = ns::unshare(libc::CLONE_NEWUSER);
    if unshared.is_ok() {
        let _ = fd::write_all(go_w.as_fd(), b"x");
    }
    // The pipe's end is the writer's cue to give up when the unshare failed.
    drop(go_w);
    let status = proc::wait_pid(pid)?;
    unshared?;
    if status == 0 {
        Ok(())
    } else {
        // Bits 0..=6 are the signal that ended it, 0 for an exit with a code in bits 8..=15.
        let signalled = status & 0x7f != 0;
        Err(Errno(if signalled {
            libc::EIO
        } else {
            (status >> 8) & 0xff
        }))
    }
}
