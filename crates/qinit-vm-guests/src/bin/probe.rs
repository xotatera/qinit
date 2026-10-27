// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The kernel facts the cell substrate relies on (spec 2026-10-27 §5.3, plan P9). Every
//! notification case reads `cgroup.events` (clearing its pending priority state), registers
//! its watch and only then triggers the change, and accepts a state only after a notification
//! (`await_notified`).
use qinit_event::Loop;
use qinit_vm_guests::{
    COMB, await_notified, e, make_cell, read_events, run, spawn_helper, spawn_helper_routed,
};
use std::ffi::CString;
use std::io::Read;
use std::os::fd::AsFd;

fn remove(name: &str) -> Result<(), String> {
    let comb = qinit_vm_guests::comb()?;
    e(qinit_sys::cgroup::rmdir_at(
        &comb,
        &CString::new(name).map_err(|x| x.to_string())?,
    ))
}

/// The case's verdict, then its cleanup (removing cell `name`): a cleanup failure is
/// reported, never in place of a failed verdict.
fn finish(verdict: Result<(), String>, name: &str) -> Result<(), String> {
    match (verdict, remove(name)) {
        (Err(v), Err(c)) => Err(format!("{v}; cleanup: rmdir {name}: {c}")),
        (Err(v), Ok(())) => Err(v),
        (Ok(()), Err(c)) => Err(format!("cleanup: rmdir {name}: {c}")),
        (Ok(()), Ok(())) => Ok(()),
    }
}

/// The child runs in its cell from the start: the helper's first action reports its own
/// `/proc/self/cgroup`.
fn placement() -> Result<(), String> {
    let (cell, _events) = make_cell("place")?;
    let (r, w) = e(qinit_sys::fd::pipe(libc::O_CLOEXEC))?;
    let (_pid, pidfd) = spawn_helper_routed(cell.as_fd(), "report-cgroup", &[(w.as_fd(), 3)])?;
    drop(w);
    let mut text = String::new();
    e(std::fs::File::from(r).read_to_string(&mut text))?;
    let status = e(qinit_sys::proc::wait_pidfd(&pidfd))?;
    let want = "0::/qinit-test/place\n";
    let verdict = if status != 0 {
        Err(format!("report-cgroup helper status {status:#x}"))
    } else if text == want {
        Ok(())
    } else {
        Err(format!(
            "the helper's /proc/self/cgroup is {text:?}, want {want:?}"
        ))
    };
    finish(verdict, "place")
}

fn events_by(name: &str, inotify: bool) -> Result<(), String> {
    let (cell, events) = make_cell(name)?;
    read_events(events.as_fd())?;
    let mut l = e(Loop::new())?;
    if inotify {
        e(l.add_inotify(
            std::path::Path::new(&format!("{COMB}/{name}/cgroup.events")),
            libc::IN_MODIFY,
            1,
        ))?;
    } else {
        e(l.add_priority(events.as_fd(), 1))?;
    }
    let (_pid, pidfd) = spawn_helper(cell.as_fd(), "wait-term")?;
    await_notified(&mut l, 1, events.as_fd(), Some(true), None)?;
    e(qinit_sys::proc::pidfd_signal(&pidfd, libc::SIGTERM))?;
    await_notified(&mut l, 1, events.as_fd(), Some(false), None)?;
    e(qinit_sys::proc::wait_pidfd(&pidfd))?;
    finish(Ok(()), name)
}

/// `cgroup.events` changes raise EPOLLPRI on the open file.
fn events_priority() -> Result<(), String> {
    events_by("pri", false)
}

/// `cgroup.events` changes raise `IN_MODIFY`.
fn events_inotify() -> Result<(), String> {
    events_by("ino", true)
}

/// A cell's inode number is the cgroup id `PIDFD_GET_INFO` reports for a member (plan P9).
fn cgroup_id() -> Result<(), String> {
    let (cell, _events) = make_cell("id")?;
    let (_pid, pidfd) = spawn_helper(cell.as_fd(), "wait-term")?;
    let by_inode = e(qinit_sys::cgroup::inode(&cell))?;
    let by_pidfd = e(qinit_sys::proc::pidfd_cgroup_id(&pidfd))?;
    e(qinit_sys::proc::pidfd_signal(&pidfd, libc::SIGTERM))?;
    e(qinit_sys::proc::wait_pidfd(&pidfd))?;
    let verdict = if by_inode == by_pidfd {
        Ok(())
    } else {
        Err(format!("inode {by_inode} != pidfd cgroup id {by_pidfd}"))
    };
    finish(verdict, "id")
}

/// Freezing and thawing a populated cell are announced in `cgroup.events`.
fn freeze() -> Result<(), String> {
    let (cell, events) = make_cell("frz")?;
    read_events(events.as_fd())?;
    let mut l = e(Loop::new())?;
    e(l.add_priority(events.as_fd(), 1))?;
    let (_pid, pidfd) = spawn_helper(cell.as_fd(), "wait-term")?;
    await_notified(&mut l, 1, events.as_fd(), Some(true), Some(false))?;
    e(qinit_sys::cgroup::write_file_at(
        &cell,
        c"cgroup.freeze",
        b"1",
    ))?;
    await_notified(&mut l, 1, events.as_fd(), None, Some(true))?;
    e(qinit_sys::cgroup::write_file_at(
        &cell,
        c"cgroup.freeze",
        b"0",
    ))?;
    await_notified(&mut l, 1, events.as_fd(), None, Some(false))?;
    e(qinit_sys::proc::pidfd_signal(&pidfd, libc::SIGTERM))?;
    e(qinit_sys::proc::wait_pidfd(&pidfd))?;
    finish(Ok(()), "frz")
}

/// `cgroup.kill` empties a cell whose member ignores TERM: it blocks TERM before its
/// readiness byte, gets a TERM, and its status names SIGKILL (a TERM death would name
/// SIGTERM).
fn kill() -> Result<(), String> {
    let (cell, events) = make_cell("kil")?;
    read_events(events.as_fd())?;
    let mut l = e(Loop::new())?;
    e(l.add_priority(events.as_fd(), 1))?;
    let (r, w) = e(qinit_sys::fd::pipe(libc::O_CLOEXEC))?;
    let (_pid, pidfd) = spawn_helper_routed(cell.as_fd(), "ready-ignore-term", &[(w.as_fd(), 3)])?;
    drop(w);
    let mut ready = [0u8; 1];
    e(std::fs::File::from(r).read_exact(&mut ready))?;
    await_notified(&mut l, 1, events.as_fd(), Some(true), None)?;
    e(qinit_sys::proc::pidfd_signal(&pidfd, libc::SIGTERM))?;
    e(qinit_sys::cgroup::write_file_at(
        &cell,
        c"cgroup.kill",
        b"1",
    ))?;
    await_notified(&mut l, 1, events.as_fd(), Some(false), None)?;
    let raw = e(qinit_sys::proc::wait_pidfd(&pidfd))?;
    let verdict = if libc::WIFSIGNALED(raw) && libc::WTERMSIG(raw) == libc::SIGKILL {
        Ok(())
    } else {
        Err(format!("status {raw:#x}, want SIGKILL"))
    };
    finish(verdict, "kil")
}

fn main() {
    run(
        "probe",
        &[
            ("placement", placement),
            ("events_priority", events_priority),
            ("events_inotify", events_inotify),
            ("cgroup_id", cgroup_id),
            ("freeze", freeze),
            ("kill", kill),
        ],
    )
}
