// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The kernel facts the cell substrate relies on (spec 2026-10-27 §5.3, plan P9).
use qinit_event::Loop;
use qinit_vm_guests::{COMB, await_events, make_cell, run, spawn_helper};
use std::ffi::CString;
use std::os::fd::AsFd;

fn e<T, E: std::fmt::Display>(r: Result<T, E>) -> Result<T, String> {
    r.map_err(|x| x.to_string())
}

fn remove(name: &str) -> Result<(), String> {
    let comb = qinit_vm_guests::comb()?;
    e(qinit_sys::cgroup::rmdir_at(
        &comb,
        &CString::new(name).map_err(|x| x.to_string())?,
    ))
}

/// The child is in its cell from its first instruction.
fn placement() -> Result<(), String> {
    let (cell, _events) = make_cell("place")?;
    let (pid, pidfd) = spawn_helper(cell.as_fd(), "wait-term")?;
    let text = e(std::fs::read_to_string(format!("/proc/{pid}/cgroup")))?;
    let want = "0::/qinit-test/place\n";
    e(qinit_sys::proc::pidfd_signal(&pidfd, libc::SIGTERM))?;
    e(qinit_sys::proc::wait_pidfd(&pidfd))?;
    remove("place")?;
    if text == want {
        Ok(())
    } else {
        Err(format!("/proc/{pid}/cgroup is {text:?}, want {want:?}"))
    }
}

fn events_by(name: &str, inotify: bool) -> Result<(), String> {
    let (cell, events) = make_cell(name)?;
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
    await_events(&mut l, 1, events.as_fd(), Some(true), None)?;
    e(qinit_sys::proc::pidfd_signal(&pidfd, libc::SIGTERM))?;
    await_events(&mut l, 1, events.as_fd(), Some(false), None)?;
    e(qinit_sys::proc::wait_pidfd(&pidfd))?;
    remove(name)
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
    remove("id")?;
    if by_inode == by_pidfd {
        Ok(())
    } else {
        Err(format!("inode {by_inode} != pidfd cgroup id {by_pidfd}"))
    }
}

/// Freezing and thawing a populated cell are reported in `cgroup.events`.
fn freeze() -> Result<(), String> {
    let (cell, events) = make_cell("frz")?;
    let mut l = e(Loop::new())?;
    e(l.add_priority(events.as_fd(), 1))?;
    let (_pid, pidfd) = spawn_helper(cell.as_fd(), "wait-term")?;
    e(qinit_sys::cgroup::write_file_at(
        &cell,
        c"cgroup.freeze",
        b"1",
    ))?;
    await_events(&mut l, 1, events.as_fd(), None, Some(true))?;
    e(qinit_sys::cgroup::write_file_at(
        &cell,
        c"cgroup.freeze",
        b"0",
    ))?;
    await_events(&mut l, 1, events.as_fd(), None, Some(false))?;
    e(qinit_sys::proc::pidfd_signal(&pidfd, libc::SIGTERM))?;
    e(qinit_sys::proc::wait_pidfd(&pidfd))?;
    remove("frz")
}

/// `cgroup.kill` empties a cell whose member ignores TERM.
fn kill() -> Result<(), String> {
    let (cell, events) = make_cell("kil")?;
    let mut l = e(Loop::new())?;
    e(l.add_priority(events.as_fd(), 1))?;
    let (_pid, pidfd) = spawn_helper(cell.as_fd(), "ignore-term")?;
    await_events(&mut l, 1, events.as_fd(), Some(true), None)?;
    e(qinit_sys::cgroup::write_file_at(
        &cell,
        c"cgroup.kill",
        b"1",
    ))?;
    await_events(&mut l, 1, events.as_fd(), Some(false), None)?;
    let raw = e(qinit_sys::proc::wait_pidfd(&pidfd))?;
    remove("kil")?;
    if libc::WIFSIGNALED(raw) && libc::WTERMSIG(raw) == libc::SIGKILL {
        Ok(())
    } else {
        Err(format!("status {raw:#x}, want SIGKILL"))
    }
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
