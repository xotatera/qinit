// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Spawning into a cell: placement from the first instruction, exec failure reported, only
//! routed descriptors arrive (spec §6.2).
use qinit_cell::{Command, ReadyMode, Report};
use qinit_cell_core::Failure;
use qinit_event::Loop;
use qinit_vm_guests::{COMB, await_events, cells, e, expect, helper_cmd, remove, reports_of, run};
use std::io::Read;
use std::os::fd::AsFd;

/// The helper's first action copies its `/proc/self/cgroup` to a routed pipe; the cell tracks
/// its pid from the spawn until its exit is seen.
fn in_cell() -> Result<(), String> {
    let mut cells = cells()?;
    let id = e(cells.create("sp"))?;
    let (r, w) = e(qinit_sys::fd::pipe(libc::O_CLOEXEC))?;
    let mut cmd = helper_cmd("report-cgroup", &[]);
    cmd.fds.push((w, 3));
    e(cells.spawn(id, cmd, ReadyMode::Exit))?;
    let tracked = cells.main_pid(id);
    let seen = expect(&mut cells, id, Report::Empty)?;
    let after = cells.main_pid(id);
    let mut text = String::new();
    e(std::fs::File::from(r).read_to_string(&mut text))?;
    remove(&mut cells, id)?;
    let got = reports_of(&seen, id);
    let want = [Report::Created, Report::Ready, Report::Empty];
    if got != want {
        Err(format!("reports {got:?}, want {want:?}"))
    } else if text != "0::/qinit-test/sp\n" {
        Err(format!("the helper started in cgroup {text:?}"))
    } else if tracked.is_none() || after.is_some() {
        Err(format!(
            "main pid {tracked:?} after the spawn, {after:?} once empty"
        ))
    } else {
        Ok(())
    }
}

fn exec_failure() -> Result<(), String> {
    let mut cells = cells()?;
    let id = e(cells.create("sf"))?;
    let cmd = Command {
        path: "/nonexistent".into(),
        argv: vec!["x".into()],
        env: Vec::new(),
        fds: Vec::new(),
        ready_fd: 3,
    };
    e(cells.spawn(id, cmd, ReadyMode::Pipe))?;
    let seen = expect(&mut cells, id, Report::Failed(Failure::Spawn))?;
    // The failed child may still be exiting: a failed cell reports no level, so the cell's
    // emptiness is awaited directly before its directory can go.
    let events = e(qinit_sys::cgroup::open_file_at(
        qinit_vm_guests::comb()?,
        c"sf/cgroup.events",
        libc::O_RDONLY,
    ))?;
    let mut l = e(Loop::new())?;
    e(l.add_priority(events.as_fd(), 1))?;
    await_events(&mut l, 1, events.as_fd(), Some(false), None)?;
    remove(&mut cells, id)?;
    let got = reports_of(&seen, id);
    let want = [Report::Created, Report::Failed(Failure::Spawn)];
    if got == want {
        Ok(())
    } else {
        Err(format!("reports {got:?}, want {want:?} ({COMB}/sf)"))
    }
}

fn only_routed_fds() -> Result<(), String> {
    let mut cells = cells()?;
    let id = e(cells.create("sr"))?;
    let (r, w) = e(qinit_sys::fd::pipe(libc::O_CLOEXEC))?;
    let mut cmd = helper_cmd("fds", &[]);
    cmd.fds.push((w, 1));
    e(cells.spawn(id, cmd, ReadyMode::Exit))?;
    expect(&mut cells, id, Report::Empty)?;
    let mut out = String::new();
    e(std::fs::File::from(r).read_to_string(&mut out))?;
    remove(&mut cells, id)?;
    // Rust's runtime reopens a closed 0 or 2 on /dev/null at startup; nothing above 2 may arrive.
    if out == "0 1 2\n" {
        Ok(())
    } else {
        Err(format!("open descriptors {out:?}, want 0 1 2"))
    }
}

fn main() {
    run(
        "spawn",
        &[
            ("in_cell", in_cell),
            ("exec_failure", exec_failure),
            ("only_routed_fds", only_routed_fds),
        ],
    )
}
