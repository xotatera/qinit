// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! A process moved out of the cell between enumeration and signal is not signalled (spec
//! §6.2).
use qinit_cell::{Polite, ReadyMode, Report};
use qinit_event::Loop;
use qinit_vm_guests::{
    COMB, HANG_GUARD, await_events, cells, e, exists, expect, helper_cmd, make_cell, reap_exited,
    remove, reports_of, run,
};
use std::os::fd::AsFd;

fn moved_member_is_spared() -> Result<(), String> {
    // The destination is a raw cell outside `Cells`, emptied with cgroup.kill at the end.
    let (other_dir, other_events) = make_cell("rg-other")?;
    let mut cells = cells()?;
    let id = e(cells.create("rg"))?;
    // The main process starts a ready child noting TERM to /tmp/rg and exits 0: ready by exit.
    e(cells.spawn(
        id,
        helper_cmd("orphan-parent", &["/tmp/rg"]),
        ReadyMode::Exit,
    ))?;
    let mut seen = expect(&mut cells, id, Report::Ready)?;
    let target = format!("{COMB}/rg-other/cgroup.procs");
    cells.set_between_hook(Box::new(move |pid| {
        let _ = std::fs::write(&target, pid.to_string());
    }));
    e(cells.stop(id, Polite::Cell, HANG_GUARD, HANG_GUARD))?;
    seen.extend(expect(&mut cells, id, Report::Empty)?);
    remove(&mut cells, id)?;
    let spared = !exists("/tmp/rg");
    let moved = qinit_vm_guests::read_events(other_events.as_fd())?.0;
    let mut l = e(Loop::new())?;
    e(l.add_priority(other_events.as_fd(), 1))?;
    e(qinit_sys::cgroup::write_file_at(
        &other_dir,
        c"cgroup.kill",
        b"1",
    ))?;
    await_events(&mut l, 1, other_events.as_fd(), Some(false), None)?;
    e(qinit_sys::cgroup::rmdir_at(
        qinit_vm_guests::comb()?,
        c"rg-other",
    ))?;
    reap_exited()?;
    let got = reports_of(&seen, id);
    let want = [Report::Created, Report::Ready, Report::Empty];
    if got != want {
        Err(format!("reports {got:?}, want {want:?}"))
    } else if !spared {
        Err("the moved process got TERM".into())
    } else if !moved {
        Err("the hook moved no process into rg-other".into())
    } else {
        Ok(())
    }
}

fn main() {
    run(
        "reuse_guard",
        &[("moved_member_is_spared", moved_member_is_spared)],
    )
}
