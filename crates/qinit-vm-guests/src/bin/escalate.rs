// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! A TERM-ignoring process is killed at the deadline and the cell empties (spec §6.2).
//!
//! A main exit during a stop is not reported (D10), and the machine reports nothing on
//! entering Killing: escalation shows as the stop's only report being `Empty`, the main
//! process's note that TERM reached it (it then ignores TERM and never exits by itself), and
//! a second TERM-ignoring member, this process's own child, ending by SIGKILL.
use qinit_cell::{Polite, ReadyMode, Report};
use qinit_vm_guests::{
    COMB, HANG_GUARD, NOTE_GRACE, cells, e, exists, expect, helper_cmd, killed, remove, reports_of,
    run, spawn_helper,
};
use std::os::fd::AsFd;
use std::path::Path;

fn killed_at_the_deadline() -> Result<(), String> {
    let mut cells = cells()?;
    let id = e(cells.create("es"))?;
    e(cells.spawn(
        id,
        helper_cmd("ready-ignore-term", &["/tmp/es-main"]),
        ReadyMode::Pipe,
    ))?;
    let mut seen = expect(&mut cells, id, Report::Ready)?;
    let dir = e(qinit_sys::cgroup::open_dir(Path::new(&format!(
        "{COMB}/es"
    ))))?;
    let (_pid, member) = spawn_helper(dir.as_fd(), "ignore-term")?;
    e(cells.stop(id, Polite::Main, NOTE_GRACE, HANG_GUARD))?;
    seen.extend(expect(&mut cells, id, Report::Empty)?);
    let status = e(qinit_sys::proc::wait_pidfd(&member))?;
    remove(&mut cells, id)?;
    let got = reports_of(&seen, id);
    let want = [Report::Created, Report::Ready, Report::Empty];
    if got != want {
        Err(format!("reports {got:?}, want {want:?}"))
    } else if !exists("/tmp/es-main") {
        Err("TERM never reached the main process".into())
    } else if !killed(status) {
        Err(format!(
            "the other member's status {status:#x}, want SIGKILL"
        ))
    } else {
        Ok(())
    }
}

fn main() {
    run(
        "escalate",
        &[("killed_at_the_deadline", killed_at_the_deadline)],
    )
}
