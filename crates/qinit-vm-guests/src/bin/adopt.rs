// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Adoption after the driver state is dropped: by name and cgroup id, a wrong id fails, and a
//! handed-over main process is watched without being reaped as a main (spec §6.2, D8).
use qinit_cell::{Notice, Polite, ReadyMode, Report};
use qinit_cell_core::{Failure, STATUS_UNKNOWN};
use qinit_vm_guests::{
    HANG_GUARD, cells, e, expect, helper_cmd, reap_exited, remove, reports_of, run,
};

/// Starts a `ready` helper in a new cell `name` and drops the `Cells` that started it: the
/// helper keeps running in its cell. Its cell's cgroup id and its pid.
fn left_running(name: &str) -> Result<(u64, libc::pid_t), String> {
    let mut first = cells()?;
    let id = e(first.create(name))?;
    e(first.spawn(id, helper_cmd("ready", &[]), ReadyMode::Pipe))?;
    expect(&mut first, id, Report::Ready)?;
    let cg = first.cgroup_id(id).ok_or("no cgroup id")?;
    let pid = first.main_pid(id).ok_or("no main pid")?;
    Ok((cg, pid))
}

fn adopt_by_name_and_id() -> Result<(), String> {
    let (cg, _pid) = left_running("ak")?;
    let mut wrong = cells()?;
    let bad = e(wrong.adopt("ak", cg + 1, None))?;
    let refused = expect(&mut wrong, bad, Report::Failed(Failure::IdMismatch))?;
    // Not removed: removing would try the directory, which is the other driver's cell.
    drop(wrong);
    let mut second = cells()?;
    let id = e(second.adopt("ak", cg, None))?;
    let mut seen = expect(&mut second, id, Report::Running)?;
    e(second.stop(id, Polite::Cell, HANG_GUARD, HANG_GUARD))?;
    seen.extend(expect(&mut second, id, Report::Empty)?);
    remove(&mut second, id)?;
    // The helper is this process's child that nothing tracks after the first driver went.
    let rest = reap_exited()?;
    let (got_bad, got) = (reports_of(&refused, bad), reports_of(&seen, id));
    if got_bad != [Report::Failed(Failure::IdMismatch)] {
        Err(format!("reports with the wrong id {got_bad:?}"))
    } else if got != [Report::Running, Report::Empty] {
        Err(format!(
            "reports with the right id {got:?}, want [Running, Empty]"
        ))
    } else if rest != [0] {
        Err(format!("the helper's statuses {rest:?}, want [0]"))
    } else {
        Ok(())
    }
}

/// A main pidfd handed over on adoption is watched without reaping: its exit reaches the cell
/// as `MainExited(STATUS_UNKNOWN)` (D8). This helper happens to be this process's child, so
/// the runtime reaps it when it lets the pidfd go and reports it as an orphan with its real
/// status (spec §5.3: a reaped child is never dropped).
fn handed_over_main() -> Result<(), String> {
    let (cg, pid) = left_running("am")?;
    let pidfd = e(qinit_sys::proc::pidfd_open(pid))?;
    let mut second = cells()?;
    let id = e(second.adopt("am", cg, Some(pidfd)))?;
    let mut seen = expect(&mut second, id, Report::Running)?;
    let tracked = second.main_pid(id);
    e(qinit_sys::proc::kill(pid, libc::SIGTERM))?;
    seen.extend(expect(&mut second, id, Report::Empty)?);
    // The orphan notice and the cell's last notification arrive in either order.
    while !seen.iter().any(|n| matches!(n, Notice::Orphan { .. })) {
        seen.extend(e(second.next())?);
    }
    let after = second.main_pid(id);
    remove(&mut second, id)?;
    let got = reports_of(&seen, id);
    let want = [
        Report::Running,
        Report::MainExited(STATUS_UNKNOWN),
        Report::Empty,
    ];
    let orphans: Vec<Notice> = seen
        .iter()
        .copied()
        .filter(|n| matches!(n, Notice::Orphan { .. }))
        .collect();
    if got != want {
        Err(format!("reports {got:?}, want {want:?}"))
    } else if orphans != [Notice::Orphan { pid, status: 0 }] {
        Err(format!(
            "orphans {orphans:?}, want the helper {pid} with status 0"
        ))
    } else if tracked != Some(pid) || after.is_some() {
        Err(format!(
            "main pid {tracked:?} once adopted, {after:?} after its exit"
        ))
    } else {
        Ok(())
    }
}

fn main() {
    run(
        "adopt",
        &[
            ("adopt_by_name_and_id", adopt_by_name_and_id),
            ("handed_over_main", handed_over_main),
        ],
    )
}
