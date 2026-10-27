// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! A cell-mode stop: a setsid double-forked escapee is still signalled; a member that dies
//! during enumeration leaves no frozen cell (spec §6.2).
use qinit_cell::{Polite, ReadyMode, Report};
use qinit_vm_guests::{
    COMB, HANG_GUARD, cells, e, exists, expect, helper_cmd, killed, reap_expected, remove,
    reports_of, run,
};

fn escapee_is_signalled() -> Result<(), String> {
    let mut cells = cells()?;
    let id = e(cells.create("se"))?;
    // A grandchild in its own session noting to /tmp/se-escapee, the main to /tmp/se-main.
    e(cells.spawn(id, helper_cmd("escape", &["/tmp/se"]), ReadyMode::Pipe))?;
    expect(&mut cells, id, Report::Ready)?;
    e(cells.stop(id, Polite::Cell, HANG_GUARD, HANG_GUARD))?;
    let seen = expect(&mut cells, id, Report::Empty)?;
    remove(&mut cells, id)?;
    // Reap both the double fork's middle and its escapee before the next case.
    // Empty may precede either becoming waitable.
    let rest = reap_expected(2)?;
    if rest != [0, 0] {
        return Err(format!("escape helper statuses {rest:?}, want [0, 0]"));
    }
    let after_stop = reports_of(&seen, id);
    if after_stop != [Report::Empty] {
        return Err(format!(
            "reports after the stop {after_stop:?}, want [Empty]"
        ));
    }
    match (exists("/tmp/se-main"), exists("/tmp/se-escapee")) {
        (true, true) => Ok(()),
        got => Err(format!("TERM noted by (main, escapee) = {got:?}")),
    }
}

fn member_dying_mid_enumeration() -> Result<(), String> {
    let mut cells = cells()?;
    let id = e(cells.create("sd"))?;
    e(cells.spawn(id, helper_cmd("family", &["/tmp/sd"]), ReadyMode::Pipe))?;
    expect(&mut cells, id, Report::Ready)?;
    // Each member dies between its pidfd being opened and being verified.
    cells.set_between_hook(Box::new(|pid| {
        let _ = qinit_sys::proc::kill(pid, libc::SIGKILL);
    }));
    e(cells.stop(id, Polite::Cell, HANG_GUARD, HANG_GUARD))?;
    let seen = expect(&mut cells, id, Report::Empty)?;
    let freeze = e(std::fs::read_to_string(format!("{COMB}/sd/cgroup.freeze")))?;
    let events = e(std::fs::read_to_string(format!("{COMB}/sd/cgroup.events")))?;
    remove(&mut cells, id)?;
    let rest = reap_expected(1)?;
    let after_stop = reports_of(&seen, id);
    if after_stop != [Report::Empty] {
        Err(format!(
            "reports after the stop {after_stop:?}, want [Empty]"
        ))
    } else if exists("/tmp/sd-main") || exists("/tmp/sd-child") {
        Err("a member got TERM: the between hook did not kill it first".into())
    } else if rest.len() != 1 || !rest.iter().all(|s| killed(*s)) {
        Err(format!("child statuses {rest:?}, want [SIGKILL]"))
    } else if freeze.trim() != "0" || !events.lines().any(|l| l == "frozen 0") {
        Err(format!(
            "after the stop cgroup.freeze is {freeze:?}, cgroup.events {events:?}"
        ))
    } else {
        Ok(())
    }
}

fn main() {
    run(
        "stop_cell",
        &[
            ("escapee_is_signalled", escapee_is_signalled),
            ("member_dying_mid_enumeration", member_dying_mid_enumeration),
        ],
    )
}
