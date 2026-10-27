// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! A main-mode stop: TERM reaches only the main process; the rest die at the kill deadline
//! (spec §6.2).
use qinit_cell::{Polite, ReadyMode, Report};
use qinit_vm_guests::{
    HANG_GUARD, NOTE_GRACE, cells, e, exists, expect, helper_cmd, killed, reap_expected, remove,
    reports_of, run,
};

fn only_main_gets_term() -> Result<(), String> {
    let mut cells = cells()?;
    let id = e(cells.create("sm"))?;
    // A ready child noting TERM to /tmp/sm-child, then the main noting to /tmp/sm-main.
    e(cells.spawn(id, helper_cmd("family", &["/tmp/sm"]), ReadyMode::Pipe))?;
    expect(&mut cells, id, Report::Ready)?;
    e(cells.stop(id, Polite::Main, NOTE_GRACE, HANG_GUARD))?;
    let seen = expect(&mut cells, id, Report::Empty)?;
    remove(&mut cells, id)?;
    // The child, re-parented to this process when the main process exited.
    let rest = reap_expected(1)?;
    let after_stop = reports_of(&seen, id);
    if after_stop != [Report::Empty] {
        return Err(format!(
            "reports after the stop {after_stop:?}, want [Empty] (D10)"
        ));
    }
    match (exists("/tmp/sm-main"), exists("/tmp/sm-child")) {
        (true, false) => {}
        got => return Err(format!("TERM noted by (main, child) = {got:?}")),
    }
    if rest.len() == 1 && rest.iter().all(|s| killed(*s)) {
        Ok(())
    } else {
        Err(format!(
            "the rest ended with statuses {rest:?}, want SIGKILL"
        ))
    }
}

fn main() {
    run("stop_main", &[("only_main_gets_term", only_main_gets_term)])
}
