// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Readiness: a newline is ready, EOF without one is not, exit mode (spec §6.2).
use qinit_cell::{Polite, ReadyMode, Report};
use qinit_vm_guests::{HANG_GUARD, cells, e, expect, helper_cmd, remove, reports_of, run};

/// Spawns `role` in cell `name` and waits for `before_stop`'s last report; with a stop, stops
/// the cell and waits for `Empty`. `id`'s whole report sequence must be `want`.
fn case(
    name: &str,
    role: &str,
    mode: ReadyMode,
    before_stop: Report,
    stop: bool,
    want: &[Report],
) -> Result<(), String> {
    let mut cells = cells()?;
    let id = e(cells.create(name))?;
    e(cells.spawn(id, helper_cmd(role, &[]), mode))?;
    let mut seen = expect(&mut cells, id, before_stop)?;
    if stop {
        e(cells.stop(id, Polite::Main, HANG_GUARD, HANG_GUARD))?;
        seen.extend(expect(&mut cells, id, Report::Empty)?);
    }
    remove(&mut cells, id)?;
    let got = reports_of(&seen, id);
    if got == want {
        Ok(())
    } else {
        Err(format!("reports {got:?}, want {want:?}"))
    }
}

fn pipe_line() -> Result<(), String> {
    use Report::{Created, Empty, Ready};
    case(
        "rl",
        "ready",
        ReadyMode::Pipe,
        Ready,
        true,
        &[Created, Ready, Empty],
    )
}

fn pipe_closed() -> Result<(), String> {
    use Report::{Created, Empty, NotReady};
    let want = [Created, NotReady, Empty];
    case("rc", "ready-close", ReadyMode::Pipe, NotReady, true, &want)
}

fn exit_zero() -> Result<(), String> {
    use Report::{Created, Empty, Ready};
    case(
        "rz",
        "exit-0",
        ReadyMode::Exit,
        Empty,
        false,
        &[Created, Ready, Empty],
    )
}

fn exit_nonzero() -> Result<(), String> {
    use Report::{Created, Empty, MainExited};
    let want = [Created, MainExited(Some(3 << 8)), Empty];
    case("rn", "exit-3", ReadyMode::Exit, Empty, false, &want)
}

fn main() {
    run(
        "ready",
        &[
            ("pipe_line", pipe_line),
            ("pipe_closed", pipe_closed),
            ("exit_zero", exit_zero),
            ("exit_nonzero", exit_nonzero),
        ],
    )
}
