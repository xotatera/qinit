// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! A fault in queen (a `SIGSEGV` on its alternate stack) parks it the same way (R13).
use qinit_vm_guests::colonyd::{model, worker};
use qinit_vm_guests::queened::{self, await_kmsg, client, signal_queen};
use qinit_vm_guests::{e, orphan};

fn a_fault_parks_queen_and_colony_serves_on() -> Result<(), String> {
    let mut c = client()?;
    signal_queen(libc::SIGUSR2)?;
    await_kmsg("queen: fatal signal", 1)?;
    e(c.status("w"))?;
    let o = orphan::start()?;
    o.exit()?;
    if !o.is_zombie()? {
        return Err("the orphan was reaped: queen is not parked".into());
    }
    Ok(())
}

fn main() {
    let first = model(vec![worker("w", "ready", &[])], &[0]);
    queened::boot(
        &[(
            "a_fault_parks_queen_and_colony_serves_on",
            a_fault_parks_queen_and_colony_serves_on,
        )],
        "queen_fault",
        &first,
    )
}
