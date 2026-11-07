// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! A panic in queen parks it (spec §3.6): one line in the kernel log, no reaping any more, and
//! colony, which queen started, serves on.
use qinit_vm_guests::colonyd::{model, worker};
use qinit_vm_guests::queened::{self, await_kmsg, client, signal_queen};
use qinit_vm_guests::{e, orphan};

fn a_panic_parks_queen_and_colony_serves_on() -> Result<(), String> {
    let mut c = client()?;
    signal_queen(libc::SIGUSR1)?;
    await_kmsg("queen: panic", 1)?;
    // Colony is a process of its own: it still answers.
    e(c.status("w"))?;
    // And queen reaps nothing any more: an orphan stays a zombie.
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
            "a_panic_parks_queen_and_colony_serves_on",
            a_panic_parks_queen_and_colony_serves_on,
        )],
        "queen_panic",
        &first,
    )
}
