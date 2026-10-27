// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! As a subreaper (not PID 1), an orphaned grandchild is reaped and reported (spec §6.2): the
//! `subreaper-host` helper runs the cell and judges what it saw.
use qinit_vm_guests::{HELPER_FLAG, run};

fn orphan_is_reported() -> Result<(), String> {
    let status = std::process::Command::new("/init")
        .args([HELPER_FLAG, "subreaper-host"])
        .status()
        .map_err(|x| x.to_string())?;
    if status.code() == Some(0) {
        Ok(())
    } else {
        Err(format!(
            "subreaper-host ended with {status} (its reason is on the console)"
        ))
    }
}

fn main() {
    run("orphan", &[("orphan_is_reported", orphan_is_reported)])
}
