// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Zero's stand-in for the `queen` suites: appends its command line (`final <mode>`) to
//! `/tmp/zero-log` and starts queen over again, so a guest can run a boot after boot and the
//! driver can count the times queen handed the machine over.
use qinit_vm_guests::queened::{QUEEN, ZERO_LOG};
use std::io::Write;

fn main() {
    let line = std::env::args().skip(1).collect::<Vec<_>>().join(" ");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(ZERO_LOG)
    {
        let _ = writeln!(f, "{line}");
    }
    let err = qinit_sys::spawn::exec_in_place(c"/usr/lib/qinit/queen", &[c"queen"], &[]);
    eprintln!("zero stand-in: cannot start {QUEEN}: {err}");
    std::process::exit(1);
}
