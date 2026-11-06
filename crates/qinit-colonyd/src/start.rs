// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Start-up, in order: what can be refused before anything is changed, then the comb, then the
//! daemon. Every refusal is logged and printed, and ends with the exit status that names it.
use crate::args::Args;
use crate::daemon::{Daemon, KMSG, inside_comb};
use crate::exit;
use crate::state::State;
use crate::syslog::{Sev, Syslog};
use qinit_cell::Cells;
use std::io::Write;
use std::path::Path;

/// The cgroup this process is in, as `/proc/self/cgroup` names it (`/18/session`).
fn own_cgroup() -> Option<String> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::to_owned)
}

/// Makes `<comb>` hand out memory and pid limits to its cells.
fn enable_controllers(comb: &Path) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(comb.join("cgroup.subtree_control"))?;
    f.write_all(b"+memory +pids")
}

/// Starts colony and serves until the graph is down or the loop fails.
#[must_use]
pub fn run(args: &Args) -> u8 {
    let mut log = Syslog::new(&args.syslog, &args.console, Path::new(KMSG));
    let mut refuse = |code: u8, why: String| {
        log.log(Sev::Err, &why);
        eprintln!("colony: {why}");
        code
    };
    // Nothing is changed before the checks that need no change.
    match qinit_sys::proc::kernel_release() {
        Ok(release) => {
            if let Err(why) = qinit_cell::text::kernel_supported(&release) {
                return refuse(exit::STARTUP, why);
            }
        }
        Err(e) => {
            return refuse(
                exit::STARTUP,
                format!("cannot read the kernel release: {e}"),
            );
        }
    }
    if let Some(own) = own_cgroup()
        && inside_comb(&own, &args.comb)
    {
        return refuse(
            exit::STARTUP,
            format!(
                "colony is inside the comb ({own} is {} or below it): it must run outside every cell",
                args.comb.display()
            ),
        );
    }
    let bytes = match std::fs::read(&args.db) {
        Ok(b) => b,
        Err(e) => {
            return refuse(
                exit::DATABASE,
                format!("cannot read the database {}: {e}", args.db.display()),
            );
        }
    };
    if let Err(e) = qinit_db::open(&bytes) {
        return refuse(
            exit::DATABASE,
            format!("the database {} is refused: {e:?}", args.db.display()),
        );
    }
    if let Err(e) = std::fs::create_dir_all(&args.run).and_then(|()| {
        std::fs::set_permissions(
            &args.run,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
    }) {
        return refuse(
            exit::STARTUP,
            format!("cannot make the run directory {}: {e}", args.run.display()),
        );
    }
    let state = match State::open(&args.run) {
        Ok(s) => s,
        Err(e) => {
            return refuse(
                exit::STARTUP,
                format!(
                    "cannot open the state directory in {}: {e}",
                    args.run.display()
                ),
            );
        }
    };
    let mut cells = match Cells::open(&args.comb) {
        Ok(c) => c,
        Err(e) => {
            return refuse(
                exit::STARTUP,
                format!("cannot open the comb {}: {e}", args.comb.display()),
            );
        }
    };
    if let Err(e) = enable_controllers(&args.comb) {
        return refuse(
            exit::STARTUP,
            format!(
                "cannot enable the memory and pids controllers in {}: {e}",
                args.comb.display()
            ),
        );
    }
    if let Err(e) = cells.subreaper() {
        return refuse(exit::STARTUP, format!("cannot become a subreaper: {e}"));
    }
    let syslog = Syslog::new(&args.syslog, &args.console, Path::new(KMSG));
    match Daemon::boot(cells, args, &bytes, state, syslog) {
        Ok(d) => d.serve(),
        Err(code) => code,
    }
}
