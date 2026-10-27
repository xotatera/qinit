// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Running a build step with its output in a log and a deadline, waiting only on the loop.
use qinit_event::{Loop, Ready, exit_code};
use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

const EXIT: u64 = 1;
const DEADLINE: u64 = 2;

fn append(log: &Path) -> Result<File, String> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .map_err(|e| format!("open {}: {e}", log.display()))
}

/// Runs `cmd` with stdout and stderr appended to `log`.
pub fn run_logged(mut cmd: Command, log: &Path, within: Duration) -> Result<(), String> {
    let out = append(log)?;
    let err = out.try_clone().map_err(|e| format!("dup the log: {e}"))?;
    cmd.stdout(out).stderr(err);
    supervise(cmd, log, within)
}

/// Runs `cmd` with only stderr appended to `log`; the caller set stdout (cargo's JSON).
pub fn run_logged_stdout_kept(
    mut cmd: Command,
    log: &Path,
    within: Duration,
) -> Result<(), String> {
    cmd.stderr(append(log)?);
    supervise(cmd, log, within)
}

/// Starts `cmd` and waits on its pidfd and a deadline; an error names the step, its exit code
/// or the deadline, and the log. A child still running at the deadline is killed with its whole
/// process group and reaped.
fn supervise(mut cmd: Command, log: &Path, within: Duration) -> Result<(), String> {
    let label = format!("{cmd:?}");
    // Its own process group, so the deadline kill reaches everything it started (make's jobs).
    cmd.stdin(Stdio::null()).process_group(0);
    let child = cmd.spawn().map_err(|e| format!("start {label}: {e}"))?;
    let pid = libc::pid_t::try_from(child.id()).map_err(|e| e.to_string())?;
    let pidfd = qinit_sys::proc::pidfd_open(pid).map_err(|e| format!("pidfd_open: {e}"))?;
    // std's Child would reap on wait; the loop reaps it through the pidfd instead.
    std::mem::forget(child);
    let mut l = Loop::new().map_err(|e| e.to_string())?;
    l.add_pidfd(pidfd.as_fd(), EXIT)
        .map_err(|e| e.to_string())?;
    l.add_deadline(within, DEADLINE)
        .map_err(|e| e.to_string())?;
    let mut killed = false;
    loop {
        for r in l.wait().map_err(|e| e.to_string())? {
            match r {
                Ready::Exited(EXIT, _) if killed => {
                    return Err(format!(
                        "{label} did not finish within {within:?}; log: {}",
                        log.display()
                    ));
                }
                Ready::Exited(EXIT, 0) => return Ok(()),
                Ready::Exited(EXIT, raw) => {
                    return Err(format!(
                        "{label} failed with exit code {}; log: {}",
                        exit_code(raw),
                        log.display()
                    ));
                }
                Ready::Deadline(DEADLINE) => {
                    killed = true;
                    qinit_sys::proc::kill(-pid, libc::SIGKILL).map_err(|e| e.to_string())?;
                }
                _ => {}
            }
        }
    }
}
