// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Booting a guest: KVM when `/dev/kvm` opens read-write, TCG otherwise (spec R7). The serial
//! console is QEMU's stdout; a guest powers off when its suite ends.
use qinit_event::{Loop, Ready};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accel {
    Kvm,
    Tcg,
}

/// KVM when `/dev/kvm` opens read-write, TCG otherwise.
#[must_use]
pub fn accel() -> Accel {
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
    {
        Ok(_) => Accel::Kvm,
        Err(_) => Accel::Tcg,
    }
}

/// A hang guard only (guests assert order, never durations): generous, longer under TCG.
#[must_use]
pub fn deadline(a: Accel) -> Duration {
    match a {
        Accel::Kvm => Duration::from_secs(120),
        Accel::Tcg => Duration::from_mins(15),
    }
}

/// QEMU's arguments for one boot.
#[must_use]
pub fn args(a: Accel, kernel: &Path, initrd: &Path) -> Vec<OsString> {
    let (machine, cpu) = match a {
        Accel::Kvm => ("q35,accel=kvm", "host"),
        Accel::Tcg => ("q35,accel=tcg", "max"),
    };
    let mut v: Vec<OsString> = [
        "-machine",
        machine,
        "-cpu",
        cpu,
        "-m",
        "512",
        "-smp",
        "2",
        "-nodefaults",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        "stdio",
        "-no-reboot",
        "-kernel",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    v.push(kernel.as_os_str().to_owned());
    v.push("-initrd".into());
    v.push(initrd.as_os_str().to_owned());
    v.push("-append".into());
    v.push("console=ttyS0 panic=-1 rdinit=/init loglevel=4".into());
    v
}

const OUT: u64 = 1;
const EXIT: u64 = 2;
const DEADLINE: u64 = 3;

/// Boots `kernel` with `initrd`; the serial text (also written to `log`). An error when QEMU
/// fails or the guest does not power off before the deadline.
pub fn boot(kernel: &Path, initrd: &Path, log: &Path) -> Result<String, String> {
    let a = accel();
    let mut child = Command::new("qemu-system-x86_64")
        .args(args(a, kernel, initrd))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("start qemu-system-x86_64: {e}"))?;
    let mut out = child.stdout.take().ok_or("qemu stdout is not piped")?;
    let pid = libc::pid_t::try_from(child.id()).map_err(|e| e.to_string())?;
    let pidfd = qinit_sys::proc::pidfd_open(pid).map_err(|e| e.to_string())?;
    std::mem::forget(child);
    let mut file =
        std::fs::File::create(log).map_err(|e| format!("create {}: {e}", log.display()))?;
    let mut text = String::new();
    let mut l = Loop::new().map_err(|e| e.to_string())?;
    l.add_fd(out.as_fd(), OUT).map_err(|e| e.to_string())?;
    l.add_pidfd(pidfd.as_fd(), EXIT)
        .map_err(|e| e.to_string())?;
    l.add_deadline(deadline(a), DEADLINE)
        .map_err(|e| e.to_string())?;
    let mut buf = [0u8; 8192];
    let mut open = true;
    let mut killed = false;
    loop {
        for r in l.wait().map_err(|e| e.to_string())? {
            match r {
                Ready::Readable(OUT) | Ready::Hangup(OUT) if open => {
                    let n = out.read(&mut buf).map_err(|e| e.to_string())?;
                    if n == 0 {
                        l.remove(OUT).map_err(|e| e.to_string())?;
                        open = false;
                    } else {
                        file.write_all(&buf[..n]).map_err(|e| e.to_string())?;
                        text.push_str(&String::from_utf8_lossy(&buf[..n]));
                    }
                }
                Ready::Exited(EXIT, raw) => {
                    let mut rest = Vec::new();
                    let _ = out.read_to_end(&mut rest);
                    file.write_all(&rest).map_err(|e| e.to_string())?;
                    text.push_str(&String::from_utf8_lossy(&rest));
                    if killed {
                        return Err(format!(
                            "the guest did not power off within {:?}; serial log: {}",
                            deadline(a),
                            log.display()
                        ));
                    }
                    if raw != 0 {
                        return Err(format!(
                            "qemu exited with code {}; serial log: {}",
                            qinit_event::exit_code(raw),
                            log.display()
                        ));
                    }
                    return Ok(text);
                }
                Ready::Deadline(DEADLINE) => {
                    killed = true;
                    qinit_sys::proc::pidfd_signal(&pidfd, libc::SIGKILL)
                        .map_err(|e| e.to_string())?;
                }
                _ => {}
            }
        }
    }
}
