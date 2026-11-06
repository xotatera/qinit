// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Colony's own messages: RFC 3164 lines `<PRI>colony[<pid>]: <text>` on a datagram socket to
//! syslog (facility daemon). Sends never block. A full socket drops the message and counts it;
//! a socket that is missing or refuses sends the line to the console instead, with one marker in
//! `/dev/kmsg` on the way down and one on the way back. Every message tries syslog first.
use std::fmt::Write as _;
use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

/// How bad a message is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sev {
    Err,
    Info,
    Debug,
}

/// Facility daemon (3) in the high bits of the priority.
const DAEMON: u8 = 3 << 3;

/// The line for `text` as `pid` writes it: `<PRI>colony[pid]: text`.
#[must_use]
pub fn line(pid: i32, sev: Sev, text: &str) -> String {
    let level = match sev {
        Sev::Err => 3,
        Sev::Info => 6,
        Sev::Debug => 7,
    };
    format!("<{}>colony[{pid}]: {text}", DAEMON | level)
}

/// The writer of colony's messages.
pub struct Syslog {
    socket_path: PathBuf,
    console: PathBuf,
    kmsg: PathBuf,
    sock: Option<OwnedFd>,
    /// Messages dropped on a full socket since one last went through.
    dropped: u32,
    /// Whether the last message went to the console: the marker is written on a change.
    fallen_back: bool,
}

impl Syslog {
    /// A writer to `syslog`, falling back to `console` and marking `kmsg`.
    #[must_use]
    pub fn new(syslog: &Path, console: &Path, kmsg: &Path) -> Syslog {
        Syslog {
            socket_path: syslog.to_owned(),
            console: console.to_owned(),
            kmsg: kmsg.to_owned(),
            sock: None,
            dropped: 0,
            fallen_back: false,
        }
    }

    /// Sends `text` at `sev`. Never blocks and never fails: what cannot be delivered is
    /// counted or goes to the console.
    pub fn log(&mut self, sev: Sev, text: &str) {
        let mut text = text.to_owned();
        if self.dropped > 0 {
            let _ = write!(text, " (dropped {} lines)", self.dropped);
        }
        let line = line(qinit_sys::proc::pid(), sev, &text);
        match self.send(line.as_bytes()) {
            Ok(()) => {
                self.dropped = 0;
                if self.fallen_back {
                    self.fallen_back = false;
                    self.mark("colony: syslog back");
                }
            }
            Err(Failure::Full) => self.dropped = self.dropped.saturating_add(1),
            Err(Failure::Unavailable) => {
                if !self.fallen_back {
                    self.fallen_back = true;
                    let note = format!(
                        "colony: syslog unavailable, writing to {}",
                        self.console.display()
                    );
                    self.mark(&note);
                }
                self.dropped = 0;
                self.to_console(&line);
            }
        }
    }

    fn send(&mut self, bytes: &[u8]) -> Result<(), Failure> {
        if self.sock.is_none() {
            let path = std::ffi::CString::new(self.socket_path.as_os_str().as_encoded_bytes())
                .map_err(|_| Failure::Unavailable)?;
            self.sock = Some(
                qinit_sys::sock::connect_unix(&path, libc::SOCK_DGRAM)
                    .map_err(|_| Failure::Unavailable)?,
            );
        }
        let Some(sock) = self.sock.as_ref() else {
            return Err(Failure::Unavailable);
        };
        match qinit_ipc::send_nowait(sock.as_fd(), bytes, &[]) {
            Ok(()) => Ok(()),
            Err(qinit_ipc::Errno(e)) if e == libc::EAGAIN || e == libc::EWOULDBLOCK => {
                Err(Failure::Full)
            }
            Err(_) => {
                // Refused (the daemon went away): reconnect on the next message.
                self.sock = None;
                Err(Failure::Unavailable)
            }
        }
    }

    fn to_console(&self, line: &str) {
        write_line(&self.console, line);
    }

    fn mark(&self, note: &str) {
        write_line(&self.kmsg, note);
    }
}

/// Appends `text` and a newline to a device or file without ever waiting on it and without
/// taking it as a controlling terminal: a console whose line is held, or one nobody reads, drops
/// the message (this is the path for when logging is already broken), and a hangup or `^C` on
/// it must not reach colony as a signal.
fn write_line(path: &Path, text: &str) {
    use std::os::unix::fs::OpenOptionsExt;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .append(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)
    {
        let _ = writeln!(f, "{text}");
    }
}

enum Failure {
    /// The queue is full: drop and count.
    Full,
    /// No socket, or it refused: use the console.
    Unavailable,
}
