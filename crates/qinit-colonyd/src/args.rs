// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The command line: seven path flags and `--queen-fd`, each at most once, as `--flag value` or
//! `--flag=value`.
use std::ffi::OsString;
use std::os::fd::RawFd;
use std::path::PathBuf;

/// Where colony finds and puts things.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Args {
    /// The compiled database.
    pub db: PathBuf,
    /// The cgroup directory every cell lives under.
    pub comb: PathBuf,
    /// The control socket.
    pub socket: PathBuf,
    /// The launch executor.
    pub overseer: PathBuf,
    /// The syslog datagram socket.
    pub syslog: PathBuf,
    /// Where colony's own lines go when syslog is unavailable.
    pub console: PathBuf,
    /// The runtime directory: the socket's parent and `state/`.
    pub run: PathBuf,
    /// The descriptor number of queen's channel, when queen started colony.
    pub queen_fd: Option<RawFd>,
}

impl Default for Args {
    fn default() -> Args {
        Args {
            db: "/etc/qinit/colony.db".into(),
            comb: "/sys/fs/cgroup/qinit".into(),
            socket: "/run/qinit/colony".into(),
            overseer: "/usr/lib/qinit/overseer".into(),
            syslog: "/dev/log".into(),
            console: "/dev/console".into(),
            run: "/run/qinit".into(),
            queen_fd: None,
        }
    }
}

/// Parses the arguments after the program name.
///
/// # Errors
///
/// Text naming the unknown flag, the missing value, the stray argument or the repeated flag.
pub fn parse(argv: &[OsString]) -> Result<Args, String> {
    let mut out = Args::default();
    let mut seen: Vec<&'static str> = Vec::new();
    let mut words = argv.iter();
    while let Some(word) = words.next() {
        let text = word.to_string_lossy();
        let Some(flag) = text.strip_prefix("--") else {
            return Err(format!("unexpected argument {text:?}"));
        };
        let (name, inline) = match flag.split_once('=') {
            Some((n, v)) => (n, Some(OsString::from(v))),
            None => (flag, None),
        };
        if name == "queen-fd" {
            if seen.contains(&"--queen-fd") {
                return Err("--queen-fd is repeated".into());
            }
            let value = inline.or_else(|| words.next().cloned());
            let n = value
                .as_ref()
                .and_then(|v| v.to_str())
                .and_then(|v| v.parse::<RawFd>().ok())
                .filter(|n| *n >= 0);
            match (value, n) {
                (None, _) => return Err("--queen-fd needs a value".into()),
                (Some(v), None) => {
                    return Err(format!(
                        "--queen-fd needs a descriptor number, not {:?}",
                        v.to_string_lossy()
                    ));
                }
                (Some(_), Some(n)) => out.queen_fd = Some(n),
            }
            seen.push("--queen-fd");
            continue;
        }
        let field = match name {
            "db" => ("--db", &mut out.db),
            "comb" => ("--comb", &mut out.comb),
            "socket" => ("--socket", &mut out.socket),
            "overseer" => ("--overseer", &mut out.overseer),
            "syslog" => ("--syslog", &mut out.syslog),
            "console" => ("--console", &mut out.console),
            "run" => ("--run", &mut out.run),
            _ => return Err(format!("unknown flag --{name}")),
        };
        if seen.contains(&field.0) {
            return Err(format!("{} is repeated", field.0));
        }
        let value = inline.or_else(|| words.next().cloned());
        match value {
            Some(v) if !v.is_empty() => *field.1 = PathBuf::from(v),
            _ => return Err(format!("{} needs a value", field.0)),
        }
        seen.push(field.0);
    }
    Ok(out)
}
