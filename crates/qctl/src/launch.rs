// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qctl launch` and `qctl run` (spec 2026-11-05 §4.1, §4.6): start an instance, wait for its
//! end, and exit with its status (the exit code, or 128 plus the signal); 0 when the wait ended
//! first, with the instance's name printed.
use crate::args::{Fds, LaunchOpts, RunOpts};
use crate::control::{Failure, wait_ms};
use crate::request;
use qinit_client::{
    Begun, Client, LaunchArgs, LaunchOutcome, PidfdExit, RunArgs, Started, StopMode, pidfd_exit,
};
use std::io::Write;
use std::os::fd::{AsFd, BorrowedFd};
use std::path::Path;

/// The process's standard streams, borrowed for the roles `--fds` names.
struct Streams {
    stdin: std::io::Stdin,
    stdout: std::io::Stdout,
    stderr: std::io::Stderr,
}

impl Streams {
    fn new() -> Streams {
        Streams {
            stdin: std::io::stdin(),
            stdout: std::io::stdout(),
            stderr: std::io::stderr(),
        }
    }

    fn pick(&self, f: Fds) -> [Option<BorrowedFd<'_>>; 3] {
        [
            f.stdin.then(|| self.stdin.as_fd()),
            f.stdout.then(|| self.stdout.as_fd()),
            f.stderr.then(|| self.stderr.as_fd()),
        ]
    }
}

fn usage(err: &mut dyn Write, msg: &str) -> i32 {
    let _ = writeln!(err, "qctl: {msg}\nTry 'qctl --help'.");
    2
}

/// `qctl launch`: an instance of the forager `opts.frame`.
pub fn launch(opts: &LaunchOpts, socket: &Path, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let wait = match wait_ms(opts.wait) {
        Ok(w) => w,
        Err(msg) => return usage(err, &msg),
    };
    let tail: Vec<&str> = opts.args.iter().map(String::as_str).collect();
    let env: Vec<(&str, &str)> = opts
        .env
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let streams = Streams::new();
    let [stdin, stdout, stderr] = streams.pick(opts.fds);
    let args = LaunchArgs {
        argv_tail: &tail,
        env: &env,
        stdin,
        stdout,
        stderr,
    };
    let result = Client::connect(socket).and_then(|mut c| {
        let begun = c.begin_launch(&opts.frame, &args, opts.pidfd, wait)?;
        Ok((c, begun))
    });
    settle(result, &opts.frame, out, err)
}

/// `qctl run`: the request in the file `opts.request`, as `~<name>#<id>`.
pub fn run(opts: &RunOpts, socket: &Path, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let wait = match wait_ms(opts.wait) {
        Ok(w) => w,
        Err(msg) => return usage(err, &msg),
    };
    let file = opts.request.display();
    let spec = match std::fs::read_to_string(&opts.request)
        .map_err(|e| e.to_string())
        .and_then(|text| request::parse(&text))
    {
        Ok(s) => s,
        Err(why) => {
            let _ = writeln!(err, "qctl: {file}: {why}");
            return 1;
        }
    };
    let streams = Streams::new();
    let [stdin, stdout, stderr] = streams.pick(opts.fds);
    let args = RunArgs {
        stdin,
        stdout,
        stderr,
        memory_max_kib: opts.memory_max,
        pids_max: opts.pids_max,
        stop_mode: if opts.stop_cell {
            StopMode::Cell
        } else {
            StopMode::Main
        },
        stop_grace_ms: opts.stop_grace,
        wait_ready: opts.wait_ready,
    };
    let result = Client::connect(socket).and_then(|mut c| {
        let begun = c.begin_run(&opts.name, &spec, &args, false, wait)?;
        Ok((c, begun))
    });
    settle(result, &format!("~{}", opts.name), out, err)
}

/// Print the start, read the end, and return the exit code.
fn settle(
    begun: Result<(Client, Begun), qinit_client::ClientError>,
    frame: &str,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    match ended(begun, frame, out) {
        Ok(code) => code,
        Err(Ended::Failure(f)) => f.report(err),
        Err(Ended::Failed { step, errno }) => {
            let why = std::io::Error::from_raw_os_error(errno.cast_signed());
            let _ = writeln!(
                err,
                "qctl: {frame}: the launch failed at step {step}: {why}"
            );
            1
        }
        Err(Ended::Unseen(name)) => {
            let _ = writeln!(err, "qctl: {name}: its exit was not seen");
            1
        }
    }
}

enum Ended {
    Failure(Failure),
    Failed { step: u32, errno: u32 },
    Unseen(String),
}

impl From<qinit_client::ClientError> for Ended {
    fn from(e: qinit_client::ClientError) -> Self {
        Ended::Failure(e.into())
    }
}

impl From<std::io::Error> for Ended {
    fn from(e: std::io::Error) -> Self {
        Ended::Failure(e.into())
    }
}

fn ended(
    begun: Result<(Client, Begun), qinit_client::ClientError>,
    frame: &str,
    out: &mut dyn Write,
) -> Result<i32, Ended> {
    let (mut client, begun) = begun?;
    let Started { id, pidfd } = match begun {
        Begun::Started(s) => s,
        Begun::Failed { step, errno } => return Err(Ended::Failed { step, errno }),
    };
    let name = format!("{frame}#{id}");
    writeln!(out, "started {name}")?;
    out.flush()?;
    match client.finish(id)? {
        LaunchOutcome::Exited { status, .. } => {
            // Where the kernel can say, the pidfd's status is the word (D45).
            let status = match pidfd.as_ref().map(pidfd_exit) {
                Some(Ok(PidfdExit::Exited(s))) => s,
                _ => status,
            };
            match exit_of(status) {
                Some(Exit::Code(code)) => {
                    writeln!(out, "exited {name} code={code}")?;
                    Ok(code)
                }
                Some(Exit::Signal(sig)) => {
                    writeln!(out, "killed {name} signal={sig}")?;
                    Ok(128 + sig)
                }
                None => Err(Ended::Unseen(name)),
            }
        }
        LaunchOutcome::Pending { .. } => {
            writeln!(out, "still running: {name}")?;
            Ok(0)
        }
        LaunchOutcome::Ready { .. } => {
            writeln!(out, "ready {name}")?;
            Ok(0)
        }
        LaunchOutcome::Failed { step, errno } => Err(Ended::Failed { step, errno }),
    }
}

/// How a process ended, from its wait status.
enum Exit {
    Code(i32),
    Signal(i32),
}

/// `None` for a status that is neither an exit nor a kill (-1: the exit was not seen).
fn exit_of(status: i32) -> Option<Exit> {
    match status & 0x7f {
        _ if status < 0 => None,
        0 => Some(Exit::Code((status >> 8) & 0xff)),
        0x7f => None,
        sig => Some(Exit::Signal(sig)),
    }
}

/// The exit code for a wait status: the process's exit code, or 128 plus the signal that
/// killed it; `None` for a status that is neither (-1: the exit was not seen).
#[must_use]
pub fn exit_code(status: i32) -> Option<i32> {
    exit_of(status).map(|e| match e {
        Exit::Code(n) => n,
        Exit::Signal(s) => 128 + s,
    })
}
