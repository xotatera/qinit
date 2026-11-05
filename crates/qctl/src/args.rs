// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The hand-written argument parser: the full grammar of spec §4.2 and §4.6.
//!
//! Options are `--key value` or `--key=value`; `--` ends the options; an unknown option is a
//! usage error. `--socket PATH` and `--help` are accepted anywhere.
use std::path::PathBuf;

/// The default colony socket.
pub const DEFAULT_SOCKET: &str = "/run/qinit/colony";
/// The default database output.
pub const DEFAULT_OUTPUT: &str = "/etc/qinit/colony.db";
/// The default `--wait` of `launch` and `run`: the protocol's maximum.
pub const DEFAULT_LAUNCH_WAIT: u32 = 600_000;

/// The text of `--help`.
pub const HELP: &str = "\
usage: qctl [--socket PATH] <command> ...   (default socket /run/qinit/colony)

  qctl compile [--layer NAME=DIR]... [--policy FILE | --no-policy] [--output FILE] [--dump FILE]
  qctl show    [--layer NAME=DIR]... [--policy FILE | --no-policy] <kind>.<name>... | policy
  qctl fill    [--layer NAME=DIR]... [--policy FILE | --no-policy] [--dry-run]
               <kind>.<name>... | policy | all
  qctl status <target>
  qctl list [all | workers | foragers | broods]
  qctl start | stop | restart | clear <node> [--wait MS]
  qctl refresh <db> [--wait MS]
  qctl poweroff | reboot | halt [--wait MS]
  qctl launch <frame> [--env K=V]... [--fds stdin,stdout,stderr] [--pidfd] [--wait MS] [-- ARG...]
  qctl run <request.toml> --name NAME [--fds ...] [--wait-ready] [--memory-max KIB]
           [--pids-max N] [--stop-mode main|cell] [--stop-grace MS] [--wait MS]
  qctl watch --all | <target>

Defaults: layers vendor=/usr/lib/qinit/frames then etc=/etc/qinit/frames (the etc layer may be
absent); policy /etc/qinit/policy.toml when it exists; output /etc/qinit/colony.db.
Exit codes: 0 done, 1 refused or failed, 2 usage.
";

/// What the command line asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parsed {
    /// The colony socket.
    pub socket: PathBuf,
    /// The command.
    pub command: Command,
}

/// The result of parsing: a command or a request for the help text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Run this.
    Run(Parsed),
    /// Print [`HELP`].
    Help,
}

/// Which policy file to check against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyChoice {
    /// `/etc/qinit/policy.toml` when it exists.
    Default,
    /// `--no-policy`.
    None,
    /// `--policy FILE`.
    File(PathBuf),
}

/// `qctl compile`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileOpts {
    /// `--layer NAME=DIR`, in order; empty means the defaults.
    pub layers: Vec<(String, PathBuf)>,
    /// The policy choice.
    pub policy: PolicyChoice,
    /// `--output`.
    pub output: PathBuf,
    /// `--dump`.
    pub dump: Option<PathBuf>,
}

/// `qctl show`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShowOpts {
    /// `--layer NAME=DIR`.
    pub layers: Vec<(String, PathBuf)>,
    /// The policy choice.
    pub policy: PolicyChoice,
    /// `<kind>.<name>...` or `policy`.
    pub targets: Vec<String>,
}

/// `qctl fill`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FillOpts {
    /// `--layer NAME=DIR`.
    pub layers: Vec<(String, PathBuf)>,
    /// The policy choice.
    pub policy: PolicyChoice,
    /// `--dry-run`.
    pub dry_run: bool,
    /// `<kind>.<name>...`, `policy` or `all`.
    pub targets: Vec<String>,
}

/// What a change does to a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// `start`.
    Start,
    /// `stop`.
    Stop,
    /// `restart`.
    Restart,
    /// `clear`.
    Clear,
}

/// How the system goes down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// `poweroff`.
    Poweroff,
    /// `reboot`.
    Reboot,
    /// `halt`.
    Halt,
}

/// Which of the standard streams `launch` and `run` pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fds {
    /// Pass standard input.
    pub stdin: bool,
    /// Pass standard output.
    pub stdout: bool,
    /// Pass standard error.
    pub stderr: bool,
}

/// `qctl launch`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchOpts {
    /// The frame.
    pub frame: String,
    /// `--env K=V`.
    pub env: Vec<(String, String)>,
    /// `--fds`.
    pub fds: Fds,
    /// `--pidfd`.
    pub pidfd: bool,
    /// `--wait`.
    pub wait: u32,
    /// Arguments after `--`.
    pub args: Vec<String>,
}

/// `qctl run`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunOpts {
    /// The request file.
    pub request: PathBuf,
    /// `--name`.
    pub name: String,
    /// `--fds`.
    pub fds: Fds,
    /// `--wait-ready`.
    pub wait_ready: bool,
    /// `--memory-max` in KiB, 0 for none.
    pub memory_max: u32,
    /// `--pids-max`, 0 for none.
    pub pids_max: u32,
    /// `--stop-mode`: true for the whole cell.
    pub stop_cell: bool,
    /// `--stop-grace` in ms.
    pub stop_grace: u32,
    /// `--wait`.
    pub wait: u32,
}

/// A command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// `compile`.
    Compile(CompileOpts),
    /// `show`.
    Show(ShowOpts),
    /// `fill`.
    Fill(FillOpts),
    /// `status`.
    Status {
        /// The node or instance.
        target: String,
    },
    /// `list`: 0 all, 1 workers, 2 foragers, 3 broods.
    List {
        /// The kind word.
        kind: u32,
    },
    /// `start`, `stop`, `restart`, `clear`.
    Change {
        /// The node.
        target: String,
        /// What to do.
        action: Action,
        /// `--wait`.
        wait: Option<u32>,
    },
    /// `refresh`.
    Refresh {
        /// The database file.
        db: PathBuf,
        /// `--wait`.
        wait: Option<u32>,
    },
    /// `poweroff`, `reboot`, `halt`.
    Shutdown {
        /// How.
        mode: Mode,
        /// `--wait`.
        wait: Option<u32>,
    },
    /// `launch`.
    Launch(LaunchOpts),
    /// `run`.
    Run(RunOpts),
    /// `watch`.
    Watch {
        /// `--all`.
        all: bool,
        /// The target (empty with `--all`).
        target: String,
    },
}

impl Command {
    /// The command word.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Command::Compile(_) => "compile",
            Command::Show(_) => "show",
            Command::Fill(_) => "fill",
            Command::Status { .. } => "status",
            Command::List { .. } => "list",
            Command::Change { action, .. } => match action {
                Action::Start => "start",
                Action::Stop => "stop",
                Action::Restart => "restart",
                Action::Clear => "clear",
            },
            Command::Refresh { .. } => "refresh",
            Command::Shutdown { mode, .. } => match mode {
                Mode::Poweroff => "poweroff",
                Mode::Reboot => "reboot",
                Mode::Halt => "halt",
            },
            Command::Launch(_) => "launch",
            Command::Run(_) => "run",
            Command::Watch { .. } => "watch",
        }
    }
}

/// One step of the option scanner.
enum Item {
    Opt(String, Option<String>),
    Pos(String),
}

/// The scanner over the arguments of one command.
struct Scan<'a> {
    rest: std::slice::Iter<'a, String>,
    only_positional: bool,
    help: bool,
    socket: Option<PathBuf>,
}

impl<'a> Scan<'a> {
    fn new(args: &'a [String]) -> Self {
        Self {
            rest: args.iter(),
            only_positional: false,
            help: false,
            socket: None,
        }
    }

    /// The next option or positional; handles `--socket` and `--help` itself.
    fn next(&mut self) -> Result<Option<Item>, String> {
        loop {
            let Some(a) = self.rest.next() else {
                return Ok(None);
            };
            if self.only_positional {
                return Ok(Some(Item::Pos(a.clone())));
            }
            if a == "--" {
                self.only_positional = true;
                continue;
            }
            if !a.starts_with("--") {
                return Ok(Some(Item::Pos(a.clone())));
            }
            let (name, inline) = match a.split_once('=') {
                Some((n, v)) => (n.to_owned(), Some(v.to_owned())),
                None => (a.clone(), None),
            };
            match name.as_str() {
                "--help" => self.help = true,
                "--socket" => {
                    let v = self.value("--socket", inline)?;
                    self.socket = Some(PathBuf::from(v));
                }
                _ => return Ok(Some(Item::Opt(name, inline))),
            }
        }
    }

    fn value(&mut self, name: &str, inline: Option<String>) -> Result<String, String> {
        match inline {
            Some(v) => Ok(v),
            None => self
                .rest
                .next()
                .cloned()
                .ok_or_else(|| format!("{name} needs a value")),
        }
    }

    fn flag(name: &str, inline: Option<&str>) -> Result<(), String> {
        match inline {
            None => Ok(()),
            Some(_) => Err(format!("{name} takes no value")),
        }
    }
}

fn number(name: &str, v: &str) -> Result<u32, String> {
    v.parse()
        .map_err(|_| format!("{name}: '{v}' is not a number"))
}

fn layer(v: &str) -> Result<(String, PathBuf), String> {
    match v.split_once('=') {
        Some((n, d)) if !n.is_empty() && !d.is_empty() => Ok((n.to_owned(), PathBuf::from(d))),
        _ => Err(format!("--layer: '{v}' is not NAME=DIR")),
    }
}

fn fds(v: &str) -> Result<Fds, String> {
    let mut f = Fds::default();
    for role in v.split(',').filter(|r| !r.is_empty()) {
        match role {
            "stdin" => f.stdin = true,
            "stdout" => f.stdout = true,
            "stderr" => f.stderr = true,
            other => return Err(format!("--fds: unknown role '{other}'")),
        }
    }
    Ok(f)
}

/// Options shared by `compile`, `show` and `fill`.
struct Source {
    layers: Vec<(String, PathBuf)>,
    policy: PolicyChoice,
}

impl Source {
    /// Take the option if it is one of the shared ones.
    fn take(
        &mut self,
        s: &mut Scan<'_>,
        name: &str,
        inline: Option<String>,
    ) -> Result<bool, String> {
        match name {
            "--layer" => {
                let v = s.value(name, inline)?;
                self.layers.push(layer(&v)?);
            }
            "--policy" => {
                if self.policy == PolicyChoice::None {
                    return Err("--policy and --no-policy are exclusive".into());
                }
                let v = s.value(name, inline)?;
                self.policy = PolicyChoice::File(PathBuf::from(v));
            }
            "--no-policy" => {
                Scan::flag(name, inline.as_deref())?;
                if matches!(self.policy, PolicyChoice::File(_)) {
                    return Err("--policy and --no-policy are exclusive".into());
                }
                self.policy = PolicyChoice::None;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}

fn unknown(name: &str) -> String {
    format!("unknown option '{name}'")
}

// One flat table of the options of every command: splitting it would scatter the grammar.
#[allow(clippy::too_many_lines)]
fn parse_command(word: &str, s: &mut Scan<'_>) -> Result<Command, String> {
    let mut pos: Vec<String> = Vec::new();
    let mut wait: Option<u32> = None;
    let mut src = Source {
        layers: Vec::new(),
        policy: PolicyChoice::Default,
    };
    let mut output = PathBuf::from(DEFAULT_OUTPUT);
    let mut dump = None;
    let mut dry_run = false;
    let mut all = false;
    let mut env = Vec::new();
    let mut fd = Fds::default();
    let mut pidfd = false;
    let mut name = None;
    let mut wait_ready = false;
    let (mut memory_max, mut pids_max, mut stop_cell, mut stop_grace) = (0, 0, false, 100);
    let mut tail = Vec::new();
    let launch_like = matches!(word, "launch" | "run");
    while let Some(item) = s.next()? {
        match item {
            Item::Pos(p)
                if s.only_positional && launch_like && word == "launch" && !pos.is_empty() =>
            {
                tail.push(p);
            }
            Item::Pos(p) => pos.push(p),
            Item::Opt(o, inline) => {
                let o = o.as_str();
                let shared = matches!(word, "compile" | "show" | "fill")
                    && src.take(s, o, inline.clone())?;
                if shared {
                    continue;
                }
                match (word, o) {
                    ("compile", "--output") => output = PathBuf::from(s.value(o, inline)?),
                    ("compile", "--dump") => dump = Some(PathBuf::from(s.value(o, inline)?)),
                    ("fill", "--dry-run") => {
                        Scan::flag(o, inline.as_deref())?;
                        dry_run = true;
                    }
                    ("watch", "--all") => {
                        Scan::flag(o, inline.as_deref())?;
                        all = true;
                    }
                    (
                        "start" | "stop" | "restart" | "clear" | "refresh" | "poweroff" | "reboot"
                        | "halt" | "launch" | "run",
                        "--wait",
                    ) => {
                        let v = s.value(o, inline)?;
                        wait = Some(number(o, &v)?);
                    }
                    ("launch", "--env") => {
                        let v = s.value(o, inline)?;
                        let (k, val) = v
                            .split_once('=')
                            .filter(|(k, _)| !k.is_empty())
                            .ok_or_else(|| format!("--env: '{v}' is not K=V"))?;
                        env.push((k.to_owned(), val.to_owned()));
                    }
                    ("launch" | "run", "--fds") => fd = fds(&s.value(o, inline)?)?,
                    ("launch", "--pidfd") => {
                        Scan::flag(o, inline.as_deref())?;
                        pidfd = true;
                    }
                    ("run", "--name") => name = Some(s.value(o, inline)?),
                    ("run", "--wait-ready") => {
                        Scan::flag(o, inline.as_deref())?;
                        wait_ready = true;
                    }
                    ("run", "--memory-max") => memory_max = number(o, &s.value(o, inline)?)?,
                    ("run", "--pids-max") => pids_max = number(o, &s.value(o, inline)?)?,
                    ("run", "--stop-grace") => stop_grace = number(o, &s.value(o, inline)?)?,
                    ("run", "--stop-mode") => {
                        stop_cell = match s.value(o, inline)?.as_str() {
                            "main" => false,
                            "cell" => true,
                            other => {
                                return Err(format!("--stop-mode: '{other}' is not main or cell"));
                            }
                        };
                    }
                    _ => return Err(unknown(o)),
                }
            }
        }
    }
    let one = |what: &str, mut pos: Vec<String>| -> Result<String, String> {
        match pos.len() {
            1 => Ok(pos.remove(0)),
            0 => Err(format!("{word}: missing {what}")),
            _ => Err(format!("{word}: unexpected argument '{}'", pos[1])),
        }
    };
    let none = |pos: &[String]| -> Result<(), String> {
        pos.first().map_or(Ok(()), |p| {
            Err(format!("{word}: unexpected argument '{p}'"))
        })
    };
    Ok(match word {
        "compile" => {
            none(&pos)?;
            Command::Compile(CompileOpts {
                layers: src.layers,
                policy: src.policy,
                output,
                dump,
            })
        }
        "show" => {
            if pos.is_empty() {
                return Err("show: missing target".into());
            }
            Command::Show(ShowOpts {
                layers: src.layers,
                policy: src.policy,
                targets: pos,
            })
        }
        "fill" => {
            if pos.is_empty() {
                return Err("fill: missing target".into());
            }
            Command::Fill(FillOpts {
                layers: src.layers,
                policy: src.policy,
                dry_run,
                targets: pos,
            })
        }
        "status" => Command::Status {
            target: one("target", pos)?,
        },
        "list" => {
            let kind = match pos.as_slice() {
                [] => 0,
                [k] => match k.as_str() {
                    "all" => 0,
                    "workers" => 1,
                    "foragers" => 2,
                    "broods" => 3,
                    other => {
                        return Err(format!(
                            "list: '{other}' is not all, workers, foragers or broods"
                        ));
                    }
                },
                [_, extra, ..] => return Err(format!("list: unexpected argument '{extra}'")),
            };
            Command::List { kind }
        }
        "start" | "stop" | "restart" | "clear" => {
            let action = match word {
                "start" => Action::Start,
                "stop" => Action::Stop,
                "restart" => Action::Restart,
                _ => Action::Clear,
            };
            Command::Change {
                target: one("node", pos)?,
                action,
                wait,
            }
        }
        "refresh" => Command::Refresh {
            db: PathBuf::from(one("database", pos)?),
            wait,
        },
        "poweroff" | "reboot" | "halt" => {
            none(&pos)?;
            let mode = match word {
                "poweroff" => Mode::Poweroff,
                "reboot" => Mode::Reboot,
                _ => Mode::Halt,
            };
            Command::Shutdown { mode, wait }
        }
        "launch" => Command::Launch(LaunchOpts {
            frame: one("frame", pos)?,
            env,
            fds: fd,
            pidfd,
            wait: wait.unwrap_or(DEFAULT_LAUNCH_WAIT),
            args: tail,
        }),
        "run" => Command::Run(RunOpts {
            request: PathBuf::from(one("request file", pos)?),
            name: name.ok_or("run: --name is required")?,
            fds: fd,
            wait_ready,
            memory_max,
            pids_max,
            stop_cell,
            stop_grace,
            wait: wait.unwrap_or(DEFAULT_LAUNCH_WAIT),
        }),
        "watch" => match (all, pos.len()) {
            (true, 0) => Command::Watch {
                all,
                target: String::new(),
            },
            (false, 1) => Command::Watch {
                all,
                target: pos.remove(0),
            },
            (true, _) => return Err("watch: --all takes no target".into()),
            (false, 0) => return Err("watch: needs --all or a target".into()),
            (false, _) => return Err(format!("watch: unexpected argument '{}'", pos[1])),
        },
        other => return Err(format!("unknown command '{other}'")),
    })
}

/// Parse the arguments (without the program name).
///
/// # Errors
/// A usage message.
pub fn parse(args: &[String]) -> Result<Outcome, String> {
    let mut s = Scan::new(args);
    // The command word is the first positional; options before it are global.
    let word = match s.next()? {
        Some(Item::Pos(w)) => w,
        Some(Item::Opt(o, _)) => return Err(unknown(&o)),
        None if s.help => return Ok(Outcome::Help),
        None => return Err("missing command".into()),
    };
    let command = parse_command(&word, &mut s);
    if s.help {
        return Ok(Outcome::Help);
    }
    Ok(Outcome::Run(Parsed {
        socket: s.socket.unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET)),
        command: command?,
    }))
}
