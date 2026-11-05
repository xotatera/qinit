// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! A deterministic, human-readable dump of a resolved model with the layer behind each key.
//!
//! One block per node in name order: a `<kind> <name>` heading, then indented
//! `key = value  # <origin>` lines in frame key syntax, then the dependency groups and their
//! edges. The origin is the layer that set the key (or the list it sits in); `template <name>`
//! when the frame inherited it from that template; `default` when no layer set it (a default,
//! or a value derived from other keys, such as `errors` following `output`). An instance's
//! `instance_of` carries the origin of its frame. The implicit logger group carries the origin
//! of the `output` or `errors` key that pipes to each logger.
//! Edge keys use the frame's own edge index (`Resolved::edge_origins`), so an edge after a
//! dropped optional edge keeps the key its frame and any warning give it; the implicit logger
//! group comes after the frame's groups.
//! The trailer lists the enabled closure and the pre-syslog nodes.
use crate::expand::kind_name;
use crate::provenance::{FrameKey, Origin, Provenance, parse_path, set_by};
use crate::resolve::{Resolved, cap_name, ns_name};
use crate::syscalls;
use qinit_db::{
    Cred, Edge, GroupKind, Kind, Mode, Model, Node, RLIMIT_KEYS, Ready, Reload, RestartOn,
    RestartPolicy, Route, Seccomp, Securebits, StopMode, Target, UserMap,
};
use qinit_db_core::{FD_STDERR, FD_STDIN, FD_STDOUT};
use std::fmt::Write as _;

/// One `key = value  # origin` line of the dump.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    /// The index of the node in the model.
    pub node: usize,
    /// The key in frame key syntax, such as `restart.policy` or `deps[0].edges[1]`.
    pub key: String,
    /// The resolved value in frame syntax.
    pub value: String,
    /// The origin label: the layer, `template <name>` or `default`.
    pub origin: String,
}

/// The keyed lines of every node of `resolved`, node by node, with the origin of each key from
/// `provenance`.
#[must_use]
pub fn lines(resolved: &Resolved, provenance: &Provenance) -> Vec<Line> {
    let model = &resolved.model;
    let mut out = Vec::new();
    for (i, node) in model.nodes.iter().enumerate() {
        let mut b = Block {
            out: &mut out,
            index: i,
            prov: provenance,
            kind: kind_name(node.kind),
            name: &node.name,
            origins: resolved.edge_origins.get(i).map_or(&[], Vec::as_slice),
            frame_groups: resolved.frame_groups.get(i).copied().unwrap_or(0),
        };
        b.node(model, node);
    }
    out
}

/// Render `resolved` with the origin of each key from `provenance`.
#[must_use]
pub fn render(resolved: &Resolved, provenance: &Provenance) -> String {
    let model = &resolved.model;
    let all = lines(resolved, provenance);
    let mut rest = all.as_slice();
    let mut out = String::new();
    for (i, node) in model.nodes.iter().enumerate() {
        let _ = writeln!(out, "{} {}", kind_name(node.kind), node.name);
        let n = rest.iter().take_while(|l| l.node == i).count();
        for l in &rest[..n] {
            let _ = writeln!(out, "  {} = {}  # {}", l.key, l.value, l.origin);
        }
        rest = &rest[n..];
        out.push('\n');
    }
    let names = |ix: &[u32]| list(ix.iter().map(|&i| quote(node_name(model, i))));
    let _ = writeln!(out, "enabled = {}", names(&model.enabled));
    let _ = writeln!(out, "presyslog = {}", names(&model.presyslog));
    out
}

/// The lines of one node.
struct Block<'a> {
    out: &'a mut Vec<Line>,
    /// The node's index in the model.
    index: usize,
    prov: &'a Provenance,
    kind: &'a str,
    name: &'a str,
    /// Per group, the frame index of each edge.
    origins: &'a [Vec<usize>],
    /// How many groups come from the frame's `deps`; a further group is the implicit logger
    /// group.
    frame_groups: usize,
}

/// The comment the dump puts after a value with origin `o`: `template <name>` for a key
/// inherited from a template, the layer for any other key a layer set, `default` for none.
#[must_use]
pub fn label(o: Option<&Origin>) -> String {
    match o {
        Some(Origin {
            template: Some(t), ..
        }) => format!("template {t}"),
        Some(o) => o.layer.clone(),
        None => "default".to_owned(),
    }
}

impl Block<'_> {
    /// The origin of `key` (frame key syntax) as the dump shows it.
    fn origin(&self, key: &str) -> String {
        label(set_by(self.prov, self.kind, self.name, &parse_path(key)))
    }

    fn line_from(&mut self, key: &str, value: &str, origin: &str) {
        self.out.push(Line {
            node: self.index,
            key: key.to_owned(),
            value: value.to_owned(),
            origin: origin.to_owned(),
        });
    }

    fn line(&mut self, key: &str, value: &str) {
        let origin = self.origin(key);
        self.line_from(key, value, &origin);
    }

    /// The origin of an implicit logger edge to `logger`: that of the stream piping to it.
    fn logger_origin(&self, model: &Model, n: &Node, logger: Option<u32>) -> String {
        let pipes_to = |r: Option<u32>| {
            r.and_then(|r| model.routes.get(r as usize))
                .is_some_and(|r| matches!(r, Route::Pipe(l) if Some(*l) == logger))
        };
        if pipes_to(n.output) {
            self.origin("output")
        } else if pipes_to(n.errors) {
            self.origin("errors")
        } else {
            label(None)
        }
    }

    /// The `reload` signal and the `launch` table of a worker or forager.
    fn reload_and_launch(&mut self, n: &Node) {
        if let Some(r) = n.reload {
            let name = match r {
                Reload::Hup => "SIGHUP",
                Reload::Usr1 => "SIGUSR1",
                Reload::Usr2 => "SIGUSR2",
            };
            self.line("reload", &quote(name));
        }
        if let Some(l) = &n.launch {
            self.line("launch.concurrency", &l.concurrency.to_string());
            self.line("launch.argv_tail", &l.argv_tail.to_string());
            self.line("launch.env", &list(l.env.iter().map(|k| quote(k))));
            let roles = [
                (FD_STDIN, "stdin"),
                (FD_STDOUT, "stdout"),
                (FD_STDERR, "stderr"),
            ];
            let fds = roles
                .iter()
                .filter(|(bit, _)| l.fds & bit != 0)
                .map(|(_, name)| quote(name));
            self.line("launch.fds", &list(fds));
        }
    }

    fn node(&mut self, model: &Model, n: &Node) {
        if let Some(t) = &n.instance_of {
            let frame = FrameKey::new(self.kind, self.name, &[]);
            let origin = label(self.prov.get(&frame));
            self.line_from("instance_of", &quote(t), &origin);
        }
        if n.kind != Kind::Brood {
            self.line("exec", &list(n.exec.iter().map(|s| quote(s))));
            self.line("ready", &ready(&n.ready));
        }
        if n.kind == Kind::Worker {
            self.line("restart.policy", &quote(policy(n.restart.policy)));
            self.line("restart.max", &n.restart.max.to_string());
            self.line(
                "restart.window",
                &quote(&format!("{}ms", n.restart.window_ms)),
            );
            self.line(
                "restart.delay",
                &quote(&format!("{}ms", n.restart.delay_ms)),
            );
        }
        if n.kind != Kind::Brood {
            let mode = match n.stop.mode {
                StopMode::Main => "main",
                StopMode::Cell => "cell",
            };
            self.line("stop.mode", &quote(mode));
            self.line("stop.grace", &quote(&format!("{}ms", n.stop.grace_ms)));
            let timeout = match n.start_timeout_ms {
                0 => "none".to_owned(),
                ms => format!("{ms}ms"),
            };
            self.line("start_timeout", &quote(&timeout));
        }
        for (key, r) in [("output", n.output), ("errors", n.errors)] {
            if let Some(r) = r {
                self.line(key, &route(model, r));
            }
        }
        if n.kind != Kind::Brood {
            self.line("cell.memory_max", &quote(&format!("{}K", n.memory_max_kib)));
            self.line("cell.pids_max", &n.pids_max.to_string());
            for entry in &n.env {
                let (k, v) = entry.split_once('=').unwrap_or((entry, ""));
                self.line(&format!("env.{k}"), &quote(v));
            }
            self.line("cwd", &quote(&n.cwd));
            self.line("umask", &format!("0o{:03o}", n.umask));
            for (key, limit) in RLIMIT_KEYS.iter().zip(n.rlimits) {
                match limit {
                    Some(u64::MAX) => self.line(&format!("rlimits.{key}"), "infinity"),
                    Some(v) => self.line(&format!("rlimits.{key}"), &v.to_string()),
                    None => {}
                }
            }
            self.reload_and_launch(n);
        }
        if let Some(c) = n.cred.and_then(|c| model.creds.get(c as usize)) {
            self.cred(c);
        }
        for (gi, g) in n.groups.iter().enumerate() {
            let implicit = gi >= self.frame_groups;
            let group_key = format!("deps[{gi}].group");
            if implicit {
                let first = g.edges.first().and_then(node_target);
                let origin = self.logger_origin(model, n, first);
                self.line_from(&group_key, &quote(group(g.kind)), &origin);
            } else {
                self.line(&group_key, &quote(group(g.kind)));
            }
            for (ei, e) in g.edges.iter().enumerate() {
                let fi = self.origins.get(gi).and_then(|o| o.get(ei)).copied();
                let key = format!("deps[{gi}].edges[{}]", fi.unwrap_or(ei));
                if implicit {
                    let origin = self.logger_origin(model, n, node_target(e));
                    self.line_from(&key, &edge(model, e), &origin);
                } else {
                    self.line(&key, &edge(model, e));
                }
            }
        }
    }

    fn cred(&mut self, c: &Cred) {
        let caps = (0..64u8)
            .filter(|b| c.caps & (1u64 << b) != 0)
            .map(|b| quote(cap_name(b).unwrap_or("?")));
        let ns = (0..32u8)
            .filter(|b| c.ns & (1u32 << b) != 0)
            .map(|b| quote(ns_name(b).unwrap_or("?")));
        let securebits = match c.securebits {
            Securebits::None => "none",
            Securebits::Noroot => "noroot",
            Securebits::NorootLocked => "noroot-locked",
        };
        let user_map = match c.user_map {
            UserMap::Own => "own",
            UserMap::Range => "range",
        };
        let names = |l: &[u32]| list(l.iter().map(|nr| quote(syscalls::name(*nr).unwrap_or("?"))));
        let seccomp = match &c.seccomp {
            Seccomp::None => quote("none"),
            Seccomp::Default => quote("default"),
            Seccomp::Deny(l) => format!("{{ deny = {} }}", names(l)),
            Seccomp::Allow(l) => format!("{{ allow = {} }}", names(l)),
        };
        self.line("credentials.uid", &quote(&c.user));
        self.line("credentials.caps", &list(caps));
        self.line("credentials.nnp", &c.nnp.to_string());
        self.line("credentials.securebits", &quote(securebits));
        self.line("sandbox.namespaces", &list(ns));
        self.line("sandbox.seccomp", &seccomp);
        self.line("sandbox.paths", &list(c.paths.iter().map(|s| quote(s))));
        self.line("sandbox.user_map", &quote(user_map));
        self.line("sandbox.inside_uid", &c.inside_uid.to_string());
        self.line("sandbox.inside_gid", &c.inside_gid.to_string());
    }
}

fn node_target(e: &Edge) -> Option<u32> {
    match e.target {
        Target::Node(i) => Some(i),
        Target::Path(_) => None,
    }
}

fn node_name(model: &Model, i: u32) -> &str {
    model.nodes.get(i as usize).map_or("?", |n| n.name.as_str())
}

fn quote(s: &str) -> String {
    format!("{s:?}")
}

fn list(items: impl Iterator<Item = String>) -> String {
    format!("[{}]", items.collect::<Vec<_>>().join(", "))
}

fn ready(r: &Ready) -> String {
    match r {
        Ready::Pipe => quote("pipe"),
        Ready::Exit => quote("exit"),
        Ready::Socket(p) => format!("{{ socket = {} }}", quote(p)),
        Ready::Path(p) => format!("{{ path = {} }}", quote(p)),
    }
}

fn policy(p: RestartPolicy) -> &'static str {
    match p {
        RestartPolicy::Never => "never",
        RestartPolicy::OnFailure => "on-failure",
        RestartPolicy::Always => "always",
    }
}

fn route(model: &Model, r: u32) -> String {
    match model.routes.get(r as usize) {
        Some(Route::Path(p)) => quote(p),
        Some(Route::Pipe(n)) => format!("{{ pipe = {} }}", quote(node_name(model, *n))),
        None => quote("?"),
    }
}

fn group(k: GroupKind) -> &'static str {
    match k {
        GroupKind::RequireAll => "require_all",
        GroupKind::RequireAny => "require_any",
        GroupKind::OptionalAll => "optional_all",
        GroupKind::ExcludeAll => "exclude_all",
    }
}

fn edge(model: &Model, e: &Edge) -> String {
    let mut s = match &e.target {
        Target::Node(i) => format!("{{ to = {}", quote(node_name(model, *i))),
        Target::Path(p) => format!("{{ path = {}", quote(p)),
    };
    match e.mode {
        Mode::Sync => s.push_str(", mode = \"sync\""),
        Mode::Async => {
            let _ = write!(s, ", mode = \"async\", deadline = \"{}ms\"", e.deadline_ms);
        }
    }
    let on = match e.restart_on {
        RestartOn::None => "none",
        RestartOn::Error => "error",
        RestartOn::Restart => "restart",
        RestartOn::Refresh => "refresh",
    };
    let _ = write!(s, ", restart_on = {}", quote(on));
    if e.stop_parallel {
        s.push_str(", stop = \"parallel\"");
    }
    if e.cascade {
        s.push_str(", cascade = true");
    }
    s.push_str(" }");
    s
}
