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
use qinit_db::{
    Cred, Edge, GroupKind, Kind, Mode, Model, Node, Ready, RestartOn, RestartPolicy, Route,
    Seccomp, Securebits, StopMode, Target,
};
use std::fmt::Write as _;

/// Render `resolved` with the origin of each key from `provenance`.
#[must_use]
pub fn render(resolved: &Resolved, provenance: &Provenance) -> String {
    let model = &resolved.model;
    let mut out = String::new();
    for (i, node) in model.nodes.iter().enumerate() {
        let mut b = Block {
            out: &mut out,
            prov: provenance,
            kind: kind_name(node.kind),
            name: &node.name,
            origins: resolved.edge_origins.get(i).map_or(&[], Vec::as_slice),
            frame_groups: resolved.frame_groups.get(i).copied().unwrap_or(0),
        };
        b.node(model, node);
        out.push('\n');
    }
    let names = |ix: &[u32]| list(ix.iter().map(|&i| quote(node_name(model, i))));
    let _ = writeln!(out, "enabled = {}", names(&model.enabled));
    let _ = writeln!(out, "presyslog = {}", names(&model.presyslog));
    out
}

/// The lines of one node.
struct Block<'a> {
    out: &'a mut String,
    prov: &'a Provenance,
    kind: &'a str,
    name: &'a str,
    /// Per group, the frame index of each edge.
    origins: &'a [Vec<usize>],
    /// How many groups come from the frame's `deps`; a further group is the implicit logger
    /// group.
    frame_groups: usize,
}

/// The comment the dump puts after a value with origin `o`.
fn label(o: Option<&Origin>) -> String {
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
        let _ = writeln!(self.out, "  {key} = {value}  # {origin}");
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

    fn node(&mut self, model: &Model, n: &Node) {
        let _ = writeln!(self.out, "{} {}", kind_name(n.kind), n.name);
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
        let seccomp = match c.seccomp {
            Seccomp::None => "none",
            Seccomp::Default => "default",
        };
        self.line("credentials.uid", &quote(&c.user));
        self.line("credentials.caps", &list(caps));
        self.line("credentials.nnp", &c.nnp.to_string());
        self.line("credentials.securebits", &quote(securebits));
        self.line("sandbox.namespaces", &list(ns));
        self.line("sandbox.seccomp", &quote(seccomp));
        self.line(
            "sandbox.landlock",
            &list(c.landlock.iter().map(|s| quote(s))),
        );
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
