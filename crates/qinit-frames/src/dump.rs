// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! A deterministic, human-readable dump of a resolved model with the layer behind each key.
//!
//! One block per node in name order: a `<kind> <name>` heading, then indented
//! `key = value  # <layer>` lines in frame key syntax, then the dependency groups and their
//! edges. The layer is the one that set the key or its nearest enclosing key (`-` if none).
//! The trailer lists the enabled closure and the pre-syslog nodes.
use crate::expand::{kind_name, layer_of};
use crate::resolve::{cap_name, ns_name};
use qinit_db::{
    Cred, Edge, GroupKind, Kind, Mode, Model, Node, Ready, RestartOn, RestartPolicy, Route,
    Seccomp, Securebits, Target,
};
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Render `model`; `provenance` maps dotted key paths to the layer that set them.
#[must_use]
pub fn render(model: &Model, provenance: &BTreeMap<String, String>) -> String {
    let mut out = String::new();
    for node in &model.nodes {
        let base = format!("{}.{}", kind_name(node.kind), node.name);
        let mut b = Block {
            out: &mut out,
            prov: provenance,
            base: &base,
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
    prov: &'a BTreeMap<String, String>,
    base: &'a str,
}

impl Block<'_> {
    fn line(&mut self, key: &str, value: &str) {
        let layer = layer_of(self.prov, &format!("{}.{key}", self.base)).unwrap_or("-");
        let _ = writeln!(self.out, "  {key} = {value}  # {layer}");
    }

    fn node(&mut self, model: &Model, n: &Node) {
        let _ = writeln!(self.out, "{} {}", kind_name(n.kind), n.name);
        if let Some(t) = &n.instance_of {
            self.line("instance_of", &quote(t));
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
            self.line(&format!("deps[{gi}].group"), &quote(group(g.kind)));
            for (ei, e) in g.edges.iter().enumerate() {
                self.line(&format!("deps[{gi}].edges[{ei}]"), &edge(model, e));
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
    s.push_str(" }");
    s
}
