// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qctl show`: a frame or the policy as effective TOML, each key with its origin (spec
//! 2026-11-05 §4.3).
//!
//! A frame prints as `[<kind>.<name>]` and one `key = value  # <origin>` line per key of the
//! dump, in the dump's order. A key a layer set keeps the value as the layer wrote it (so `%i`
//! and units stay as written), taken from the frame's merged table or, for a key it inherits,
//! from its template's. A key no layer set prints the resolved default. Keys that are derived
//! (`errors` following `output`, the implicit logger group) are left out. Every default prints
//! as a key (`start_timeout` "none" and `sandbox.user_map` "own" have words), so the output
//! compiles back to the same nodes. The template is resolved into the frame: its name is a
//! comment and the keys it gives are marked `# template <name>`.
use crate::args::{PolicyChoice, ShowOpts};
use crate::compile::{Defaults, checked_input};
use crate::{report, toml_text};
use qinit_db::{RLIMIT_KEYS, Userns};
use qinit_frames::compile::{Compiled, compile};
use qinit_frames::dump::{self, Line};
use qinit_frames::error::Error;
use qinit_frames::layers::load_enable_origins;
use qinit_frames::policy;
use qinit_frames::provenance::{Provenance, Seg, parse_path, set_by};
use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;
use toml::{Table, Value};

/// The kind words a frame target may start with.
pub(crate) const KINDS: [&str; 4] = ["worker", "forager", "brood", "template"];

/// One target of the command line.
enum Target<'a> {
    Policy,
    Enable,
    Frame { kind: &'a str, name: &'a str },
}

fn target(t: &str) -> Option<Target<'_>> {
    match t {
        "policy" => return Some(Target::Policy),
        "enable" => return Some(Target::Enable),
        _ => {}
    }
    let (kind, name) = t.split_once('.')?;
    (KINDS.contains(&kind) && !name.is_empty()).then_some(Target::Frame { kind, name })
}

/// Run `qctl show`; returns the exit code.
pub fn run(opts: &ShowOpts, defaults: &Defaults, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let mut targets = Vec::new();
    for t in &opts.targets {
        let Some(parsed) = target(t) else {
            let _ = writeln!(
                err,
                "qctl: show: '{t}' is not <kind>.<name>, enable or policy\nTry 'qctl --help'."
            );
            return 2;
        };
        targets.push(parsed);
    }
    let input = match checked_input(&opts.layers, &opts.policy, defaults, err) {
        Ok(i) => i,
        Err(code) => return code,
    };
    let compiled = if targets.iter().any(|t| matches!(t, Target::Frame { .. })) {
        match compile(&input) {
            Ok(c) => {
                for w in &c.warnings {
                    let _ = writeln!(err, "{}", report::warning_line(w));
                }
                Some(c)
            }
            Err(errors) => {
                for e in &errors {
                    let _ = writeln!(err, "{}", report::error_line(e));
                }
                return 1;
            }
        }
    } else {
        None
    };
    let mut text = Vec::new();
    for t in &targets {
        let shown = match (t, &compiled) {
            (Target::Frame { kind, name }, Some(c)) => frame(c, kind, name).map_err(Unshown::from),
            (Target::Frame { .. }, None) => Err("show: the frames were not compiled".into()),
            (Target::Enable, _) => show_enable(&input.layers),
            (Target::Policy, _) => match (&input.policy, &opts.policy) {
                (Some(p), _) => show_policy(p),
                (None, PolicyChoice::None) => Err("show policy: --no-policy was given".into()),
                (None, _) => Err("show policy: there is no policy file".into()),
            },
        };
        match shown {
            Ok(s) => text.push(s),
            Err(Unshown::Message(m)) => {
                let _ = writeln!(err, "qctl: {m}");
                return 1;
            }
            Err(Unshown::Errors(errors)) => {
                for e in &errors {
                    let _ = writeln!(err, "{}", report::error_line(e));
                }
                return 1;
            }
        }
    }
    let _ = out.write_all(text.join("\n").as_bytes());
    0
}

/// Why a target is not shown.
enum Unshown {
    /// A message of `qctl`'s, printed after `qctl: `.
    Message(String),
    /// The errors of reading a file, printed one per line as `compile` prints them.
    Errors(Vec<Error>),
}

impl From<String> for Unshown {
    fn from(m: String) -> Self {
        Unshown::Message(m)
    }
}

impl From<&str> for Unshown {
    fn from(m: &str) -> Self {
        Unshown::Message(m.to_owned())
    }
}

/// The merged `enable` and `syslog` lists as an `enable.toml`, each with the layer that set it
/// last (`default` when none did, then the list is empty). A layer given as one file has no
/// `enable.toml`, as for the compiler.
fn show_enable(layers: &[qinit_frames::layers::LayerInput]) -> Result<String, Unshown> {
    let (list, origins) = load_enable_origins(layers).map_err(Unshown::Errors)?;
    let mut text = String::new();
    for (key, items) in [("enable", list.roots), ("syslog", list.syslog)] {
        let items: Vec<Value> = items.into_iter().map(Value::String).collect();
        let origin = dump::label(origins.get(key));
        let _ = writeln!(
            text,
            "{key} = {}  # {origin}",
            toml_text::value(&Value::Array(items))
        );
    }
    Ok(text)
}

/// The table at `kind.name` of the merged frames.
pub(crate) fn merged_frame<'a>(c: &'a Compiled, kind: &str, name: &str) -> Option<&'a Table> {
    c.merged.table.get(kind)?.as_table()?.get(name)?.as_table()
}

/// The value at the table-key `path` below `t`.
fn at<'a>(t: &'a Table, path: &[Seg]) -> Option<&'a Value> {
    let (first, rest) = path.split_first()?;
    let Seg::Key(k) = first else { return None };
    let v = t.get(k)?;
    if rest.is_empty() {
        Some(v)
    } else {
        at(v.as_table()?, rest)
    }
}

/// The frame `kind.name` (or the frame of instance `name`) as TOML.
fn frame(c: &Compiled, kind: &str, name: &str) -> Result<String, String> {
    if kind == "template" {
        return template(c, name);
    }
    let missing = || format!("show: no frame {kind}.{name}");
    let model = &c.resolved.model;
    let (frame_name, mut text) = match name.split_once('@') {
        Some((f, _)) => {
            model
                .nodes
                .iter()
                .find(|n| n.name == name && kind_word(n) == kind)
                .ok_or_else(missing)?;
            (f, format!("# {name} is an instance of {kind}.{f}\n"))
        }
        None => (name, String::new()),
    };
    let table = merged_frame(c, kind, frame_name).ok_or_else(missing)?;
    let index = model
        .nodes
        .iter()
        .position(|n| {
            kind_word(n) == kind
                && (n.name == frame_name || n.instance_of.as_deref() == Some(frame_name))
        })
        .ok_or_else(missing)?;
    let node = &model.nodes[index];
    let tpl_name = table.get("template").and_then(Value::as_str);
    let tpl = tpl_name.and_then(|t| merged_frame(c, "template", t));
    let f = Frame {
        prov: &c.provenance,
        kind,
        node: &node.name,
        table,
        tpl,
    };
    let _ = writeln!(text, "[{kind}.{}]", toml_text::key(frame_name));
    if let Some(t) = tpl_name {
        let origin = f.origin("template");
        let _ = writeln!(
            text,
            "# template {} ({origin}) is resolved: the keys it gives are marked `# template {t}`",
            toml_text::string(t)
        );
    }
    let lines = dump::lines(&c.resolved, &c.provenance);
    for l in lines.iter().filter(|l| l.node == index) {
        f.line(&mut text, l);
    }
    f.deps(&mut text);
    Ok(text)
}

/// The node's kind word.
pub(crate) fn kind_word(n: &qinit_db::Node) -> &'static str {
    match n.kind {
        qinit_db::Kind::Worker => "worker",
        qinit_db::Kind::Forager => "forager",
        qinit_db::Kind::Brood => "brood",
    }
}

/// One frame being shown: its merged table, its template's and the provenance of its node.
struct Frame<'a> {
    prov: &'a Provenance,
    kind: &'a str,
    /// The node the dump lines come from: the frame itself or its first instance.
    node: &'a str,
    table: &'a Table,
    tpl: Option<&'a Table>,
}

impl Frame<'_> {
    fn origin_at(&self, path: &[Seg]) -> String {
        dump::label(set_by(self.prov, self.kind, self.node, path))
    }

    fn origin(&self, key: &str) -> String {
        self.origin_at(&parse_path(key))
    }

    /// The value a layer wrote for `path`: the frame's, or the template's when it inherited it.
    fn written(&self, path: &[Seg]) -> Option<&Value> {
        let o = set_by(self.prov, self.kind, self.node, path)?;
        let table = if o.template.is_some() {
            self.tpl?
        } else {
            self.table
        };
        at(table, path)
    }

    fn line(&self, text: &mut String, l: &Line) {
        if l.key.starts_with("deps[") || (l.key == "errors" && l.origin == "default") {
            return;
        }
        let (key, path) = if l.key == "instance_of" {
            ("instances", vec![Seg::Key("instances".into())])
        } else {
            (l.key.as_str(), parse_path(&l.key))
        };
        let origin = self.origin_at(&path);
        let written = (origin != "default").then(|| self.written(&path)).flatten();
        let value = match written {
            Some(Value::Integer(u)) if key == "umask" => format!("0o{u:03o}"),
            Some(v) => toml_text::value(v),
            None => l.value.clone(),
        };
        let _ = writeln!(text, "{key} = {value}  # {origin}");
    }

    /// `deps` as the frame gets it: the template's groups, then the frame's own, one per line.
    fn deps(&self, text: &mut String) {
        let deps = |t: Option<&Table>| {
            t.and_then(|t| t.get("deps"))
                .and_then(Value::as_array)
                .cloned()
        };
        let (mine, theirs) = (deps(Some(self.table)), deps(self.tpl));
        if mine.is_none() && theirs.is_none() {
            return;
        }
        let groups: Vec<Value> = theirs.into_iter().chain(mine).flatten().collect();
        let deps = Seg::Key("deps".into());
        write_deps(text, &groups, |i| match i {
            Some(i) => self.origin_at(&[deps.clone(), Seg::Index(i)]),
            None => self.origin_at(std::slice::from_ref(&deps)),
        });
    }
}

/// A `deps` list, one group per line with its origin (`origin(Some(i))`; `origin(None)` is the
/// list's, for an empty one).
fn write_deps(text: &mut String, groups: &[Value], origin: impl Fn(Option<usize>) -> String) {
    if groups.is_empty() {
        let _ = writeln!(text, "deps = []  # {}", origin(None));
        return;
    }
    text.push_str("deps = [\n");
    for (i, g) in groups.iter().enumerate() {
        let _ = writeln!(text, "  {},  # {}", toml_text::value(g), origin(Some(i)));
    }
    text.push_str("]\n");
}

/// A template as its layers merged it, one dotted key per value, each with its origin.
fn template(c: &Compiled, name: &str) -> Result<String, String> {
    let table = merged_frame(c, "template", name)
        .ok_or_else(|| format!("show: no frame template.{name}"))?;
    let mut text = format!("[template.{}]\n", toml_text::key(name));
    flat(c, name, table, &mut Vec::new(), &mut text);
    Ok(text)
}

fn flat(c: &Compiled, name: &str, t: &Table, path: &mut Vec<String>, text: &mut String) {
    for (k, v) in t {
        path.push(k.clone());
        let segs: Vec<Seg> = path.iter().cloned().map(Seg::Key).collect();
        let origin_at = |segs: &[Seg]| dump::label(set_by(&c.provenance, "template", name, segs));
        if let Value::Table(sub) = v {
            flat(c, name, sub, path, text);
        } else if let (1, "deps", Value::Array(groups)) = (path.len(), k.as_str(), v) {
            write_deps(text, groups, |i| {
                let mut at = segs.clone();
                at.extend(i.map(Seg::Index));
                origin_at(&at)
            });
        } else {
            let origin = origin_at(&segs);
            let key: Vec<String> = path.iter().map(|p| toml_text::key(p)).collect();
            let value = match v {
                Value::Integer(u) if k == "umask" => format!("0o{u:03o}"),
                _ => toml_text::value(v),
            };
            let _ = writeln!(text, "{} = {value}  # {origin}", key.join("."));
        }
        path.pop();
    }
}

/// The policy file `path` with every rule and every key; implicit defaults marked `# default`.
fn show_policy(path: &Path) -> Result<String, Unshown> {
    let p = policy::load_policy(path).map_err(Unshown::Errors)?;
    let m = policy::to_model(&p);
    let raw = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.parse::<Table>().ok())
        .ok_or_else(|| format!("{}: unreadable", path.display()))?;
    Ok(policy_text(&raw, &m))
}

/// The text of policy `p`, `raw` (the file's table) telling which keys the file set.
fn policy_text(raw: &Table, p: &qinit_db::Policy) -> String {
    let mut text = String::new();
    let set = |text: &mut String, t: &Table, key: &str, default: String| {
        match t.get(key) {
            Some(v) => writeln!(text, "{key} = {}  # policy", toml_text::value(v)),
            None => writeln!(text, "{default}  # default"),
        }
        .ok();
    };
    let word = if p.allow_by_default { "allow" } else { "deny" };
    set(&mut text, raw, "default", format!("default = \"{word}\""));
    let top = raw.get("rlimits_max").and_then(Value::as_table);
    for (r, key) in RLIMIT_KEYS.iter().enumerate() {
        if *key == "core" {
            continue;
        }
        match top.and_then(|t| t.get(*key)) {
            Some(v) => {
                let _ = writeln!(
                    text,
                    "rlimits_max.{key} = {}  # policy",
                    toml_text::value(v)
                );
            }
            None => {
                let _ = writeln!(text, "{}  # default", ceiling(key, p.ceiling[r]));
            }
        }
    }
    let rules = raw.get("rule").and_then(Value::as_array);
    for (i, rule) in p.rules.iter().enumerate() {
        let empty = Table::new();
        let t = rules
            .and_then(|a| a.get(i))
            .and_then(Value::as_table)
            .unwrap_or(&empty);
        text.push_str("\n[[rule]]\n");
        set(
            &mut text,
            t,
            "match",
            format!("match = {}", toml_text::string(&rule.pattern)),
        );
        set(&mut text, t, "users", "# users: any user".into());
        set(&mut text, t, "caps_max", "caps_max = []".into());
        for (key, v) in [
            ("require_nnp", rule.require_nnp),
            ("require_seccomp", rule.require_seccomp),
        ] {
            set(&mut text, t, key, format!("{key} = {v}"));
        }
        let userns = match rule.allow_userns {
            Userns::No => "false",
            Userns::Own => "true",
            Userns::Range => "\"range\"",
        };
        set(
            &mut text,
            t,
            "allow_userns",
            format!("allow_userns = {userns}"),
        );
        for (key, v) in [
            ("allow_inside_ids", rule.allow_inside_ids),
            ("allow_idmap", rule.allow_idmap),
        ] {
            set(&mut text, t, key, format!("{key} = {v}"));
        }
        set(
            &mut text,
            t,
            "rlimits_max",
            "# rlimits_max: the top-level ceilings".into(),
        );
    }
    text
}

/// The top-level ceiling of `key` as a line: a value, or a comment when there is none.
fn ceiling(key: &str, c: Option<u64>) -> String {
    match c {
        Some(u64::MAX) => format!("rlimits_max.{key} = \"infinity\""),
        Some(n) => format!("rlimits_max.{key} = {n}"),
        None => format!("# rlimits_max.{key}: no ceiling, any value needs a rule"),
    }
}
