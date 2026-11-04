// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The strict frame schema (spec §5). Unknown keys are errors; per-kind rules and value checks
//! live in `parse_frame`.
use crate::error::{Code, Error};
use crate::units::{duration_ms, size_kib};
use serde::Deserialize;
use std::collections::BTreeMap;

/// One frame (worker, forager, brood or template); every field is optional until resolved.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub exec: Option<Vec<String>>,
    pub template: Option<String>,
    pub instances: Option<Vec<String>>,
    pub ready: Option<Ready>,
    pub restart: Option<Restart>,
    pub stop: Option<StopCfg>,
    pub start_timeout: Option<String>,
    pub output: Option<Output>,
    pub errors: Option<Output>,
    pub cell: Option<CellCfg>,
    pub credentials: Option<Creds>,
    pub sandbox: Option<Sandbox>,
    pub env: Option<BTreeMap<String, String>>,
    pub cwd: Option<String>,
    pub umask: Option<u32>,
    pub rlimits: Option<Rlimits>,
    pub reload: Option<String>,
    pub launch: Option<LaunchCfg>,
    pub deps: Option<Vec<DepGroup>>,
}

/// The forager `launch` table: what a caller may do when it launches an instance.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchCfg {
    pub concurrency: Option<u32>,
    pub argv_tail: Option<u32>,
    pub env: Option<Vec<String>>,
    pub fds: Option<Vec<String>>,
}

/// Resource limits applied before exec.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rlimits {
    pub nofile: Option<u32>,
}

/// How a worker signals readiness: `"pipe"`, `"exit"`, a socket or a path.
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Ready {
    Kind(String),
    Socket { socket: String },
    Path { path: String },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Restart {
    pub policy: String,
    pub max: Option<u32>,
    pub window: Option<String>,
    pub delay: Option<String>,
}

/// How a node is stopped: the polite mode and the grace period.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopCfg {
    pub mode: Option<String>,
    pub grace: Option<String>,
}

/// Where a stream goes: a path, or the logger worker's pipe.
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Output {
    Path(String),
    Pipe { pipe: String },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellCfg {
    pub memory_max: Option<String>,
    pub pids_max: Option<u32>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Creds {
    pub uid: String,
    pub caps: Option<Vec<String>>,
    pub nnp: Option<bool>,
    pub securebits: Option<String>,
}

/// The `sandbox` table of the spec §5 example.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sandbox {
    pub namespaces: Option<Vec<String>>,
    pub seccomp: Option<SeccompCfg>,
    pub landlock: Option<Vec<String>>,
}

/// The seccomp filter: `"none"`, `"default"`, a denylist or an allowlist of syscall names.
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum SeccompCfg {
    Kind(String),
    Deny { deny: Vec<String> },
    Allow { allow: Vec<String> },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepGroup {
    pub group: String,
    pub edges: Vec<DepEdge>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepEdge {
    pub to: Option<String>,
    pub path: Option<String>,
    pub mode: Option<String>,
    pub deadline: Option<String>,
    pub restart_on: Option<String>,
    pub stop: Option<String>,
    pub cascade: Option<bool>,
}

const GROUPS: [&str; 4] = ["require_all", "require_any", "optional_all", "exclude_all"];
const RESTART_ON: [&str; 4] = ["none", "error", "restart", "refresh"];
const POLICIES: [&str; 3] = ["never", "on-failure", "always"];

/// Parse one merged frame table of `kind` and `name` and apply the per-kind rules.
///
/// # Errors
/// `UnknownKey` for an unknown field, `BadValue` for a wrong type, a bad value or a key the
/// kind does not allow.
pub fn parse_frame(kind: &str, name: &str, value: &toml::Value) -> Result<Frame, Error> {
    let base = format!("{kind}.{name}");
    if !["worker", "forager", "brood", "template"].contains(&kind) {
        return Err(Error::new(
            Code::BadValue,
            base,
            format!("unknown frame kind `{kind}`"),
        ));
    }
    let frame =
        Frame::deserialize(value.clone()).map_err(|e| serde_error(&base, value, e.message()))?;
    check_kind(kind, &frame, &base)?;
    check_values(&frame, &base)?;
    Ok(frame)
}

fn bad(base: &str, field: &str, detail: impl Into<String>) -> Error {
    Error::new(Code::BadValue, format!("{base}.{field}"), detail)
}

/// Keys a forager or brood must not carry. Expansion runs it again after a template merge.
pub(crate) fn check_kind(kind: &str, f: &Frame, base: &str) -> Result<(), Error> {
    let mut banned: Vec<(&str, bool)> = Vec::new();
    if kind == "worker" {
        banned.push(("launch", f.launch.is_some()));
    }
    if kind == "forager" {
        banned.push(("restart", f.restart.is_some()));
        banned.push(("instances", f.instances.is_some()));
        // A forager never becomes ready, so it has no running process to signal.
        banned.push(("reload", f.reload.is_some()));
    }
    if kind == "brood" {
        banned.extend([
            ("exec", f.exec.is_some()),
            ("instances", f.instances.is_some()),
            ("ready", f.ready.is_some()),
            ("restart", f.restart.is_some()),
            ("stop", f.stop.is_some()),
            ("start_timeout", f.start_timeout.is_some()),
            ("output", f.output.is_some()),
            ("errors", f.errors.is_some()),
            ("cell", f.cell.is_some()),
            ("credentials", f.credentials.is_some()),
            ("sandbox", f.sandbox.is_some()),
            ("env", f.env.is_some()),
            ("cwd", f.cwd.is_some()),
            ("umask", f.umask.is_some()),
            ("rlimits", f.rlimits.is_some()),
            ("reload", f.reload.is_some()),
            ("launch", f.launch.is_some()),
        ]);
    }
    match banned.into_iter().find(|(_, present)| *present) {
        Some((field, _)) => Err(bad(base, field, format!("not allowed on a {kind}"))),
        None => Ok(()),
    }
}

/// The shortest delay or grace the format allows (`MIN_DELAY_MS`).
const FLOOR_MS: u32 = 100;

/// `value`, when set, is a duration of at least [`FLOOR_MS`].
fn at_least_floor(base: &str, field: &str, value: Option<&str>) -> Result<(), Error> {
    let Some(v) = value else {
        return Ok(());
    };
    match duration_ms(v) {
        None => Err(bad(base, field, format!("`{v}` is not a duration like 1s"))),
        Some(ms) if ms < FLOOR_MS => Err(bad(
            base,
            field,
            format!("`{v}` is under the {FLOOR_MS}ms floor"),
        )),
        Some(_) => Ok(()),
    }
}

/// The largest `umask`.
const MAX_UMASK: u32 = 0o777;

/// An environment key: `^[A-Za-z_][A-Za-z0-9_]*$`.
fn env_key_ok(k: &str) -> bool {
    let mut bytes = k.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn check_launch(f: &Frame, base: &str) -> Result<(), Error> {
    for (k, v) in f.env.iter().flatten() {
        if !env_key_ok(k) {
            let why = "key must match ^[A-Za-z_][A-Za-z0-9_]*$";
            return Err(bad(base, &format!("env.{k}"), why));
        }
        if v.contains('\0') {
            return Err(bad(base, &format!("env.{k}"), "value holds NUL"));
        }
    }
    if let Some(c) = f.cwd.as_deref().filter(|c| !c.starts_with('/')) {
        return Err(bad(base, "cwd", format!("`{c}` must be an absolute path")));
    }
    if let Some(u) = f.umask.filter(|u| *u > MAX_UMASK) {
        return Err(bad(base, "umask", format!("0o{u:o} must be at most 0o777")));
    }
    if f.rlimits.as_ref().and_then(|r| r.nofile) == Some(0) {
        return Err(bad(base, "rlimits.nofile", "must be at least 1"));
    }
    Ok(())
}

/// The environment keys the overseer sets itself, which a caller may not.
const RESERVED_ENV: [&str; 5] = ["PATH", "HOME", "USER", "LOGNAME", "QINIT_READY_FD"];

/// The most instances of one forager at once, extra argv elements, and (see `LaunchCfg`) caller
/// environment keys the database format allows.
const MAX_LAUNCH_CONCURRENCY: u32 = 64;
const MAX_ARGV_TAIL: u32 = 64;

fn check_reload(f: &Frame, base: &str) -> Result<(), Error> {
    match f.reload.as_deref() {
        None | Some("SIGHUP" | "SIGUSR1" | "SIGUSR2") => Ok(()),
        Some(other) => Err(bad(
            base,
            "reload",
            format!("`{other}` is not SIGHUP, SIGUSR1 or SIGUSR2"),
        )),
    }
}

fn check_launch_table(f: &Frame, base: &str) -> Result<(), Error> {
    let Some(l) = &f.launch else {
        return Ok(());
    };
    let key = |k: &str| format!("launch.{k}");
    match l.concurrency {
        Some(c) if (1..=MAX_LAUNCH_CONCURRENCY).contains(&c) => {}
        Some(c) => {
            let why = format!("{c} is not between 1 and {MAX_LAUNCH_CONCURRENCY}");
            return Err(bad(base, &key("concurrency"), why));
        }
        None => {
            return Err(bad(
                base,
                &key("concurrency"),
                "a launch table needs a concurrency",
            ));
        }
    }
    if let Some(t) = l.argv_tail.filter(|t| *t > MAX_ARGV_TAIL) {
        let why = format!("{t} is more than {MAX_ARGV_TAIL}");
        return Err(bad(base, &key("argv_tail"), why));
    }
    let mut seen: Vec<&str> = Vec::new();
    for k in l.env.iter().flatten() {
        if !env_key_ok(k) {
            let why = format!("`{k}` must match ^[A-Za-z_][A-Za-z0-9_]*$");
            return Err(bad(base, &key("env"), why));
        }
        if RESERVED_ENV.contains(&k.as_str()) {
            let why = format!("`{k}` is set by the overseer");
            return Err(bad(base, &key("env"), why));
        }
        if seen.contains(&k.as_str()) {
            return Err(bad(base, &key("env"), format!("`{k}` is listed twice")));
        }
        seen.push(k);
    }
    let mut roles: Vec<&str> = Vec::new();
    for r in l.fds.iter().flatten() {
        if !["stdin", "stdout", "stderr"].contains(&r.as_str()) {
            let why = format!("`{r}` is not stdin, stdout or stderr");
            return Err(bad(base, &key("fds"), why));
        }
        if roles.contains(&r.as_str()) {
            return Err(bad(base, &key("fds"), format!("`{r}` is listed twice")));
        }
        roles.push(r);
    }
    Ok(())
}

fn check_values(f: &Frame, base: &str) -> Result<(), Error> {
    check_launch(f, base)?;
    check_reload(f, base)?;
    check_launch_table(f, base)?;
    if let Some(k) = f.ready.as_ref().and_then(|r| match r {
        Ready::Kind(k) if k != "pipe" && k != "exit" => Some(k),
        _ => None,
    }) {
        return Err(bad(base, "ready", format!("`{k}` is not pipe or exit")));
    }
    if let Some(r) = &f.restart {
        if !POLICIES.contains(&r.policy.as_str()) {
            return Err(bad(
                base,
                "restart.policy",
                format!("`{}` is not never, on-failure or always", r.policy),
            ));
        }
        if let Some(w) = r.window.as_deref().filter(|w| duration_ms(w).is_none()) {
            return Err(bad(
                base,
                "restart.window",
                format!("`{w}` is not a duration like 60s"),
            ));
        }
        at_least_floor(base, "restart.delay", r.delay.as_deref())?;
    }
    if let Some(s) = &f.stop {
        if let Some(m) = s.mode.as_deref().filter(|m| *m != "main" && *m != "cell") {
            return Err(bad(base, "stop.mode", format!("`{m}` is not main or cell")));
        }
        at_least_floor(base, "stop.grace", s.grace.as_deref())?;
    }
    if let Some(t) = f
        .start_timeout
        .as_deref()
        .filter(|t| duration_ms(t).is_none())
    {
        return Err(bad(
            base,
            "start_timeout",
            format!("`{t}` is not a duration like 90s"),
        ));
    }
    let mem = f.cell.as_ref().and_then(|c| c.memory_max.as_deref());
    if let Some(m) = mem.filter(|m| size_kib(m).is_none()) {
        let why = format!("`{m}` is not a size like 512M");
        return Err(bad(base, "cell.memory_max", why));
    }
    for (gi, g) in f.deps.iter().flatten().enumerate() {
        if !GROUPS.contains(&g.group.as_str()) {
            return Err(bad(
                base,
                &format!("deps[{gi}].group"),
                format!("unknown group `{}`", g.group),
            ));
        }
        if g.group.starts_with("require_") && g.edges.is_empty() {
            return Err(bad(
                base,
                &format!("deps[{gi}].edges"),
                format!("a {} group needs at least one edge", g.group),
            ));
        }
        for (ei, e) in g.edges.iter().enumerate() {
            check_edge(e, &g.group, &format!("deps[{gi}].edges[{ei}]"), base)?;
        }
    }
    Ok(())
}

fn check_edge(e: &DepEdge, group: &str, at: &str, base: &str) -> Result<(), Error> {
    if e.to.is_some() == e.path.is_some() {
        return Err(bad(
            base,
            at,
            "an edge needs exactly one of `to` and `path`",
        ));
    }
    let mode = e.mode.as_deref().unwrap_or("sync");
    if mode != "sync" && mode != "async" {
        return Err(bad(
            base,
            &format!("{at}.mode"),
            format!("`{mode}` is not sync or async"),
        ));
    }
    if let Some(d) = e.deadline.as_deref() {
        if mode != "async" {
            return Err(bad(
                base,
                &format!("{at}.deadline"),
                "a deadline needs mode = \"async\"",
            ));
        }
        if duration_ms(d).is_none() {
            return Err(bad(
                base,
                &format!("{at}.deadline"),
                format!("`{d}` is not a duration like 1s"),
            ));
        }
    }
    if let Some(r) = e.restart_on.as_deref().filter(|r| !RESTART_ON.contains(r)) {
        return Err(bad(
            base,
            &format!("{at}.restart_on"),
            format!("`{r}` is not none, error, restart or refresh"),
        ));
    }
    if e.cascade == Some(true) && (group != "require_all" || e.to.is_none()) {
        return Err(bad(
            base,
            &format!("{at}.cascade"),
            "cascade needs a require_all edge to a frame",
        ));
    }
    if let Some(s) = e.stop.as_deref().filter(|s| *s != "parallel") {
        return Err(bad(
            base,
            &format!("{at}.stop"),
            format!("`{s}` is not parallel"),
        ));
    }
    Ok(())
}

/// The keys each table of a frame allows: the frame itself, then the named tables, then a
/// `deps` group and an edge.
const FRAME_KEYS: [&str; 19] = [
    "exec",
    "template",
    "instances",
    "ready",
    "restart",
    "stop",
    "start_timeout",
    "output",
    "errors",
    "cell",
    "credentials",
    "sandbox",
    "env",
    "cwd",
    "umask",
    "rlimits",
    "reload",
    "launch",
    "deps",
];
const TABLE_KEYS: [(&str, &[&str]); 7] = [
    ("restart", &["policy", "max", "window", "delay"]),
    ("stop", &["mode", "grace"]),
    ("cell", &["memory_max", "pids_max"]),
    ("credentials", &["uid", "caps", "nnp", "securebits"]),
    ("sandbox", &["namespaces", "seccomp", "landlock"]),
    ("rlimits", &["nofile"]),
    ("launch", &["concurrency", "argv_tail", "env", "fds"]),
];
const GROUP_KEYS: [&str; 2] = ["group", "edges"];
const EDGE_KEYS: [&str; 7] = [
    "to",
    "path",
    "mode",
    "deadline",
    "restart_on",
    "stop",
    "cascade",
];

/// Every place in `frame` where `field` is a key its table does not allow, as a path below the
/// frame (`restart.bogus`, `deps[0].edges[1].bogus`). `ready` and `output` are left out: an
/// unknown key there is reported as a `BadValue`, not by name.
fn unknown_at(frame: &toml::Value, field: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(t) = frame.as_table() else {
        return out;
    };
    let mut check = |table: &toml::Table, allowed: &[&str], at: String| {
        if table.contains_key(field) && !allowed.contains(&field) {
            out.push(if at.is_empty() {
                field.to_owned()
            } else {
                format!("{at}.{field}")
            });
        }
    };
    check(t, &FRAME_KEYS, String::new());
    for (name, allowed) in TABLE_KEYS {
        if let Some(inner) = t.get(name).and_then(toml::Value::as_table) {
            check(inner, allowed, name.to_owned());
        }
    }
    let groups = t.get("deps").and_then(toml::Value::as_array);
    for (gi, g) in groups.into_iter().flatten().enumerate() {
        let Some(g) = g.as_table() else { continue };
        check(g, &GROUP_KEYS, format!("deps[{gi}]"));
        let edges = g.get("edges").and_then(toml::Value::as_array);
        for (ei, e) in edges.into_iter().flatten().enumerate() {
            if let Some(e) = e.as_table() {
                check(e, &EDGE_KEYS, format!("deps[{gi}].edges[{ei}]"));
            }
        }
    }
    out
}

/// Map a serde message about `frame` to an error. Serde reports an unknown field as "unknown
/// field `x`, ..." without saying where; the key is the path of the one table in the frame that
/// holds `x` and does not allow it (`worker.t.restart.x`). When no such table, or more than one,
/// is found, the key is the frame's and the detail says so. Anything else (wrong type, no
/// matching untagged variant, so an unknown key inside `ready` or `output` too) is a `BadValue`
/// on the frame.
fn serde_error(base: &str, frame: &toml::Value, msg: &str) -> Error {
    let field = msg
        .strip_prefix("unknown field `")
        .and_then(|rest| rest.split_once('`'))
        .map(|(f, _)| f);
    let Some(f) = field else {
        return Error::new(Code::BadValue, base, msg);
    };
    if let [one] = unknown_at(frame, f).as_slice() {
        return Error::new(Code::UnknownKey, format!("{base}.{one}"), msg);
    }
    let why = format!("{msg} (the table holding `{f}` could not be told)");
    Error::new(Code::UnknownKey, base, why)
}
