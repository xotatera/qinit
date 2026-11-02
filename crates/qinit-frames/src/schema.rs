// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The strict frame schema (spec §5). Unknown keys are errors; per-kind rules and value checks
//! live in `parse_frame`.
use crate::error::{Code, Error};
use crate::units::{duration_ms, size_kib};
use serde::Deserialize;

/// One frame (worker, forager, brood or template); every field is optional until resolved.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub exec: Option<Vec<String>>,
    pub template: Option<String>,
    pub instances: Option<Vec<String>>,
    pub ready: Option<Ready>,
    pub restart: Option<Restart>,
    pub output: Option<Output>,
    pub errors: Option<Output>,
    pub cell: Option<CellCfg>,
    pub credentials: Option<Creds>,
    pub sandbox: Option<Sandbox>,
    pub deps: Option<Vec<DepGroup>>,
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
    pub seccomp: Option<String>,
    pub landlock: Option<Vec<String>>,
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
    let frame = Frame::deserialize(value.clone()).map_err(|e| serde_error(&base, e.message()))?;
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
    if kind == "forager" {
        banned.push(("restart", f.restart.is_some()));
        banned.push(("instances", f.instances.is_some()));
    }
    if kind == "brood" {
        banned.extend([
            ("exec", f.exec.is_some()),
            ("instances", f.instances.is_some()),
            ("ready", f.ready.is_some()),
            ("restart", f.restart.is_some()),
            ("output", f.output.is_some()),
            ("errors", f.errors.is_some()),
            ("cell", f.cell.is_some()),
            ("credentials", f.credentials.is_some()),
            ("sandbox", f.sandbox.is_some()),
        ]);
    }
    match banned.into_iter().find(|(_, present)| *present) {
        Some((field, _)) => Err(bad(base, field, format!("not allowed on a {kind}"))),
        None => Ok(()),
    }
}

fn check_values(f: &Frame, base: &str) -> Result<(), Error> {
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
        for (ei, e) in g.edges.iter().enumerate() {
            check_edge(e, &format!("deps[{gi}].edges[{ei}]"), base)?;
        }
    }
    Ok(())
}

fn check_edge(e: &DepEdge, at: &str, base: &str) -> Result<(), Error> {
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
    if let Some(s) = e.stop.as_deref().filter(|s| *s != "parallel") {
        return Err(bad(
            base,
            &format!("{at}.stop"),
            format!("`{s}` is not parallel"),
        ));
    }
    Ok(())
}

/// Map a serde message to an error. Serde reports an unknown field as "unknown field `x`, ...";
/// the field then joins the key path. Anything else (wrong type, no matching untagged variant,
/// so an unknown key inside `ready` or `output` too) is a `BadValue` on the frame.
fn serde_error(base: &str, msg: &str) -> Error {
    let field = msg
        .strip_prefix("unknown field `")
        .and_then(|rest| rest.split_once('`'))
        .map(|(f, _)| f);
    match field {
        Some(f) => Error::new(Code::UnknownKey, format!("{base}.{f}"), msg),
        None => Error::new(Code::BadValue, base, msg),
    }
}
