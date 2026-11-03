// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Reference resolution: expanded frames to a `qinit_db::Model` (spec §5 and §7 step 5).
//!
//! `resolve` produces a model that `qinit_db::write` and `qinit_db::open` accept whenever the
//! ordering graph is acyclic (cycles other than a worker logging to itself are left to the
//! graph pass). It sorts nodes by name, maps every field to its record, adds the implicit
//! logger edges, computes the enable closure and the pre-syslog list, and checks the
//! `qinit_db_core` limits.
//!
//! Choices made here:
//! - `ready` defaults to `pipe` for a worker and `exit` for a forager or brood; `restart`
//!   defaults to `never` with `max` and `window` 0.
//! - `errors` defaults to the `output` route.
//! - Path routes are shared by every node writing the same path. A pipe route is per producer:
//!   a producer's `output` and `errors` piping to the same logger share one route, two
//!   producers never do.
//! - Every node piping to a logger gets one extra `require_all` group, appended after its own
//!   groups, with one sync edge per distinct logger (output first).
//! - Every worker and forager declares `credentials.uid`; its `Cred` record carries the
//!   `sandbox` table too (see `docs/db-format.md`, "Credentials are required"). A brood has no
//!   record.
//! - `env` is stored as sorted `KEY=VALUE` entries; `cwd` defaults to `/`, `umask` to `0o027`
//!   and `rlimits.nofile` to 0 (the kernel default).
mod closure;
mod cred;
mod deps;
mod limits;

use crate::error::{Code, Error, Warning};
use crate::expand::{Expanded, kind_name};
use crate::layers::Enable;
use crate::provenance::{locate, locate_all};
use crate::schema::{Frame, Output, Ready as SReady};
use crate::units::{duration_ms, size_kib};
pub(crate) use cred::{cap_bit, cap_name, ns_name};
use qinit_db::{
    Group, GroupKind, Kind, Model, Node, Ready, Restart, RestartPolicy, Route, Stop, StopMode,
};
use qinit_db_core::MAX_NODES;
use std::collections::BTreeMap;

/// The resolved model and the non-fatal findings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    /// The model `qinit_db::write` turns into bytes.
    pub model: Model,
    /// Non-fatal findings, such as a dropped optional edge.
    pub warnings: Vec<Warning>,
    /// Per node, per group, per edge of `model`: the edge's index in the frame's
    /// `deps[g].edges` list, which differs once a missing optional edge was dropped. The
    /// implicit logger group, which has no frame key, maps each edge to its own index.
    pub edge_origins: Vec<Vec<Vec<usize>>>,
    /// Per node of `model`: how many of its groups come from the frame's `deps`. A further
    /// group is the implicit logger group.
    pub frame_groups: Vec<usize>,
}

/// The state shared by the per-node conversions.
pub(super) struct Cx<'a> {
    /// Name → (node index, kind).
    pub names: BTreeMap<&'a str, (u32, Kind)>,
    pub errs: Vec<Error>,
    pub warnings: Vec<Warning>,
    pub routes: Vec<Route>,
    pub path_routes: BTreeMap<String, u32>,
    pub edge_origins: Vec<Vec<Vec<usize>>>,
    pub frame_groups: Vec<usize>,
}

impl Cx<'_> {
    pub(super) fn bad(&mut self, key: impl Into<String>, detail: impl Into<String>) {
        self.errs.push(Error::new(Code::BadValue, key, detail));
    }

    /// A non-empty string without NUL, or a `BadValue` at `key`.
    pub(super) fn text(&mut self, key: &str, s: &str) -> bool {
        if s.is_empty() || s.contains('\0') {
            self.bad(key, format!("{s:?} must be non-empty and hold no NUL"));
            return false;
        }
        true
    }

    fn route(&mut self, r: Route) -> u32 {
        let next = u32::try_from(self.routes.len()).unwrap_or(u32::MAX);
        if let Route::Path(p) = &r {
            if let Some(i) = self.path_routes.get(p) {
                return *i;
            }
            self.path_routes.insert(p.clone(), next);
        }
        self.routes.push(r);
        next
    }
}

/// Where one stream goes before it becomes a route.
#[derive(Clone, PartialEq, Eq)]
enum Stream {
    Path(String),
    Pipe(u32),
}

/// Resolve one `output` or `errors` value of node `me`.
fn stream(cx: &mut Cx, key: &str, o: &Output, me: u32) -> Option<Stream> {
    match o {
        Output::Path(p) => cx.text(key, p).then(|| Stream::Path(p.clone())),
        Output::Pipe { pipe } => match cx.names.get(pipe.as_str()).copied() {
            None => {
                let why = format!("no frame `{pipe}` to pipe to");
                cx.errs.push(Error::new(Code::MissingTarget, key, why));
                None
            }
            Some((i, _)) if i == me => {
                let why = format!("`{pipe}` pipes its own output to itself");
                cx.errs.push(Error::new(Code::Cycle, key, why));
                None
            }
            Some((i, Kind::Worker)) => Some(Stream::Pipe(i)),
            Some(_) => {
                cx.bad(key, format!("logger `{pipe}` is not a worker"));
                None
            }
        },
    }
}

/// Output and error routes of node `me`, plus its implicit logger group.
fn streams(
    cx: &mut Cx,
    base: &str,
    f: &Frame,
    me: u32,
) -> (Option<u32>, Option<u32>, Option<Group>) {
    let out = f
        .output
        .as_ref()
        .and_then(|o| stream(cx, &format!("{base}.output"), o, me));
    let err = match &f.errors {
        None => out.clone(),
        Some(o) => stream(cx, &format!("{base}.errors"), o, me),
    };
    let mut pipes: Vec<(u32, u32)> = Vec::new();
    let mut place = |cx: &mut Cx, s: Option<Stream>| -> Option<u32> {
        match s? {
            Stream::Path(p) => Some(cx.route(Route::Path(p))),
            Stream::Pipe(l) => {
                if let Some((_, r)) = pipes.iter().find(|(lg, _)| *lg == l) {
                    return Some(*r);
                }
                let r = cx.route(Route::Pipe(l));
                pipes.push((l, r));
                Some(r)
            }
        }
    };
    let (o, e) = (place(cx, out), place(cx, err));
    let group = (!pipes.is_empty()).then(|| Group {
        kind: GroupKind::RequireAll,
        edges: pipes.iter().map(|(l, _)| deps::logger_edge(*l)).collect(),
    });
    (o, e, group)
}

fn exec(cx: &mut Cx, base: &str, kind: Kind, f: &Frame) -> Vec<String> {
    let key = format!("{base}.exec");
    let exec = f.exec.clone().unwrap_or_default();
    if kind != Kind::Brood && exec.is_empty() {
        cx.bad(&key, "a worker or forager needs a non-empty exec");
    }
    if !exec.iter().all(|a| !a.is_empty() && !a.contains('\0')) {
        cx.bad(&key, "exec elements must be non-empty and hold no NUL");
    }
    exec
}

fn ready(cx: &mut Cx, base: &str, kind: Kind, f: &Frame) -> Ready {
    let key = format!("{base}.ready");
    match &f.ready {
        None if kind == Kind::Worker => Ready::Pipe,
        None => Ready::Exit,
        Some(SReady::Kind(k)) if k == "exit" => Ready::Exit,
        Some(SReady::Kind(k)) if k == "pipe" => Ready::Pipe,
        Some(SReady::Kind(k)) => {
            cx.bad(&key, format!("`{k}` is not pipe or exit"));
            Ready::Pipe
        }
        Some(SReady::Socket { socket }) => {
            cx.text(&key, socket);
            Ready::Socket(socket.clone())
        }
        Some(SReady::Path { path }) => {
            cx.text(&key, path);
            Ready::Path(path.clone())
        }
    }
}

/// The restart delay used when a frame sets none, in milliseconds.
const DEFAULT_DELAY_MS: u32 = 1000;

/// The `umask` used when a frame sets none.
const DEFAULT_UMASK: u32 = 0o027;

/// The sum of the back-off delays before restart number `max`: the base delay doubling to ten
/// times itself.
fn backoff_sum_ms(delay: u32, max: u32) -> u64 {
    let cap = u64::from(delay) * 10;
    (0..max.min(64))
        .map(|k| (u64::from(delay) << k.min(20)).min(cap))
        .sum()
}

/// A duration of at least `MIN_DELAY_MS`, or a `BadValue` at `key`.
fn floor_duration(cx: &mut Cx, key: &str, v: &str) -> Option<u32> {
    match duration_ms(v) {
        Some(ms) if ms >= qinit_db_core::MIN_DELAY_MS => Some(ms),
        Some(_) => {
            cx.bad(key, format!("`{v}` is under the 100ms floor"));
            None
        }
        None => {
            cx.bad(key, format!("`{v}` is not a duration like 1s"));
            None
        }
    }
}

/// The restart record; a bad policy word, window or delay is a `BadValue`. A limit without a
/// window gets `max x 10 x delay`, so the breaker can always trip; an explicit window shorter
/// than the back-off up to `max` is a warning.
fn restart(cx: &mut Cx, base: &str, f: &Frame) -> Restart {
    let Some(s) = &f.restart else {
        return Restart {
            policy: RestartPolicy::Never,
            max: 0,
            window_ms: 0,
            delay_ms: DEFAULT_DELAY_MS,
        };
    };
    let policy = match s.policy.as_str() {
        "never" => RestartPolicy::Never,
        "on-failure" => RestartPolicy::OnFailure,
        "always" => RestartPolicy::Always,
        p => {
            let why = format!("`{p}` is not never, on-failure or always");
            cx.bad(format!("{base}.restart.policy"), why);
            RestartPolicy::Never
        }
    };
    let delay_ms = match s.delay.as_deref() {
        None => DEFAULT_DELAY_MS,
        Some(d) => {
            floor_duration(cx, &format!("{base}.restart.delay"), d).unwrap_or(DEFAULT_DELAY_MS)
        }
    };
    let max = s.max.unwrap_or(0);
    let given = match s.window.as_deref() {
        None => 0,
        Some(w) => duration_ms(w).unwrap_or_else(|| {
            cx.bad(
                format!("{base}.restart.window"),
                format!("`{w}` is not a duration like 60s"),
            );
            0
        }),
    };
    let window_ms = if max > 0 && given == 0 {
        max.saturating_mul(10).saturating_mul(delay_ms)
    } else {
        given
    };
    if max > 0 && given > 0 && u64::from(given) < backoff_sum_ms(delay_ms, max) {
        cx.warnings.push(Warning {
            key: format!("{base}.restart.window"),
            detail: "shorter than the back-off up to max; the breaker may never trip".to_owned(),
        });
    }
    Restart {
        policy,
        max,
        window_ms,
        delay_ms,
    }
}

/// How a node is stopped: `main` or `cell` mode, 10 s grace by default.
fn stop(cx: &mut Cx, base: &str, f: &Frame) -> Stop {
    let s = f.stop.as_ref();
    let mode = match s.and_then(|s| s.mode.as_deref()) {
        None | Some("main") => StopMode::Main,
        Some("cell") => StopMode::Cell,
        Some(m) => {
            cx.bad(
                format!("{base}.stop.mode"),
                format!("`{m}` is not main or cell"),
            );
            StopMode::Main
        }
    };
    let grace_ms = match s.and_then(|s| s.grace.as_deref()) {
        None => 10_000,
        Some(g) => floor_duration(cx, &format!("{base}.stop.grace"), g).unwrap_or(10_000),
    };
    Stop { mode, grace_ms }
}

/// The start timeout: 90 s by default, none for a node that is ready when it exits (its start
/// is its whole run).
fn start_timeout(cx: &mut Cx, base: &str, f: &Frame, ready: &Ready) -> u32 {
    match f.start_timeout.as_deref() {
        None if *ready == Ready::Exit => 0,
        None => 90_000,
        Some(t) => duration_ms(t).unwrap_or_else(|| {
            cx.bad(
                format!("{base}.start_timeout"),
                format!("`{t}` is not a duration like 90s"),
            );
            90_000
        }),
    }
}

fn node(
    cx: &mut Cx,
    creds: &mut Vec<qinit_db::Cred>,
    me: u32,
    name: &str,
    kind: Kind,
    f: &Frame,
) -> Node {
    let base = format!("{}.{name}", kind_name(kind));
    let exec = exec(cx, &base, kind, f);
    let ready = ready(cx, &base, kind, f);
    let start_timeout_ms = start_timeout(cx, &base, f, &ready);
    let restart = restart(cx, &base, f);
    let (output, errors, logger) = streams(cx, &base, f, me);
    let (mut groups, mut origins) = deps::groups(cx, &base, f.deps.as_deref().unwrap_or_default());
    cx.frame_groups.push(groups.len());
    origins.extend(logger.iter().map(|g| (0..g.edges.len()).collect()));
    groups.extend(logger);
    cx.edge_origins.push(origins);
    if kind != Kind::Brood && f.credentials.is_none() {
        cx.bad(
            format!("{base}.credentials.uid"),
            "a worker or forager must declare its user",
        );
    }
    let cred = cred::cred(cx, &base, f.credentials.as_ref(), f.sandbox.as_ref()).map(|c| {
        creds.push(c);
        u32::try_from(creds.len() - 1).unwrap_or(u32::MAX)
    });
    let env: Vec<String> = f
        .env
        .iter()
        .flatten()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let cell = f.cell.as_ref();
    let memory_max_kib = match cell.and_then(|c| c.memory_max.as_deref()) {
        None => 0,
        Some(m) => size_kib(m).unwrap_or_else(|| {
            cx.bad(
                format!("{base}.cell.memory_max"),
                format!("`{m}` is not a size like 512M"),
            );
            0
        }),
    };
    Node {
        kind,
        name: name.to_owned(),
        exec,
        ready,
        restart,
        stop: stop(cx, &base, f),
        start_timeout_ms,
        output,
        errors,
        cred,
        groups,
        memory_max_kib,
        pids_max: cell.and_then(|c| c.pids_max).unwrap_or(0),
        instance_of: name.split_once('@').map(|(t, _)| t.to_owned()),
        env,
        cwd: f.cwd.clone().unwrap_or_else(|| "/".to_owned()),
        umask: f.umask.unwrap_or(DEFAULT_UMASK),
        rlimit_nofile: f.rlimits.as_ref().and_then(|r| r.nofile).unwrap_or(0),
    }
}

/// Resolve the expanded frames against each other and the enable set.
///
/// The frames need not come from [`crate::expand::expand`]: the ready word, restart policy and
/// window, memory size, group kinds and edge fields are checked here too, each a `BadValue`.
///
/// # Errors
/// Every `BadValue`, `MissingTarget`, `Cycle` (a worker logging to itself), `HardParallel`,
/// `DuplicateName` and `Limit` error found.
pub fn resolve(expanded: &Expanded, enable: &Enable) -> Result<Resolved, Vec<Error>> {
    if expanded.frames.len() > MAX_NODES {
        let why = format!(
            "{} nodes; the limit is {MAX_NODES} (table nodes)",
            expanded.frames.len()
        );
        return Err(vec![Error::new(Code::Limit, "", why)]);
    }
    let mut frames: Vec<_> = expanded.frames.iter().collect();
    frames.sort_by(|a, b| a.0.cmp(&b.0));
    let mut cx = Cx {
        names: BTreeMap::new(),
        errs: Vec::new(),
        warnings: Vec::new(),
        routes: Vec::new(),
        path_routes: BTreeMap::new(),
        edge_origins: Vec::new(),
        frame_groups: Vec::new(),
    };
    let prov = &expanded.provenance;
    for (i, (name, kind, _)) in frames.iter().enumerate() {
        let i = u32::try_from(i).unwrap_or(u32::MAX);
        if cx.names.insert(name.as_str(), (i, *kind)).is_some() {
            let key = format!("{}.{name}", kind_name(*kind));
            let mut e = Error::new(Code::DuplicateName, key, format!("`{name}` appears twice"));
            locate(prov, kind_name(*kind), name, &mut e);
            cx.errs.push(e);
        }
    }
    let mut model = Model::default();
    for (i, (name, kind, f)) in frames.iter().enumerate() {
        let me = u32::try_from(i).unwrap_or(u32::MAX);
        let start = cx.errs.len();
        let n = node(&mut cx, &mut model.creds, me, name, *kind, f);
        locate_all(prov, kind_name(*kind), name, &mut cx.errs[start..]);
        model.nodes.push(n);
    }
    model.enabled = closure::enabled(&mut cx, &model.nodes, &enable.roots);
    model.presyslog = closure::presyslog(&mut cx, &model.nodes, &model.enabled, &enable.syslog);
    model.routes = std::mem::take(&mut cx.routes);
    if cx.errs.is_empty() {
        limits::check(&mut cx.errs, &model, prov);
    }
    if cx.errs.is_empty() {
        Ok(Resolved {
            model,
            warnings: cx.warnings,
            edge_origins: cx.edge_origins,
            frame_groups: cx.frame_groups,
        })
    } else {
        Err(cx.errs)
    }
}
