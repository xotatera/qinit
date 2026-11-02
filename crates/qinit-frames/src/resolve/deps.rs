// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Dependency groups and edges (spec §5): a missing target of a `require_*` group is an
//! error, of an `optional_all` or `exclude_all` group a warning that drops the edge.
use super::Cx;
use crate::error::{Code, Error, Warning};
use crate::schema::{DepEdge, DepGroup};
use crate::units::duration_ms;
use qinit_db::{Edge, Group, GroupKind, Mode, RestartOn, Target};

/// The implicit sync edge from a producer to its logger.
pub(super) fn logger_edge(logger: u32) -> Edge {
    Edge {
        target: Target::Node(logger),
        mode: Mode::Sync,
        deadline_ms: 0,
        restart_on: RestartOn::None,
        stop_parallel: false,
        cascade: false,
    }
}

/// The group kind of a word, or a `BadValue` at `key`. `schema::parse_frame` rejects the same
/// words first on the compile path; `resolve` is public, so it checks them again.
fn group_kind(cx: &mut Cx, key: &str, g: &str) -> Option<GroupKind> {
    match g {
        "require_all" => Some(GroupKind::RequireAll),
        "require_any" => Some(GroupKind::RequireAny),
        "optional_all" => Some(GroupKind::OptionalAll),
        "exclude_all" => Some(GroupKind::ExcludeAll),
        _ => {
            cx.bad(key, format!("unknown group `{g}`"));
            None
        }
    }
}

/// The words of one edge, each a `BadValue` at `{at}.<field>` when it is not one the schema
/// admits. Returns the mode, deadline, `restart_on` and whether `stop` is set.
fn edge_fields(cx: &mut Cx, at: &str, e: &DepEdge) -> (Mode, u32, RestartOn, bool) {
    let mode = match e.mode.as_deref() {
        None | Some("sync") => Mode::Sync,
        Some("async") => Mode::Async,
        Some(m) => {
            cx.bad(format!("{at}.mode"), format!("`{m}` is not sync or async"));
            Mode::Sync
        }
    };
    let deadline_ms = match e.deadline.as_deref() {
        None => 0,
        Some(d) => duration_ms(d).unwrap_or_else(|| {
            cx.bad(
                format!("{at}.deadline"),
                format!("`{d}` is not a duration like 1s"),
            );
            0
        }),
    };
    if e.deadline.is_some() && mode != Mode::Async {
        cx.bad(
            format!("{at}.deadline"),
            "a deadline needs mode = \"async\"",
        );
    }
    let restart_on = match e.restart_on.as_deref() {
        None | Some("none") => RestartOn::None,
        Some("error") => RestartOn::Error,
        Some("restart") => RestartOn::Restart,
        Some("refresh") => RestartOn::Refresh,
        Some(r) => {
            let why = format!("`{r}` is not none, error, restart or refresh");
            cx.bad(format!("{at}.restart_on"), why);
            RestartOn::None
        }
    };
    let stop_parallel = match e.stop.as_deref() {
        None => false,
        Some("parallel") => true,
        Some(s) => {
            cx.bad(format!("{at}.stop"), format!("`{s}` is not parallel"));
            false
        }
    };
    (mode, deadline_ms, restart_on, stop_parallel)
}

/// One edge; `None` when it is dropped (a missing optional or exclude target) or wrong.
fn edge(cx: &mut Cx, at: &str, kind: GroupKind, e: &DepEdge) -> Option<Edge> {
    let requires = matches!(kind, GroupKind::RequireAll | GroupKind::RequireAny);
    let (mode, deadline_ms, restart_on, stop_parallel) = edge_fields(cx, at, e);
    // This fires for every sync require edge, including one whose target is a path. That is
    // stricter than the validator, which only looks at node targets, so that a hard edge never
    // carries `stop = "parallel"`, whatever it points at.
    if stop_parallel && requires && mode == Mode::Sync {
        let why = "stop = \"parallel\" on a hard (sync require) edge";
        cx.errs
            .push(Error::new(Code::HardParallel, format!("{at}.stop"), why));
    }
    let cascade = e.cascade == Some(true);
    if cascade && (kind != GroupKind::RequireAll || e.to.is_none()) {
        cx.bad(
            format!("{at}.cascade"),
            "cascade needs a require_all edge to a frame",
        );
    }
    let target = match (&e.to, &e.path) {
        (Some(to), None) => match cx.names.get(to.as_str()) {
            Some((i, _)) => Target::Node(*i),
            None if requires => {
                let why = format!("no frame `{to}`");
                cx.errs
                    .push(Error::new(Code::MissingTarget, format!("{at}.to"), why));
                return None;
            }
            None => {
                cx.warnings.push(Warning {
                    key: format!("{at}.to"),
                    detail: format!("no frame `{to}`; the edge is dropped"),
                });
                return None;
            }
        },
        (None, Some(p)) => {
            if !cx.text(&format!("{at}.path"), p) {
                return None;
            }
            Target::Path(p.clone())
        }
        (Some(_), Some(_)) | (None, None) => {
            cx.bad(at, "an edge needs exactly one of `to` and `path`");
            return None;
        }
    };
    Some(Edge {
        target,
        mode,
        deadline_ms,
        restart_on,
        stop_parallel,
        cascade,
    })
}

/// The groups of one frame, `base` its `kind.name` key, and per group the frame index of each
/// kept edge.
pub(super) fn groups(cx: &mut Cx, base: &str, deps: &[DepGroup]) -> (Vec<Group>, Vec<Vec<usize>>) {
    let mut out = Vec::with_capacity(deps.len());
    let mut origins = Vec::with_capacity(deps.len());
    for (gi, g) in deps.iter().enumerate() {
        let Some(kind) = group_kind(cx, &format!("{base}.deps[{gi}].group"), &g.group) else {
            continue;
        };
        let (mut edges, mut from) = (Vec::new(), Vec::new());
        for (ei, e) in g.edges.iter().enumerate() {
            if let Some(kept) = edge(cx, &format!("{base}.deps[{gi}].edges[{ei}]"), kind, e) {
                edges.push(kept);
                from.push(ei);
            }
        }
        out.push(Group { kind, edges });
        origins.push(from);
    }
    (out, origins)
}
