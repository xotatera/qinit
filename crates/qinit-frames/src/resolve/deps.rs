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
    }
}

/// The group kind of a word `schema::parse_frame` has checked.
fn group_kind(g: &str) -> GroupKind {
    match g {
        "require_all" => GroupKind::RequireAll,
        "require_any" => GroupKind::RequireAny,
        "optional_all" => GroupKind::OptionalAll,
        _ => GroupKind::ExcludeAll,
    }
}

/// One edge; `None` when it is dropped (a missing optional or exclude target) or wrong.
/// `schema::parse_frame` has checked the mode, deadline, `restart_on` and `stop` words and
/// that exactly one of `to` and `path` is given.
fn edge(cx: &mut Cx, at: &str, kind: GroupKind, e: &DepEdge) -> Option<Edge> {
    let requires = matches!(kind, GroupKind::RequireAll | GroupKind::RequireAny);
    let mode = match e.mode.as_deref() {
        Some("async") => Mode::Async,
        _ => Mode::Sync,
    };
    let deadline_ms = e.deadline.as_deref().and_then(duration_ms).unwrap_or(0);
    let restart_on = match e.restart_on.as_deref() {
        Some("error") => RestartOn::Error,
        Some("restart") => RestartOn::Restart,
        Some("refresh") => RestartOn::Refresh,
        _ => RestartOn::None,
    };
    let stop_parallel = e.stop.is_some();
    // This fires for every sync require edge, including one whose target is a path. That is
    // stricter than the validator, which only looks at node targets, so that a hard edge never
    // carries `stop = "parallel"`, whatever it points at.
    if stop_parallel && requires && mode == Mode::Sync {
        let why = "stop = \"parallel\" on a hard (sync require) edge";
        cx.errs
            .push(Error::new(Code::HardParallel, format!("{at}.stop"), why));
    }
    let target = match (&e.to, &e.path) {
        (Some(to), _) => match cx.names.get(to.as_str()) {
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
        (None, None) => return None,
    };
    Some(Edge {
        target,
        mode,
        deadline_ms,
        restart_on,
        stop_parallel,
    })
}

/// The groups of one frame, `base` its `kind.name` key, and per group the frame index of each
/// kept edge.
pub(super) fn groups(cx: &mut Cx, base: &str, deps: &[DepGroup]) -> (Vec<Group>, Vec<Vec<usize>>) {
    let mut out = Vec::with_capacity(deps.len());
    let mut origins = Vec::with_capacity(deps.len());
    for (gi, g) in deps.iter().enumerate() {
        let kind = group_kind(&g.group);
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
