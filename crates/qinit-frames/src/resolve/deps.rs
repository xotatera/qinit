// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Dependency groups and edges (spec §5, plan ruling Q2, review focus 4).
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

fn group_kind(cx: &mut Cx, key: &str, g: &str) -> GroupKind {
    match g {
        "require_all" => GroupKind::RequireAll,
        "require_any" => GroupKind::RequireAny,
        "optional_all" => GroupKind::OptionalAll,
        "exclude_all" => GroupKind::ExcludeAll,
        _ => {
            cx.bad(key, format!("unknown group `{g}`"));
            GroupKind::OptionalAll
        }
    }
}

/// One edge; `None` when it is dropped (a missing optional or exclude target) or wrong.
fn edge(cx: &mut Cx, at: &str, kind: GroupKind, e: &DepEdge) -> Option<Edge> {
    let requires = matches!(kind, GroupKind::RequireAll | GroupKind::RequireAny);
    let mode = match e.mode.as_deref() {
        None | Some("sync") => Mode::Sync,
        Some("async") => Mode::Async,
        Some(m) => {
            cx.bad(format!("{at}.mode"), format!("`{m}` is not sync or async"));
            Mode::Sync
        }
    };
    let deadline_ms = match (e.deadline.as_deref(), mode) {
        (None, _) => 0,
        (Some(_), Mode::Sync) => {
            cx.bad(
                format!("{at}.deadline"),
                "a deadline needs mode = \"async\"",
            );
            0
        }
        (Some(d), Mode::Async) => duration_ms(d).unwrap_or_else(|| {
            cx.bad(format!("{at}.deadline"), format!("`{d}` is not a duration"));
            0
        }),
    };
    let restart_on = match e.restart_on.as_deref() {
        None | Some("none") => RestartOn::None,
        Some("error") => RestartOn::Error,
        Some("restart") => RestartOn::Restart,
        Some("refresh") => RestartOn::Refresh,
        Some(r) => {
            cx.bad(
                format!("{at}.restart_on"),
                format!("`{r}` is not a restart_on value"),
            );
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
    if stop_parallel && requires && mode == Mode::Sync {
        let why = "stop = \"parallel\" on a hard (sync require) edge";
        cx.errs
            .push(Error::new(Code::HardParallel, format!("{at}.stop"), why));
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
        _ => {
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
    })
}

/// The groups of one frame, `base` its `kind.name` key.
pub(super) fn groups(cx: &mut Cx, base: &str, deps: &[DepGroup]) -> Vec<Group> {
    let mut out = Vec::with_capacity(deps.len());
    for (gi, g) in deps.iter().enumerate() {
        let kind = group_kind(cx, &format!("{base}.deps[{gi}].group"), &g.group);
        let edges = g
            .edges
            .iter()
            .enumerate()
            .filter_map(|(ei, e)| edge(cx, &format!("{base}.deps[{gi}].edges[{ei}]"), kind, e))
            .collect();
        out.push(Group { kind, edges });
    }
    out
}
