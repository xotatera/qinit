// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The enable closure and the pre-syslog list.
use super::Cx;
use crate::error::{Code, Error};
use qinit_db::{GroupKind, Kind, Node, Target};
use std::collections::VecDeque;

/// The node targets of `n`'s `require_all` and `require_any` groups (implicit logger edges
/// included, since they are `require_all` groups).
fn requires(n: &Node) -> impl Iterator<Item = usize> + '_ {
    n.groups
        .iter()
        .filter(|g| matches!(g.kind, GroupKind::RequireAll | GroupKind::RequireAny))
        .flat_map(|g| g.edges.iter())
        .filter_map(|e| match e.target {
            Target::Node(i) => Some(i as usize),
            Target::Path(_) => None,
        })
}

/// Look up each name of the `list` key; a name with no node is a `MissingTarget`.
fn lookup(cx: &mut Cx, list: &str, names: &[String]) -> Vec<(usize, Kind)> {
    let mut out = Vec::new();
    for name in names {
        if let Some((i, k)) = cx.names.get(name.as_str()) {
            out.push((*i as usize, *k));
        } else {
            let why = format!("no frame `{name}`");
            cx.errs.push(Error::new(Code::MissingTarget, list, why));
        }
    }
    out
}

/// Breadth-first search from `starts` along `next`; the visited nodes as a mask.
fn reach(n: usize, starts: impl Iterator<Item = usize>, next: &[Vec<usize>]) -> Vec<bool> {
    let mut seen = vec![false; n];
    let mut queue: VecDeque<usize> = VecDeque::new();
    for s in starts {
        if s < n && !seen[s] {
            seen[s] = true;
            queue.push_back(s);
        }
    }
    while let Some(i) = queue.pop_front() {
        for &j in next.get(i).into_iter().flatten() {
            if j < n && !seen[j] {
                seen[j] = true;
                queue.push_back(j);
            }
        }
    }
    seen
}

fn indices(mask: &[bool]) -> Vec<u32> {
    mask.iter()
        .enumerate()
        .filter(|(_, on)| **on)
        .filter_map(|(i, _)| u32::try_from(i).ok())
        .collect()
}

/// The roots and every node they reach over require edges, ascending.
pub(super) fn enabled(cx: &mut Cx, nodes: &[Node], roots: &[String]) -> Vec<u32> {
    let roots = lookup(cx, "enable", roots);
    let next: Vec<Vec<usize>> = nodes.iter().map(|n| requires(n).collect()).collect();
    indices(&reach(
        nodes.len(),
        roots.into_iter().map(|(i, _)| i),
        &next,
    ))
}

/// Every enabled worker that is not a syslog worker and has no require path to one,
/// ascending; empty when `syslog` is empty. A syslog entry must name a worker.
pub(super) fn presyslog(
    cx: &mut Cx,
    nodes: &[Node],
    enabled: &[u32],
    syslog: &[String],
) -> Vec<u32> {
    let found = lookup(cx, "syslog", syslog);
    for (i, k) in &found {
        if *k != Kind::Worker {
            let name = nodes.get(*i).map_or("", |n| n.name.as_str());
            cx.bad("syslog", format!("syslog entry `{name}` is not a worker"));
        }
    }
    if found.is_empty() {
        return Vec::new();
    }
    let mut back: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
    for (from, n) in nodes.iter().enumerate() {
        for to in requires(n) {
            if let Some(b) = back.get_mut(to) {
                b.push(from);
            }
        }
    }
    let logs = reach(nodes.len(), found.into_iter().map(|(i, _)| i), &back);
    enabled
        .iter()
        .copied()
        .filter(|&i| {
            let i = i as usize;
            nodes.get(i).is_some_and(|n| n.kind == Kind::Worker)
                && !logs.get(i).copied().unwrap_or(true)
        })
        .collect()
}
