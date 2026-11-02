// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The `qinit_db_core` table limits, checked before the writer sees the model.
use crate::error::{Code, Error};
use crate::expand::kind_name;
use qinit_db::{Model, Ready, Target};
use qinit_db_core::{
    MAX_CREDS, MAX_EDGES, MAX_EDGES_PER_GROUP, MAX_GROUPS, MAX_GROUPS_PER_NODE, MAX_NODES,
    MAX_POOL, MAX_ROUTES,
};
use std::collections::BTreeSet;

fn over(errs: &mut Vec<Error>, key: &str, table: &str, n: usize, limit: usize) {
    if n > limit {
        let why = format!("{n} entries in table {table}; the limit is {limit}");
        errs.push(Error::new(Code::Limit, key, why));
    }
}

/// The string pool the writer would build: every distinct non-empty string, lists joined by
/// NUL as the writer interns them.
fn pool_bytes(m: &Model) -> usize {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for n in &m.nodes {
        seen.insert(n.name.clone());
        seen.insert(n.exec.join("\0"));
        if let Ready::Socket(s) | Ready::Path(s) = &n.ready {
            seen.insert(s.clone());
        }
        seen.extend(n.instance_of.clone());
        for e in n.groups.iter().flat_map(|g| g.edges.iter()) {
            if let Target::Path(p) = &e.target {
                seen.insert(p.clone());
            }
        }
    }
    for c in &m.creds {
        seen.insert(c.user.clone());
        seen.insert(c.landlock.join("\0"));
    }
    for r in &m.routes {
        if let qinit_db::Route::Path(p) = r {
            seen.insert(p.clone());
        }
    }
    seen.iter().map(String::len).sum()
}

/// Push a `Limit` error for every table over its limit; the detail names the table.
pub(super) fn check(errs: &mut Vec<Error>, m: &Model) {
    over(errs, "", "nodes", m.nodes.len(), MAX_NODES);
    for n in &m.nodes {
        let key = format!("{}.{}", kind_name(n.kind), n.name);
        over(
            errs,
            &key,
            "groups per node",
            n.groups.len(),
            MAX_GROUPS_PER_NODE,
        );
        for g in &n.groups {
            over(
                errs,
                &key,
                "edges per group",
                g.edges.len(),
                MAX_EDGES_PER_GROUP,
            );
        }
    }
    let groups: usize = m.nodes.iter().map(|n| n.groups.len()).sum();
    let edges: usize = m
        .nodes
        .iter()
        .flat_map(|n| n.groups.iter())
        .map(|g| g.edges.len())
        .sum();
    over(errs, "", "groups", groups, MAX_GROUPS);
    over(errs, "", "edges", edges, MAX_EDGES);
    over(errs, "", "creds", m.creds.len(), MAX_CREDS);
    over(errs, "", "routes", m.routes.len(), MAX_ROUTES);
    over(errs, "", "pool", pool_bytes(m), MAX_POOL);
}
