// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Instance expansion: `%i` substitution, instance name checks and per-instance provenance.
use super::{kind_name, valid_instance, valid_name};
use crate::error::{Code, Error};
use crate::provenance::{FrameKey, Provenance};
use crate::schema::{Creds, DepEdge, DepGroup, Frame, Output, Ready, Sandbox};
use qinit_db::Kind;
use std::collections::BTreeSet;

fn sub(s: &str, inst: &str) -> String {
    s.replace("%i", inst)
}

fn sub_all(v: &[String], inst: &str) -> Vec<String> {
    v.iter().map(|s| sub(s, inst)).collect()
}

fn sub_output(o: &Output, inst: &str) -> Output {
    match o {
        Output::Path(p) => Output::Path(sub(p, inst)),
        Output::Pipe { pipe } => Output::Pipe {
            pipe: sub(pipe, inst),
        },
    }
}

/// One instance of `f`: `%i` replaced in exec, ready, output, errors, credentials, sandbox,
/// environment values, cwd and dependency targets.
fn instantiate(f: &Frame, inst: &str) -> Frame {
    let s = |o: &Option<String>| o.as_deref().map(|x| sub(x, inst));
    let sl = |o: &Option<Vec<String>>| o.as_deref().map(|x| sub_all(x, inst));
    Frame {
        exec: sl(&f.exec),
        template: None,
        instances: None,
        ready: f.ready.as_ref().map(|r| match r {
            Ready::Kind(k) => Ready::Kind(k.clone()),
            Ready::Socket { socket } => Ready::Socket {
                socket: sub(socket, inst),
            },
            Ready::Path { path } => Ready::Path {
                path: sub(path, inst),
            },
        }),
        restart: f.restart.clone(),
        stop: f.stop.clone(),
        start_timeout: f.start_timeout.clone(),
        output: f.output.as_ref().map(|o| sub_output(o, inst)),
        errors: f.errors.as_ref().map(|o| sub_output(o, inst)),
        cell: f.cell.clone(),
        credentials: f.credentials.as_ref().map(|c| Creds {
            uid: sub(&c.uid, inst),
            caps: sl(&c.caps),
            nnp: c.nnp,
            securebits: s(&c.securebits),
        }),
        sandbox: f.sandbox.as_ref().map(|x| Sandbox {
            namespaces: sl(&x.namespaces),
            seccomp: x.seccomp.clone(),
            paths: sl(&x.paths),
        }),
        env: f
            .env
            .as_ref()
            .map(|e| e.iter().map(|(k, v)| (k.clone(), sub(v, inst))).collect()),
        cwd: s(&f.cwd),
        umask: f.umask,
        rlimits: f.rlimits.clone(),
        reload: f.reload.clone(),
        launch: f.launch.clone(),
        deps: f.deps.as_ref().map(|gs| {
            gs.iter()
                .map(|g| DepGroup {
                    group: g.group.clone(),
                    edges: g
                        .edges
                        .iter()
                        .map(|e| DepEdge {
                            to: s(&e.to),
                            path: s(&e.path),
                            ..e.clone()
                        })
                        .collect(),
                })
                .collect()
        }),
    }
}

/// Expand one frame's instances into `out`, checking every instance string and final name.
pub(super) fn instances(
    name: &str,
    kind: Kind,
    f: &Frame,
    list: &[String],
    out: &mut Vec<(String, Kind, Frame)>,
    errs: &mut Vec<Error>,
) {
    let key = format!("{}.{name}.instances", kind_name(kind));
    if list.is_empty() {
        // An empty list would silently drop the frame, so it is refused; a deliberate mask is
        // `disable = true`.
        let why = "an empty instance list defines nothing; use `disable = true` to mask a frame";
        errs.push(Error::new(Code::Instance, key, why));
        return;
    }
    let mut seen = BTreeSet::new();
    for inst in list {
        let full = format!("{name}@{inst}");
        if !valid_instance(inst) || !valid_name(&full) {
            let why = format!("instance {inst:?} makes the invalid name {full:?}");
            errs.push(Error::new(Code::BadName, key.clone(), why));
        } else if !seen.insert(inst.as_str()) {
            let why = format!("instance `{inst}` is listed twice");
            errs.push(Error::new(Code::Instance, key.clone(), why));
        } else {
            out.push((full, kind, instantiate(f, inst)));
        }
    }
}

/// Copy the provenance of every key of an instanced frame to each of its instances.
pub(super) fn instance_provenance(prov: &mut Provenance, out: &[(String, Kind, Frame)]) {
    let mut add = Vec::new();
    for (full, kind, _) in out {
        let Some((name, _)) = full.split_once('@') else {
            continue;
        };
        let kind = kind_name(*kind);
        let keys = prov
            .range(FrameKey::new(kind, name, &[])..)
            .take_while(|(k, _)| k.kind == kind && k.name == name);
        for (k, o) in keys {
            let key = FrameKey {
                kind: kind.to_owned(),
                name: full.clone(),
                path: k.path.clone(),
            };
            add.push((key, o.clone()));
        }
    }
    prov.extend(add);
}
