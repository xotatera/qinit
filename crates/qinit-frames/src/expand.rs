// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Template and instance expansion (spec §5, plan ruling Q8).
//!
//! Every merged frame goes through `schema::parse_frame`. A frame naming a `template` inherits
//! each field the frame leaves unset; `deps` concatenate, template groups first. A template
//! cannot name a template. A worker with `instances` (its own or inherited) becomes one frame per
//! instance, `<name>@<instance>`, with `%i` replaced by the instance in every string except
//! `cell` and durations. A bare name may not contain `@`, so the part of an expanded name before
//! its `@` is always the instanced frame's name (`resolve` stores it as `instance_of`).
use crate::error::{Code, Error};
use crate::layers::Merged;
use crate::schema::{self, Creds, DepEdge, DepGroup, Frame, Output, Ready, Sandbox};
use qinit_db::Kind;
use qinit_db_core::MAX_NAME_LEN;
use std::collections::{BTreeMap, BTreeSet};

/// The flat frame set: templates applied, instances expanded, sorted by name.
#[derive(Clone, Debug, Default)]
pub struct Expanded {
    pub frames: Vec<(String, Kind, Frame)>,
    /// Per dotted key path, the layer that set it last; instance keys copy their frame's.
    pub provenance: BTreeMap<String, String>,
}

const NODE_KINDS: [(&str, Kind); 3] = [
    ("worker", Kind::Worker),
    ("forager", Kind::Forager),
    ("brood", Kind::Brood),
];

/// The frame-kind word of `kind`, as it appears in keys.
#[must_use]
pub(crate) fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Worker => "worker",
        Kind::Forager => "forager",
        Kind::Brood => "brood",
    }
}

fn name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"._@:+-".contains(&b)
}

/// A node name: 1 to `MAX_NAME_LEN` bytes of `[A-Za-z0-9._@:+-]`, not starting with `.` or `-`.
#[must_use]
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME_LEN
        && s.bytes().all(name_byte)
        && !s.starts_with(['.', '-'])
}

fn valid_instance(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b != b'@' && name_byte(b))
}

/// Attach the layer that set `e.key`, or the nearest enclosing key that has one.
pub(crate) fn with_layer(prov: &BTreeMap<String, String>, mut e: Error) -> Error {
    let mut key = e.key.clone();
    loop {
        if let Some(layer) = prov.get(&key) {
            e.layer = Some(layer.clone());
            return e;
        }
        match key.rfind(['.', '[']) {
            Some(i) => key.truncate(i),
            None => return e,
        }
    }
}

fn frames_of<'a>(
    merged: &'a Merged,
    kind: &str,
) -> impl Iterator<Item = (&'a String, &'a toml::Value)> {
    merged
        .table
        .get(kind)
        .and_then(toml::Value::as_table)
        .into_iter()
        .flatten()
}

/// Parse every template; a template naming a template is a `Template` error. Failed templates
/// are left out of the map and recorded in `failed`, so frames using them add no second error.
fn templates(
    merged: &Merged,
    failed: &mut BTreeSet<String>,
    errs: &mut Vec<Error>,
) -> BTreeMap<String, Frame> {
    let mut out = BTreeMap::new();
    for (name, value) in frames_of(merged, "template") {
        match schema::parse_frame("template", name, value) {
            Ok(f) if f.template.is_some() => {
                let key = format!("template.{name}.template");
                errs.push(Error::new(
                    Code::Template,
                    key,
                    "a template cannot name a template",
                ));
                failed.insert(name.clone());
            }
            Ok(f) => {
                out.insert(name.clone(), f);
            }
            Err(e) => {
                errs.push(e);
                failed.insert(name.clone());
            }
        }
    }
    out
}

/// Q8: every field the frame sets replaces the template's; `deps` concatenate, template first.
fn inherit(f: Frame, t: &Frame) -> Frame {
    let deps = match (&t.deps, f.deps) {
        (None, None) => None,
        (td, fd) => Some(
            td.iter()
                .flatten()
                .cloned()
                .chain(fd.into_iter().flatten())
                .collect(),
        ),
    };
    Frame {
        exec: f.exec.or_else(|| t.exec.clone()),
        template: None,
        instances: f.instances.or_else(|| t.instances.clone()),
        ready: f.ready.or_else(|| t.ready.clone()),
        restart: f.restart.or_else(|| t.restart.clone()),
        output: f.output.or_else(|| t.output.clone()),
        errors: f.errors.or_else(|| t.errors.clone()),
        cell: f.cell.or_else(|| t.cell.clone()),
        credentials: f.credentials.or_else(|| t.credentials.clone()),
        sandbox: f.sandbox.or_else(|| t.sandbox.clone()),
        deps,
    }
}

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

/// One instance of `f`: `%i` replaced in exec, ready, output, errors, credentials, sandbox and
/// dependency targets.
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
            seccomp: s(&x.seccomp),
            landlock: sl(&x.landlock),
        }),
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

/// Parse one frame and apply its template.
fn one(
    kname: &str,
    name: &str,
    value: &toml::Value,
    tpl: &BTreeMap<String, Frame>,
    failed: &BTreeSet<String>,
) -> Result<Option<Frame>, Error> {
    let base = format!("{kname}.{name}");
    let mut f = schema::parse_frame(kname, name, value)?;
    if let Some(t) = f.template.take() {
        if failed.contains(&t) {
            return Ok(None);
        }
        let Some(tf) = tpl.get(&t) else {
            let key = format!("{base}.template");
            return Err(Error::new(
                Code::Template,
                key,
                format!("no template `{t}`"),
            ));
        };
        f = inherit(f, tf);
        schema::check_kind(kname, &f, &base)?;
    }
    Ok(Some(f))
}

/// Expand one frame's instances into `out`, checking every instance string and final name.
fn instances(
    name: &str,
    kind: Kind,
    f: &Frame,
    list: &[String],
    out: &mut Vec<(String, Kind, Frame)>,
    errs: &mut Vec<Error>,
) {
    let key = format!("{}.{name}.instances", kind_name(kind));
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

/// Copy the provenance of `kind.name` and every key below it to each of its instances.
fn instance_provenance(
    prov: &BTreeMap<String, String>,
    out: &[(String, Kind, Frame)],
) -> BTreeMap<String, String> {
    let mut all = prov.clone();
    for (full, kind, _) in out {
        let Some((name, _)) = full.split_once('@') else {
            continue;
        };
        let base = format!("{}.{name}", kind_name(*kind));
        let below = format!("{base}.");
        for (k, layer) in prov {
            if k == &base || k.starts_with(&below) {
                let key = format!("{}.{full}{}", kind_name(*kind), &k[base.len()..]);
                all.insert(key, layer.clone());
            }
        }
    }
    all
}

/// Expand templates and instances of the merged frames.
///
/// # Errors
/// Every parse, `Template`, `BadName`, `Instance` and `DuplicateName` error of every frame.
pub fn expand(merged: &Merged) -> Result<Expanded, Vec<Error>> {
    let (mut errs, mut failed) = (Vec::new(), BTreeSet::new());
    let tpl = templates(merged, &mut failed, &mut errs);
    let mut out = Vec::new();
    let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
    for (kname, kind) in NODE_KINDS {
        for (name, value) in frames_of(merged, kname) {
            let base = format!("{kname}.{name}");
            if !valid_name(name) || name.contains('@') {
                let why = format!("{name:?} is not a valid frame name");
                errs.push(Error::new(Code::BadName, base, why));
                continue;
            }
            if let Some(prev) = seen.insert(name, kname) {
                let why = format!("`{name}` is also a {prev}");
                errs.push(Error::new(Code::DuplicateName, base, why));
                continue;
            }
            match one(kname, name, value, &tpl, &failed) {
                Ok(Some(mut f)) => match f.instances.take() {
                    Some(list) => instances(name, kind, &f, &list, &mut out, &mut errs),
                    None => out.push((name.clone(), kind, f)),
                },
                Ok(None) => {}
                Err(e) => errs.push(e),
            }
        }
    }
    if !errs.is_empty() {
        return Err(errs
            .into_iter()
            .map(|e| with_layer(&merged.provenance, e))
            .collect());
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    let provenance = instance_provenance(&merged.provenance, &out);
    Ok(Expanded {
        frames: out,
        provenance,
    })
}
