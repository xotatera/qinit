// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Template and instance expansion (spec §5).
//!
//! Every merged frame goes through `schema::parse_frame`. A frame naming a `template` inherits
//! each field the frame leaves unset; `deps` concatenate, template groups first. A template
//! cannot name a template. A worker with `instances` (its own or inherited) becomes one frame per
//! instance, `<name>@<instance>`, with `%i` replaced by the instance in every string except
//! `cell` and durations. A bare name may not contain `@`, so the part of an expanded name before
//! its `@` is always the instanced frame's name (`resolve` stores it as `instance_of`).
use crate::error::{Code, Error};
use crate::layers::Merged;
use crate::provenance::{FrameKey, Origin, Provenance, Seg, locate_all};
use crate::schema::{self, Creds, DepEdge, DepGroup, Frame, Output, Ready, Sandbox};
use qinit_db::Kind;
use qinit_db_core::MAX_NAME_LEN;
use std::collections::{BTreeMap, BTreeSet};

/// The flat frame set: templates applied, instances expanded, sorted by name.
#[derive(Clone, Debug, Default)]
pub struct Expanded {
    /// Name, kind and frame of every node, sorted by name.
    pub frames: Vec<(String, Kind, Frame)>,
    /// The merged provenance, plus the keys each frame inherits from its template (marked
    /// with the template's name) and, for every instance, a copy of its frame's keys.
    pub provenance: Provenance,
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
        let start = errs.len();
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
        locate_all(&merged.provenance, "template", name, &mut errs[start..]);
    }
    out
}

/// Every field the frame sets replaces the template's; `deps` concatenate, template first.
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

/// Which of the fields a template can pass on `f` sets.
fn fields_set(f: &Frame) -> [(&'static str, bool); 10] {
    [
        ("exec", f.exec.is_some()),
        ("instances", f.instances.is_some()),
        ("ready", f.ready.is_some()),
        ("restart", f.restart.is_some()),
        ("output", f.output.is_some()),
        ("errors", f.errors.is_some()),
        ("cell", f.cell.is_some()),
        ("credentials", f.credentials.is_some()),
        ("sandbox", f.sandbox.is_some()),
        ("deps", f.deps.is_some()),
    ]
}

/// The recorded keys of template `tname` at or below `path`, marked with the template.
fn template_keys(prov: &Provenance, tname: &str, path: &[Seg]) -> Vec<(Vec<Seg>, Origin)> {
    let start = FrameKey {
        kind: "template".to_owned(),
        name: tname.to_owned(),
        path: path.to_vec(),
    };
    prov.range(start..)
        .take_while(|(k, _)| k.kind == "template" && k.name == tname && k.path.starts_with(path))
        .map(|(k, o)| {
            let mut o = o.clone();
            o.template = Some(tname.to_owned());
            (k.path.clone(), o)
        })
        .collect()
}

/// Record in `prov` the keys frame `kind.name` (`f`, before inheriting) takes from template
/// `tname` (`t`): each field the frame leaves unset and the template sets, and, when both have
/// `deps`, each of the template's groups at the head of the concatenated list.
fn inherit_provenance(
    prov: &mut Provenance,
    kind: &str,
    name: &str,
    f: &Frame,
    tname: &str,
    t: &Frame,
) {
    let mut add = Vec::new();
    for ((field, mine), (_, theirs)) in fields_set(f).into_iter().zip(fields_set(t)) {
        if theirs && !mine {
            add.extend(template_keys(prov, tname, &[Seg::Key(field.to_owned())]));
        }
    }
    if let (Some(_), Some(td)) = (&f.deps, &t.deps) {
        let deps = Seg::Key("deps".to_owned());
        if let Some((_, o)) = template_keys(prov, tname, std::slice::from_ref(&deps))
            .into_iter()
            .next()
        {
            add.extend((0..td.len()).map(|i| (vec![deps.clone(), Seg::Index(i)], o.clone())));
        }
    }
    for (path, o) in add {
        let key = FrameKey {
            kind: kind.to_owned(),
            name: name.to_owned(),
            path,
        };
        prov.insert(key, o);
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

/// Parse one frame and apply its template, recording the inherited keys in `prov`.
fn one(
    kname: &str,
    name: &str,
    value: &toml::Value,
    tpl: &BTreeMap<String, Frame>,
    failed: &BTreeSet<String>,
    prov: &mut Provenance,
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
        inherit_provenance(prov, kname, name, &f, &t, tf);
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
fn instance_provenance(prov: &mut Provenance, out: &[(String, Kind, Frame)]) {
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

/// The state `expand` threads through each frame.
struct Run<'a> {
    tpl: BTreeMap<String, Frame>,
    failed: BTreeSet<String>,
    /// Bare frame name to the kind word that defined it first.
    seen: BTreeMap<&'a str, &'static str>,
    prov: Provenance,
    out: Vec<(String, Kind, Frame)>,
    errs: Vec<Error>,
}

impl<'a> Run<'a> {
    /// Check one merged frame's name, apply its template and expand its instances.
    fn frame(&mut self, kname: &'static str, kind: Kind, name: &'a str, value: &toml::Value) {
        let base = format!("{kname}.{name}");
        if !valid_name(name) || name.contains('@') {
            let why = format!("{name:?} is not a valid frame name");
            return self.errs.push(Error::new(Code::BadName, base, why));
        }
        if let Some(prev) = self.seen.insert(name, kname) {
            let why = format!("`{name}` is also a {prev}");
            return self.errs.push(Error::new(Code::DuplicateName, base, why));
        }
        match one(kname, name, value, &self.tpl, &self.failed, &mut self.prov) {
            Ok(Some(mut f)) => match f.instances.take() {
                Some(list) => instances(name, kind, &f, &list, &mut self.out, &mut self.errs),
                None => self.out.push((name.to_owned(), kind, f)),
            },
            Ok(None) => {}
            Err(e) => self.errs.push(e),
        }
    }
}

/// Expand templates and instances of the merged frames.
///
/// Every error is located: its file and layer are those of the key it names (or of the nearest
/// enclosing key a layer set, down to the frame itself), the template's when the frame inherited
/// the key.
///
/// # Errors
/// Every parse, `Template`, `BadName`, `Instance` and `DuplicateName` error of every frame.
pub fn expand(merged: &Merged) -> Result<Expanded, Vec<Error>> {
    let (mut errs, mut failed) = (Vec::new(), BTreeSet::new());
    let tpl = templates(merged, &mut failed, &mut errs);
    let mut run = Run {
        tpl,
        failed,
        seen: BTreeMap::new(),
        prov: merged.provenance.clone(),
        out: Vec::new(),
        errs,
    };
    for (kname, kind) in NODE_KINDS {
        for (name, value) in frames_of(merged, kname) {
            let start = run.errs.len();
            run.frame(kname, kind, name, value);
            locate_all(&run.prov, kname, name, &mut run.errs[start..]);
        }
    }
    if !run.errs.is_empty() {
        return Err(run.errs);
    }
    run.out.sort_by(|a, b| a.0.cmp(&b.0));
    instance_provenance(&mut run.prov, &run.out);
    Ok(Expanded {
        frames: run.out,
        provenance: run.prov,
    })
}
