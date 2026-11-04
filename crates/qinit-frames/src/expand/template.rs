// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Template inheritance: parsing templates, applying one to a frame and recording the inherited keys.
use super::frames_of;
use crate::error::{Code, Error};
use crate::layers::Merged;
use crate::provenance::{FrameKey, Origin, Provenance, Seg, locate_all};
use crate::schema::{self, Frame};
use std::collections::{BTreeMap, BTreeSet};

/// Parse every template; a template naming a template is a `Template` error. Failed templates
/// are left out of the map and recorded in `failed`, so frames using them add no second error.
pub(super) fn templates(
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

/// Every field the frame sets replaces the template's; `deps` concatenate, template first, and
/// `env` merges key by key, the frame's entries winning.
pub(super) fn inherit(f: Frame, t: &Frame) -> Frame {
    let env = match (&t.env, f.env) {
        (None, None) => None,
        (te, fe) => {
            let mut merged = te.clone().unwrap_or_default();
            merged.extend(fe.into_iter().flatten());
            Some(merged)
        }
    };
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
        stop: f.stop.or_else(|| t.stop.clone()),
        start_timeout: f.start_timeout.or_else(|| t.start_timeout.clone()),
        output: f.output.or_else(|| t.output.clone()),
        errors: f.errors.or_else(|| t.errors.clone()),
        cell: f.cell.or_else(|| t.cell.clone()),
        credentials: f.credentials.or_else(|| t.credentials.clone()),
        sandbox: f.sandbox.or_else(|| t.sandbox.clone()),
        env,
        cwd: f.cwd.or_else(|| t.cwd.clone()),
        umask: f.umask.or(t.umask),
        rlimits: f.rlimits.or_else(|| t.rlimits.clone()),
        reload: f.reload.or_else(|| t.reload.clone()),
        launch: f.launch.or_else(|| t.launch.clone()),
        deps,
    }
}

/// Which of the fields a template can pass on `f` sets.
fn fields_set(f: &Frame) -> [(&'static str, bool); 18] {
    [
        ("exec", f.exec.is_some()),
        ("instances", f.instances.is_some()),
        ("ready", f.ready.is_some()),
        ("restart", f.restart.is_some()),
        ("stop", f.stop.is_some()),
        ("start_timeout", f.start_timeout.is_some()),
        ("output", f.output.is_some()),
        ("errors", f.errors.is_some()),
        ("cell", f.cell.is_some()),
        ("credentials", f.credentials.is_some()),
        ("sandbox", f.sandbox.is_some()),
        ("env", f.env.is_some()),
        ("cwd", f.cwd.is_some()),
        ("umask", f.umask.is_some()),
        ("rlimits", f.rlimits.is_some()),
        ("reload", f.reload.is_some()),
        ("launch", f.launch.is_some()),
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
/// `tname` (`t`): each field the frame leaves unset and the template sets; when both have
/// `deps`, each of the template's groups at the head of the concatenated list; when both have
/// `env`, each template entry whose key the frame does not set.
pub(super) fn inherit_provenance(
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
    if let (Some(fe), Some(te)) = (&f.env, &t.env) {
        let env = Seg::Key("env".to_owned());
        for key in te.keys().filter(|k| !fe.contains_key(*k)) {
            add.extend(template_keys(
                prov,
                tname,
                &[env.clone(), Seg::Key(key.clone())],
            ));
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
