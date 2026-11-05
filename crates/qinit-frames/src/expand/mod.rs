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
mod instances;
mod template;

use crate::error::{Code, Error};
use crate::layers::Merged;
use crate::provenance::{Provenance, locate_all};
use crate::schema::{self, Frame};
use instances::{instance_provenance, instances};
use qinit_db::Kind;
use qinit_db_core::MAX_NAME_LEN;
use std::collections::{BTreeMap, BTreeSet};
use template::{inherit, inherit_provenance, templates};

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

/// The words a cgroup directory already uses for its own interface files (`memory.max`,
/// `cgroup.procs`): a node cell named `memory.max` would collide with one.
const CGROUP_WORDS: [&str; 11] = [
    "cgroup", "cpu", "cpuset", "io", "memory", "pids", "hugetlb", "misc", "rdma", "dmem", "irq",
];

/// The reserved word `name` starts with (the part before its first `.`), if any.
pub(super) fn reserved_word(name: &str) -> Option<&'static str> {
    let head = name.split('.').next().unwrap_or(name);
    CGROUP_WORDS.into_iter().find(|w| *w == head)
}

pub(super) fn reserved_why(name: &str, word: &str) -> String {
    format!(
        "{name:?} is reserved: `{word}` would collide with a cgroup interface file such as `{word}.max`"
    )
}

pub(super) fn valid_instance(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b != b'@' && name_byte(b))
}

pub(super) fn frames_of<'a>(
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
        if let Some(word) = reserved_word(name) {
            let why = reserved_why(name, word);
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
