// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Layer loading and the amend merge (spec §6): scalars replace, tables merge key by key, lists
//! change only through the explicit `append`, `remove` and `replace` forms.
use crate::error::{Code, Error};
use crate::provenance::{FrameKey, Origin, Provenance, Seg};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use toml::{Table, Value};

const KINDS: [&str; 4] = ["worker", "forager", "brood", "template"];
const VERBS: [&str; 3] = ["append", "remove", "replace"];
const ENABLE_FILE: &str = "enable.toml";
const ENABLE_KEYS: [&str; 2] = ["enable", "syslog"];

/// The merged frames and, per frame key, the layer and file that set it last.
#[derive(Clone, Debug, PartialEq)]
pub struct Merged {
    /// `kind` to `name` to the merged frame table.
    pub table: Table,
    /// Where each recorded frame key was set; see [`crate::provenance`].
    pub provenance: Provenance,
}

/// Provenance during the merge: a key path from the top of the merged table (`kind`, `name`,
/// then the keys inside the frame; or an `enable.toml` key) to where it was set.
type Paths = BTreeMap<Vec<String>, Origin>;

/// One layer: a name for provenance and the directory holding its files.
#[derive(Clone, Debug)]
pub struct LayerInput {
    pub name: String,
    pub dir: PathBuf,
    /// The one file the layer is, whatever its name, in place of the `*.toml` files of `dir`;
    /// the layer then has no `enable.toml`. `qctl run --frame` compiles the caller's file so,
    /// and its errors name that file.
    pub only: Option<PathBuf>,
}

/// The merged `enable.toml`: root names and the workers that provide `/dev/log`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Enable {
    pub roots: Vec<String>,
    pub syslog: Vec<String>,
}

/// Where a merge is happening, and what it has found so far.
struct Cx<'a> {
    layer: &'a str,
    file: &'a Path,
    prov: &'a mut Paths,
    errs: &'a mut Vec<Error>,
}

impl Cx<'_> {
    fn err(&mut self, code: Code, path: &[String], detail: String) {
        self.errs.push(
            Error::new(code, path.join("."), detail)
                .in_file(self.file)
                .in_layer(self.layer),
        );
    }

    /// Record that this layer and file set `path`, dropping provenance of anything below it.
    fn set(&mut self, path: &[String]) {
        self.prov
            .retain(|k, _| !(k.len() > path.len() && k.starts_with(path)));
        let origin = Origin {
            layer: self.layer.to_owned(),
            file: self.file.to_owned(),
            template: None,
        };
        self.prov.insert(path.to_vec(), origin);
    }
}

fn join(path: &[String], key: &str) -> Vec<String> {
    let mut p = path.to_vec();
    p.push(key.to_owned());
    p
}

fn is_list_op(t: &Table) -> bool {
    !t.is_empty() && t.keys().all(|k| VERBS.contains(&k.as_str()))
}

/// Apply one `append`, `remove` or `replace` table to the list `base`.
fn apply_list_op(base: &mut Vec<Value>, op: &Table, path: &[String], cx: &mut Cx) {
    let mut it = op.iter();
    let (Some((verb, arg)), None) = (it.next(), it.next()) else {
        let keys: Vec<_> = op.keys().map(String::as_str).collect();
        let why =
            format!("a list change takes exactly one of append, remove, replace; got {keys:?}");
        return cx.err(Code::ListOp, path, why);
    };
    let Some(items) = arg.as_array() else {
        return cx.err(Code::ListOp, path, format!("`{verb}` takes an array"));
    };
    match verb.as_str() {
        "append" => base.extend(items.iter().cloned()),
        "replace" => base.clone_from(items),
        "remove" => {
            if let Some(absent) = items.iter().find(|i| !base.contains(i)) {
                return cx.err(
                    Code::ListOp,
                    path,
                    format!("remove of an absent item: {absent:?}"),
                );
            }
            base.retain(|e| !items.contains(e));
        }
        _ => return cx.err(Code::ListOp, path, format!("unknown list verb `{verb}`")),
    }
    cx.set(path);
}

/// Merge `overlay` into `base`; every problem goes to `cx.errs` and the merge carries on.
fn merge(base: &mut Table, overlay: Table, path: &[String], cx: &mut Cx) {
    for (key, new) in overlay {
        let p = join(path, &key);
        match (base.get_mut(&key), new) {
            (Some(Value::Table(b)), Value::Table(o)) if !is_list_op(&o) => merge(b, o, &p, cx),
            (Some(Value::Array(b)), Value::Table(o)) => apply_list_op(b, &o, &p, cx),
            (Some(Value::Array(_)), Value::Array(_)) => {
                let why = "a plain array over an existing list; use append, remove or replace";
                cx.err(Code::ListOp, &p, why.into());
            }
            (_, Value::Table(o)) if is_list_op(&o) => {
                cx.err(
                    Code::ListOp,
                    &p,
                    "a list change over a key that holds no list".into(),
                );
            }
            (_, Value::Table(o)) => {
                cx.set(&p);
                let mut fresh = Table::new();
                merge(&mut fresh, o, &p, cx);
                base.insert(key, Value::Table(fresh));
            }
            (_, v) => {
                cx.set(&p);
                base.insert(key, v);
            }
        }
    }
}

/// Merge one file's `kind.name` frames into `acc`, honouring `disable`.
fn merge_frames(acc: &mut Table, file_table: Table, cx: &mut Cx) {
    for (kind, names) in file_table {
        let Value::Table(names) = names else { continue };
        for (name, frame) in names {
            let path = vec![kind.clone(), name.clone()];
            let Value::Table(mut frame) = frame else {
                cx.err(Code::BadValue, &path, "a frame must be a table".into());
                continue;
            };
            match frame.remove("disable") {
                None | Some(Value::Boolean(false)) => {}
                Some(Value::Boolean(true)) => {
                    if let Some(Value::Table(k)) = acc.get_mut(&kind) {
                        k.remove(&name);
                    }
                    cx.set(&path);
                    continue;
                }
                Some(_) => {
                    let why = "disable must be true or false".into();
                    cx.err(Code::BadValue, &join(&path, "disable"), why);
                    continue;
                }
            }
            let slot = acc
                .entry(kind.clone())
                .or_insert_with(|| Value::Table(Table::new()));
            let Value::Table(slot) = slot else { continue };
            let mut one = Table::new();
            one.insert(name, Value::Table(frame));
            merge(slot, one, std::slice::from_ref(&kind), cx);
        }
    }
}

fn read_toml(path: &Path, layer: &str) -> Result<Table, Error> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::new(Code::Io, "", e.to_string())
            .in_file(path)
            .in_layer(layer)
    })?;
    text.parse::<Table>().map_err(|e| {
        Error::new(Code::Parse, "", e.to_string())
            .in_file(path)
            .in_layer(layer)
    })
}

/// The `*.toml` files of a layer directory (minus `enable.toml`), in byte order of file name;
/// or the layer's one file.
fn layer_files(layer: &LayerInput) -> Result<Vec<PathBuf>, Error> {
    if let Some(file) = &layer.only {
        return Ok(vec![file.clone()]);
    }
    let io = |e: std::io::Error| {
        Error::new(Code::Io, "", e.to_string())
            .in_file(&layer.dir)
            .in_layer(&layer.name)
    };
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&layer.dir).map_err(io)? {
        let name = entry.map_err(io)?.file_name();
        let bytes = name.as_encoded_bytes();
        if bytes.ends_with(b".toml") && bytes != ENABLE_FILE.as_bytes() {
            files.push(layer.dir.join(&name));
        }
    }
    files.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    Ok(files)
}

/// Check a parsed frame file's top level; record each frame in `seen` to catch duplicates.
fn check_file(
    t: &Table,
    file: &Path,
    layer: &str,
    seen: &mut BTreeSet<String>,
    errs: &mut Vec<Error>,
) {
    for (kind, names) in t {
        let known = KINDS.contains(&kind.as_str());
        let Some(names) = names.as_table().filter(|_| known) else {
            let (code, why) = if known {
                (Code::BadValue, "expected a table of named frames")
            } else {
                (
                    Code::UnknownKey,
                    "expected one of worker, forager, brood, template",
                )
            };
            errs.push(
                Error::new(code, kind.clone(), why)
                    .in_file(file)
                    .in_layer(layer),
            );
            continue;
        };
        for name in names.keys() {
            let path = format!("{kind}.{name}");
            if !seen.insert(path.clone()) {
                let why = "defined twice in one layer";
                errs.push(
                    Error::new(Code::DuplicateFrame, path, why)
                        .in_file(file)
                        .in_layer(layer),
                );
            }
        }
    }
}

/// Load every layer in order and merge the frames across them.
///
/// Layers are listed explicitly by the caller, so a missing layer directory is an `Io` error.
/// Read, parse, unknown-key and duplicate-frame errors are all collected, and once one exists
/// nothing is merged (the data is incomplete). List-operation errors do not stop the merge: those
/// from every layer and frame are reported together.
///
/// Disable rules: `disable = true` removes the frame and discards every other key in the same
/// table; a later layer that defines the frame again inserts it fresh, with that layer as the
/// provenance; `disable` on a frame that does not exist is accepted; `disable = false` is ignored.
///
/// # Errors
/// Every I/O, parse, duplicate, unknown-key and list-op error found in all layers.
pub fn load(layers: &[LayerInput]) -> Result<Merged, Vec<Error>> {
    let (mut table, mut paths, mut errs) = (Table::new(), Paths::new(), Vec::new());
    let mut blocked = false;
    for layer in layers {
        let files = match layer_files(layer) {
            Ok(f) => f,
            Err(e) => {
                errs.push(e);
                blocked = true;
                continue;
            }
        };
        let (mut seen, mut parsed, before) = (BTreeSet::new(), Vec::new(), errs.len());
        for file in files {
            match read_toml(&file, &layer.name) {
                Ok(t) => {
                    check_file(&t, &file, &layer.name, &mut seen, &mut errs);
                    parsed.push((file, t));
                }
                Err(e) => errs.push(e),
            }
        }
        blocked |= errs.len() > before;
        if blocked {
            continue;
        }
        for (file, t) in parsed {
            let mut cx = Cx {
                layer: &layer.name,
                file: &file,
                prov: &mut paths,
                errs: &mut errs,
            };
            merge_frames(&mut table, t, &mut cx);
        }
    }
    if errs.is_empty() {
        Ok(Merged {
            table,
            provenance: frame_keys(paths),
        })
    } else {
        Err(errs)
    }
}

/// The frame keys of `paths`: every path of at least `kind` and `name`.
fn frame_keys(paths: Paths) -> Provenance {
    paths
        .into_iter()
        .filter_map(|(mut p, origin)| {
            if p.len() < 2 {
                return None;
            }
            let rest = p.split_off(2);
            let name = p.pop()?;
            let kind = p.pop()?;
            let path = rest.into_iter().map(Seg::Key).collect();
            Some((FrameKey { kind, name, path }, origin))
        })
        .collect()
}

/// Read the string list at `key` of the merged enable table. A missing key is empty; a
/// non-array value or a non-string element is a `BadValue` naming the layer and file that set it.
///
/// Attribution is to the last layer that set the key (the provenance entry of `key`), not to the
/// layer that wrote the offending element: a bad element from `vendor` that `etc` then appended
/// to is reported against `etc`.
fn string_list(t: &Table, key: &str, prov: &Paths, errs: &mut Vec<Error>) -> Vec<String> {
    let Some(value) = t.get(key) else {
        return Vec::new();
    };
    let origin = prov.get(&[key.to_owned()][..]);
    let at = |e: Error| match origin {
        Some(o) => e.in_layer(o.layer.clone()).in_file(o.file.clone()),
        None => e,
    };
    let Value::Array(items) = value else {
        let why = format!("expected an array of strings, got {value:?}");
        errs.push(at(Error::new(Code::BadValue, key, why)));
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in items {
        if let Some(s) = item.as_str() {
            out.push(s.to_string());
        } else {
            let why = format!("expected a string, got {item:?}");
            errs.push(at(Error::new(Code::BadValue, key, why)));
        }
    }
    out
}

/// Load `enable.toml` from every layer but a one-file layer; its `enable` and `syslog` lists merge
/// with the list forms.
///
/// # Errors
/// Every I/O, parse, unknown-key, list-op and bad-value error found in all layers.
pub fn load_enable(layers: &[LayerInput]) -> Result<Enable, Vec<Error>> {
    load_enable_origins(layers).map(|(e, _)| e)
}

/// [`load_enable`], and for each of the keys `enable` and `syslog` that a layer set, the layer
/// and file that set it last. A key no layer set has no entry.
///
/// # Errors
/// As [`load_enable`].
pub fn load_enable_origins(
    layers: &[LayerInput],
) -> Result<(Enable, BTreeMap<String, Origin>), Vec<Error>> {
    let (mut table, mut prov, mut errs) = (Table::new(), Paths::new(), Vec::new());
    for layer in layers.iter().filter(|l| l.only.is_none()) {
        let file = layer.dir.join(ENABLE_FILE);
        let t = match read_toml(&file, &layer.name) {
            Ok(t) => t,
            Err(e) if e.code == Code::Io && !file.exists() => continue,
            Err(e) => {
                errs.push(e);
                continue;
            }
        };
        let (known, unknown): (Table, Table) = t
            .into_iter()
            .partition(|(k, _)| ENABLE_KEYS.contains(&k.as_str()));
        for k in unknown.keys() {
            let e = Error::new(Code::UnknownKey, k.clone(), "expected enable or syslog");
            errs.push(e.in_file(&file).in_layer(&layer.name));
        }
        let mut cx = Cx {
            layer: &layer.name,
            file: &file,
            prov: &mut prov,
            errs: &mut errs,
        };
        merge(&mut table, known, &[], &mut cx);
    }
    let roots = string_list(&table, "enable", &prov, &mut errs);
    let syslog = string_list(&table, "syslog", &prov, &mut errs);
    if errs.is_empty() {
        let origins = prov
            .into_iter()
            .filter_map(|(mut p, o)| (p.len() == 1).then(|| (p.remove(0), o)))
            .collect();
        Ok((Enable { roots, syslog }, origins))
    } else {
        Err(errs)
    }
}
