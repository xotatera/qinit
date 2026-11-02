// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Layer loading and the amend merge (spec §6): scalars replace, tables merge key by key, lists
//! change only through the explicit `append`, `remove` and `replace` forms.
use crate::error::{Code, Error};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use toml::{Table, Value};

const KINDS: [&str; 4] = ["worker", "forager", "brood", "template"];
const VERBS: [&str; 3] = ["append", "remove", "replace"];
const ENABLE_FILE: &str = "enable.toml";
const ENABLE_KEYS: [&str; 2] = ["enable", "syslog"];

/// The merged frames and, per dotted key path, the layer that set it last.
#[derive(Clone, Debug, PartialEq)]
pub struct Merged {
    pub table: Table,
    pub provenance: BTreeMap<String, String>,
}

/// One layer: a name for provenance and the directory holding its files.
#[derive(Clone, Debug)]
pub struct LayerInput {
    pub name: String,
    pub dir: PathBuf,
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
    prov: &'a mut BTreeMap<String, String>,
    errs: &'a mut Vec<Error>,
}

impl Cx<'_> {
    fn err(&mut self, code: Code, key: &str, detail: String) {
        self.errs.push(
            Error::new(code, key, detail)
                .in_file(self.file)
                .in_layer(self.layer),
        );
    }

    /// Record that this layer set `path`, dropping provenance of anything below it.
    fn set(&mut self, path: &str) {
        let below = format!("{path}.");
        self.prov.retain(|k, _| !k.starts_with(&below));
        self.prov.insert(path.to_string(), self.layer.to_string());
    }
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}.{key}")
    }
}

fn is_list_op(t: &Table) -> bool {
    !t.is_empty() && t.keys().all(|k| VERBS.contains(&k.as_str()))
}

/// Apply one `append`, `remove` or `replace` table to the list `base`.
fn apply_list_op(base: &mut Vec<Value>, op: &Table, path: &str, cx: &mut Cx) {
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
fn merge(base: &mut Table, overlay: Table, path: &str, cx: &mut Cx) {
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
            let path = join(&kind, &name);
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
            merge(slot, one, &kind, cx);
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

/// The `*.toml` files of a layer directory (minus `enable.toml`), in byte order of file name.
fn layer_files(layer: &LayerInput) -> Result<Vec<PathBuf>, Error> {
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
            let path = join(kind, name);
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
/// # Errors
/// Every I/O, parse, duplicate, unknown-key and list-op error found in all layers.
pub fn load(layers: &[LayerInput]) -> Result<Merged, Vec<Error>> {
    let (mut table, mut provenance, mut errs) = (Table::new(), BTreeMap::new(), Vec::new());
    for layer in layers {
        let files = match layer_files(layer) {
            Ok(f) => f,
            Err(e) => {
                errs.push(e);
                continue;
            }
        };
        let (mut seen, mut parsed) = (BTreeSet::new(), Vec::new());
        for file in files {
            match read_toml(&file, &layer.name) {
                Ok(t) => {
                    check_file(&t, &file, &layer.name, &mut seen, &mut errs);
                    parsed.push((file, t));
                }
                Err(e) => errs.push(e),
            }
        }
        if !errs.is_empty() {
            continue;
        }
        for (file, t) in parsed {
            let mut cx = Cx {
                layer: &layer.name,
                file: &file,
                prov: &mut provenance,
                errs: &mut errs,
            };
            merge_frames(&mut table, t, &mut cx);
        }
    }
    if errs.is_empty() {
        Ok(Merged { table, provenance })
    } else {
        Err(errs)
    }
}

fn string_list(t: &Table, key: &str, file: &Path, errs: &mut Vec<Error>) -> Vec<String> {
    let Some(Value::Array(items)) = t.get(key) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in items {
        if let Some(s) = item.as_str() {
            out.push(s.to_string());
        } else {
            let why = format!("expected a string, got {item:?}");
            errs.push(Error::new(Code::BadValue, key, why).in_file(file));
        }
    }
    out
}

/// Load `enable.toml` from every layer; its `enable` and `syslog` lists merge with the list forms.
///
/// # Errors
/// Every I/O, parse, unknown-key, list-op and bad-value error found in all layers.
pub fn load_enable(layers: &[LayerInput]) -> Result<Enable, Vec<Error>> {
    let (mut table, mut prov, mut errs) = (Table::new(), BTreeMap::new(), Vec::new());
    let mut last = PathBuf::from(ENABLE_FILE);
    for layer in layers {
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
        merge(&mut table, known, "", &mut cx);
        last = file;
    }
    let roots = string_list(&table, "enable", &last, &mut errs);
    let syslog = string_list(&table, "syslog", &last, &mut errs);
    if errs.is_empty() {
        Ok(Enable { roots, syslog })
    } else {
        Err(errs)
    }
}
