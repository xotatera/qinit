// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qctl fill`: the implicit defaults written into the administrator's files (spec 2026-11-05
//! §4.5).
//!
//! [`plan`] decides, from the compiled tree alone, which key goes into which table of which
//! file: only keys whose origin is `default` and whose default is a schema constant
//! ([`FILL_KEYS`], [`POLICY_KEYS`]), never a default the schema has no word for, and never into
//! a layer below the last. [`apply`] makes the edits with `toml_edit`, as inserted lines (or
//! keys inserted inside an inline table) and nothing else, and writes each file through a
//! temporary file and a rename, keeping its mode and owner; a dry run prints the diff instead.
use crate::args::{FillOpts, PolicyChoice};
use crate::compile::{Defaults, checked_input};
use crate::show::{KINDS, kind_word, merged_frame, unwritable_default, user_ns};
use crate::{owner, report};
use qinit_frames::compile::{Compiled, compile};
use qinit_frames::dump;
use qinit_frames::layers::LayerInput;
use qinit_frames::provenance::{FrameKey, Provenance};
use std::fmt::Write as _;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use toml::Value as TomlValue;
use toml_edit::{Decor, DocumentMut, InlineTable, Item, Key, Table, Value};

/// The frame keys `fill` writes: those whose default is a constant of the schema (a key is
/// filled when it is one of these or lies below one). Derived values (`errors`) are not here.
pub const FILL_KEYS: [&str; 11] = [
    "ready",
    "restart",
    "stop",
    "start_timeout",
    "cell",
    "cwd",
    "umask",
    "credentials.caps",
    "credentials.nnp",
    "credentials.securebits",
    "sandbox",
];

/// The policy rule keys with a default, and that default as `show policy` prints it.
pub const POLICY_KEYS: [(&str, &str); 6] = [
    ("caps_max", "[]"),
    ("require_nnp", "false"),
    ("require_seccomp", "false"),
    ("allow_userns", "false"),
    ("allow_inside_ids", "false"),
    ("allow_idmap", "false"),
];

/// The comment after a filled key, with the two spaces before it.
pub const COMMENT: &str = "  # default, filled by qctl";

/// The indentation of a filled key line.
const INDENT: &str = "  ";

/// One key to insert: into `table` (the path of table keys from the top of `file`; an
/// all-digit step indexes an array of tables) as `key` (dotted below the table) = `value` (TOML
/// value syntax).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edit {
    pub file: PathBuf,
    pub table: Vec<String>,
    pub key: String,
    pub value: String,
}

/// Which frames to fill.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frames {
    /// Every frame that is a node or expands to nodes.
    All,
    /// These `(kind, name)` frames; a `template` kind fills what its frames leave to it.
    Some(Vec<(String, String)>),
}

/// What [`plan`] fills and where it writes.
#[derive(Clone, Debug)]
pub struct Targets<'a> {
    /// The last layer: the only one written.
    pub last: &'a LayerInput,
    /// The frames to fill.
    pub frames: Frames,
    /// The policy file and its table, when the policy is filled.
    pub policy: Option<(&'a Path, &'a toml::Table)>,
}

fn fillable(key: &str) -> bool {
    FILL_KEYS.iter().any(|f| {
        key.strip_prefix(f)
            .is_some_and(|r| r.is_empty() || r.starts_with('.'))
    })
}

/// One frame of the compiled tree as `fill` sees it, from its first node.
struct FrameDefaults<'a> {
    kind: &'static str,
    name: &'a str,
    table: &'a toml::Table,
    template: Option<&'a str>,
    /// The keys `fill` may write, in dump order, with their default values.
    keys: Vec<(String, String)>,
}

impl FrameDefaults<'_> {
    /// Whether the frame sets the field `top` itself (then it takes nothing of it from its
    /// template: a field the frame sets replaces the template's whole).
    fn sets(&self, top: &str) -> bool {
        self.table.contains_key(top)
    }

    fn default_of(&self, key: &str) -> Option<&str> {
        self.keys
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Every frame of `c` with nodes, in model order.
fn frames(c: &Compiled) -> Vec<FrameDefaults<'_>> {
    let model = &c.resolved.model;
    let lines = dump::lines(&c.resolved, &c.provenance);
    let mut out: Vec<FrameDefaults> = Vec::new();
    for (i, node) in model.nodes.iter().enumerate() {
        let kind = kind_word(node);
        let name = node.instance_of.as_deref().unwrap_or(&node.name);
        if out.iter().any(|f| f.kind == kind && f.name == name) {
            continue;
        }
        let Some(table) = merged_frame(c, kind, name) else {
            continue;
        };
        let ns = user_ns(model, node);
        let keys = lines
            .iter()
            .filter(|l| l.node == i && l.origin == "default" && fillable(&l.key))
            .filter(|l| !unwritable_default(&l.key, &l.value, ns))
            .map(|l| (l.key.clone(), l.value.clone()))
            .collect();
        out.push(FrameDefaults {
            kind,
            name,
            table,
            template: table.get("template").and_then(TomlValue::as_str),
            keys,
        });
    }
    out
}

/// The file of layer `last` for the table `kind.name`: the one that already amends it, or the
/// file of the same base name as the one that declared it.
fn file_for(prov: &Provenance, last: &LayerInput, kind: &str, name: &str) -> PathBuf {
    let start = FrameKey::new(kind, name, &[]);
    let amending = prov
        .range(start.clone()..)
        .take_while(|(k, _)| k.kind == kind && k.name == name)
        .find(|(_, o)| o.layer == last.name && o.template.is_none())
        .map(|(_, o)| o.file.clone());
    amending.unwrap_or_else(|| {
        let base = prov
            .get(&start)
            .and_then(|o| o.file.file_name())
            .map_or_else(|| format!("{name}.toml").into(), ToOwned::to_owned);
        last.dir.join(base)
    })
}

/// The edits that fill `targets` in `c`.
///
/// # Errors
/// A target frame that does not exist.
pub fn plan(c: &Compiled, targets: &Targets) -> Result<Vec<Edit>, String> {
    let all = frames(c);
    let chosen: Vec<(&FrameDefaults, Option<&str>)> = match &targets.frames {
        Frames::All => all.iter().map(|f| (f, None)).collect(),
        Frames::Some(list) => {
            let mut v = Vec::new();
            for (kind, name) in list {
                if kind == "template" {
                    let users: Vec<_> = all
                        .iter()
                        .filter(|f| f.template == Some(name.as_str()))
                        .collect();
                    if users.is_empty() && merged_frame(c, kind, name).is_none() {
                        return Err(format!("fill: no frame {kind}.{name}"));
                    }
                    v.extend(users.into_iter().map(|f| (f, Some(name.as_str()))));
                } else {
                    let f = all
                        .iter()
                        .find(|f| f.kind == kind && f.name == name)
                        .ok_or_else(|| format!("fill: no frame {kind}.{name}"))?;
                    v.push((f, None));
                }
            }
            v
        }
    };
    let mut edits: Vec<Edit> = Vec::new();
    let mut push = |e: Edit| {
        if !edits
            .iter()
            .any(|o| o.file == e.file && o.table == e.table && o.key == e.key)
        {
            edits.push(e);
        }
    };
    for (f, only_template) in chosen {
        for (key, value) in &f.keys {
            let top = key.split('.').next().unwrap_or(key);
            // A key goes into the template when the frame takes the whole field from it and
            // every frame that does gets the same default: one value there fills them all.
            let into_template = f.template.filter(|t| {
                !f.sets(top)
                    && all
                        .iter()
                        .filter(|o| o.template == Some(*t) && !o.sets(top))
                        .all(|o| o.default_of(key) == Some(value))
            });
            // A frame that takes the field from its template and sets none of it would, by a key
            // of its own, replace the template's whole field: refuse rather than change it.
            if into_template.is_none()
                && let Some(t) = f.template
                && !f.sets(top)
                && merged_frame(c, "template", t).is_some_and(|tt| tt.contains_key(top))
            {
                return Err(format!(
                    "fill: {}.{}: {key}: the template {t} sets part of {top} and the frames \
                     using it need different defaults for it; fill it by hand",
                    f.kind, f.name
                ));
            }
            let (kind, name) = match into_template {
                Some(t) => ("template", t),
                None => (f.kind, f.name),
            };
            if only_template.is_some_and(|t| into_template != Some(t)) {
                continue;
            }
            push(Edit {
                file: file_for(&c.provenance, targets.last, kind, name),
                table: vec![kind.to_owned(), name.to_owned()],
                key: key.clone(),
                value: value.clone(),
            });
        }
    }
    if let Some((path, raw)) = targets.policy {
        let rules = raw.get("rule").and_then(TomlValue::as_array);
        for (i, rule) in rules.into_iter().flatten().enumerate() {
            let Some(rule) = rule.as_table() else {
                continue;
            };
            for (key, value) in POLICY_KEYS {
                if !rule.contains_key(key) {
                    push(Edit {
                        file: path.to_path_buf(),
                        table: vec!["rule".into(), i.to_string()],
                        key: key.into(),
                        value: value.into(),
                    });
                }
            }
        }
    }
    Ok(edits)
}

/// A table being edited: a standard (or dotted) table or an inline one.
enum Slot<'a> {
    Std(&'a mut Table),
    Inline(&'a mut InlineTable),
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// The largest table position in `t` and below.
fn max_position(t: &Table) -> isize {
    let mut most = t.position().unwrap_or(0);
    for (_, item) in t {
        match item {
            Item::Table(sub) => most = most.max(max_position(sub)),
            Item::ArrayOfTables(tables) => {
                for sub in tables {
                    most = most.max(max_position(sub));
                }
            }
            _ => {}
        }
    }
    most
}

/// The table at `path` in `root`, created when absent (the last step as a table with a header
/// at the end of the file, the steps above it as implicit tables).
fn table_at<'a>(
    root: &'a mut Table,
    path: &[String],
    next: &mut isize,
) -> Result<Slot<'a>, String> {
    let mut slot = Slot::Std(root);
    let mut step = 0;
    while step < path.len() {
        let seg = path[step].as_str();
        let is_last = step + 1 == path.len();
        let index = path.get(step + 1).and_then(|s| s.parse::<usize>().ok());
        slot = match slot {
            Slot::Std(table) => {
                if !table.contains_key(seg) {
                    let mut fresh = Table::new();
                    if is_last {
                        *next += 1;
                        fresh.set_position(Some(*next));
                    } else {
                        fresh.set_implicit(true);
                    }
                    table.insert(seg, Item::Table(fresh));
                }
                match (table.get_mut(seg), index) {
                    (Some(Item::ArrayOfTables(tables)), Some(n)) => {
                        step += 1;
                        let absent = || format!("{seg}[{n}]: absent");
                        Slot::Std(tables.get_mut(n).ok_or_else(absent)?)
                    }
                    (Some(Item::Value(Value::Array(values))), Some(n)) => {
                        step += 1;
                        let element = values
                            .get_mut(n)
                            .ok_or_else(|| format!("{seg}[{n}]: absent"))?;
                        Slot::Inline(
                            element
                                .as_inline_table_mut()
                                .ok_or_else(|| format!("{seg}[{n}]: not a table"))?,
                        )
                    }
                    (Some(Item::Table(sub)), _) => Slot::Std(sub),
                    (Some(Item::Value(Value::InlineTable(sub))), _) => Slot::Inline(sub),
                    _ => return Err(format!("{seg}: not a table")),
                }
            }
            Slot::Inline(table) => {
                if !table.contains_key(seg) {
                    insert_inline(table, seg, Value::InlineTable(InlineTable::new()));
                }
                match table.get_mut(seg) {
                    Some(Value::InlineTable(sub)) => Slot::Inline(sub),
                    _ => return Err(format!("{seg}: not a table")),
                }
            }
        };
        step += 1;
    }
    Ok(slot)
}

/// Insert `key = value` at the end of inline table `t`, moving the space before `}` from the
/// last value to the new one so the braces keep their look.
fn insert_inline(t: &mut InlineTable, key: &str, mut value: Value) {
    let trailing = t.iter_mut().last().map_or_else(
        || " ".to_owned(),
        |(_, last)| {
            let decor = last.decor_mut();
            let space = decor
                .suffix()
                .and_then(|s| s.as_str())
                .unwrap_or(" ")
                .to_owned();
            decor.set_suffix("");
            space
        },
    );
    value.decor_mut().set_prefix(" ");
    value.decor_mut().set_suffix(trailing);
    t.insert(key, value);
}

/// Insert the dotted `segs` = `value` into `slot`: into a nested table that exists (standard,
/// dotted or inline), else as a dotted key. Returns `false` when the key is already there.
fn put(slot: Slot, segs: &[&str], value: Value) -> Result<bool, String> {
    let (first, rest) = segs.split_first().ok_or("an empty key")?;
    match slot {
        Slot::Std(t) => {
            if rest.is_empty() {
                if t.contains_key(first) {
                    return Ok(false);
                }
                let mut value = value;
                value.decor_mut().set_prefix(" ");
                value.decor_mut().set_suffix(COMMENT);
                let key = Key::new(*first).with_leaf_decor(Decor::new(INDENT, " "));
                t.insert_formatted(&key, Item::Value(value));
                return Ok(true);
            }
            if !t.contains_key(first) {
                let mut dotted = Table::new();
                dotted.set_dotted(true);
                t.insert(first, Item::Table(dotted));
            }
            match t.get_mut(first) {
                Some(Item::Table(sub)) => put(Slot::Std(sub), rest, value),
                Some(Item::Value(Value::InlineTable(sub))) => put(Slot::Inline(sub), rest, value),
                _ => Err(format!("{first}: not a table")),
            }
        }
        Slot::Inline(t) => {
            if rest.is_empty() {
                if t.contains_key(first) {
                    return Ok(false);
                }
                insert_inline(t, first, value);
                return Ok(true);
            }
            if !t.contains_key(first) {
                insert_inline(t, first, Value::InlineTable(InlineTable::new()));
            }
            match t.get_mut(first) {
                Some(Value::InlineTable(sub)) => put(Slot::Inline(sub), rest, value),
                _ => Err(format!("{first}: not a table")),
            }
        }
    }
}

/// One file to rewrite: its text before and after, and its metadata when it exists.
struct Rewrite {
    path: PathBuf,
    old: String,
    new: String,
    meta: Option<Metadata>,
    keys: usize,
}

fn rewrite(path: &Path, edits: &[&Edit]) -> io::Result<Rewrite> {
    let ctx = |m: String| invalid(format!("{}: {m}", path.display()));
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => return Err(ctx("is a symbolic link".into())),
        Ok(m) if !m.is_file() => return Err(ctx("is not a regular file".into())),
        Ok(m) => Some(m),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let old = match meta {
        Some(_) => std::fs::read_to_string(path)?,
        None => String::new(),
    };
    let mut doc: DocumentMut = old.parse().map_err(|e| ctx(format!("{e}")))?;
    if doc.to_string() != old {
        let why = if old.contains('\r') {
            "it has CRLF line ends"
        } else if !old.is_empty() && !old.ends_with('\n') {
            "it does not end in a newline"
        } else {
            "keys of one dotted table apart?"
        };
        return Err(ctx(format!(
            "toml_edit cannot write this file back byte for byte ({why}); fill it by hand"
        )));
    }
    let mut next = max_position(doc.as_table());
    let mut keys = 0;
    for e in edits {
        let value: Value = e
            .value
            .parse()
            .map_err(|err| ctx(format!("{}: {err}", e.key)))?;
        let slot = table_at(doc.as_table_mut(), &e.table, &mut next).map_err(ctx)?;
        let segs: Vec<&str> = e.key.split('.').collect();
        if put(slot, &segs, value).map_err(ctx)? {
            keys += 1;
        }
    }
    Ok(Rewrite {
        path: path.to_path_buf(),
        new: doc.to_string(),
        old,
        meta,
        keys,
    })
}

/// What [`apply`] did: the keys filled and the files they went into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Applied {
    /// The keys inserted.
    pub keys: usize,
    /// The files with at least one key inserted.
    pub files: usize,
}

/// Make `edits`, file by file; with `dry_run` print the unified diff of each file to `out`
/// instead of writing. Every file is edited, and then every new text is written to its
/// temporary file with the old file's owner and mode, before any is renamed over its file: a
/// file that cannot be edited, or whose owner or mode cannot be kept, stops the run with no file
/// changed. A file whose edits insert nothing is not written.
///
/// # Errors
/// A file that is a symbolic link, does not parse, would not keep its bytes, or fails to
/// write.
pub fn apply(edits: &[Edit], dry_run: bool, out: &mut dyn Write) -> io::Result<Applied> {
    let mut by_file: Vec<(&Path, Vec<&Edit>)> = Vec::new();
    for e in edits {
        match by_file.iter_mut().find(|(f, _)| *f == e.file) {
            Some((_, v)) => v.push(e),
            None => by_file.push((&e.file, vec![e])),
        }
    }
    let rewrites = by_file
        .iter()
        .map(|(f, es)| rewrite(f, es))
        .collect::<io::Result<Vec<_>>>()?;
    let changed: Vec<&Rewrite> = rewrites.iter().filter(|r| r.keys > 0).collect();
    let done = Applied {
        keys: changed.iter().map(|r| r.keys).sum(),
        files: changed.len(),
    };
    if dry_run {
        for r in &changed {
            out.write_all(diff(&r.path, r.meta.is_some(), &r.old, &r.new).as_bytes())?;
        }
        return Ok(done);
    }
    let mut staged = Vec::new();
    for r in &changed {
        match stage(&r.path, r.new.as_bytes(), r.meta.as_ref()) {
            Ok(s) => staged.push(s),
            Err(e) => {
                for s in &staged {
                    let _ = std::fs::remove_file(&s.tmp);
                }
                return Err(e);
            }
        }
    }
    let mut result = Ok(());
    for s in &staged {
        if result.is_ok() {
            result = s.commit();
        }
        if result.is_err() {
            let _ = std::fs::remove_file(&s.tmp);
        }
    }
    result.map(|()| done)
}

/// A new text written and synced to a temporary file beside its file, not yet renamed over it.
struct Staged {
    tmp: PathBuf,
    path: PathBuf,
    dir: PathBuf,
}

impl Staged {
    /// Rename the temporary file over the file, then sync the directory.
    fn commit(&self) -> io::Result<()> {
        std::fs::rename(&self.tmp, &self.path)
            .and_then(|()| File::open(&self.dir)?.sync_all())
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", self.path.display())))
    }
}

/// Write `bytes` to a new temporary file beside `path` (creating the directory for a new file),
/// with the mode and owner of `meta` (the old file's; 0644 and the caller's for a new file),
/// synced. Nothing already at the temporary name is followed or removed.
fn stage(path: &Path, bytes: &[u8], meta: Option<&Metadata>) -> io::Result<Staged> {
    let at = |e: io::Error| io::Error::new(e.kind(), format!("{}: {e}", path.display()));
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    if meta.is_none() && !dir.is_dir() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(dir)
            .map_err(at)?;
    }
    let name = path
        .file_name()
        .ok_or_else(|| invalid(format!("{}: no file name", path.display())))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(".qctl-fill-{}", std::process::id()));
    let tmp = dir.join(tmp_name);
    let mode = meta.map_or(0o644, |m| m.permissions().mode() & 0o7777);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode & 0o777)
        .open(&tmp)
        .map_err(at)?;
    let result = (|| {
        if let Some(m) = meta {
            std::os::unix::fs::fchown(&f, Some(m.uid()), Some(m.gid()))?;
        }
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        f.write_all(bytes)?;
        f.sync_all()
    })();
    match result {
        Ok(()) => Ok(Staged {
            tmp,
            path: path.to_path_buf(),
            dir: dir.to_path_buf(),
        }),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(at(e))
        }
    }
}

/// One step of a line diff.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Same,
    Del,
    Add,
}

/// The steps from `before` to `after` by their longest common subsequence: each step with its
/// line index in both.
fn line_ops(before: &[&str], after: &[&str]) -> Vec<(Op, usize, usize)> {
    let (na, nb) = (before.len(), after.len());
    // lcs[x][y]: the length of the common subsequence of before[x..] and after[y..].
    let mut lcs = vec![vec![0usize; nb + 1]; na + 1];
    for x in (0..na).rev() {
        for y in (0..nb).rev() {
            lcs[x][y] = if before[x] == after[y] {
                lcs[x + 1][y + 1] + 1
            } else {
                lcs[x + 1][y].max(lcs[x][y + 1])
            };
        }
    }
    let (mut x, mut y, mut ops) = (0, 0, Vec::new());
    while x < na || y < nb {
        if x < na && y < nb && before[x] == after[y] {
            ops.push((Op::Same, x, y));
            x += 1;
            y += 1;
        } else if x < na && (y == nb || lcs[x + 1][y] >= lcs[x][y + 1]) {
            ops.push((Op::Del, x, y));
            x += 1;
        } else {
            ops.push((Op::Add, x, y));
            y += 1;
        }
    }
    ops
}

/// The unified diff (three lines of context) of `old` to `new`, as file `path` (`existed`
/// false: a new file, `--- /dev/null`).
fn diff(path: &Path, existed: bool, old: &str, new: &str) -> String {
    const CONTEXT: usize = 3;
    let before: Vec<&str> = old.lines().collect();
    let after: Vec<&str> = new.lines().collect();
    let ops = line_ops(&before, &after);
    let shown = path.display();
    let mut text = if existed {
        format!("--- {shown}\n+++ {shown}\n")
    } else {
        format!("--- /dev/null\n+++ {shown}\n")
    };
    let changes: Vec<usize> = (0..ops.len()).filter(|&k| ops[k].0 != Op::Same).collect();
    let mut k = 0;
    while k < changes.len() {
        let start = changes[k].saturating_sub(CONTEXT);
        let mut end = changes[k];
        while k < changes.len() && changes[k] <= end + 2 * CONTEXT + 1 {
            end = changes[k];
            k += 1;
        }
        let end = (end + CONTEXT + 1).min(ops.len());
        let hunk = &ops[start..end];
        let count = |op: Op| {
            hunk.iter()
                .filter(|(o, _, _)| *o == Op::Same || *o == op)
                .count()
        };
        let (n_old, n_new) = (count(Op::Del), count(Op::Add));
        let from = |at: usize, n: usize| if n == 0 { at } else { at + 1 };
        let _ = writeln!(
            text,
            "@@ -{},{n_old} +{},{n_new} @@",
            from(hunk[0].1, n_old),
            from(hunk[0].2, n_new)
        );
        for &(op, ia, ib) in hunk {
            let (sign, line) = match op {
                Op::Same => (' ', before[ia]),
                Op::Del => ('-', before[ia]),
                Op::Add => ('+', after[ib]),
            };
            text.push(sign);
            text.push_str(line);
            text.push('\n');
        }
    }
    text
}

/// One target of the command line.
enum Target {
    All,
    Policy,
    Frame(String, String),
}

fn target(t: &str) -> Option<Target> {
    match t {
        "all" => return Some(Target::All),
        "policy" => return Some(Target::Policy),
        _ => {}
    }
    let (kind, name) = t.split_once('.')?;
    // An instance is not a table of its own: it is filled through its frame.
    let name = name.split_once('@').map_or(name, |(f, _)| f);
    (KINDS.contains(&kind) && !name.is_empty())
        .then(|| Target::Frame(kind.to_owned(), name.to_owned()))
}

/// Run `qctl fill`; returns the exit code.
pub fn run(opts: &FillOpts, defaults: &Defaults, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let (mut all, mut policy_wanted, mut named) = (false, false, Vec::new());
    for t in &opts.targets {
        match target(t) {
            Some(Target::All) => all = true,
            Some(Target::Policy) => policy_wanted = true,
            Some(Target::Frame(k, n)) => named.push((k, n)),
            None => {
                let _ = writeln!(
                    err,
                    "qctl: fill: '{t}' is not <kind>.<name>, policy or all\nTry 'qctl --help'."
                );
                return 2;
            }
        }
    }
    let input = match checked_input(&opts.layers, &opts.policy, defaults, err) {
        Ok(i) => i,
        Err(code) => return code,
    };
    let last = match input.layers.as_slice() {
        [_, .., top] => top.clone(),
        _ if opts.layers.is_empty() => LayerInput {
            name: "etc".into(),
            dir: defaults.etc.clone(),
        },
        _ => {
            let _ = writeln!(
                err,
                "qctl: fill: one layer given: fill writes into the last layer above the \
                 lowest, never into the lowest (the package manager's)"
            );
            return 1;
        }
    };
    // An absent default etc layer is no root of the ownership check: as root, check where it
    // would be created before anything is.
    if defaults.euid == 0
        && !last.dir.is_dir()
        && let Err(r) = owner::creatable(&last.dir)
    {
        let _ = writeln!(err, "{r}");
        return 1;
    }
    let compiled = match compile(&input) {
        Ok(c) => c,
        Err(errors) => {
            for e in &errors {
                let _ = writeln!(err, "{}", report::error_line(e));
            }
            return 1;
        }
    };
    for w in &compiled.warnings {
        let _ = writeln!(err, "{}", report::warning_line(w));
    }
    let raw = match (&input.policy, policy_wanted || all) {
        (Some(p), true) => match std::fs::read_to_string(p)
            .map_err(|e| e.to_string())
            .and_then(|s| s.parse::<toml::Table>().map_err(|e| e.to_string()))
        {
            Ok(t) => Some((p.as_path(), t)),
            Err(e) => {
                let _ = writeln!(err, "qctl: {}: {e}", p.display());
                return 1;
            }
        },
        (None, _) if policy_wanted => {
            let why = match opts.policy {
                PolicyChoice::None => "--no-policy was given",
                _ => "there is no policy file",
            };
            let _ = writeln!(err, "qctl: fill policy: {why}");
            return 1;
        }
        _ => None,
    };
    let targets = Targets {
        last: &last,
        frames: if all {
            Frames::All
        } else {
            Frames::Some(named)
        },
        policy: raw.as_ref().map(|(p, t)| (*p, t)),
    };
    let edits = match plan(&compiled, &targets) {
        Ok(e) => e,
        Err(m) => {
            let _ = writeln!(err, "qctl: {m}");
            return 1;
        }
    };
    if edits.is_empty() {
        let _ = writeln!(out, "qctl: fill: nothing to fill");
        return 0;
    }
    match apply(&edits, opts.dry_run, out) {
        Ok(done) if !opts.dry_run => {
            let _ = writeln!(
                out,
                "qctl: fill: {} keys filled in {} files",
                done.keys, done.files
            );
            0
        }
        Ok(_) => 0,
        Err(e) => {
            let _ = writeln!(err, "qctl: fill: {e}");
            1
        }
    }
}
