// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Provenance: which layer and file set each key of each frame.
//!
//! A key is structured, `(kind, name, path)`, never a dotted string: a frame name may hold `.`,
//! so `worker.a.b.exec` alone cannot tell frame `a.b` from a key `b` of frame `a`. Keys are
//! recorded as the merge sets them: a table key, or a whole list (lists change as a unit).
//! Expansion adds the keys a frame inherits from its template (marked with the template's
//! name) and copies an instanced frame's keys to each instance.
use crate::error::Error;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// One step of a key path inside a frame: a table key or a list index.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Seg {
    /// A table key.
    Key(String),
    /// An index into a list.
    Index(usize),
}

/// A key of one frame: the frame's kind word, its name and the path inside it.
///
/// The empty path is the frame itself; it records the layer and file that defined the frame.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FrameKey {
    /// `worker`, `forager`, `brood` or `template`.
    pub kind: String,
    /// The frame name (an instance's full `<name>@<instance>` after expansion).
    pub name: String,
    /// The path inside the frame; empty for the frame itself.
    pub path: Vec<Seg>,
}

impl FrameKey {
    /// The key `keys` (table keys only) of frame `kind.name`.
    #[must_use]
    pub fn new(kind: &str, name: &str, keys: &[&str]) -> Self {
        Self {
            kind: kind.to_owned(),
            name: name.to_owned(),
            path: keys.iter().map(|k| Seg::Key((*k).to_owned())).collect(),
        }
    }

    fn at(kind: &str, name: &str, path: &[Seg]) -> Self {
        Self {
            kind: kind.to_owned(),
            name: name.to_owned(),
            path: path.to_vec(),
        }
    }
}

/// Where a key was set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    /// The layer that set the key last.
    pub layer: String,
    /// The file of that layer that set it.
    pub file: PathBuf,
    /// When the frame inherited the key from a template: that template's name. `layer` and
    /// `file` then name where the template set it.
    pub template: Option<String>,
}

/// Every recorded key and where it was set.
pub type Provenance = BTreeMap<FrameKey, Origin>;

/// The path of a key in frame key syntax, such as `restart.policy` or `deps[0].edges[1].to`,
/// with or without a leading `.`. Parsing stops at the first malformed step; the steps before
/// it are kept.
#[must_use]
pub fn parse_path(s: &str) -> Vec<Seg> {
    let mut out = Vec::new();
    let mut rest = s.strip_prefix('.').unwrap_or(s);
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix('[') {
            let Some((digits, after)) = r.split_once(']') else {
                break;
            };
            let Ok(i) = digits.parse::<usize>() else {
                break;
            };
            out.push(Seg::Index(i));
            rest = after.strip_prefix('.').unwrap_or(after);
            continue;
        }
        let end = rest.find(['.', '[']).unwrap_or(rest.len());
        if end == 0 {
            break;
        }
        out.push(Seg::Key(rest[..end].to_owned()));
        rest = &rest[end..];
        rest = rest.strip_prefix('.').unwrap_or(rest);
    }
    out
}

/// The origin of `path` in frame `kind.name`, or of its nearest enclosing recorded key, down to
/// the frame itself.
#[must_use]
pub fn nearest<'a>(
    prov: &'a Provenance,
    kind: &str,
    name: &str,
    path: &[Seg],
) -> Option<&'a Origin> {
    (0..=path.len())
        .rev()
        .find_map(|n| prov.get(&FrameKey::at(kind, name, &path[..n])))
}

/// The origin of a value shown in the dump: the key itself, or an enclosing list (or list
/// element) it sits in. A key no layer set, such as a default inside a table a layer did set,
/// has none.
#[must_use]
pub fn set_by<'a>(
    prov: &'a Provenance,
    kind: &str,
    name: &str,
    path: &[Seg],
) -> Option<&'a Origin> {
    let get = |p: &[Seg]| prov.get(&FrameKey::at(kind, name, p));
    get(path).or_else(|| {
        (0..path.len())
            .rev()
            .filter(|&j| matches!(path[j], Seg::Index(_)))
            .find_map(|j| get(&path[..=j]).or_else(|| get(&path[..j])))
    })
}

/// Attach to `e` the layer and file behind its key when the key lies in frame `kind.name`
/// (the frame's own key, or a path below it); any other key is left alone.
pub(crate) fn locate(prov: &Provenance, kind: &str, name: &str, e: &mut Error) {
    let Some(rest) = e
        .key
        .strip_prefix(kind)
        .and_then(|r| r.strip_prefix('.'))
        .and_then(|r| r.strip_prefix(name))
        .filter(|r| r.is_empty() || r.starts_with(['.', '[']))
    else {
        return;
    };
    if let Some(o) = nearest(prov, kind, name, &parse_path(rest)) {
        e.layer = Some(o.layer.clone());
        e.file = Some(o.file.clone());
    }
}

/// [`locate`] every error of `errs`.
pub(crate) fn locate_all(prov: &Provenance, kind: &str, name: &str, errs: &mut [Error]) {
    for e in errs {
        locate(prov, kind, name, e);
    }
}

#[cfg(test)]
mod tests {
    use super::{Seg, parse_path};

    #[test]
    fn paths_parse_into_keys_and_indices() {
        let k = |s: &str| Seg::Key(s.to_owned());
        assert_eq!(parse_path(""), Vec::<Seg>::new());
        assert_eq!(parse_path(".exec"), vec![k("exec")]);
        assert_eq!(
            parse_path("restart.policy"),
            vec![k("restart"), k("policy")]
        );
        assert_eq!(
            parse_path(".deps[0].edges[12].to"),
            vec![
                k("deps"),
                Seg::Index(0),
                k("edges"),
                Seg::Index(12),
                k("to")
            ]
        );
        assert_eq!(parse_path("deps[x].group"), vec![k("deps")]);
        assert_eq!(parse_path("a..b"), vec![k("a")]);
    }
}
