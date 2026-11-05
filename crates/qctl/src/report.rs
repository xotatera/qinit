// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Error and warning lines: `<file>:<line>: <key>: <message>`.
use qinit_frames::error::{Error, Warning};
use std::path::Path;
use toml_edit::{Document, Item};

/// The 1-based line of the key at the dotted path `key` in `file`, or `None` when the file
/// cannot be read or parsed or the path is not there.
#[must_use]
pub fn location(file: &Path, key: &str) -> Option<usize> {
    let text = std::fs::read_to_string(file).ok()?;
    let doc = Document::parse(text.as_str()).ok()?;
    let offset = key_offset(doc.as_item(), key)?;
    Some(text[..offset.min(text.len())].matches('\n').count() + 1)
}

/// Follow the dotted path from `root`; a segment may itself hold dots only as written, so the
/// path is tried split at every dot.
fn key_offset(root: &Item, path: &str) -> Option<usize> {
    if path.is_empty() {
        return None;
    }
    walk(root, path)
}

fn walk(item: &Item, rest: &str) -> Option<usize> {
    let mut starts = vec![rest.len()];
    starts.extend(rest.match_indices('.').map(|(i, _)| i));
    for end in starts {
        let (head, tail) = (&rest[..end], rest.get(end + 1..).unwrap_or(""));
        let Some(table) = item.as_table_like() else {
            continue;
        };
        let Some((k, child)) = table.get_key_value(head) else {
            continue;
        };
        if end == rest.len() {
            return k.span().or_else(|| child.span()).map(|s| s.start);
        }
        if let Some(found) = walk(child, tail) {
            return Some(found);
        }
    }
    None
}

/// One compile error as a line.
#[must_use]
pub fn error_line(e: &Error) -> String {
    let line = match (&e.file, e.key.is_empty()) {
        (Some(f), false) => location(f, &e.key),
        _ => None,
    };
    match (&e.file, e.key.is_empty(), line) {
        (Some(f), false, Some(n)) => format!("{}:{n}: {}: {}", f.display(), e.key, e.detail),
        (Some(f), false, None) => format!("{}: {}: {}", f.display(), e.key, e.detail),
        (Some(f), true, _) => format!("{}: {}", f.display(), e.detail),
        (None, false, _) => format!("{}: {}", e.key, e.detail),
        (None, true, _) => e.detail.clone(),
    }
}

/// One compile warning as a line.
#[must_use]
pub fn warning_line(w: &Warning) -> String {
    if w.key.is_empty() {
        format!("warning: {}", w.detail)
    } else {
        format!("warning: {}: {}", w.key, w.detail)
    }
}
