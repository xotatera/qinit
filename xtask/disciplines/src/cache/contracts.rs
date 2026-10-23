// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The spine's interface for contract-keyed proofs (`spine = "contracts"`):
//! a source file with the bodies of functions that carry a Kani contract
//! (`requires`, `ensures`, `modifies`, also inside `cfg_attr`) replaced by
//! `{}`. A tooth's harness stubs those functions with `stub_verified`, so
//! only their contracts can change its result.
use std::os::unix::ffi::OsStrExt;

use tree_sitter::{Node, Parser};

const CONTRACT_ATTRS: &[&str] = &["kani::requires", "kani::ensures", "kani::modifies"];

/// `// <path>` and `source` with contracted bodies erased.
///
/// # Errors
/// When the grammar cannot be loaded or the parser gives up.
pub fn interface_text(path: &str, source: &str) -> Result<String, String> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .map_err(|e| format!("tree-sitter-rust: {e}"))?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| format!("{path}: parse failed"))?;
    let mut erase = Vec::new();
    collect(tree.root_node(), source.as_bytes(), &mut erase);
    erase.sort_unstable();
    let mut out = format!("// {path}\n");
    let mut at = 0;
    for (start, end) in erase {
        if start < at {
            continue;
        }
        out.push_str(&source[at..start]);
        out.push_str("{}");
        at = end;
    }
    out.push_str(&source[at..]);
    Ok(out)
}

/// Byte ranges of the bodies of contracted functions under `node`.
fn collect(node: Node, src: &[u8], out: &mut Vec<(usize, usize)>) {
    let mut cursor = node.walk();
    let children: Vec<Node> = node.children(&mut cursor).collect();
    for (i, child) in children.iter().enumerate() {
        if child.kind() == "function_item"
            && contracted(&children[..i], src)
            && let Some(body) = child.child_by_field_name("body")
        {
            out.push((body.start_byte(), body.end_byte()));
        }
        collect(*child, src, out);
    }
}

/// Whether the attributes directly before an item (comments between them
/// skipped) include a Kani contract.
fn contracted(before: &[Node], src: &[u8]) -> bool {
    before
        .iter()
        .rev()
        .take_while(|n| {
            matches!(
                n.kind(),
                "attribute_item" | "line_comment" | "block_comment"
            )
        })
        .filter(|n| n.kind() == "attribute_item")
        .any(|n| {
            let text: String = n
                .utf8_text(src)
                .unwrap_or("")
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let body = text.trim_start_matches('#').trim_start_matches('[');
            is_contract(body.strip_suffix(']').unwrap_or(body))
        })
}

/// Whether one attribute's content (whitespace removed) is a Kani
/// contract: `kani::ensures(…)`, or one inside `cfg_attr(pred, …)` at any
/// depth. Text that merely mentions a contract (`doc = "…"`) is not.
fn is_contract(content: &str) -> bool {
    if CONTRACT_ATTRS.iter().any(|a| {
        content
            .strip_prefix(a)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('('))
    }) {
        return true;
    }
    content
        .strip_prefix("cfg_attr(")
        .and_then(|c| c.strip_suffix(')'))
        .is_some_and(|inner| top_level_items(inner).into_iter().skip(1).any(is_contract))
}

/// `s` split at commas outside brackets and strings.
fn top_level_items(s: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let (mut depth, mut quoted, mut escaped, mut start) = (0usize, false, false, 0);
    for (i, c) in s.char_indices() {
        if quoted {
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => quoted = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => quoted = true,
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                items.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    items.push(&s[start..]);
    items
}

/// The `.rs` files of the spine crate in `dir` (relative to `root`), as
/// git sees them: tracked and untracked but not ignored, symlinks included
/// (read through), files deleted from the work tree left out. Sorted.
///
/// # Errors
/// When git cannot list the directory.
pub fn spine_sources(root: &std::path::Path, dir: &str) -> Result<Vec<std::path::PathBuf>, String> {
    let out = crate::git::command()
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            dir,
        ])
        .current_dir(root)
        .output()
        .map_err(|e| format!("git ls-files: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git ls-files {dir}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let mut files: Vec<std::path::PathBuf> = out
        .stdout
        .split(|b| *b == 0)
        .filter(|p| p.ends_with(b".rs"))
        .map(|p| root.join(std::ffi::OsStr::from_bytes(p)))
        .filter(|p| p.exists())
        .collect();
    files.sort();
    files.dedup();
    Ok(files)
}
