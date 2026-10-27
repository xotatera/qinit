// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The fmt gate's migration switch.

/// `Some(reason)` keeps fmt registered but skipping (e.g. while a mass
/// reformat is pending). `tests/fmt_gate.rs` asserts `None`, so a skip cannot
/// outlive its migration unnoticed.
pub const BLOCKED: Option<&str> = None;

/// Whether verusfmt should see `text`: it invokes `verus!` (a path-qualified
/// `vstd::prelude::verus!` included, and one inside another macro's body),
/// read from the parsed source, so a mention in a comment or a string does
/// not count. A file the parser cannot read whole counts when it names the
/// macro anywhere (fail closed).
#[must_use]
pub fn invokes_verus(text: &str) -> bool {
    verus_starts(text).map_or_else(|| text.contains("verus!"), |starts| !starts.is_empty())
}

/// The 1-based lines where an indented `verus!` invocation starts. verusfmt
/// lays a block out from column 0 and rustfmt re-indents it, so no indented
/// block passes both: the gate asks for `verus!` at the top level.
/// A file the parser cannot read whole falls back to a line rule (fail
/// closed).
#[must_use]
pub fn indented_verus(text: &str) -> Vec<usize> {
    let Some(starts) = verus_starts(text) else {
        return indented_lines(text);
    };
    starts
        .into_iter()
        .filter(|point| point.column > 0)
        .map(|point| point.row + 1)
        .collect()
}

/// The line rule for a file that does not parse: an indented line starting
/// with `verus!` or a path ending in `::verus!`.
fn indented_lines(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| {
            let body = l.trim_start();
            body.len() < l.len()
                && (body.starts_with("verus!")
                    || body.split_once("::verus!").is_some_and(|(path, _)| {
                        path.chars()
                            .all(|c| c.is_alphanumeric() || c == '_' || c == ':')
                    }))
        })
        .map(|(i, _)| i + 1)
        .collect()
}

/// Where each `verus!` macro invocation starts, from tree-sitter's Rust
/// grammar: a parsed invocation, or inside another macro's token tree the
/// identifier `verus` followed by `!`. `None` when the source does not parse
/// cleanly.
fn verus_starts(text: &str) -> Option<Vec<tree_sitter::Point>> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(text, None)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }
    let mut starts = Vec::new();
    let mut cursor = root.walk();
    loop {
        let node = cursor.node();
        if (node.kind() == "macro_invocation" && names_verus(node, text))
            || bang_in_token_tree(node, text)
        {
            starts.push(node.start_position());
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return Some(starts);
            }
        }
    }
}

/// Whether `node` is the identifier `verus` followed by `!` inside a token
/// tree: a `verus!` call within another macro's body.
fn bang_in_token_tree(node: tree_sitter::Node<'_>, text: &str) -> bool {
    node.kind() == "identifier"
        && node.parent().is_some_and(|p| p.kind() == "token_tree")
        && is_verus(node, text)
        && node.next_sibling().is_some_and(|n| n.kind() == "!")
}

/// Whether a `macro_invocation` node calls `verus` (bare or path-qualified).
fn names_verus(node: tree_sitter::Node<'_>, text: &str) -> bool {
    let Some(name) = node.child_by_field_name("macro") else {
        return false;
    };
    let last = if name.kind() == "scoped_identifier" {
        name.child_by_field_name("name")
    } else {
        Some(name)
    };
    last.is_some_and(|n| is_verus(n, text))
}

/// Whether an identifier node is `verus` (the raw form `r#verus` included).
fn is_verus(node: tree_sitter::Node<'_>, text: &str) -> bool {
    node.utf8_text(text.as_bytes())
        .is_ok_and(|name| name.strip_prefix("r#").unwrap_or(name) == "verus")
}

/// What the fmt gate tells someone without verusfmt whose tree needs it.
pub const VERUSFMT_HINT: &str = "verusfmt is not on PATH: `cargo install --locked verusfmt` (it formats the code inside `verus!`, which rustfmt leaves alone)";
