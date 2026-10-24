// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Function extraction and normalisation for the duplication gate.
//!
//! Each function body gives two token streams:
//! - `strict` (gate tier): comments dropped, local bindings renamed by first
//!   appearance (`$0`, `$1`, …), string literals replaced by `"S"`. Field,
//!   function, type and macro names, numbers and chars are kept, so `self.w`
//!   and `self.h`, or presets that differ in values, stay distinct.
//! - `loose` (advisory tier): additionally every name is renamed and every
//!   number and char replaced.
use std::collections::{HashMap, HashSet};

use tree_sitter::{Node, Parser};

/// One function that has a body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    /// `path::Scope::name`, unique per file (`~2`, `~3` for repeats). Keys
    /// carry no line numbers, so a baseline does not churn on edits above.
    pub key: String,
    /// 1-based line of the `fn`, for messages only.
    pub line: usize,
    pub is_test: bool,
    pub strict: Vec<String>,
    pub loose: Vec<String>,
}

/// # Errors
/// When the grammar cannot be loaded or the parser gives up.
pub fn functions(path: &str, source: &str) -> Result<Vec<Function>, String> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .map_err(|e| format!("tree-sitter-rust: {e}"))?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| format!("{path}: parse failed"))?;
    let ctx = Ctx {
        src: source.as_bytes(),
        path,
    };
    let file_is_test = path
        .split('/')
        .any(|c| c == "tests" || c == "benches" || c == "tests.rs")
        || has_inner_test_attr(&ctx, tree.root_node());
    let mut out = Vec::new();
    collect(
        &ctx,
        tree.root_node(),
        &mut Vec::new(),
        file_is_test,
        &mut out,
    );
    disambiguate(&mut out);
    Ok(out)
}

struct Ctx<'a> {
    src: &'a [u8],
    path: &'a str,
}

impl Ctx<'_> {
    fn text(&self, node: Node) -> &str {
        node.utf8_text(self.src).unwrap_or("")
    }
}

fn collect(ctx: &Ctx, node: Node, scope: &mut Vec<String>, in_test: bool, out: &mut Vec<Function>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let testing = in_test || preceded_by_test_attr(ctx, child);
        match child.kind() {
            "function_item" => out.extend(function(ctx, child, scope, testing)),
            "mod_item" | "impl_item" | "trait_item" => {
                if let Some(body) = child.child_by_field_name("body") {
                    scope.push(scope_name(ctx, child));
                    collect(ctx, body, scope, testing, out);
                    scope.pop();
                }
            }
            _ => collect(ctx, child, scope, testing, out),
        }
    }
}

fn scope_name(ctx: &Ctx, node: Node) -> String {
    let field = |name| node.child_by_field_name(name).map(|n| squash(ctx.text(n)));
    match node.kind() {
        "impl_item" => match (field("type"), field("trait")) {
            (Some(ty), Some(tr)) => format!("<{ty} as {tr}>"),
            (Some(ty), None) => ty,
            _ => "impl".to_string(),
        },
        _ => field("name").unwrap_or_default(),
    }
}

/// `#![cfg(test)]` at the top of a file marks the whole file as test code.
fn has_inner_test_attr(ctx: &Ctx, root: Node) -> bool {
    let mut cursor = root.walk();
    root.named_children(&mut cursor)
        .any(|n| n.kind() == "inner_attribute_item" && is_test_attr(ctx.text(n)))
}

fn squash(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn preceded_by_test_attr(ctx: &Ctx, node: Node) -> bool {
    let mut prev = node.prev_named_sibling();
    while let Some(p) = prev {
        match p.kind() {
            "attribute_item" if is_test_attr(ctx.text(p)) => return true,
            "attribute_item" | "line_comment" | "block_comment" => {}
            _ => return false,
        }
        prev = p.prev_named_sibling();
    }
    false
}

/// A test attribute: a path whose last segment is `test` or `rstest`, with
/// or without arguments (`#[test]`, `#[tokio::test(flavor = "…")]`); or a
/// `cfg` whose predicate implies `test` (see `implies_test`).
fn is_test_attr(attr: &str) -> bool {
    let tokens = attr_tokens(attr);
    let tokens: Vec<&str> = tokens.iter().map(String::as_str).collect();
    match tokens[..] {
        ["cfg", "(", ..] => implies_test(&tokens[2..]).0,
        [path] | [path, "(", ..] => matches!(path.rsplit("::").next(), Some("test" | "rstest")),
        _ => false,
    }
}

/// Paths (`a::b`, whitespace inside them ignored), `(`, `)` and `,` of an
/// attribute's text. String literals and `=` are dropped; the `#`, `!`, `[`
/// and `]` around it are not tokens.
fn attr_tokens(attr: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut chars = attr.chars();
    while let Some(c) = chars.next() {
        if c.is_alphanumeric() || c == '_' || c == ':' {
            word.push(c);
        } else if c.is_whitespace() {
            // Skipped entirely: valid cfg/test-attribute syntax never puts two
            // bare words side by side, so `tokio :: test` lexes as `tokio::test`.
        } else {
            if !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
            match c {
                '(' | ')' | ',' => out.push(c.to_string()),
                '"' => {
                    while let Some(s) = chars.next() {
                        if s == '\\' {
                            chars.next();
                        } else if s == '"' {
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}

/// Whether the predicate starting at `tokens[0]` implies `test`, and how many
/// tokens it spans. A bare `test`, or `all(…)` with one implying member; an
/// `any(…)` implies it only when every alternative does; `not(…)` never.
fn implies_test(tokens: &[&str]) -> (bool, usize) {
    let Some(&name) = tokens.first() else {
        return (false, 0);
    };
    if tokens.get(1) != Some(&"(") {
        return (name == "test", 1);
    }
    let mut results = Vec::new();
    let mut at = 2;
    while at < tokens.len() && tokens[at] != ")" {
        if tokens[at] == "," {
            at += 1;
            continue;
        }
        let (r, used) = implies_test(&tokens[at..]);
        results.push(r);
        at += used;
    }
    let verdict = match name {
        "any" => !results.is_empty() && results.iter().all(|&r| r),
        "all" => results.contains(&true),
        _ => false,
    };
    (verdict, at + 1)
}

fn function(ctx: &Ctx, node: Node, scope: &[String], is_test: bool) -> Option<Function> {
    let body = node.child_by_field_name("body")?;
    let name = ctx.text(node.child_by_field_name("name")?);
    let mut key = ctx.path.to_string();
    for s in scope {
        key.push_str("::");
        key.push_str(s);
    }
    key.push_str("::");
    key.push_str(name);
    let locals = local_bindings(ctx, node);
    Some(Function {
        key,
        line: node.start_position().row + 1,
        is_test,
        strict: tokens(ctx, body, &locals, false),
        loose: tokens(ctx, body, &locals, true),
    })
}

/// Names bound by patterns anywhere in the function: parameters, `let`,
/// `if let` / `while let`, `for`, closures, match arms (not their guards).
/// Only names starting with a lowercase letter or `_`: an uppercase
/// identifier in a pattern is an enum variant or a constant, and renaming it
/// would make `Red => …` equal to `Blue => …`.
fn local_bindings(ctx: &Ctx, func: Node) -> HashSet<String> {
    let mut names = HashSet::new();
    visit(func, &mut |n| {
        let patterns: Vec<Node> = match n.kind() {
            "parameter" | "let_declaration" | "for_expression" | "let_condition" => {
                n.child_by_field_name("pattern").into_iter().collect()
            }
            "closure_parameters" => {
                // Only the pattern part of each parameter, never its type.
                let mut c = n.walk();
                n.named_children(&mut c)
                    .filter_map(|p| {
                        if p.kind() == "parameter" {
                            p.child_by_field_name("pattern")
                        } else {
                            Some(p)
                        }
                    })
                    .collect()
            }
            "match_pattern" => {
                let guard = n.child_by_field_name("condition").map(|g| g.id());
                let mut c = n.walk();
                n.children(&mut c)
                    .filter(|ch| Some(ch.id()) != guard)
                    .collect()
            }
            _ => Vec::new(),
        };
        for p in patterns {
            visit(p, &mut |leaf| {
                if matches!(leaf.kind(), "identifier" | "shorthand_field_identifier") {
                    let t = ctx.text(leaf);
                    if t.starts_with(|c: char| c.is_lowercase() || c == '_') {
                        names.insert(t.to_string());
                    }
                }
            });
        }
    });
    names
}

fn visit<'t>(node: Node<'t>, f: &mut impl FnMut(Node<'t>)) {
    f(node);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        visit(child, f);
    }
}

fn tokens(ctx: &Ctx, body: Node, locals: &HashSet<String>, loose: bool) -> Vec<String> {
    let mut renamed = HashMap::new();
    let mut out = Vec::new();
    push_tokens(ctx, body, locals, loose, &mut renamed, &mut out);
    out
}

fn push_tokens(
    ctx: &Ctx,
    node: Node,
    locals: &HashSet<String>,
    loose: bool,
    renamed: &mut HashMap<String, String>,
    out: &mut Vec<String>,
) {
    match node.kind() {
        "line_comment" | "block_comment" => return,
        "string_literal" | "raw_string_literal" => {
            out.push("\"S\"".to_string());
            return;
        }
        _ => {}
    }
    if node.child_count() == 0 {
        let text = ctx.text(node);
        let shorthand = node.kind() == "identifier"
            && node
                .parent()
                .is_some_and(|p| p.kind() == "shorthand_field_initializer");
        if shorthand {
            // `Self { w }` means `w: w`: the field name stays, the value is a use.
            out.push(if loose {
                positional(renamed, text)
            } else {
                text.to_string()
            });
            out.push(":".to_string());
        }
        let token = match node.kind() {
            "identifier" if loose || (locals.contains(text) && is_variable_use(node)) => {
                positional(renamed, text)
            }
            "field_identifier" | "type_identifier" | "shorthand_field_identifier" if loose => {
                positional(renamed, text)
            }
            "integer_literal" | "float_literal" if loose => "N".to_string(),
            "char_literal" if loose => "C".to_string(),
            _ => text.to_string(),
        };
        out.push(token);
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        push_tokens(ctx, child, locals, loose, renamed, out);
    }
}

/// False for identifiers that are path segments, macro names, loop labels or
/// lifetimes, or, inside a macro token tree (where the grammar gives no
/// roles), field/method/path names.
fn is_variable_use(node: Node) -> bool {
    if node.parent().is_some_and(|p| {
        matches!(
            p.kind(),
            "scoped_identifier"
                | "scoped_type_identifier"
                | "macro_invocation"
                | "label"
                | "lifetime"
        )
    }) {
        return false;
    }
    let in_token_tree = node.parent().is_some_and(|p| p.kind() == "token_tree");
    if in_token_tree {
        let after_separator = node
            .prev_sibling()
            .is_some_and(|s| matches!(s.kind(), "." | "::"));
        let before_path = node
            .next_sibling()
            .is_some_and(|s| matches!(s.kind(), "::" | "!"));
        return !(after_separator || before_path);
    }
    true
}

fn positional(renamed: &mut HashMap<String, String>, name: &str) -> String {
    let next = renamed.len();
    renamed
        .entry(name.to_string())
        .or_insert_with(|| format!("${next}"))
        .clone()
}

fn disambiguate(fns: &mut [Function]) {
    let mut seen: HashMap<String, usize> = HashMap::new();
    for f in fns {
        let n = seen.entry(f.key.clone()).or_insert(0);
        *n += 1;
        if *n > 1 {
            f.key = format!("{}~{n}", f.key);
        }
    }
}
