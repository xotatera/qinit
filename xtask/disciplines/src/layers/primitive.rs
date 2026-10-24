// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `primitive` layer's source rules, checked by the `layers` gate: no
//! `pub unsafe fn` or `pub unsafe trait` (the public API is safe), no
//! `extern` blocks, and no `#[link]`, `#[no_mangle]` or `#[export_name]`
//! (no foreign code). Macro definitions and invocations are scanned for
//! tokens that would produce those items. Pure: the gate reads the files.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use tree_sitter::{Node, Parser};

const SAFE_API: &str = "a primitive's public API is safe";

/// The rule breaks in one source file, as `<path>:<line>: <what>`.
///
/// # Errors
/// When the grammar cannot be loaded or the parser gives up.
pub fn findings(path: &str, source: &str) -> Result<Vec<String>, String> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .map_err(|e| format!("tree-sitter-rust: {e}"))?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| format!("{path}: parse failed"))?;
    let mut out = Vec::new();
    walk(tree.root_node(), source.as_bytes(), path, &mut out);
    Ok(out)
}

fn walk(node: Node, src: &[u8], path: &str, out: &mut Vec<String>) {
    let at = |n: Node| format!("{path}:{}", n.start_position().row + 1);
    match node.kind() {
        "function_item" if is_pub(node, src) && has_unsafe_modifier(node, src) => {
            out.push(format!(
                "{}: `pub unsafe fn {}`: {SAFE_API} (wrap it, or make it pub(crate))",
                at(node),
                name(node, src)
            ));
        }
        "trait_item" if is_pub(node, src) => {
            if has_child_kind(node, "unsafe") {
                out.push(format!(
                    "{}: `pub unsafe trait {}`: {SAFE_API}",
                    at(node),
                    name(node, src)
                ));
            }
            // A public trait's methods are public whatever their syntax.
            if let Some(body) = node.child_by_field_name("body") {
                let mut cursor = body.walk();
                for item in body.children(&mut cursor) {
                    if matches!(item.kind(), "function_signature_item" | "function_item")
                        && has_unsafe_modifier(item, src)
                    {
                        out.push(format!(
                            "{}: `unsafe fn {}` in pub trait `{}`: {SAFE_API}",
                            at(item),
                            name(item, src),
                            name(node, src)
                        ));
                    }
                }
            }
        }
        "foreign_mod_item" => {
            out.push(format!(
                "{}: `extern` block: a primitive makes no foreign calls",
                at(node)
            ));
        }
        "macro_definition" | "macro_invocation" => {
            let field = if node.kind() == "macro_definition" {
                "name"
            } else {
                "macro"
            };
            let macro_name = node
                .child_by_field_name(field)
                .map_or("?", |n| text(n, src));
            let mut toks = Vec::new();
            leaf_tokens(node, src, &mut toks);
            if let Some(what) = generated(&toks) {
                out.push(format!(
                    "{}: macro `{macro_name}` can generate {what}: a primitive's public API is safe and it makes no foreign calls; write the item out where this check can see it",
                    at(node)
                ));
            }
        }
        "attribute_item" | "inner_attribute_item" => {
            if let Some(attr) = banned_attribute(text(node, src)) {
                out.push(format!(
                    "{}: `#[{attr}]`: a primitive exports no foreign symbols",
                    at(node)
                ));
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, src, path, out);
    }
}

fn text<'a>(node: Node, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

/// Exactly `pub`: `pub(crate)` and narrower are not exported.
fn is_pub(node: Node, src: &[u8]) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|c| c.kind() == "visibility_modifier" && text(c, src) == "pub")
}

fn has_unsafe_modifier(node: Node, src: &[u8]) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|c| {
        c.kind() == "function_modifiers" && text(c, src).split_whitespace().any(|w| w == "unsafe")
    })
}

fn has_child_kind(node: Node, kind: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|c| c.kind() == kind)
}

fn name<'a>(node: Node, src: &'a [u8]) -> &'a str {
    node.child_by_field_name("name")
        .map_or("?", |n| text(n, src))
}

/// `link`, `no_mangle` or `export_name` when the attribute is one of them,
/// also inside edition 2024's `unsafe(…)` or any depth of `cfg_attr(…)`.
fn banned_attribute(attr: &str) -> Option<&'static str> {
    let compact: String = attr.chars().filter(|c| !c.is_whitespace()).collect();
    let body = compact
        .trim_start_matches("#!")
        .trim_start_matches('#')
        .trim_start_matches('[');
    banned_in(body.strip_suffix(']').unwrap_or(body))
}

/// The banned attribute in one attribute's content (`no_mangle`,
/// `unsafe(no_mangle)`, `cfg_attr(pred, a, b)`), whitespace removed.
fn banned_in(content: &str) -> Option<&'static str> {
    let content = content
        .strip_prefix("unsafe(")
        .and_then(|c| c.strip_suffix(')'))
        .unwrap_or(content);
    let ident: String = content
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if ident == "cfg_attr" {
        let inner = content
            .strip_prefix("cfg_attr(")
            .and_then(|c| c.strip_suffix(')'))?;
        // Skip the predicate; each later item is an attribute.
        return top_level_items(inner)
            .into_iter()
            .skip(1)
            .find_map(banned_in);
    }
    ["link", "no_mangle", "export_name"]
        .into_iter()
        .find(|b| *b == ident)
}

/// `s` split at commas outside brackets and strings.
fn top_level_items(s: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let (mut depth, mut quoted, mut start) = (0usize, false, 0);
    let mut escaped = false;
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

/// A declared source that can't be scanned: a module with no file, an
/// `include!` of a path that isn't a literal, a file outside the repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub file: PathBuf,
    pub line: usize,
    pub message: String,
}

/// A crate's source files and what kept a declared source from being read.
#[derive(Debug, Default)]
pub struct Sources {
    pub files: Vec<PathBuf>,
    pub problems: Vec<Problem>,
}

/// Every source file of the crate whose lib root is `lib_root`, found by
/// following its `mod` declarations (`#[path]`, also inside `cfg_attr`) and
/// literal `include!`s the way rustc does, so tests, examples and build
/// output beside the sources are never read. Files are visited once each
/// (by canonical path), so `#[path]` cycles end. Sorted. Unreadable files,
/// and `mod`s inside macros that cannot be placed, are problems.
///
/// # Errors
/// When the grammar cannot be loaded or a file cannot be parsed.
pub fn crate_sources(lib_root: &Path) -> Result<Sources, String> {
    let mut seen = BTreeSet::new();
    let mut out = Sources::default();
    // (file, whether its child modules live in its own directory: the lib
    // root, `mod.rs`, and `#[path]`/`include!` files)
    let mut stack = vec![(lib_root.to_path_buf(), true)];
    while let Some((file, mod_rs)) = stack.pop() {
        let Ok(canonical) = file.canonicalize() else {
            continue;
        };
        if !seen.insert(canonical) {
            continue;
        }
        let source = match std::fs::read_to_string(&file) {
            Ok(s) => s,
            Err(e) => {
                out.problems.push(Problem {
                    file: file.clone(),
                    line: 1,
                    message: format!("cannot read it ({e}): the source check cannot see it"),
                });
                continue;
            }
        };
        out.files.push(file.clone());
        let dir = file.parent().map_or_else(PathBuf::new, Path::to_path_buf);
        let base = if mod_rs {
            dir.clone()
        } else {
            dir.join(file.file_stem().unwrap_or_default())
        };
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .map_err(|e| format!("tree-sitter-rust: {e}"))?;
        let tree = parser
            .parse(&source, None)
            .ok_or_else(|| format!("{}: parse failed", file.display()))?;
        let mut cx = ModCx {
            src: source.as_bytes(),
            file: &file,
            stack: &mut stack,
            problems: &mut out.problems,
        };
        modules(tree.root_node(), &base, &dir, &mut cx);
    }
    out.files.sort();
    Ok(out)
}

struct ModCx<'a> {
    src: &'a [u8],
    file: &'a Path,
    stack: &'a mut Vec<(PathBuf, bool)>,
    problems: &'a mut Vec<Problem>,
}

impl ModCx<'_> {
    fn problem(&mut self, node: Node, message: String) {
        self.problems.push(Problem {
            file: self.file.to_path_buf(),
            line: node.start_position().row + 1,
            message,
        });
    }
}

/// Pushes the file of each `mod x;` under `node`: `<base>/x.rs`, else
/// `<base>/x/mod.rs`, or its `#[path]` relative to `path_dir`; and of each
/// literal `include!`. Inline modules extend `base` by their name.
fn modules(node: Node, base: &Path, path_dir: &Path, cx: &mut ModCx) {
    let mut cursor = node.walk();
    let children: Vec<Node> = node.children(&mut cursor).collect();
    for (i, child) in children.iter().enumerate() {
        match child.kind() {
            "mod_item" => {}
            "macro_invocation" => {
                include(*child, path_dir, cx);
                macro_modules(*child, base, cx, false);
                continue;
            }
            "macro_definition" => {
                macro_modules(*child, base, cx, true);
                continue;
            }
            _ => {
                modules(*child, base, path_dir, cx);
                continue;
            }
        }
        let name = self::name(*child, cx.src).to_string();
        let path_attr = children[..i]
            .iter()
            .rev()
            .take_while(|n| {
                matches!(
                    n.kind(),
                    "attribute_item" | "line_comment" | "block_comment"
                )
            })
            .find_map(|n| path_attribute(text(*n, cx.src)));
        if let Some(body) = child.child_by_field_name("body") {
            let inner = path_attr.map_or_else(|| base.join(&name), |p| base.join(p));
            modules(body, &inner, &inner, cx);
            continue;
        }
        let candidates = match path_attr {
            Some(p) => vec![(path_dir.join(p), true)],
            None => default_candidates(base, &name),
        };
        follow(&candidates, &name, *child, cx);
    }
}

/// `<base>/x.rs`, else `<base>/x/mod.rs`.
fn default_candidates(base: &Path, name: &str) -> Vec<(PathBuf, bool)> {
    vec![
        (base.join(format!("{name}.rs")), false),
        (base.join(name).join("mod.rs"), true),
    ]
}

/// Pushes the first candidate that exists, else records that the module
/// has no file.
fn follow(candidates: &[(PathBuf, bool)], name: &str, node: Node, cx: &mut ModCx) {
    if let Some(found) = candidates.iter().find(|(f, _)| f.is_file()) {
        cx.stack.push(found.clone());
    } else {
        let looked: Vec<String> = candidates
            .iter()
            .map(|(f, _)| f.display().to_string())
            .collect();
        cx.problem(
            node,
            format!(
                "module `{name}` has no file (looked for {}): the source check cannot see it",
                looked.join(", ")
            ),
        );
    }
}

/// `mod x;` among a macro's tokens (`cfg_if! { … mod imp; … }`): rustc
/// declares it where the invocation expands, here, so its file is
/// followed like a plain `mod`'s (not in `quote!`/`quote_spanned!`, which
/// only build tokens). Two forms cannot be placed and are
/// problems: a `mod x;` in a `macro_rules!` body (it lands wherever the
/// macro is invoked), and one among tokens that set a `path`.
fn macro_modules(node: Node, base: &Path, cx: &mut ModCx, definition: bool) {
    // `quote!` builds tokens for another crate's code: no `mod` there is
    // declared here.
    let callee = node
        .child_by_field_name("macro")
        .map_or("", |n| text(n, cx.src));
    if matches!(callee.rsplit("::").next(), Some("quote" | "quote_spanned")) {
        return;
    }
    let mut toks = Vec::new();
    leaf_tokens(node, cx.src, &mut toks);
    let has_path = toks.windows(2).any(|w| w[0] == "path" && w[1] == "=");
    let names: Vec<String> = toks
        .windows(3)
        .filter(|w| w[0] == "mod" && w[2] == ";" && is_ident(&w[1]))
        .map(|w| w[1].clone())
        .collect();
    for name in names {
        if definition || has_path {
            let place = if definition {
                "a macro definition"
            } else {
                "a macro with a `#[path]`"
            };
            cx.problem(
                node,
                format!("module `{name}` is declared inside {place}: the source check cannot see it; declare it outside the macro"),
            );
        } else {
            follow(&default_candidates(base, &name), &name, node, cx);
        }
    }
}

/// A Rust identifier as tree-sitter lexes one (`r#` raw forms included).
fn is_ident(t: &str) -> bool {
    let t = t.strip_prefix("r#").unwrap_or(t);
    t.chars()
        .next()
        .is_some_and(|c| c.is_alphabetic() || c == '_')
        && t.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// Follows `include!("x.rs")` (also `std::`/`core::include!`); any other
/// form is a problem, since the included code can't be seen or keyed.
fn include(node: Node, dir: &Path, cx: &mut ModCx) {
    let name = node
        .child_by_field_name("macro")
        .map_or("", |n| text(n, cx.src));
    if !matches!(name, "include" | "std::include" | "core::include") {
        return;
    }
    let mut toks = Vec::new();
    leaf_tokens(node, cx.src, &mut toks);
    // `include ! ( "x.rs" )`, possibly with a path prefix and a trailing `;`.
    let args: Vec<&String> = toks
        .iter()
        .skip_while(|t| *t != "(")
        .skip(1)
        .take_while(|t| *t != ")")
        .collect();
    match args.as_slice() {
        [lit] if lit.ends_with('"') => {
            let path = dir.join(unquote(lit));
            if path.is_file() {
                cx.stack.push((path, true));
            } else {
                cx.problem(node, format!("`include!` file {lit} not found: the source check cannot see it"));
            }
        }
        _ => cx.problem(
            node,
            "`include!` of a path that is not a string literal: the source check cannot see or key the included code".to_string(),
        ),
    }
}

/// The text of a string literal, plain or raw: `"a"`, `r"a"`, `r#"a"#`.
fn unquote(lit: &str) -> String {
    lit.trim_start_matches('r')
        .trim_matches('#')
        .trim_matches('"')
        .to_string()
}

/// The value of `#[path = "…"]`, also inside `cfg_attr(pred, …)`.
fn path_attribute(attr: &str) -> Option<String> {
    let compact: String = attr.chars().filter(|c| !c.is_whitespace()).collect();
    let body = compact.strip_prefix("#[")?.strip_suffix(']')?;
    find_path(body)
}

fn find_path(content: &str) -> Option<String> {
    if let Some(value) = content.strip_prefix("path=") {
        return Some(unquote(value));
    }
    let inner = content.strip_prefix("cfg_attr(")?.strip_suffix(')')?;
    top_level_items(inner)
        .into_iter()
        .skip(1)
        .find_map(find_path)
}

/// The files among `files` that git ignores, and those outside the
/// repository (git can't say), under `root`.
///
/// # Errors
/// When git cannot run.
pub fn ignored(root: &Path, files: &[PathBuf]) -> Result<(Vec<PathBuf>, Vec<PathBuf>), String> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let top = crate::git::command()
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("git rev-parse: {e}"))?;
    if !top.status.success() {
        return Err(format!(
            "git rev-parse: {}",
            String::from_utf8_lossy(&top.stderr).trim()
        ));
    }
    let top = PathBuf::from(std::ffi::OsString::from_vec(
        top.stdout.trim_ascii_end().to_vec(),
    ));
    let (inside, outside): (Vec<PathBuf>, Vec<PathBuf>) = files
        .iter()
        .cloned()
        .partition(|f| f.canonicalize().is_ok_and(|c| c.starts_with(&top)));
    let mut input = Vec::new();
    for f in &inside {
        input.extend_from_slice(f.as_os_str().as_bytes());
        input.push(0);
    }
    let out = crate::git::with_stdin(root, &["check-ignore", "-z", "--stdin"], input)?;
    // Exit 1 means nothing is ignored.
    if !out.status.success() && out.status.code() != Some(1) {
        return Err(format!(
            "git check-ignore: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let ignored = out
        .stdout
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| PathBuf::from(std::ffi::OsString::from_vec(p.to_vec())))
        .collect();
    Ok((ignored, outside))
}

/// The source tokens under `node` as tree-sitter lexes them: literals whole,
/// comments dropped.
fn leaf_tokens(node: Node, src: &[u8], out: &mut Vec<String>) {
    match node.kind() {
        "string_literal" | "raw_string_literal" | "char_literal" => {
            out.push(text(node, src).to_string());
        }
        "line_comment" | "block_comment" => {}
        _ if node.child_count() == 0 => {
            let t = text(node, src);
            if !t.is_empty() {
                out.push(t.to_string());
            }
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                leaf_tokens(child, src, out);
            }
        }
    }
}

/// What banned item a macro's tokens can produce, if any: a `pub` function
/// or trait marked `unsafe` (`const`, `async`, `extern "abi"` in any
/// order), an `extern` block, or a symbol-exporting attribute (also inside
/// `cfg_attr`).
fn generated(t: &[String]) -> Option<String> {
    let at = |i: usize| t.get(i).map_or("", String::as_str);
    for i in 0..t.len() {
        if at(i) == "pub" && at(i + 1) != "(" {
            let mut j = i + 1;
            let mut unsafe_seen = false;
            loop {
                match at(j) {
                    "const" | "async" | "extern" | "default" => {}
                    "unsafe" => unsafe_seen = true,
                    s if s.starts_with('"') => {}
                    "fn" | "trait" if unsafe_seen => {
                        return Some(format!("`pub unsafe {}`", at(j)));
                    }
                    _ => break,
                }
                j += 1;
            }
        }
        if at(i) == "extern"
            && (at(i + 1) == "{" || (at(i + 1).starts_with('"') && at(i + 2) == "{"))
        {
            return Some("an `extern` block".to_string());
        }
        if at(i) == "#" && at(i + 1) == "[" {
            let mut depth = 0usize;
            let mut content = String::new();
            for tok in &t[i + 1..] {
                match tok.as_str() {
                    "[" | "(" | "{" => depth += 1,
                    "]" | ")" | "}" => depth = depth.saturating_sub(1),
                    _ => {}
                }
                if depth == 0 {
                    break;
                }
                content.push_str(tok);
            }
            if let Some(b) = banned_in(content.trim_start_matches('[')) {
                return Some(format!("`#[{b}]`"));
            }
        }
    }
    None
}
