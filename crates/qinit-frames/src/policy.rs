// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The privilege policy: ordered rules that bound the credentials a compiled model may grant.
//!
//! A policy file has a required `default = "allow" | "deny"` and ordered `[[rule]]` tables
//! (`match`, `users`, `caps_max`, `require_nnp`, `require_seccomp`). For each node that may hold privilege, the
//! first rule whose `match` glob fits the node name decides, and a rule that rejects a node is
//! final: later rules are never consulted. A node no rule matches follows `default`.
//!
//! Least privilege is the default. A node whose credential set names a user other than `root`,
//! grants no capabilities and keeps no-new-privileges on is unprivileged: it needs no rule and
//! passes even under `default = "deny"`, since a rule would have nothing to bound. A brood has
//! no credential set and is never checked. Every other node (root, a capability, or `nnp =
//! false`) is checked against the first matching rule, or refused by `default = "deny"`.
//!
//! `users` lists the user names a rule allows. Omitting `users` allows any user; `users = []`
//! allows no user, so every matching node is refused.
use crate::error::{Code, Error};
use crate::expand::kind_name;
use crate::resolve::{cap_bit, cap_name};
use qinit_db::{Cred, Model, Node, Seccomp};
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    default: Option<String>,
    #[serde(default)]
    rule: Vec<RawRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    #[serde(rename = "match")]
    pattern: String,
    users: Option<Vec<String>>,
    caps_max: Option<Vec<String>>,
    require_nnp: Option<bool>,
    require_seccomp: Option<bool>,
}

#[derive(Clone, Debug)]
struct Rule {
    pattern: String,
    users: Option<Vec<String>>,
    ceiling: u64,
    require_nnp: bool,
    require_seccomp: bool,
}

/// A parsed policy.
#[derive(Clone, Debug)]
pub struct Policy {
    allow_by_default: bool,
    rules: Vec<Rule>,
}

/// Whether `name` matches `pattern`, where `*` matches any run of characters (possibly empty)
/// and every other byte matches itself. Iterative two-pointer with single-star backtracking:
/// at most `pattern.len() * name.len()` steps.
#[must_use]
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let (p, n) = (pattern.as_bytes(), name.as_bytes());
    let (mut pi, mut ni) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        match p.get(pi) {
            Some(b'*') => {
                star = Some((pi, ni));
                pi += 1;
            }
            Some(c) if *c == n[ni] => {
                pi += 1;
                ni += 1;
            }
            _ => match star {
                Some((sp, sn)) => {
                    star = Some((sp, sn + 1));
                    pi = sp + 1;
                    ni = sn + 1;
                }
                None => return false,
            },
        }
    }
    p[pi..].iter().all(|c| *c == b'*')
}

/// The bare key of the `key = ` prefix of the line at the end of `before`, else `None`. In an
/// inline table (`{ a = 1, b = `) it is the key just before the last `=`.
fn key_before_value(before: &str) -> Option<&str> {
    let bare = |b: &u8| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-';
    let line = before.rsplit('\n').next()?;
    let key = if line.contains('{') {
        let (left, _) = line.rsplit_once('=')?;
        let left = left.trim_end();
        let start = left.bytes().rposition(|b| !bare(&b)).map_or(0, |i| i + 1);
        &left[start..]
    } else {
        line.split_once('=')?.0.trim()
    };
    (!key.is_empty() && key.bytes().all(|b| bare(&b))).then_some(key)
}

/// The text between the first pair of backticks of `msg` after `prefix`.
fn quoted<'a>(msg: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = msg.strip_prefix(prefix)?;
    rest.split_once('`').map(|(f, _)| f)
}

/// The index of the `rule` array element that contains byte `at`, from a TOML parse of `text`
/// (so inline arrays, spaced headers and header-like lines in strings are all handled). An
/// inline table owns its braces; a `[[rule]]` header owns the text up to the next element (the
/// parser spans only the header). `None` when `rule` is missing or not an array, or no element
/// contains `at`.
fn rule_at(text: &str, at: usize) -> Option<usize> {
    let table = toml::de::DeTable::parse(text).ok()?;
    let toml::de::DeValue::Array(rules) = table.get_ref().get("rule")?.get_ref() else {
        return None;
    };
    rules.iter().enumerate().position(|(i, r)| {
        let span = r.span();
        let end = if text.get(span.clone()).is_some_and(|t| t.starts_with('{')) {
            span.end
        } else {
            rules.get(i + 1).map_or(text.len(), |n| n.span().start)
        };
        (span.start..end).contains(&at)
    })
}

/// The error for a policy whose TOML is valid but whose shape is not.
///
/// The key is `rule[i].<field>` inside the `i`-th `[[rule]]` table, the bare field at top level
/// (`default`, or an unknown key), and `policy` when neither the rule nor the field can be told.
/// Both come from the error's byte span: the field is the unknown or missing field the message
/// names, else the key on the span's line; the rule is the `rule` element containing the span
/// ([`rule_at`]). An unknown field is an `UnknownKey`, anything else a `BadValue`.
fn serde_error(path: &Path, text: &str, e: &toml::de::Error) -> Error {
    let msg = e.message();
    let unknown = quoted(msg, "unknown field `");
    let start = e.span().map(|s| s.start.min(text.len()));
    let field = unknown
        .or_else(|| quoted(msg, "missing field `"))
        .or_else(|| key_before_value(text.get(..start?)?));
    let rule = start.and_then(|at| rule_at(text, at));
    let key = match (rule, field) {
        (Some(i), Some(f)) => format!("rule[{i}].{f}"),
        (Some(i), None) => format!("rule[{i}]"),
        (None, Some(f)) => f.to_string(),
        (None, None) => "policy".to_string(),
    };
    let code = if unknown.is_some() {
        Code::UnknownKey
    } else {
        Code::BadValue
    };
    Error::new(code, key, msg).in_file(path)
}

fn build_rule(path: &Path, i: usize, r: RawRule, errs: &mut Vec<Error>) -> Rule {
    let mut ceiling = 0u64;
    for name in r.caps_max.as_deref().unwrap_or_default() {
        match cap_bit(name) {
            Some(b) => ceiling |= 1u64 << b,
            None => errs.push(
                Error::new(
                    Code::BadValue,
                    format!("rule[{i}].caps_max"),
                    format!("unknown capability `{name}`"),
                )
                .in_file(path),
            ),
        }
    }
    Rule {
        pattern: r.pattern,
        users: r.users,
        ceiling,
        require_nnp: r.require_nnp.unwrap_or(false),
        require_seccomp: r.require_seccomp.unwrap_or(false),
    }
}

/// Read and validate a policy file; every shape problem found is returned.
///
/// # Errors
/// `Io` when unreadable, `Parse` for invalid TOML, `UnknownKey` for an unknown key and `BadValue`
/// for a missing or invalid `default` or an unknown capability name.
pub fn load_policy(path: &Path) -> Result<Policy, Vec<Error>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| vec![Error::new(Code::Io, "", e.to_string()).in_file(path)])?;
    text.parse::<toml::Table>().map_err(|e: toml::de::Error| {
        vec![Error::new(Code::Parse, "", e.message()).in_file(path)]
    })?;
    let raw: RawPolicy = toml::from_str(&text).map_err(|e| vec![serde_error(path, &text, &e)])?;
    let mut errs = Vec::new();
    let allow_by_default = match raw.default.as_deref() {
        Some("allow") => true,
        Some("deny") => false,
        Some(x) => {
            let why = format!("`{x}` is not allow or deny");
            errs.push(Error::new(Code::BadValue, "default", why).in_file(path));
            false
        }
        None => {
            let why = "required: allow or deny";
            errs.push(Error::new(Code::BadValue, "default", why).in_file(path));
            false
        }
    };
    let rules: Vec<Rule> = raw
        .rule
        .into_iter()
        .enumerate()
        .map(|(i, r)| build_rule(path, i, r, &mut errs))
        .collect();
    if errs.is_empty() {
        Ok(Policy {
            allow_by_default,
            rules,
        })
    } else {
        Err(errs)
    }
}

fn violation(node: &Node, detail: String) -> Error {
    let key = format!("{}.{}.credentials", kind_name(node.kind), node.name);
    Error::new(Code::Policy, key, detail)
}

fn cap_names(bits: u64) -> String {
    (0u8..64)
        .filter(|b| bits & (1u64 << b) != 0)
        .map(|b| cap_name(b).map_or_else(|| format!("cap{b}"), str::to_string))
        .collect::<Vec<_>>()
        .join(", ")
}

fn check_rule(rule: &Rule, node: &Node, cred: &Cred, errs: &mut Vec<(usize, Error)>, i: usize) {
    if let Some(users) = &rule.users
        && !users.contains(&cred.user)
    {
        let why = format!(
            "user `{}` is not allowed by rule `{}`",
            cred.user, rule.pattern
        );
        errs.push((i, violation(node, why)));
    }
    let over = cred.caps & !rule.ceiling;
    if over != 0 {
        let why = format!(
            "capabilities above the ceiling of rule `{}`: {}",
            rule.pattern,
            cap_names(over)
        );
        errs.push((i, violation(node, why)));
    }
    if rule.require_nnp && !cred.nnp {
        let why = format!("nnp required by rule `{}`", rule.pattern);
        errs.push((i, violation(node, why)));
    }
    if rule.require_seccomp && cred.seccomp == Seccomp::None {
        let why = format!("seccomp required by rule `{}`", rule.pattern);
        errs.push((i, violation(node, why)));
    }
}

/// A credential set that holds no privilege: not root, no capabilities, no-new-privileges on.
fn unprivileged(c: &Cred) -> bool {
    c.user != "root" && c.caps == 0 && c.nnp
}

/// Every violation of `policy` by `model`, with the index of the offending node.
pub(crate) fn violations(policy: &Policy, model: &Model) -> Vec<(usize, Error)> {
    let mut errs = Vec::new();
    for (i, node) in model.nodes.iter().enumerate() {
        let Some(cred) = node
            .cred
            .and_then(|c| model.creds.get(usize::try_from(c).ok()?))
        else {
            continue;
        };
        if unprivileged(cred) {
            continue;
        }
        match policy
            .rules
            .iter()
            .find(|r| glob_match(&r.pattern, &node.name))
        {
            Some(rule) => check_rule(rule, node, cred, &mut errs, i),
            None if policy.allow_by_default => {}
            None => errs.push((
                i,
                violation(node, "no rule matches and the default is deny".to_string()),
            )),
        }
    }
    errs
}

/// Check every node that may hold privilege against the policy; all violations are returned.
/// Unprivileged nodes (see the module documentation) need no rule.
///
/// # Errors
/// One `Policy` error per violation, keyed `<kind>.<name>.credentials` with the node's kind
/// word (`worker`, `forager` or `brood`).
pub fn check(policy: &Policy, model: &Model) -> Result<(), Vec<Error>> {
    let errs: Vec<Error> = violations(policy, model)
        .into_iter()
        .map(|(_, e)| e)
        .collect();
    if errs.is_empty() { Ok(()) } else { Err(errs) }
}
