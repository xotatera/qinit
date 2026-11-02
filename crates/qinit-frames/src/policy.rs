// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The privilege policy: ordered rules that bound the credentials a compiled model may grant.
//!
//! A policy file has a required `default = "allow" | "deny"` and ordered `[[rule]]` tables
//! (`match`, `users`, `caps_max`, `require_nnp`). For each node that has a credential set, the
//! first rule whose `match` glob fits the node name decides, and a rule that rejects a node is
//! final: later rules are never consulted. A node no rule matches follows `default`. A node
//! without a credential set needs no rule.
//!
//! `users` lists the user names a rule allows. Omitting `users` allows any user; `users = []`
//! allows no user, so every matching node with a user set is refused. A credential set whose
//! user is empty (only a `sandbox` table was given, so no uid change) is not checked against
//! `users`, as there is no uid to compare; its capability ceiling and `require_nnp` still apply.
use crate::error::{Code, Error};
use crate::resolve::{cap_bit, cap_name};
use qinit_db::{Cred, Model};
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
}

#[derive(Clone, Debug)]
struct Rule {
    pattern: String,
    users: Option<Vec<String>>,
    ceiling: u64,
    require_nnp: bool,
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

/// The bare key at the end of `before` when it is a `key = ` prefix of a line, else `None`.
fn key_before_value(before: &str) -> Option<&str> {
    let line = before.rsplit('\n').next()?;
    let (key, _) = line.split_once('=')?;
    let key = key.trim();
    let bare = !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    bare.then_some(key)
}

/// The text between the first pair of backticks of `msg` after `prefix`.
fn quoted<'a>(msg: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = msg.strip_prefix(prefix)?;
    rest.split_once('`').map(|(f, _)| f)
}

/// The index of the `[[rule]]` table that contains byte `at`: the last `[[rule]]` header line at
/// or before it. This is a line scan, not a TOML parse, so a `[[rule]]` line inside a
/// multi-line string, rules written as an inline `rule = [...]` array, and a header with inner
/// spaces such as `[[ rule ]]` are not recognised, so the error is keyed by the last recognised
/// `[[rule]]` before it (or by the bare field when none precedes it).
fn rule_at(text: &str, at: usize) -> Option<usize> {
    let mut headers = 0usize;
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if offset > at {
            break;
        }
        if line.trim_start().starts_with("[[rule]]") {
            headers += 1;
        }
        offset += line.len();
    }
    headers.checked_sub(1)
}

/// The error for a policy whose TOML is valid but whose shape is not.
///
/// The key is `rule[i].<field>` inside the `i`-th `[[rule]]` table, the bare field at top level
/// (`default`, or an unknown key), and `policy` when neither the rule nor the field can be told.
/// Both come from the error's byte span: the field is the unknown or missing field the message
/// names, else the key on the span's line; the rule is found by [`rule_at`], so the limits
/// documented there apply: an unrecognised header is keyed by the last recognised `[[rule]]`
/// before it, or by the bare field when none precedes it. An unknown field is an `UnknownKey`, anything else a `BadValue`.
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

fn violation(name: &str, detail: String) -> Error {
    Error::new(Code::Policy, format!("worker.{name}.credentials"), detail)
}

fn cap_names(bits: u64) -> String {
    (0u8..64)
        .filter(|b| bits & (1u64 << b) != 0)
        .map(|b| cap_name(b).map_or_else(|| format!("cap{b}"), str::to_string))
        .collect::<Vec<_>>()
        .join(", ")
}

fn check_rule(rule: &Rule, name: &str, cred: &Cred, errs: &mut Vec<Error>) {
    if let Some(users) = &rule.users
        && !cred.user.is_empty()
        && !users.contains(&cred.user)
    {
        let why = format!(
            "user `{}` is not allowed by rule `{}`",
            cred.user, rule.pattern
        );
        errs.push(violation(name, why));
    }
    let over = cred.caps & !rule.ceiling;
    if over != 0 {
        let why = format!(
            "capabilities above the ceiling of rule `{}`: {}",
            rule.pattern,
            cap_names(over)
        );
        errs.push(violation(name, why));
    }
    if rule.require_nnp && !cred.nnp {
        let why = format!("nnp required by rule `{}`", rule.pattern);
        errs.push(violation(name, why));
    }
}

/// Check every node that has credentials against the policy; all violations are returned.
///
/// # Errors
/// One `Policy` error per violation, keyed `worker.<name>.credentials`.
pub fn check(policy: &Policy, model: &Model) -> Result<(), Vec<Error>> {
    let mut errs = Vec::new();
    for node in &model.nodes {
        let Some(cred) = node
            .cred
            .and_then(|i| model.creds.get(usize::try_from(i).ok()?))
        else {
            continue;
        };
        match policy
            .rules
            .iter()
            .find(|r| glob_match(&r.pattern, &node.name))
        {
            Some(rule) => check_rule(rule, &node.name, cred, &mut errs),
            None if policy.allow_by_default => {}
            None => errs.push(violation(
                &node.name,
                "no rule matches and the default is deny".to_string(),
            )),
        }
    }
    if errs.is_empty() { Ok(()) } else { Err(errs) }
}
