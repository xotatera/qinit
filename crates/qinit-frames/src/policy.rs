// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The privilege policy: ordered rules that bound the credentials a compiled model may grant.
//!
//! A policy file has a required `default = "allow" | "deny"` and ordered `[[rule]]` tables
//! (`match`, `users`, `caps_max`, `require_nnp`, `require_seccomp`, `allow_userns`). For each node that may hold privilege, the
//! first rule whose `match` glob fits the node name decides, and a rule that rejects a node is
//! final: later rules are never consulted. A node no rule matches follows `default`.
//!
//! Least privilege is the default. A node whose credential set names a user other than `root`,
//! grants no capabilities, keeps no-new-privileges on and has no user namespace is unprivileged: it needs no rule and
//! passes even under `default = "deny"`, since a rule would have nothing to bound. A brood has
//! no credential set and is never checked. Every other node (root, a capability, or `nnp =
//! false`) is checked against the first matching rule, or refused by `default = "deny"`.
//!
//! Resource limits are bounded too. A limit above its ceiling counts as privilege (the overseer
//! applies limits as root, so a frame could otherwise grant itself the effect of `CAP_SYS_NICE`,
//! `CAP_IPC_LOCK` or `CAP_SYS_RESOURCE`). The built-in ceiling is the kernel's boot hard limits:
//! `as cpu data fsize locks rss rttime stack` infinity, `nofile` 4096, `memlock` 8388608,
//! `msgqueue` 819200, `nice` 0, `rtprio` 0, and `nproc` and `sigpending` none (any value needs
//! a rule). A node with a limit above it is checked like a privileged one. A rule's
//! `rlimits_max = { <key> = <value> }` (the frame syntax) replaces the ceiling of the keys it
//! lists for the nodes it matches; a top-level `rlimits_max` replaces the built-in ceiling the
//! same way. `infinity` compares above every number. A limit above the ceiling of the matching
//! rule is refused with the key `rule[i].rlimits_max`.
//!
//! `users` lists the user names a rule allows. Omitting `users` allows any user; `users = []`
//! allows no user, so every matching node is refused.
use crate::error::{Code, Error};
use crate::expand::kind_name;
use crate::resolve::{cap_bit, cap_name};
use crate::schema::{Rlimits, rlimit_value};
use qinit_db::{Cred, Model, Node, RLIMIT_COUNT, RLIMIT_KEYS, Seccomp, UserMap, Userns};
use qinit_db_core::MAX_PATTERN_LEN;
use serde::Deserialize;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    default: Option<String>,
    rlimits_max: Option<Rlimits>,
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
    rlimits_max: Option<Rlimits>,
    allow_userns: Option<toml::Value>,
}

/// The kernel's boot hard limits by resource number (`include/asm-generic/resource.h`,
/// `INIT_RLIMITS`): `None` is no ceiling, so any set value is above it.
const BOOT_CEILING: [Option<u64>; RLIMIT_COUNT] = [
    Some(u64::MAX),  // cpu
    Some(u64::MAX),  // fsize
    Some(u64::MAX),  // data
    Some(u64::MAX),  // stack
    None,            // core: never set
    Some(u64::MAX),  // rss
    None,            // nproc
    Some(4096),      // nofile
    Some(8_388_608), // memlock
    Some(u64::MAX),  // as
    Some(u64::MAX),  // locks
    None,            // sigpending
    Some(819_200),   // msgqueue
    Some(0),         // nice
    Some(0),         // rtprio
    Some(u64::MAX),  // rttime
];

#[derive(Clone, Debug)]
struct Rule {
    rlimits: [Option<u64>; RLIMIT_COUNT],
    pattern: String,
    users: Option<Vec<String>>,
    ceiling: u64,
    require_nnp: bool,
    require_seccomp: bool,
    allow_userns: Userns,
}

/// A parsed policy.
#[derive(Clone, Debug)]
pub struct Policy {
    path: PathBuf,
    ceiling: [Option<u64>; RLIMIT_COUNT],
    allow_by_default: bool,
    rules: Vec<Rule>,
}

/// The policy as the database stores it: the rules, the default and the top-level ceilings
/// (the boot ceilings already merged in).
#[must_use]
pub fn to_model(p: &Policy) -> qinit_db::Policy {
    qinit_db::Policy {
        allow_by_default: p.allow_by_default,
        ceiling: p.ceiling,
        rules: p
            .rules
            .iter()
            .map(|r| qinit_db::PolicyRule {
                pattern: r.pattern.clone(),
                users: r.users.clone(),
                caps_max: r.ceiling,
                require_nnp: r.require_nnp,
                require_seccomp: r.require_seccomp,
                allow_userns: r.allow_userns,
                rlimits: r.rlimits,
            })
            .collect(),
    }
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

/// The text between the first pair of backticks of `msg` after `prefix`.
fn quoted<'a>(msg: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = msg.strip_prefix(prefix)?;
    rest.split_once('`').map(|(f, _)| f)
}

/// The key path of the entry of `text` that contains byte `at`, from a TOML parse: `rule[i]`
/// for the `i`-th `[[rule]]` element, then the keys below it (`rule[1].rlimits_max.core`,
/// `rlimits_max.nofile`), and whether the walk reached a leaf value (`false`: it stopped at a
/// table or element, so a missing field belongs under it). An inline table owns its braces; a
/// header table owns the text up to the next entry that starts after it (the parser spans only
/// the header). `None` when `text` does not parse or `at` precedes every key.
fn path_at(text: &str, at: usize) -> Option<(String, bool)> {
    use toml::de::DeValue;
    type Table<'a> = toml::de::DeTable<'a>;
    /// The entry of `t` whose text holds `at`: the last key starting at or before it.
    fn entry<'t, 'i>(
        t: &'t Table<'i>,
        at: usize,
    ) -> Option<(&'t str, &'t toml::Spanned<DeValue<'i>>)> {
        // A header entry starts at its first element's `[[`, before its key.
        let start = |k: &toml::Spanned<_>, v: &toml::Spanned<DeValue<'_>>| {
            k.span().start.min(v.span().start)
        };
        t.iter()
            .filter(|(k, v)| start(k, v) <= at)
            .max_by_key(|(k, v)| start(k, v))
            .map(|(k, v)| (k.get_ref().as_ref(), v))
    }
    fn walk(t: &Table<'_>, at: usize, out: &mut String) -> bool {
        let Some((key, value)) = entry(t, at) else {
            return false;
        };
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(key);
        match value.get_ref() {
            DeValue::Table(sub) => walk(sub, at, out),
            DeValue::Array(items) => {
                // Elements are ordered; the one holding `at` is the last starting at or before it.
                let Some((i, item)) = items
                    .iter()
                    .enumerate()
                    .rfind(|(_, v)| v.span().start <= at)
                else {
                    return false;
                };
                let _ = write!(out, "[{i}]");
                match item.get_ref() {
                    DeValue::Table(sub) => walk(sub, at, out),
                    _ => true,
                }
            }
            _ => true,
        }
    }
    let table = toml::de::DeTable::parse(text).ok()?;
    let mut out = String::new();
    let leaf = walk(table.get_ref(), at, &mut out);
    (!out.is_empty()).then_some((out, leaf))
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
    let missing = quoted(msg, "missing field `");
    let start = e.span().map(|s| s.start.min(text.len()));
    let at = start.and_then(|at| path_at(text, at));
    let key = match (at, unknown.or(missing)) {
        // An unknown field is spanned at its own key, so the path already ends in it.
        (Some((p, _)), Some(_)) if unknown.is_some() => p,
        (Some((p, false)), Some(f)) => format!("{p}.{f}"),
        (Some((p, _)), _) => p,
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

/// The limits listed in an `rlimits_max` table, by resource number; `scope` is its key prefix.
fn ceilings(
    path: &Path,
    scope: &str,
    set: Option<&Rlimits>,
    errs: &mut Vec<Error>,
) -> [Option<u64>; RLIMIT_COUNT] {
    std::array::from_fn(|r| {
        let v = set?.get(r)?;
        let key = RLIMIT_KEYS[r];
        match rlimit_value(key, v) {
            Ok(n) => Some(n),
            Err(why) => {
                errs.push(Error::new(Code::BadValue, format!("{scope}.{key}"), why).in_file(path));
                None
            }
        }
    })
}

/// A byte of a node name, or `*`, or `~`: what the database's pattern field holds.
fn pattern_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"._@:+-*~".contains(&c)
}

/// A user name by the overseer's grammar `^[a-z_][a-z0-9_-]{0,31}$`.
fn user_name(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=32).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

fn build_rule(path: &Path, i: usize, r: RawRule, errs: &mut Vec<Error>) -> Rule {
    if r.pattern.is_empty()
        || r.pattern.len() > MAX_PATTERN_LEN
        || !r.pattern.bytes().all(pattern_byte)
    {
        errs.push(
            Error::new(
                Code::BadValue,
                format!("rule[{i}].match"),
                format!(
                    "`{}` is not 1 to {MAX_PATTERN_LEN} bytes of a node name, `*` and `~`",
                    r.pattern
                ),
            )
            .in_file(path),
        );
    }
    if let Some(bad) = r.users.iter().flatten().find(|u| !user_name(u)) {
        errs.push(
            Error::new(
                Code::BadValue,
                format!("rule[{i}].users"),
                format!("`{bad}` is not a user name"),
            )
            .in_file(path),
        );
    }
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
    let allow_userns = match r.allow_userns.as_ref() {
        None | Some(toml::Value::Boolean(false)) => Userns::No,
        Some(toml::Value::Boolean(true)) => Userns::Own,
        Some(toml::Value::String(w)) if w == "range" => Userns::Range,
        Some(v) => {
            errs.push(
                Error::new(
                    Code::BadValue,
                    format!("rule[{i}].allow_userns"),
                    match v {
                        toml::Value::String(w) => {
                            format!("`{w}` is not false, true or \"range\"")
                        }
                        other => format!("a {} is not false, true or \"range\"", other.type_str()),
                    },
                )
                .in_file(path),
            );
            Userns::No
        }
    };
    Rule {
        allow_userns,
        rlimits: ceilings(
            path,
            &format!("rule[{i}].rlimits_max"),
            r.rlimits_max.as_ref(),
            errs,
        ),
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
    let listed = ceilings(path, "rlimits_max", raw.rlimits_max.as_ref(), &mut errs);
    let ceiling = std::array::from_fn(|r| listed[r].or(BOOT_CEILING[r]));
    if errs.is_empty() {
        Ok(Policy {
            path: path.to_path_buf(),
            ceiling,
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

fn check_rule(
    policy: &Policy,
    ri: usize,
    node: &Node,
    cred: &Cred,
    errs: &mut Vec<(usize, Error)>,
    i: usize,
) {
    let rule = &policy.rules[ri];
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
    if cred.ns & USER_NS != 0 {
        let allowed = match (rule.allow_userns, cred.user_map) {
            (Userns::No, _) | (Userns::Own, UserMap::Range) => false,
            (Userns::Own | Userns::Range, UserMap::Own) | (Userns::Range, UserMap::Range) => true,
        };
        if !allowed {
            let why = format!(
                "{} `{}` uses a user namespace not allowed by rule `{}`",
                kind_name(node.kind),
                node.name,
                rule.pattern
            );
            let key = format!("rule[{ri}].allow_userns");
            errs.push((i, Error::new(Code::Policy, key, why).in_file(&policy.path)));
        }
    }
    let over = raised(node, &policy.ceiling, Some(&rule.rlimits));
    if !over.is_empty() {
        let why = format!(
            "{} `{}` sets limits above the ceiling of rule `{}`: {}",
            kind_name(node.kind),
            node.name,
            rule.pattern,
            over.join(", ")
        );
        let key = format!("rule[{ri}].rlimits_max");
        errs.push((i, Error::new(Code::Policy, key, why).in_file(&policy.path)));
    }
}

/// The `user` bit of `Cred::ns`.
const USER_NS: u32 = 1 << 5;

/// A credential set that holds no privilege: not root, no capabilities, no-new-privileges on,
/// no user namespace.
fn unprivileged(c: &Cred) -> bool {
    c.user != "root" && c.caps == 0 && c.nnp && c.ns & USER_NS == 0
}

/// The names of the limits `node` sets above `ceiling` (`None` there: any value is above it),
/// where `listed` replaces the ceiling of the keys it holds.
fn raised(
    node: &Node,
    ceiling: &[Option<u64>; RLIMIT_COUNT],
    listed: Option<&[Option<u64>; RLIMIT_COUNT]>,
) -> Vec<&'static str> {
    (0..RLIMIT_COUNT)
        .filter(|&r| {
            let max = listed.and_then(|l| l[r]).or(ceiling[r]);
            node.rlimits[r].is_some_and(|v| max.is_none_or(|m| v > m))
        })
        .map(|r| RLIMIT_KEYS[r])
        .collect()
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
        let over = raised(node, &policy.ceiling, None);
        if unprivileged(cred) && over.is_empty() {
            continue;
        }
        match policy
            .rules
            .iter()
            .position(|r| glob_match(&r.pattern, &node.name))
        {
            Some(ri) => check_rule(policy, ri, node, cred, &mut errs, i),
            None if policy.allow_by_default => {}
            None => {
                let mut why = "no rule matches and the default is deny".to_string();
                if !over.is_empty() {
                    why = format!("{why}; limits above the ceiling: {}", over.join(", "));
                }
                errs.push((i, violation(node, why)));
            }
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
