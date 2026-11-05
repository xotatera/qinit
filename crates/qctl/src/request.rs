// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The TOML request file of `qctl run` (spec 2026-11-05 §4.6): the fields of [`RequestSpec`]
//! with the names and spellings of `docs/launch-request.md`. A key the file does not know is an
//! error; a key it leaves out takes [`RequestSpec::default`].
use qinit_db::RLIMIT_KEYS;
use qinit_frames::resolve::{cap_bit, ns_name};
use qinit_frames::schema::{Rlimits, rlimit_value};
use qinit_launch::{RequestSpec, Seccomp, Securebits, Stream, UserMap};
use serde::Deserialize;

/// The file as written; every field optional but `argv`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    argv: Vec<String>,
    env: Option<Vec<String>>,
    cwd: Option<String>,
    umask: Option<u32>,
    rlimits: Option<Rlimits>,
    user: Option<String>,
    caps: Option<Vec<String>>,
    securebits: Option<String>,
    nnp: Option<bool>,
    namespaces: Option<Vec<String>>,
    user_map: Option<String>,
    inside_uid: Option<u32>,
    inside_gid: Option<u32>,
    seccomp: Option<String>,
    syscalls: Option<Vec<String>>,
    paths: Option<Vec<String>>,
    stdin: Option<String>,
    stdout: Option<String>,
    stderr: Option<String>,
    ready_fd: Option<u32>,
    die_with_parent: Option<bool>,
    deadline_ms: Option<u32>,
}

/// The request in `text`.
///
/// # Errors
/// The TOML error (an unknown key, a missing `argv`, a value of the wrong type), or the key and
/// why its value is not one: an unknown capability, namespace, syscall or mode, a stream that
/// is not a path, `"fd:N"` or `"same"`, a limit out of range.
pub fn parse(text: &str) -> Result<RequestSpec, String> {
    let f: File = toml::from_str(text).map_err(|e| e.to_string().trim_end().to_owned())?;
    let d = RequestSpec::default();
    Ok(RequestSpec {
        rlimits: rlimits(f.rlimits.as_ref())?,
        caps: caps(f.caps.as_deref().unwrap_or_default())?,
        securebits: securebits(f.securebits.as_deref())?,
        ns: namespaces(f.namespaces.as_deref().unwrap_or_default())?,
        user_map: match f.user_map.as_deref() {
            None | Some("own") => UserMap::Own,
            Some("range") => UserMap::Range,
            Some(o) => return Err(format!("user_map: `{o}` is not own or range")),
        },
        seccomp: seccomp(f.seccomp.as_deref(), f.syscalls.as_deref())?,
        stdin: stream("stdin", f.stdin, d.stdin, false)?,
        stdout: stream("stdout", f.stdout, d.stdout, false)?,
        stderr: stream("stderr", f.stderr, d.stderr, true)?,
        argv: f.argv,
        env: f.env.unwrap_or(d.env),
        cwd: f.cwd.unwrap_or(d.cwd),
        umask: f.umask.unwrap_or(d.umask),
        user: f.user.unwrap_or(d.user),
        nnp: f.nnp.unwrap_or(d.nnp),
        inside_uid: f.inside_uid.unwrap_or(d.inside_uid),
        inside_gid: f.inside_gid.unwrap_or(d.inside_gid),
        paths: f.paths.unwrap_or(d.paths),
        ready_fd: f.ready_fd.or(d.ready_fd),
        die_with_parent: f.die_with_parent.unwrap_or(d.die_with_parent),
        deadline_ms: f.deadline_ms.unwrap_or(d.deadline_ms),
    })
}

/// The limits by kernel resource number, through the frame schema's names and values.
fn rlimits(set: Option<&Rlimits>) -> Result<[Option<u64>; 16], String> {
    let mut out = [None; 16];
    let Some(set) = set else {
        return Ok(out);
    };
    for (r, slot) in out.iter_mut().enumerate() {
        if let Some(v) = set.get(r) {
            let key = RLIMIT_KEYS[r];
            *slot = Some(rlimit_value(key, v).map_err(|why| format!("rlimits.{key}: {why}"))?);
        }
    }
    Ok(out)
}

fn caps(names: &[String]) -> Result<u64, String> {
    names.iter().try_fold(0u64, |bits, n| {
        cap_bit(n)
            .map(|b| bits | (1u64 << b))
            .ok_or_else(|| format!("caps: unknown capability `{n}`"))
    })
}

fn namespaces(names: &[String]) -> Result<u32, String> {
    names.iter().try_fold(0u32, |bits, n| {
        (0u8..32)
            .find(|b| ns_name(*b) == Some(n.as_str()))
            .map(|b| bits | (1u32 << b))
            .ok_or_else(|| format!("namespaces: unknown namespace `{n}`"))
    })
}

fn securebits(s: Option<&str>) -> Result<Securebits, String> {
    match s {
        None | Some("none") => Ok(Securebits::None),
        Some("noroot") => Ok(Securebits::Noroot),
        Some("noroot-locked") => Ok(Securebits::NorootLocked),
        Some(o) => Err(format!(
            "securebits: `{o}` is not none, noroot or noroot-locked"
        )),
    }
}

/// `seccomp` names the mode; `syscalls` is the list of a `deny` or `allow` filter, by name.
fn seccomp(mode: Option<&str>, syscalls: Option<&[String]>) -> Result<Seccomp, String> {
    let list = || -> Result<Vec<u32>, String> {
        let names = syscalls.unwrap_or_default();
        if names.is_empty() {
            return Err("syscalls: a deny or allow filter needs at least one syscall".into());
        }
        names
            .iter()
            .map(|n| {
                qinit_frames::syscalls::number(n)
                    .ok_or_else(|| format!("syscalls: unknown syscall `{n}`"))
            })
            .collect()
    };
    match mode {
        None | Some("none" | "default") if syscalls.is_some() => {
            Err("syscalls: only a deny or allow seccomp filter takes a list".into())
        }
        None | Some("none") => Ok(Seccomp::None),
        Some("default") => Ok(Seccomp::Default),
        Some("deny") => list().map(Seccomp::Deny),
        Some("allow") => list().map(Seccomp::Allow),
        Some(o) => Err(format!(
            "seccomp: `{o}` is not none, default, deny or allow"
        )),
    }
}

/// A stream: `"same"` (standard error only), `"fd:N"`, or a path.
fn stream(key: &str, v: Option<String>, default: Stream, same_ok: bool) -> Result<Stream, String> {
    let Some(v) = v else {
        return Ok(default);
    };
    if v == "same" {
        return if same_ok {
            Ok(Stream::Same)
        } else {
            Err(format!(
                "{key}: only stderr can be \"same\" (wherever stdout goes)"
            ))
        };
    }
    match v.strip_prefix("fd:") {
        Some(n) => n
            .parse()
            .map(Stream::Fd)
            .map_err(|_| format!("{key}: `{v}` is not fd:N with a descriptor number")),
        None => Ok(Stream::Path(v)),
    }
}
