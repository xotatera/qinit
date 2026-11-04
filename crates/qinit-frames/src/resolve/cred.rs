// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `credentials` and `sandbox` tables to one `Cred` record.
use super::Cx;
use crate::schema::{Creds, Sandbox, SeccompCfg};
use crate::syscalls;
use qinit_db::{Cred, Seccomp, Securebits, UserMap};
use qinit_db_core::CAP_SYS_ADMIN_BIT;

/// Capability names without the `cap_` prefix; the index is the capability number.
const CAPS: [&str; 41] = [
    "chown",
    "dac_override",
    "dac_read_search",
    "fowner",
    "fsetid",
    "kill",
    "setgid",
    "setuid",
    "setpcap",
    "linux_immutable",
    "net_bind_service",
    "net_broadcast",
    "net_admin",
    "net_raw",
    "ipc_lock",
    "ipc_owner",
    "sys_module",
    "sys_rawio",
    "sys_chroot",
    "sys_ptrace",
    "sys_pacct",
    "sys_admin",
    "sys_boot",
    "sys_nice",
    "sys_resource",
    "sys_time",
    "sys_tty_config",
    "mknod",
    "lease",
    "audit_write",
    "audit_control",
    "setfcap",
    "mac_override",
    "mac_admin",
    "syslog",
    "wake_alarm",
    "block_suspend",
    "audit_read",
    "perfmon",
    "bpf",
    "checkpoint_restore",
];

/// Namespace names; the index is the bit in `Cred::ns`.
const NAMESPACES: [&str; 6] = ["mount", "pid", "ipc", "uts", "net", "user"];

/// The capability number of `name` (no `cap_` prefix), 0 to 40.
#[must_use]
pub(crate) fn cap_bit(name: &str) -> Option<u8> {
    CAPS.iter()
        .position(|c| *c == name)
        .and_then(|i| u8::try_from(i).ok())
}

fn caps(cx: &mut Cx, key: &str, names: &[String]) -> u64 {
    let mut bits = 0u64;
    for n in names {
        match cap_bit(n) {
            Some(b) => bits |= 1u64 << b,
            None => cx.bad(key, format!("unknown capability `{n}`")),
        }
    }
    bits
}

fn namespaces(cx: &mut Cx, key: &str, names: &[String]) -> u32 {
    let mut bits = 0u32;
    for n in names {
        match NAMESPACES.iter().position(|x| x == n) {
            Some(b) => bits |= 1u32 << b,
            None => cx.bad(key, format!("unknown namespace `{n}`")),
        }
    }
    bits
}

/// A canonical absolute path: starts with `/`, no empty, `.` or `..` component, no trailing `/`
/// (except `/` itself), no NUL. The same rule as the validator's `canonical` (spec §2.1).
pub(crate) fn canonical(p: &str) -> bool {
    p.starts_with('/')
        && !p.contains('\0')
        && (p == "/"
            || p[1..]
                .split('/')
                .all(|c| !c.is_empty() && c != "." && c != ".."))
}

/// The modes of a path entry, three bytes before the path: read-only, writable, and each of
/// them idmapped (`i`) or following the host's later mounts (`s`).
const MODES: [&str; 6] = ["ro:", "rw:", "ri:", "wi:", "rs:", "ws:"];

/// The path of an entry, when it starts with one of the [`MODES`].
fn entry_path(s: &str) -> Option<&str> {
    MODES.iter().find_map(|m| s.strip_prefix(m))
}

fn path_entry(s: &str) -> bool {
    entry_path(s).is_some_and(canonical)
}

/// The entry's mode is idmapped (`ri:` or `wi:`).
fn idmapped(e: &str) -> bool {
    e.starts_with("ri:") || e.starts_with("wi:")
}

/// The `user` bit of `Cred::ns`.
const USER_BIT: u32 = 1 << 5;

/// The id map of a user namespace: `own` (the default) or `range`; either word needs the
/// `user` namespace.
fn user_map(cx: &mut Cx, base: &str, word: Option<&str>, ns: u32) -> UserMap {
    let key = format!("{base}.sandbox.user_map");
    let map = match word {
        None | Some("own") => UserMap::Own,
        Some("range") => UserMap::Range,
        Some(w) => {
            cx.bad(&key, format!("`{w}` is not own or range"));
            UserMap::Own
        }
    };
    if word.is_some() && ns & USER_BIT == 0 {
        cx.bad(&key, "user_map needs \"user\" in namespaces");
    }
    map
}

/// `e` is an entry a list may not hold: `/`, `/dev`, `/tmp`, or `/proc` writable (`rw:`, `wi:`
/// or `ws:`).
fn forbidden(e: &str) -> bool {
    let path = &e[3..];
    let writable = ["rw:", "wi:", "ws:"].iter().any(|m| e.starts_with(m));
    matches!(path, "/" | "/dev" | "/tmp") || (writable && path == "/proc")
}

/// The entries ordered by path, bytewise; a forbidden or repeated path is refused (and the
/// list kept as given, since the error ends the compile).
fn sorted_paths(cx: &mut Cx, base: &str, mut paths: Vec<String>) -> Vec<String> {
    let key = format!("{base}.sandbox.paths");
    if !paths.iter().all(|e| path_entry(e)) {
        return paths;
    }
    if let Some(bad) = paths.iter().find(|e| forbidden(e)) {
        let why = format!("path entry {bad:?} is built by the view itself and cannot be listed");
        cx.bad(&key, why);
        return paths;
    }
    paths.sort_by(|a, b| a[3..].cmp(&b[3..]));
    if let Some(w) = paths.windows(2).find(|w| w[0][3..] == w[1][3..]) {
        let why = format!(
            "path {:?} is listed twice ({:?} and {:?})",
            &w[0][3..],
            w[0],
            w[1]
        );
        cx.bad(&key, why);
    }
    paths
}

/// `path` is `entry` or below it, by whole components.
fn at_or_below(path: &str, entry: &str) -> bool {
    path == entry
        || path
            .strip_prefix(entry)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// With a path list, the program and the working directory are inside it: `exec[0]` is
/// absolute and at or below an entry, and `cwd` is `/` or at or below an entry.
pub(crate) fn check_inside_paths(cx: &mut Cx, base: &str, c: &Cred, exec: &[String], cwd: &str) {
    if c.paths.is_empty() || !c.paths.iter().all(|e| path_entry(e)) {
        return;
    }
    let covered = |p: &str| c.paths.iter().any(|e| at_or_below(p, &e[3..]));
    if let Some(program) = exec.first() {
        if !program.starts_with('/') {
            let why =
                format!("with sandbox.paths the program {program:?} must be an absolute path");
            cx.bad(format!("{base}.exec"), why);
        } else if !covered(program) {
            let why = format!("the program {program:?} is not inside any sandbox.paths entry");
            cx.bad(format!("{base}.exec"), why);
        }
    }
    if cwd != "/" && canonical(cwd) && !covered(cwd) {
        let why = format!("the working directory {cwd:?} is not inside any sandbox.paths entry");
        cx.bad(format!("{base}.cwd"), why);
    }
}

fn from_creds(cx: &mut Cx, base: &str, c: &Creds, out: &mut Cred) {
    if cx.text(&format!("{base}.credentials.uid"), &c.uid) {
        out.user.clone_from(&c.uid);
    }
    out.caps = caps(
        cx,
        &format!("{base}.credentials.caps"),
        c.caps.as_deref().unwrap_or_default(),
    );
    out.nnp = c.nnp.unwrap_or(true);
    out.securebits = match c.securebits.as_deref() {
        None | Some("none") => Securebits::None,
        Some("noroot") => Securebits::Noroot,
        Some("noroot-locked") => Securebits::NorootLocked,
        Some(s) => {
            let why = format!("`{s}` is not none, noroot or noroot-locked");
            cx.bad(format!("{base}.credentials.securebits"), why);
            Securebits::None
        }
    };
}

fn from_sandbox(cx: &mut Cx, base: &str, s: &Sandbox, out: &mut Cred) {
    let key = format!("{base}.sandbox.namespaces");
    out.ns = namespaces(cx, &key, s.namespaces.as_deref().unwrap_or_default());
    let paths = s.paths.clone().unwrap_or_default();
    if let Some(bad) = paths.iter().find(|e| !path_entry(e)) {
        let why = format!(
            "path entry {bad:?} must start with ro:, rw:, ri:, wi:, rs: or ws: and have a canonical absolute path"
        );
        cx.bad(format!("{base}.sandbox.paths"), why);
    } else if let Some(bad) = paths.iter().find(|e| idmapped(e))
        && out.ns & USER_BIT == 0
    {
        let why = format!("path entry {bad:?} is idmapped and needs \"user\" in namespaces");
        cx.bad(format!("{base}.sandbox.paths"), why);
    }
    out.user_map = user_map(cx, base, s.user_map.as_deref(), out.ns);
    out.paths = sorted_paths(cx, base, paths);
    if !out.paths.is_empty() {
        // A path list is a view: it needs its own mount namespace.
        out.ns |= 1;
    }
    let key = format!("{base}.sandbox.seccomp");
    out.seccomp = match &s.seccomp {
        None => Seccomp::None,
        Some(SeccompCfg::Kind(k)) if k == "none" => Seccomp::None,
        Some(SeccompCfg::Kind(k)) if k == "default" => Seccomp::Default,
        Some(SeccompCfg::Kind(k)) => {
            let why =
                format!("`{k}` is not none, default, {{ deny = [...] }} or {{ allow = [...] }}");
            cx.bad(key, why);
            Seccomp::None
        }
        Some(SeccompCfg::Deny { deny }) => {
            // The program answers these four before it reads the list (clone and unshare by
            // their flags, setns always, clone3 with ENOSYS), so naming one would change nothing.
            for n in deny
                .iter()
                .filter(|n| ALWAYS_ANSWERED.contains(&n.as_str()))
            {
                let why =
                    format!("`{n}` is already restricted by the sandbox and cannot be listed");
                cx.bad(key.clone(), why);
            }
            Seccomp::Deny(syscall_numbers(cx, &key, deny))
        }
        Some(SeccompCfg::Allow { allow }) => Seccomp::Allow(syscall_numbers(cx, &key, allow)),
    };
}

/// The calls the seccomp program answers by itself in every mode but `allow`.
const ALWAYS_ANSWERED: [&str; 4] = ["clone", "unshare", "clone3", "setns"];

/// The numbers of the syscall `names`; an unknown name or an empty list is a `BadValue`.
fn syscall_numbers(cx: &mut Cx, key: &str, names: &[String]) -> Vec<u32> {
    if names.is_empty() {
        cx.bad(key, "a seccomp list needs at least one syscall");
    }
    let mut out = Vec::new();
    for n in names {
        match syscalls::number(n) {
            Some(nr) => out.push(nr),
            None => cx.bad(key, format!("unknown syscall `{n}`")),
        }
    }
    out
}

/// The `Cred` of a frame: `None` without `credentials` (the caller has reported the missing
/// user); otherwise the identity from `credentials` and the sandbox from `sandbox`, which
/// has no effect on its own. Installing a Landlock ruleset or a seccomp filter without
/// `no_new_privs` needs `CAP_SYS_ADMIN`, so `nnp = false` next to either is refused without it.
pub(super) fn cred(
    cx: &mut Cx,
    base: &str,
    c: Option<&Creds>,
    s: Option<&Sandbox>,
) -> Option<Cred> {
    let c = c?;
    let mut out = Cred {
        user: String::new(),
        caps: 0,
        securebits: Securebits::None,
        nnp: true,
        ns: 0,
        seccomp: Seccomp::None,
        paths: Vec::new(),
        user_map: UserMap::Own,
    };
    from_creds(cx, base, c, &mut out);
    if let Some(s) = s {
        from_sandbox(cx, base, s, &mut out);
    }
    if out.ns & USER_BIT != 0 && out.user == "root" {
        cx.bad(
            format!("{base}.credentials.uid"),
            "a user namespace maps the service to inside root: its uid names the outside user, which cannot be root",
        );
    }
    let restricts = !out.paths.is_empty() || out.seccomp != Seccomp::None;
    if !out.nnp && restricts && out.caps & (1 << CAP_SYS_ADMIN_BIT) == 0 {
        cx.bad(
            format!("{base}.credentials.nnp"),
            "nnp = false with a Landlock list or seccomp needs sys_admin in caps",
        );
    }
    Some(out)
}

/// The name (no `cap_` prefix) of capability number `bit`.
#[must_use]
pub(crate) fn cap_name(bit: u8) -> Option<&'static str> {
    CAPS.get(usize::from(bit)).copied()
}

/// The name of namespace bit `bit` of `Cred::ns`.
#[must_use]
pub(crate) fn ns_name(bit: u8) -> Option<&'static str> {
    NAMESPACES.get(usize::from(bit)).copied()
}

#[cfg(test)]
mod tests {
    use super::{CAPS, cap_bit, cap_name};

    #[test]
    fn cap_name_inverts_cap_bit_for_every_name() {
        assert_eq!(CAPS.len(), 41);
        for n in CAPS {
            let b = cap_bit(n).expect("known");
            assert_eq!(cap_name(b), Some(n));
        }
        assert_eq!(cap_name(41), None);
    }
}
