// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `credentials` and `sandbox` tables to one `Cred` record.
use super::Cx;
use crate::schema::{Creds, Sandbox};
use qinit_db::{Cred, Seccomp, Securebits};

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
const NAMESPACES: [&str; 5] = ["mount", "pid", "ipc", "uts", "net"];

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

fn landlock_entry(s: &str) -> bool {
    (s.starts_with("ro:/") || s.starts_with("rw:/")) && !s.contains('\0')
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
    out.nnp = c.nnp.unwrap_or(false);
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
    let landlock = s.landlock.clone().unwrap_or_default();
    if let Some(bad) = landlock.iter().find(|e| !landlock_entry(e)) {
        let why = format!("landlock entry {bad:?} must start with ro:/ or rw:/ and hold no NUL");
        cx.bad(format!("{base}.sandbox.landlock"), why);
    }
    out.landlock = landlock;
    out.seccomp = match s.seccomp.as_deref() {
        None | Some("none") => Seccomp::None,
        Some("default") => Seccomp::Default,
        Some(x) => {
            cx.bad(
                format!("{base}.sandbox.seccomp"),
                format!("`{x}` is not none or default"),
            );
            Seccomp::None
        }
    };
}

/// The `Cred` of a frame, `None` when it has neither table. Without `credentials` the user is
/// empty, meaning no uid change.
pub(super) fn cred(
    cx: &mut Cx,
    base: &str,
    c: Option<&Creds>,
    s: Option<&Sandbox>,
) -> Option<Cred> {
    if c.is_none() && s.is_none() {
        return None;
    }
    let mut out = Cred {
        user: String::new(),
        caps: 0,
        securebits: Securebits::None,
        nnp: false,
        ns: 0,
        seccomp: Seccomp::None,
        landlock: Vec::new(),
    };
    if let Some(c) = c {
        from_creds(cx, base, c, &mut out);
    }
    if let Some(s) = s {
        from_sandbox(cx, base, s, &mut out);
    }
    Some(out)
}

/// The name (no `cap_` prefix) of capability number `bit`.
#[must_use]
pub(crate) fn cap_name(bit: u8) -> Option<&'static str> {
    CAPS.get(usize::from(bit)).copied()
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
