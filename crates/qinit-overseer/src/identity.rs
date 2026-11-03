// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Identity from `/etc/passwd` and `/etc/group` only, parsed strictly (spec R6): no NSS.
use qinit_sys::Errno;

/// A resolved account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub uid: u32,
    pub gid: u32,
    /// Supplementary groups: every group that lists the user as a member, sorted, once each.
    pub groups: Vec<u32>,
    pub home: String,
}

/// Why a user name did not resolve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityError {
    /// The name is outside `^[a-z_][a-z0-9_-]{0,31}$`.
    BadName,
    /// No passwd line has the name.
    Unknown,
    /// More than one passwd line has the name.
    Ambiguous,
    /// A passwd or group line (1-based) has the wrong field count or a non-numeric id.
    Malformed(usize),
    /// uid 0 under a name other than `root`.
    RootAlias,
    /// Reading `/etc/passwd` or `/etc/group` failed.
    Io(Errno),
}

fn name_ok(name: &str) -> bool {
    let b = name.as_bytes();
    let first = |c: u8| c.is_ascii_lowercase() || c == b'_';
    let rest = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-';
    (1..=32).contains(&b.len()) && first(b[0]) && b[1..].iter().copied().all(rest)
}

/// Lines with their 1-based numbers, the empty ones skipped.
fn lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l))
        .filter(|(_, l)| !l.is_empty())
}

/// Resolves `user` against the text of `passwd` and `group`.
///
/// # Errors
/// See [`IdentityError`]; every passwd and group line is checked, not only the matching one.
pub fn parse(user: &str, passwd: &str, group: &str) -> Result<Identity, IdentityError> {
    if !name_ok(user) {
        return Err(IdentityError::BadName);
    }
    let mut found: Option<(u32, u32, &str)> = None;
    let mut count = 0;
    for (n, line) in lines(passwd) {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() != 7 {
            return Err(IdentityError::Malformed(n));
        }
        let (Ok(uid), Ok(gid)) = (f[2].parse::<u32>(), f[3].parse::<u32>()) else {
            return Err(IdentityError::Malformed(n));
        };
        if f[0] == user {
            count += 1;
            found = Some((uid, gid, f[5]));
        }
    }
    let Some((uid, gid, home)) = found else {
        return Err(IdentityError::Unknown);
    };
    if count > 1 {
        return Err(IdentityError::Ambiguous);
    }
    if uid == 0 && user != "root" {
        return Err(IdentityError::RootAlias);
    }
    let mut groups = Vec::new();
    for (n, line) in lines(group) {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() != 4 {
            return Err(IdentityError::Malformed(n));
        }
        let Ok(g) = f[2].parse::<u32>() else {
            return Err(IdentityError::Malformed(n));
        };
        if f[3].split(',').any(|m| m == user) {
            groups.push(g);
        }
    }
    groups.sort_unstable();
    groups.dedup();
    Ok(Identity {
        uid,
        gid,
        groups,
        home: home.to_owned(),
    })
}

/// Resolves `user` from `/etc/passwd` and `/etc/group`; the name is checked before any read.
///
/// # Errors
/// See [`IdentityError`].
pub fn resolve(user: &str) -> Result<Identity, IdentityError> {
    if !name_ok(user) {
        return Err(IdentityError::BadName);
    }
    let read = |p: &str| {
        std::fs::read_to_string(p)
            .map_err(|e| IdentityError::Io(Errno(e.raw_os_error().unwrap_or(libc::EIO))))
    };
    parse(user, &read("/etc/passwd")?, &read("/etc/group")?)
}
