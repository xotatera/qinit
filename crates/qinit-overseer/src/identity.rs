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
    /// The user's range in `/etc/subuid` (first id, count), read only for a range map.
    pub subuid: Option<(u32, u32)>,
    /// The user's range in `/etc/subgid`, read only for a range map.
    pub subgid: Option<(u32, u32)>,
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
    /// A user other than `root` whose primary or supplementary group is gid 0: the group of
    /// root owns files that no service account should reach by name.
    RootGroup,
    /// Reading `/etc/passwd`, `/etc/group`, `/etc/subuid` or `/etc/subgid` failed.
    Io(Errno),
    /// No `/etc/subuid` or `/etc/subgid` line has the name.
    SubidMissing,
    /// More than one line has the name.
    SubidAmbiguous,
    /// A subid line (1-based) is not `name:first:count` with decimal numbers, `first` and
    /// `count` at least 1, and `first + count` at most `2^32 - 1`.
    SubidMalformed(usize),
    /// The range holds an id of `/etc/passwd` (`/etc/group`).
    SubidOverlap,
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
    if user != "root" && (gid == 0 || groups.first() == Some(&0)) {
        return Err(IdentityError::RootGroup);
    }
    Ok(Identity {
        uid,
        gid,
        groups,
        home: home.to_owned(),
        subuid: None,
        subgid: None,
    })
}

/// A decimal id: digits only, no sign and no leading zero, in `u32`.
fn decimal(s: &str) -> Option<u32> {
    let ok =
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    if ok { s.parse().ok() } else { None }
}

/// The range of `user` in the text of `/etc/subuid` or `/etc/subgid`: lines `name:first:count`,
/// the name by the grammar of [`parse`] (a numeric first field is refused, not resolved),
/// decimal numbers, `first` and `count` at least 1, `first + count` at most `2^32 - 1`, exactly
/// one line for `user`, and no id of `taken` (the uids of passwd, or the gids of group) inside it.
///
/// # Errors
/// See [`IdentityError`]; every line is checked, not only the matching one.
pub fn parse_subids(user: &str, text: &str, taken: &[u32]) -> Result<(u32, u32), IdentityError> {
    let mut found: Option<(u32, u32)> = None;
    let mut count = 0;
    for (n, line) in lines(text) {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() != 3 || !name_ok(f[0]) {
            return Err(IdentityError::SubidMalformed(n));
        }
        let (Some(first), Some(len)) = (decimal(f[1]), decimal(f[2])) else {
            return Err(IdentityError::SubidMalformed(n));
        };
        if first < 1 || len < 1 || u64::from(first) + u64::from(len) > u64::from(u32::MAX) {
            return Err(IdentityError::SubidMalformed(n));
        }
        if f[0] == user {
            count += 1;
            found = Some((first, len));
        }
    }
    let Some((first, len)) = found else {
        return Err(IdentityError::SubidMissing);
    };
    if count > 1 {
        return Err(IdentityError::SubidAmbiguous);
    }
    let end = u64::from(first) + u64::from(len);
    if taken
        .iter()
        .any(|t| u64::from(*t) >= u64::from(first) && u64::from(*t) < end)
    {
        return Err(IdentityError::SubidOverlap);
    }
    Ok((first, len))
}

/// The ids in column `column` of the colon-separated `text`, the lines that do not parse
/// skipped (the strict parse of the same text has already refused them).
fn ids(text: &str, column: usize) -> Vec<u32> {
    lines(text)
        .filter_map(|(_, l)| l.split(':').nth(column)?.parse().ok())
        .collect()
}

/// Resolves `user` from `/etc/passwd` and `/etc/group`, and with `range` also its subordinate
/// ranges from `/etc/subuid` and `/etc/subgid`; the name is checked before any read.
///
/// # Errors
/// See [`IdentityError`].
pub fn resolve(user: &str, range: bool) -> Result<Identity, IdentityError> {
    if !name_ok(user) {
        return Err(IdentityError::BadName);
    }
    let read = |p: &str| {
        std::fs::read_to_string(p)
            .map_err(|e| IdentityError::Io(Errno(e.raw_os_error().unwrap_or(libc::EIO))))
    };
    let (passwd, group) = (read("/etc/passwd")?, read("/etc/group")?);
    let mut id = parse(user, &passwd, &group)?;
    if range {
        id.subuid = Some(parse_subids(user, &read("/etc/subuid")?, &ids(&passwd, 2))?);
        id.subgid = Some(parse_subids(user, &read("/etc/subgid")?, &ids(&group, 2))?);
    }
    Ok(id)
}
