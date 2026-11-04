// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The deterministic writer: `Model` to database bytes.

use crate::crc::file_crc;
use crate::model::{
    Cred, Edge, GroupKind, Kind, Launch, Mode, Model, Node, Policy, PolicyRule, Ready, Reload,
    RestartOn, RestartPolicy, Route, Seccomp, Securebits, StopMode, Target, UserMap, Userns,
};
use qinit_db_core::{
    HEADER_WORDS, MAGIC, MAX_CREDS, MAX_EDGES, MAX_EDGES_PER_GROUP, MAX_GROUPS,
    MAX_GROUPS_PER_NODE, MAX_NAME_LEN, MAX_NODES, MAX_POLICY_RULES, MAX_POOL, MAX_ROUTES,
    MAX_SYSCALL, N_RLIMIT_BASE, NONE, P_ALLOW_INSIDE_IDS, P_ALLOW_USERNS, P_CAPS_HI, P_CAPS_LO,
    P_PATTERN_LEN, P_PATTERN_OFF, P_REQUIRE_NNP, P_REQUIRE_SECCOMP, P_RLIMIT_BASE, P_RLIMIT_MASK,
    P_USERS_ANY, P_USERS_LEN, P_USERS_OFF, PH_ALLOW, PH_RLIMIT_BASE, PH_RLIMIT_MASK, RLIMIT_COUNT,
    SECCOMP_ALLOW, SECCOMP_DEFAULT, SECCOMP_DENY, SECCOMP_NONE, T_POOL, VERSION, WORDS,
};
use std::collections::BTreeMap;

/// Why a model cannot be written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// A limit is exceeded; the name says which.
    Limit(&'static str),
    /// Node names are not strictly ascending.
    Unsorted,
    /// An index points outside its table.
    Index,
}

/// The string pool, interning in first-come order.
#[derive(Default)]
struct Pool {
    bytes: Vec<u8>,
    seen: BTreeMap<String, (u32, u32)>,
}

impl Pool {
    /// `(offset, length)` of `s`; the empty string is `(0, 0)`.
    fn intern(&mut self, s: &str) -> Result<(u32, u32), WriteError> {
        if s.is_empty() {
            return Ok((0, 0));
        }
        if let Some(r) = self.seen.get(s) {
            return Ok(*r);
        }
        let off = u32::try_from(self.bytes.len()).map_err(|_| WriteError::Limit("pool"))?;
        let len = u32::try_from(s.len()).map_err(|_| WriteError::Limit("pool"))?;
        self.bytes.extend_from_slice(s.as_bytes());
        if self.bytes.len() > MAX_POOL {
            return Err(WriteError::Limit("pool"));
        }
        self.seen.insert(s.to_owned(), (off, len));
        Ok((off, len))
    }

    /// Several strings joined by NUL. An empty or NUL-bearing element would not decode back
    /// to the same list, so it is refused.
    fn intern_list(&mut self, list: &[String]) -> Result<(u32, u32), WriteError> {
        for item in list {
            if item.is_empty() {
                return Err(WriteError::Limit("empty list element"));
            }
            if item.contains('\0') {
                return Err(WriteError::Limit("nul in list element"));
            }
        }
        self.intern(&list.join("\0"))
    }
}

fn count(n: usize, limit: usize, what: &'static str) -> Result<u32, WriteError> {
    if n > limit {
        return Err(WriteError::Limit(what));
    }
    u32::try_from(n).map_err(|_| WriteError::Limit(what))
}

fn in_range(index: u32, len: usize) -> Result<(), WriteError> {
    if (index as usize) < len {
        Ok(())
    } else {
        Err(WriteError::Index)
    }
}

fn opt_in_range(index: Option<u32>, len: usize) -> Result<u32, WriteError> {
    match index {
        None => Ok(NONE),
        Some(i) => in_range(i, len).map(|()| i),
    }
}

fn kind_word(k: Kind) -> u32 {
    match k {
        Kind::Worker => 0,
        Kind::Forager => 1,
        Kind::Brood => 2,
    }
}

fn policy_word(p: RestartPolicy) -> u32 {
    match p {
        RestartPolicy::Never => 0,
        RestartPolicy::OnFailure => 1,
        RestartPolicy::Always => 2,
    }
}

/// The database word of a group kind.
#[must_use]
pub fn group_word(k: GroupKind) -> u32 {
    match k {
        GroupKind::RequireAll => 0,
        GroupKind::RequireAny => 1,
        GroupKind::OptionalAll => 2,
        GroupKind::ExcludeAll => 3,
    }
}

fn restart_on_word(r: RestartOn) -> u32 {
    match r {
        RestartOn::None => 0,
        RestartOn::Error => 1,
        RestartOn::Restart => 2,
        RestartOn::Refresh => 3,
    }
}

/// The node record, with its group run starting at `group_first`; `limits` are the route and
/// credential counts.
fn node_words(
    n: &Node,
    pool: &mut Pool,
    group_first: u32,
    limits: (usize, usize),
) -> Result<[u32; WORDS[0]], WriteError> {
    let (routes, creds) = limits;
    if n.name.is_empty() || n.name.len() > MAX_NAME_LEN {
        return Err(WriteError::Limit("name"));
    }
    let name = pool.intern(&n.name)?;
    let exec = pool.intern_list(&n.exec)?;
    let (ready_kind, ready) = match &n.ready {
        Ready::Pipe => (0, (0, 0)),
        Ready::Exit => (1, (0, 0)),
        Ready::Socket(s) => (2, pool.intern(s)?),
        Ready::Path(s) => (3, pool.intern(s)?),
    };
    let instance = match &n.instance_of {
        Some(s) if s.is_empty() => return Err(WriteError::Limit("empty instance_of")),
        Some(s) => pool.intern(s)?,
        None => (0, 0),
    };
    let group_count = count(n.groups.len(), MAX_GROUPS_PER_NODE, "groups per node")?;
    let env = pool.intern_list(&n.env)?;
    let cwd = pool.intern(&n.cwd)?;
    let launch = launch_words(n.launch.as_ref(), pool)?;
    let head = [
        kind_word(n.kind),
        name.0,
        name.1,
        exec.0,
        exec.1,
        ready_kind,
        ready.0,
        ready.1,
        policy_word(n.restart.policy),
        n.restart.max,
        n.restart.window_ms,
        opt_in_range(n.output, routes)?,
        opt_in_range(n.errors, routes)?,
        opt_in_range(n.cred, creds)?,
        group_first,
        group_count,
        n.memory_max_kib,
        n.pids_max,
        instance.0,
        instance.1,
        n.restart.delay_ms,
        u32::from(n.stop.mode == StopMode::Cell),
        n.stop.grace_ms,
        n.start_timeout_ms,
        env.0,
        env.1,
        cwd.0,
        cwd.1,
        n.umask,
        rlimit_mask(&n.rlimits),
        match n.reload {
            None => 0,
            Some(Reload::Hup) => 1,
            Some(Reload::Usr1) => 2,
            Some(Reload::Usr2) => 3,
        },
        launch[0],
        launch[1],
        launch[2],
        launch[3],
        launch[4],
    ];
    let mut words = [0u32; WORDS[0]];
    words[..head.len()].copy_from_slice(&head);
    for (r, limit) in n.rlimits.iter().enumerate() {
        if let Some(v) = *limit
            && !rlimit_writable(r, v)
        {
            return Err(WriteError::Limit("rlimit"));
        }
        let v = limit.unwrap_or(0);
        #[allow(clippy::cast_possible_truncation)] // the low word, then the high word
        {
            words[N_RLIMIT_BASE + 2 * r] = v as u32;
            words[N_RLIMIT_BASE + 2 * r + 1] = (v >> 32) as u32;
        }
    }
    Ok(words)
}

/// Whether the validator would take limit `v` of resource `r`: not `core`, `nofile` finite and
/// at least 1, `nice` at most 40, `rtprio` at most 99.
fn rlimit_writable(r: usize, v: u64) -> bool {
    match r {
        4 => false,
        7 => (1..u64::MAX).contains(&v),
        13 => v <= 40,
        14 => v <= 99,
        _ => true,
    }
}

/// The `rlimit_mask` word: bit `r` is set when resource `r` has a limit.
fn rlimit_mask(limits: &[Option<u64>; RLIMIT_COUNT]) -> u32 {
    limits
        .iter()
        .enumerate()
        .fold(0, |m, (r, l)| m | (u32::from(l.is_some()) << r))
}

/// The launch words of a node: concurrency, argv tail, env offset and length, descriptor mask.
fn launch_words(l: Option<&Launch>, pool: &mut Pool) -> Result<[u32; 5], WriteError> {
    let Some(l) = l else {
        return Ok([0; 5]);
    };
    let env = pool.intern_list(&l.env)?;
    Ok([l.concurrency, l.argv_tail, env.0, env.1, l.fds])
}

/// The seccomp mode word and the list as canonical decimals (`n.to_string()` for `n <
/// MAX_SYSCALL`, which has no leading zero).
fn seccomp_words(s: &Seccomp, pool: &mut Pool) -> Result<(u32, (u32, u32)), WriteError> {
    let (mode, list) = match s {
        Seccomp::None => return Ok((SECCOMP_NONE, (0, 0))),
        Seccomp::Default => return Ok((SECCOMP_DEFAULT, (0, 0))),
        Seccomp::Deny(list) => (SECCOMP_DENY, list),
        Seccomp::Allow(list) => (SECCOMP_ALLOW, list),
    };
    if list.is_empty() {
        return Err(WriteError::Limit("seccomp list"));
    }
    if list.iter().any(|n| *n >= MAX_SYSCALL) {
        return Err(WriteError::Limit("syscall"));
    }
    let text: Vec<String> = list.iter().map(u32::to_string).collect();
    Ok((mode, pool.intern_list(&text)?))
}

fn edge_words(e: &Edge, pool: &mut Pool, nodes: usize) -> Result<[u32; 7], WriteError> {
    let (kind, target, len) = match &e.target {
        Target::Node(i) => {
            in_range(*i, nodes)?;
            (0, *i, 0)
        }
        Target::Path(p) => {
            let (off, len) = pool.intern(p)?;
            (1, off, len)
        }
    };
    Ok([
        kind,
        target,
        len,
        u32::from(e.mode == Mode::Async),
        e.deadline_ms,
        restart_on_word(e.restart_on),
        u32::from(e.stop_parallel) | (u32::from(e.cascade) << 1),
    ])
}

fn cred_words(c: &Cred, pool: &mut Pool) -> Result<[u32; 15], WriteError> {
    let user = pool.intern(&c.user)?;
    let paths = pool.intern_list(&c.paths)?;
    let (seccomp, list) = seccomp_words(&c.seccomp, pool)?;
    Ok([
        user.0,
        user.1,
        u32::try_from(c.caps & 0xFFFF_FFFF).unwrap_or(0),
        u32::try_from(c.caps >> 32).unwrap_or(0),
        match c.securebits {
            Securebits::None => 0,
            Securebits::Noroot => 1,
            Securebits::NorootLocked => 2,
        },
        u32::from(c.nnp),
        c.ns,
        seccomp,
        paths.0,
        paths.1,
        list.0,
        list.1,
        u32::from(c.user_map == UserMap::Range),
        c.inside_uid,
        c.inside_gid,
    ])
}

/// The 16 low/high limit pairs of `limits` and the mask of the ones set, refusing what the
/// validator would.
fn limit_pairs(limits: &[Option<u64>; 16]) -> Result<(u32, [u32; 32]), WriteError> {
    let mut words = [0u32; 32];
    for (r, limit) in limits.iter().enumerate() {
        if let Some(v) = *limit
            && !rlimit_writable(r, v)
        {
            return Err(WriteError::Limit("rlimit"));
        }
        let v = limit.unwrap_or(0);
        #[allow(clippy::cast_possible_truncation)] // the low word, then the high word
        {
            words[2 * r] = v as u32;
            words[2 * r + 1] = (v >> 32) as u32;
        }
    }
    Ok((rlimit_mask(limits), words))
}

fn rule_words(r: &PolicyRule, pool: &mut Pool) -> Result<[u32; 44], WriteError> {
    let pattern = pool.intern(&r.pattern)?;
    let users = match &r.users {
        Some(u) => pool.intern_list(u)?,
        None => (0, 0),
    };
    let (mask, pairs) = limit_pairs(&r.rlimits)?;
    let mut words = [0u32; 44];
    words[P_PATTERN_OFF] = pattern.0;
    words[P_PATTERN_LEN] = pattern.1;
    words[P_USERS_OFF] = users.0;
    words[P_USERS_LEN] = users.1;
    words[P_USERS_ANY] = u32::from(r.users.is_none());
    words[P_CAPS_LO] = u32::try_from(r.caps_max & 0xFFFF_FFFF).unwrap_or(0);
    words[P_CAPS_HI] = u32::try_from(r.caps_max >> 32).unwrap_or(0);
    words[P_REQUIRE_NNP] = u32::from(r.require_nnp);
    words[P_REQUIRE_SECCOMP] = u32::from(r.require_seccomp);
    words[P_ALLOW_USERNS] = match r.allow_userns {
        Userns::No => 0,
        Userns::Own => 1,
        Userns::Range => 2,
    };
    words[P_ALLOW_INSIDE_IDS] = u32::from(r.allow_inside_ids);
    words[P_RLIMIT_MASK] = mask;
    words[P_RLIMIT_BASE..P_RLIMIT_BASE + 32].copy_from_slice(&pairs);
    Ok(words)
}

fn head_words(p: &Policy) -> Result<[u32; 34], WriteError> {
    let (mask, pairs) = limit_pairs(&p.ceiling)?;
    let mut words = [0u32; 34];
    words[PH_ALLOW] = u32::from(p.allow_by_default);
    words[PH_RLIMIT_MASK] = mask;
    words[PH_RLIMIT_BASE..].copy_from_slice(&pairs);
    Ok(words)
}

fn route_words(r: &Route, pool: &mut Pool, nodes: usize) -> Result<[u32; 3], WriteError> {
    match r {
        Route::Path(p) => {
            let (off, len) = pool.intern(p)?;
            Ok([0, off, len])
        }
        Route::Pipe(i) => {
            in_range(*i, nodes)?;
            Ok([1, *i, 0])
        }
    }
}

fn list_words(list: &[u32], nodes: usize) -> Result<Vec<u32>, WriteError> {
    count(list.len(), MAX_NODES, "list")?;
    for i in list {
        in_range(*i, nodes)?;
    }
    Ok(list.to_vec())
}

/// Writes `model` as a database. Equal models give identical bytes, and every model it accepts
/// decodes back to itself.
///
/// It checks only ranges, limits and sort order. It does NOT check the validator's semantic
/// rules (forager/brood restart policy, brood exec, sync-edge deadline, pipe route target
/// kind, caps/ns bit ranges, required credentials, environment and cwd content, the `nnp`
/// rule, enabled/presyslog order and closure): callers must run [`crate::open`] on the result.
///
/// # Errors
/// A limit overflow, unsorted node names, or an index out of range. The checks run in a fixed
/// order, so the reported error does not depend on which problem the input happens to hit first:
/// 1. the table counts (nodes, creds, routes) against their limits (`Limit`);
/// 2. node-name order (`Unsorted`);
/// 3. per node, in order: the name and field limits, the group and edge counts (`Limit`), and
///    node, route and cred indices (`Index`), then creds, routes, and the enabled and presyslog
///    lists.
pub fn write(model: &Model) -> Result<Vec<u8>, WriteError> {
    let nodes = model.nodes.len();
    count(nodes, MAX_NODES, "nodes")?;
    count(model.creds.len(), MAX_CREDS, "creds")?;
    count(model.routes.len(), MAX_ROUTES, "routes")?;
    if !model.nodes.windows(2).all(|w| w[0].name < w[1].name) {
        return Err(WriteError::Unsorted);
    }
    let mut pool = Pool::default();
    // Tables in header order: nodes, groups, edges, creds, routes, enabled, presyslog, policy
    // rules, policy header.
    let mut tables: [Vec<u32>; 9] = Default::default();
    let mut group_total = 0usize;
    let mut edge_total = 0usize;
    for n in &model.nodes {
        let first = count(group_total, MAX_GROUPS, "groups")?;
        let words = node_words(n, &mut pool, first, (model.routes.len(), model.creds.len()))?;
        tables[0].extend_from_slice(&words);
        for g in &n.groups {
            let edge_first = count(edge_total, MAX_EDGES, "edges")?;
            let edge_count = count(g.edges.len(), MAX_EDGES_PER_GROUP, "edges per group")?;
            tables[1].extend_from_slice(&[group_word(g.kind), edge_first, edge_count]);
            for e in &g.edges {
                tables[2].extend_from_slice(&edge_words(e, &mut pool, nodes)?);
            }
            edge_total += g.edges.len();
            group_total += 1;
            count(group_total, MAX_GROUPS, "groups")?;
            count(edge_total, MAX_EDGES, "edges")?;
        }
    }
    for c in &model.creds {
        tables[3].extend_from_slice(&cred_words(c, &mut pool)?);
    }
    for r in &model.routes {
        tables[4].extend_from_slice(&route_words(r, &mut pool, nodes)?);
    }
    tables[5] = list_words(&model.enabled, nodes)?;
    tables[6] = list_words(&model.presyslog, nodes)?;
    if let Some(p) = &model.policy {
        count(p.rules.len(), MAX_POLICY_RULES, "policy rules")?;
        for r in &p.rules {
            tables[7].extend_from_slice(&rule_words(r, &mut pool)?);
        }
        tables[8].extend_from_slice(&head_words(p)?);
    }

    let size = |n: usize| u32::try_from(n).map_err(|_| WriteError::Limit("size"));
    let mut header = [0u32; HEADER_WORDS];
    header[0] = MAGIC;
    header[1] = VERSION;
    let mut out = vec![0u8; 4 * HEADER_WORDS];
    for (t, words) in tables.iter().enumerate() {
        // Every table but the pool starts on a 4-byte boundary; the padding is zero.
        out.resize(out.len().next_multiple_of(4), 0);
        header[4 + 2 * t] = size(out.len())?;
        header[5 + 2 * t] = size(words.len() / WORDS[t])?;
        for w in words {
            out.extend_from_slice(&w.to_le_bytes());
        }
    }
    header[4 + 2 * T_POOL] = size(out.len())?;
    header[5 + 2 * T_POOL] = count(pool.bytes.len(), MAX_POOL, "pool")?;
    out.extend_from_slice(&pool.bytes);
    header[2] = size(out.len())?;
    for (i, w) in header.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    let crc = file_crc(&out);
    out[12..16].copy_from_slice(&crc.to_le_bytes());
    Ok(out)
}
