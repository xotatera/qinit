// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! A hand-built database for the validator tests, laid out from the word indices in `layout.rs`
//! alone, so the tests do not depend on `qinit-db`.
#![allow(dead_code)] // each test binary uses a different part of the builder

use qinit_db_core::*;

/// One edge.
#[derive(Clone)]
pub struct EdgeSpec {
    /// A node index, or a path in the pool.
    pub target: Target,
    /// 0 sync, 1 async.
    pub mode: u32,
    /// Deadline in milliseconds.
    pub deadline_ms: u32,
    /// 0 none, 1 error, 2 restart, 3 refresh.
    pub restart_on: u32,
    /// Bit 0: stop in parallel.
    pub flags: u32,
}

/// An edge target.
#[derive(Clone)]
pub enum Target {
    /// A node index.
    Node(u32),
    /// A path.
    Path(&'static str),
}

/// One dependency group.
#[derive(Clone)]
pub struct GroupSpec {
    /// 0 `require_all`, 1 `require_any`, 2 `optional_all`, 3 `exclude_all`.
    pub kind: u32,
    /// The group's edges.
    pub edges: Vec<EdgeSpec>,
}

/// One node.
#[derive(Clone)]
pub struct NodeSpec {
    /// The name (raw bytes, so tests can plant invalid UTF-8).
    pub name: Vec<u8>,
    /// 0 worker, 1 forager, 2 brood.
    pub kind: u32,
    /// The node's groups.
    pub groups: Vec<GroupSpec>,
    /// Output route index or `NONE`.
    pub output: u32,
    /// Credential index or `NONE`.
    pub cred: u32,
    /// The environment, raw NUL-joined `KEY=VALUE` entries.
    pub env: &'static str,
    /// The program (the first element of the argument list).
    pub exec: &'static str,
    /// The working directory.
    pub cwd: &'static str,
    /// The file-mode creation mask.
    pub umask: u32,
    /// 0 none, 1 `SIGHUP`, 2 `SIGUSR1`, 3 `SIGUSR2`.
    pub reload: u32,
    /// The forager launch table; all zero for a node that is not launchable.
    pub launch: LaunchSpec,
}

/// The launch words of a node record.
#[derive(Clone, Default)]
pub struct LaunchSpec {
    /// 0 for not launchable, else 1..=64.
    pub concurrency: u32,
    /// Extra argv elements a caller may append.
    pub argv_tail: u32,
    /// The keys a caller may set, raw NUL-joined.
    pub env: &'static str,
    /// Bitmask of `FD_STDIN`, `FD_STDOUT`, `FD_STDERR`.
    pub fds: u32,
}

/// One credential record.
#[derive(Clone)]
pub struct CredSpec {
    /// The user name.
    pub user: &'static str,
    /// Capabilities, bits 0..=40.
    pub caps: u64,
    /// `no_new_privs`, 0 or 1.
    pub nnp: u32,
    /// 0 none, 1 default, 2 deny-list, 3 allow-list.
    pub seccomp: u32,
    /// The seccomp list, raw NUL-joined decimals.
    pub seccomp_list: &'static str,
    /// The path list, raw NUL-joined `ro:`/`rw:` entries.
    pub paths: &'static str,
    /// Namespace bits.
    pub ns: u32,
    /// 0 own map, 1 range map.
    pub user_map: u32,
    /// The ids the service runs as inside its user namespace.
    pub inside_uid: u32,
    pub inside_gid: u32,
}

/// A credential for `user`: no caps, `no_new_privs` on, no seccomp.
pub fn cred(user: &'static str) -> CredSpec {
    CredSpec {
        user,
        caps: 0,
        nnp: 1,
        seccomp: 0,
        seccomp_list: "",
        paths: "",
        ns: 0,
        user_map: 0,
        inside_uid: 0,
        inside_gid: 0,
    }
}

/// One route.
#[derive(Clone)]
pub enum RouteSpec {
    /// A file path.
    Path(&'static str),
    /// A pipe into a logger node.
    Pipe(u32),
}

/// One policy rule.
#[derive(Clone)]
pub struct RuleSpec {
    /// The glob.
    pub pattern: &'static str,
    /// The users, raw NUL-joined names; empty with `users_any`.
    pub users: &'static str,
    /// 1 when the rule names no users.
    pub users_any: u32,
    /// The capability ceiling, bits 0..=40.
    pub caps: u64,
    pub require_nnp: u32,
    pub require_seccomp: u32,
    /// 0 none, 1 own, 2 own or range.
    pub allow_userns: u32,
    /// 1 when the rule lets a request run as a non-zero inside id.
    pub allow_inside_ids: u32,
    /// 1 when the rule lets a request have an idmapped path entry.
    pub allow_idmap: u32,
    /// The ceilings, by kernel resource number; `u64::MAX` is infinity.
    pub rlimits: [Option<u64>; 16],
}

/// A rule matching `pattern` for any user: no capabilities, nothing required or allowed.
pub fn rule(pattern: &'static str) -> RuleSpec {
    RuleSpec {
        pattern,
        users: "",
        users_any: 1,
        caps: 0,
        require_nnp: 0,
        require_seccomp: 0,
        allow_userns: 0,
        allow_inside_ids: 0,
        allow_idmap: 0,
        rlimits: [None; 16],
    }
}

/// The policy header: the default and the top-level ceilings.
#[derive(Clone)]
pub struct HeadSpec {
    /// 1 when the default is to allow.
    pub allow: u32,
    pub rlimits: [Option<u64>; 16],
}

/// A header with default deny and no ceilings.
pub fn head() -> HeadSpec {
    HeadSpec {
        allow: 0,
        rlimits: [None; 16],
    }
}

/// The whole database.
#[derive(Clone, Default)]
pub struct DbSpec {
    pub policy: Vec<RuleSpec>,
    pub policy_head: Option<HeadSpec>,
    pub nodes: Vec<NodeSpec>,
    pub creds: Vec<CredSpec>,
    pub routes: Vec<RouteSpec>,
    pub enabled: Vec<u32>,
    pub presyslog: Vec<u32>,
}

/// A worker named `name` with `groups`, running under credential 0.
pub fn node(name: &str, groups: Vec<GroupSpec>) -> NodeSpec {
    NodeSpec {
        name: name.as_bytes().to_vec(),
        kind: 0,
        groups,
        output: NONE,
        cred: 0,
        env: "",
        exec: "/bin/true",
        cwd: "/",
        umask: 0o027,
        reload: 0,
        launch: LaunchSpec::default(),
    }
}

/// A group of `kind` with `edges`.
pub fn group(kind: u32, edges: Vec<EdgeSpec>) -> GroupSpec {
    GroupSpec { kind, edges }
}

/// A sync edge to node `to`.
pub fn sync(to: u32) -> EdgeSpec {
    EdgeSpec {
        target: Target::Node(to),
        mode: 0,
        deadline_ms: 0,
        restart_on: 0,
        flags: 0,
    }
}

/// A sync edge to `to` that may stop in parallel.
pub fn parallel(to: u32) -> EdgeSpec {
    EdgeSpec {
        flags: 1,
        ..sync(to)
    }
}

/// A sync edge to a path.
pub fn path(p: &'static str) -> EdgeSpec {
    EdgeSpec {
        target: Target::Path(p),
        ..sync(0)
    }
}

fn intern(pool: &mut Vec<u8>, s: &[u8]) -> (u32, u32) {
    let off = u32::try_from(pool.len()).unwrap();
    pool.extend_from_slice(s);
    (off, u32::try_from(s.len()).unwrap())
}

fn n32(x: usize) -> u32 {
    u32::try_from(x).unwrap()
}

/// Lays out `spec` as a database.
#[allow(clippy::too_many_lines)] // one table after the other
pub fn build(spec: &DbSpec) -> Vec<u8> {
    let mut pool = Vec::new();
    let mut nodes: Vec<u32> = Vec::new();
    let mut groups: Vec<u32> = Vec::new();
    let mut edges: Vec<u32> = Vec::new();
    let mut gcount = 0usize;
    let mut ecount = 0usize;
    for n in &spec.nodes {
        let (name_off, name_len) = intern(&mut pool, &n.name);
        let (exec_off, exec_len) = if n.kind == 2 {
            (0, 0)
        } else {
            intern(&mut pool, n.exec.as_bytes())
        };
        let (env_off, env_len) = intern(&mut pool, n.env.as_bytes());
        let (cwd_off, cwd_len) = intern(&mut pool, n.cwd.as_bytes());
        let (launch_env_off, launch_env_len) = intern(&mut pool, n.launch.env.as_bytes());
        let mut rec = [0u32; WORDS[T_NODES]];
        rec[N_RELOAD] = n.reload;
        rec[N_LAUNCH_CONCURRENCY] = n.launch.concurrency;
        rec[N_LAUNCH_ARGV_TAIL] = n.launch.argv_tail;
        rec[N_LAUNCH_ENV_OFF] = launch_env_off;
        rec[N_LAUNCH_ENV_LEN] = launch_env_len;
        rec[N_LAUNCH_FDS] = n.launch.fds;
        rec[N_ENV_OFF] = env_off;
        rec[N_ENV_LEN] = env_len;
        rec[N_CWD_OFF] = cwd_off;
        rec[N_CWD_LEN] = cwd_len;
        rec[N_UMASK] = n.umask;
        rec[N_RESTART_DELAY_MS] = 1000;
        rec[N_STOP_GRACE_MS] = 10_000;
        rec[N_KIND] = n.kind;
        rec[N_NAME_OFF] = name_off;
        rec[N_NAME_LEN] = name_len;
        rec[N_EXEC_OFF] = exec_off;
        rec[N_EXEC_LEN] = exec_len;
        rec[N_OUTPUT] = n.output;
        rec[N_ERRORS] = NONE;
        rec[N_CRED] = n.cred;
        rec[N_GROUP_FIRST] = n32(gcount);
        rec[N_GROUP_COUNT] = n32(n.groups.len());
        nodes.extend_from_slice(&rec);
        for g in &n.groups {
            groups.extend_from_slice(&[g.kind, n32(ecount), n32(g.edges.len())]);
            gcount += 1;
            for e in &g.edges {
                let (kind, target, len) = match e.target {
                    Target::Node(i) => (0, i, 0),
                    Target::Path(p) => {
                        let (o, l) = intern(&mut pool, p.as_bytes());
                        (1, o, l)
                    }
                };
                let mut rec = [0u32; 7];
                rec[E_TARGET_KIND] = kind;
                rec[E_TARGET] = target;
                rec[E_TARGET_LEN] = len;
                rec[E_MODE] = e.mode;
                rec[E_DEADLINE_MS] = e.deadline_ms;
                rec[E_RESTART_ON] = e.restart_on;
                rec[E_FLAGS] = e.flags;
                edges.extend_from_slice(&rec);
                ecount += 1;
            }
        }
    }
    let mut creds: Vec<u32> = Vec::new();
    for c in &spec.creds {
        let (uo, ul) = intern(&mut pool, c.user.as_bytes());
        let (so, sl) = intern(&mut pool, c.seccomp_list.as_bytes());
        let (po, pl) = intern(&mut pool, c.paths.as_bytes());
        let mut rec = [0u32; 15];
        rec[C_USER_OFF] = uo;
        rec[C_USER_LEN] = ul;
        rec[C_NNP] = c.nnp;
        rec[C_SECCOMP] = c.seccomp;
        rec[C_SECCOMP_OFF] = so;
        rec[C_SECCOMP_LEN] = sl;
        rec[C_NS] = c.ns;
        rec[C_USER_MAP] = c.user_map;
        rec[C_INSIDE_UID] = c.inside_uid;
        rec[C_INSIDE_GID] = c.inside_gid;
        rec[C_PATHS_OFF] = po;
        rec[C_PATHS_LEN] = pl;
        rec[C_CAPS_LO] = n32(usize::try_from(c.caps & 0xffff_ffff).unwrap());
        rec[C_CAPS_HI] = n32(usize::try_from(c.caps >> 32).unwrap());
        creds.extend_from_slice(&rec);
    }
    let limit_words = |limits: &[Option<u64>; 16], mask: &mut u32, words: &mut [u32]| {
        for (r, l) in limits.iter().enumerate() {
            if let Some(v) = l {
                *mask |= 1 << r;
                words[2 * r] = n32(usize::try_from(*v & 0xffff_ffff).unwrap());
                words[2 * r + 1] = n32(usize::try_from(*v >> 32).unwrap());
            }
        }
    };
    let mut policy_words: Vec<u32> = Vec::new();
    for r in &spec.policy {
        let (po, pl) = intern(&mut pool, r.pattern.as_bytes());
        let (uo, ul) = intern(&mut pool, r.users.as_bytes());
        let mut rec = [0u32; 45];
        rec[P_PATTERN_OFF] = po;
        rec[P_PATTERN_LEN] = pl;
        rec[P_USERS_OFF] = uo;
        rec[P_USERS_LEN] = ul;
        rec[P_USERS_ANY] = r.users_any;
        rec[P_CAPS_LO] = n32(usize::try_from(r.caps & 0xffff_ffff).unwrap());
        rec[P_CAPS_HI] = n32(usize::try_from(r.caps >> 32).unwrap());
        rec[P_REQUIRE_NNP] = r.require_nnp;
        rec[P_REQUIRE_SECCOMP] = r.require_seccomp;
        rec[P_ALLOW_USERNS] = r.allow_userns;
        rec[P_ALLOW_INSIDE_IDS] = r.allow_inside_ids;
        rec[P_ALLOW_IDMAP] = r.allow_idmap;
        let mut mask = 0;
        limit_words(&r.rlimits, &mut mask, &mut rec[P_RLIMIT_BASE..]);
        rec[P_RLIMIT_MASK] = mask;
        policy_words.extend_from_slice(&rec);
    }
    let mut head_words: Vec<u32> = Vec::new();
    if let Some(h) = &spec.policy_head {
        let mut rec = [0u32; 34];
        rec[PH_ALLOW] = h.allow;
        let mut mask = 0;
        limit_words(&h.rlimits, &mut mask, &mut rec[PH_RLIMIT_BASE..]);
        rec[PH_RLIMIT_MASK] = mask;
        head_words.extend_from_slice(&rec);
    }
    let mut routes: Vec<u32> = Vec::new();
    for r in &spec.routes {
        match r {
            RouteSpec::Path(p) => {
                let (o, l) = intern(&mut pool, p.as_bytes());
                routes.extend_from_slice(&[0, o, l]);
            }
            RouteSpec::Pipe(i) => routes.extend_from_slice(&[1, *i, 0]),
        }
    }
    let tables: [(&[u32], usize); 9] = [
        (&nodes, spec.nodes.len()),
        (&groups, gcount),
        (&edges, ecount),
        (&creds, spec.creds.len()),
        (&routes, spec.routes.len()),
        (&spec.enabled, spec.enabled.len()),
        (&spec.presyslog, spec.presyslog.len()),
        (&policy_words, spec.policy.len()),
        (&head_words, usize::from(spec.policy_head.is_some())),
    ];
    let mut header = [0u32; HEADER_WORDS];
    header[H_MAGIC] = MAGIC;
    header[H_VERSION] = VERSION;
    let mut body: Vec<u8> = Vec::new();
    let mut at = 4 * HEADER_WORDS;
    for (t, (words, count)) in tables.iter().enumerate() {
        header[4 + 2 * t] = n32(at);
        header[5 + 2 * t] = n32(*count);
        for w in *words {
            body.extend_from_slice(&w.to_le_bytes());
        }
        at += 4 * words.len();
    }
    header[4 + 2 * T_POOL] = n32(at);
    header[5 + 2 * T_POOL] = n32(pool.len());
    body.extend_from_slice(&pool);
    header[H_TOTAL_LEN] = n32(4 * HEADER_WORDS + body.len());
    let mut out: Vec<u8> = header.iter().flat_map(|w| w.to_le_bytes()).collect();
    out.extend_from_slice(&body);
    out
}

/// The minimal spec: two workers `a` and `b` under credential 0 (user `svc`), `a` requires `b`
/// sync, both enabled.
pub fn minimal_spec() -> DbSpec {
    DbSpec {
        nodes: vec![node("a", vec![group(0, vec![sync(1)])]), node("b", vec![])],
        creds: vec![cred("svc")],
        enabled: vec![0, 1],
        ..DbSpec::default()
    }
}

/// [`minimal_spec`] laid out.
pub fn valid_minimal() -> Vec<u8> {
    build(&minimal_spec())
}

/// `bytes` with its words patched by `f` (the trailing partial word kept as it was).
pub fn with(bytes: &[u8], f: impl FnOnce(&mut Vec<u32>)) -> Vec<u8> {
    let mut words: Vec<u32> = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c))
        .collect();
    f(&mut words);
    let mut out: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    out.extend_from_slice(&bytes[out.len()..]);
    out
}

/// Word index of word `w` of record `r` in table `t`.
pub fn at(words: &[u32], t: usize, r: usize, w: usize) -> usize {
    words[4 + 2 * t] as usize / 4 + r * WORDS[t] + w
}

/// Byte index of pool offset `off`.
pub fn pool_at(bytes: &[u8], off: u32) -> usize {
    let w = 4 + 2 * T_POOL;
    let b = u32::from_le_bytes([
        bytes[4 * w],
        bytes[4 * w + 1],
        bytes[4 * w + 2],
        bytes[4 * w + 3],
    ]);
    (b + off) as usize
}

/// Scratch space for repeated validator runs.
pub struct Scratch {
    edges: Vec<qinit_graph_core::GEdge>,
    levels: Vec<u32>,
}

impl Scratch {
    /// Scratch of the sizes `validate` requires.
    pub fn new() -> Self {
        let edge = qinit_graph_core::GEdge {
            from: 0,
            to: 0,
            hard: false,
            parallel: false,
        };
        Self {
            edges: vec![edge; MAX_EDGES],
            levels: vec![0u32; MAX_NODES],
        }
    }

    /// Runs the validator on `bytes`.
    pub fn check(&mut self, bytes: &[u8]) -> Result<(), DbError> {
        validate(bytes, &mut self.edges, &mut self.levels)
    }
}

/// Runs the validator with fresh scratch space.
pub fn check(bytes: &[u8]) -> Result<(), DbError> {
    Scratch::new().check(bytes)
}
