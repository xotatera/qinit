// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! A hand-built launch request for the decoder tests, laid out from the word indices in
//! `layout.rs` alone.
#![allow(dead_code)] // each test binary uses a different part of the builder

use qinit_overseer_core::*;

/// Where a stream goes.
#[derive(Clone)]
pub enum Stream {
    Path(&'static str),
    Fd(u32),
    Same,
}

/// One request.
#[derive(Clone)]
pub struct ReqSpec {
    pub argv: &'static str,
    pub env: &'static str,
    pub cwd: &'static str,
    pub umask: u32,
    /// The resource limits, by kernel resource number; `u64::MAX` is infinity.
    pub rlimits: [Option<u64>; 16],
    pub user: &'static str,
    pub caps: u64,
    pub securebits: u32,
    pub nnp: u32,
    pub ns: u32,
    pub user_map: u32,
    pub seccomp: u32,
    pub seccomp_list: &'static str,
    pub paths: &'static str,
    pub stdin: Stream,
    pub stdout: Stream,
    pub stderr: Stream,
    pub ready: Option<u32>,
    pub flags: u32,
    pub deadline_ms: u32,
}

/// The valid minimal request: `/bin/true` as `svc` in `/`, umask `0o027`, stdout to
/// `/dev/null`, stderr the same, no ready pipe, a one-second deadline.
pub fn minimal() -> ReqSpec {
    ReqSpec {
        argv: "/bin/true",
        env: "",
        cwd: "/",
        umask: 0o027,
        rlimits: [None; 16],
        user: "svc",
        caps: 0,
        securebits: 0,
        nnp: 1,
        ns: 0,
        user_map: 0,
        seccomp: 0,
        seccomp_list: "",
        paths: "",
        stdin: Stream::Path("/dev/null"),
        stdout: Stream::Path("/dev/null"),
        stderr: Stream::Same,
        ready: None,
        flags: 0,
        deadline_ms: 1000,
    }
}

fn n32(x: usize) -> u32 {
    u32::try_from(x).unwrap()
}

/// Lays out `spec` as a request.
#[allow(clippy::cast_possible_truncation)] // a limit's low and high words
pub fn build(spec: &ReqSpec) -> Vec<u8> {
    let mut pool: Vec<u8> = Vec::new();
    let mut intern = |s: &str| {
        let off = n32(pool.len());
        pool.extend_from_slice(s.as_bytes());
        (off, n32(s.len()))
    };
    let mut rec = [0u32; REQ_WORDS];
    let argv = intern(spec.argv);
    let env = intern(spec.env);
    let cwd = intern(spec.cwd);
    let user = intern(spec.user);
    let seccomp = intern(spec.seccomp_list);
    let paths = intern(spec.paths);
    let mut stream = |s: &Stream, kind: usize, a: usize, b: usize| match s {
        Stream::Path(p) => {
            let (o, l) = intern(p);
            rec[kind] = STREAM_PATH;
            rec[a] = o;
            rec[b] = l;
        }
        Stream::Fd(fd) => {
            rec[kind] = STREAM_FD;
            rec[a] = *fd;
        }
        Stream::Same => rec[kind] = STREAM_SAME,
    };
    stream(&spec.stdin, Q_STDIN_KIND, Q_STDIN_A, Q_STDIN_B);
    stream(&spec.stdout, Q_STDOUT_KIND, Q_STDOUT_A, Q_STDOUT_B);
    stream(&spec.stderr, Q_STDERR_KIND, Q_STDERR_A, Q_STDERR_B);
    rec[Q_ARGV_OFF] = argv.0;
    rec[Q_ARGV_LEN] = argv.1;
    rec[Q_ENV_OFF] = env.0;
    rec[Q_ENV_LEN] = env.1;
    rec[Q_CWD_OFF] = cwd.0;
    rec[Q_CWD_LEN] = cwd.1;
    rec[Q_UMASK] = spec.umask;
    for (r, limit) in spec.rlimits.iter().enumerate() {
        if let Some(v) = limit {
            rec[Q_RLIMIT_MASK] |= 1 << r;
            rec[Q_RLIMIT_BASE + 2 * r] = *v as u32;
            rec[Q_RLIMIT_BASE + 2 * r + 1] = (*v >> 32) as u32;
        }
    }
    rec[Q_USER_OFF] = user.0;
    rec[Q_USER_LEN] = user.1;
    rec[Q_CAPS_LO] = n32(usize::try_from(spec.caps & 0xffff_ffff).unwrap());
    rec[Q_CAPS_HI] = n32(usize::try_from(spec.caps >> 32).unwrap());
    rec[Q_SECUREBITS] = spec.securebits;
    rec[Q_NNP] = spec.nnp;
    rec[Q_NS] = spec.ns;
    rec[Q_USER_MAP] = spec.user_map;
    rec[Q_SECCOMP] = spec.seccomp;
    rec[Q_SECCOMP_OFF] = seccomp.0;
    rec[Q_SECCOMP_LEN] = seccomp.1;
    rec[Q_PATHS_OFF] = paths.0;
    rec[Q_PATHS_LEN] = paths.1;
    match spec.ready {
        None => rec[Q_READY_KIND] = READY_NONE,
        Some(fd) => {
            rec[Q_READY_KIND] = READY_PIPE;
            rec[Q_READY_FD] = fd;
        }
    }
    rec[Q_FLAGS] = spec.flags;
    rec[Q_DEADLINE_MS] = spec.deadline_ms;
    let pool_off = 4 * (HEADER_WORDS + REQ_WORDS);
    let header = [
        LAUNCH_MAGIC,
        LAUNCH_VERSION,
        n32(pool_off + pool.len()),
        n32(pool_off),
        n32(pool.len()),
    ];
    let mut out: Vec<u8> = header
        .iter()
        .chain(rec.iter())
        .flat_map(|w| w.to_le_bytes())
        .collect();
    out.extend_from_slice(&pool);
    out
}

/// [`minimal`] laid out.
pub fn valid() -> Vec<u8> {
    build(&minimal())
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

/// Word index of record word `w`.
pub fn at(w: usize) -> usize {
    HEADER_WORDS + w
}

/// Byte index of pool offset `off`.
pub fn pool_at(bytes: &[u8], off: u32) -> usize {
    let w = 4 * H_POOL_OFF;
    let b = u32::from_le_bytes([bytes[w], bytes[w + 1], bytes[w + 2], bytes[w + 3]]);
    (b + off) as usize
}
