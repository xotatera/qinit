// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! The launch request (QLR1) as a value and its encoder. The layout is `qinit_proto_core::launch`;
//! `qinit_overseer_core::decode` is the judge of what the encoder produces.
use qinit_proto_core::launch::{
    FLAG_DIE_WITH_PARENT, HEADER_WORDS, LAUNCH_MAGIC, LAUNCH_VERSION, MAX_REQUEST, Q_ARGV_LEN,
    Q_ARGV_OFF, Q_CAPS_HI, Q_CAPS_LO, Q_CWD_LEN, Q_CWD_OFF, Q_DEADLINE_MS, Q_ENV_LEN, Q_ENV_OFF,
    Q_FLAGS, Q_INSIDE_GID, Q_INSIDE_UID, Q_NNP, Q_NS, Q_PATHS_LEN, Q_PATHS_OFF, Q_READY_FD,
    Q_READY_KIND, Q_RLIMIT_BASE, Q_RLIMIT_MASK, Q_SECCOMP, Q_SECCOMP_LEN, Q_SECCOMP_OFF,
    Q_SECUREBITS, Q_STDERR_A, Q_STDERR_B, Q_STDERR_KIND, Q_STDIN_A, Q_STDIN_B, Q_STDIN_KIND,
    Q_STDOUT_A, Q_STDOUT_B, Q_STDOUT_KIND, Q_UMASK, Q_USER_LEN, Q_USER_MAP, Q_USER_OFF, READY_NONE,
    READY_PIPE, REQ_WORDS, STREAM_FD, STREAM_PATH, STREAM_SAME,
};

/// The seccomp policy of a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Seccomp {
    None,
    Default,
    Deny(Vec<u32>),
    Allow(Vec<u32>),
}

/// What a user namespace maps: the service's own ids only, or its subordinate range too.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UserMap {
    #[default]
    Own,
    Range,
}

/// The securebits of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Securebits {
    None,
    Noroot,
    NorootLocked,
}

/// Where a stream goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stream {
    /// A path the executor opens by file type.
    Path(String),
    /// A routed descriptor, by number.
    Fd(u32),
    /// Standard error only: wherever standard output goes.
    Same,
}

/// A launch request as a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestSpec {
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub umask: u32,
    /// The resource limits to set, by kernel resource number; `u64::MAX` is infinity.
    pub rlimits: [Option<u64>; 16],
    pub user: String,
    pub caps: u64,
    pub securebits: Securebits,
    pub nnp: bool,
    pub ns: u32,
    /// Only `Range` with the `user` bit (32) of `ns`.
    pub user_map: UserMap,
    /// The ids the service runs as inside its user namespace; non-zero only with the `user`
    /// bit, at most 4294967294.
    pub inside_uid: u32,
    pub inside_gid: u32,
    pub seccomp: Seccomp,
    pub paths: Vec<String>,
    pub stdin: Stream,
    pub stdout: Stream,
    pub stderr: Stream,
    pub ready_fd: Option<u32>,
    pub die_with_parent: bool,
    pub deadline_ms: u32,
}

impl Default for RequestSpec {
    fn default() -> Self {
        RequestSpec {
            argv: Vec::new(),
            env: Vec::new(),
            cwd: "/".into(),
            umask: 0o027,
            rlimits: [None; 16],
            user: String::new(),
            caps: 0,
            securebits: Securebits::None,
            nnp: true,
            ns: 0,
            user_map: UserMap::Own,
            inside_uid: 0,
            inside_gid: 0,
            seccomp: Seccomp::None,
            paths: Vec::new(),
            stdin: Stream::Path("/dev/null".into()),
            stdout: Stream::Path("/dev/null".into()),
            stderr: Stream::Same,
            ready_fd: None,
            die_with_parent: false,
            deadline_ms: 30_000,
        }
    }
}

/// Why a request could not be encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The request is longer than `MAX_REQUEST`.
    TooLarge,
    /// Standard input or output was [`Stream::Same`].
    BadStream,
}

/// The pool under construction.
struct Pool(Vec<u8>);

impl Pool {
    fn put(&mut self, bytes: &[u8]) -> Result<(u32, u32), EncodeError> {
        let off = u32::try_from(self.0.len()).map_err(|_| EncodeError::TooLarge)?;
        let len = u32::try_from(bytes.len()).map_err(|_| EncodeError::TooLarge)?;
        self.0.extend_from_slice(bytes);
        Ok((off, len))
    }

    fn list(&mut self, items: &[String]) -> Result<(u32, u32), EncodeError> {
        self.put(items.join("\0").as_bytes())
    }
}

impl RequestSpec {
    /// Lays the request out: header, record and pool.
    ///
    /// # Errors
    /// [`EncodeError::TooLarge`] past `MAX_REQUEST`, [`EncodeError::BadStream`] for a `Same`
    /// standard input or output. Nothing else is checked here: `decode` is the judge.
    pub fn bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut pool = Pool(Vec::new());
        let mut rec = [0u32; REQ_WORDS];
        let (o, l) = pool.list(&self.argv)?;
        (rec[Q_ARGV_OFF], rec[Q_ARGV_LEN]) = (o, l);
        let (o, l) = pool.list(&self.env)?;
        (rec[Q_ENV_OFF], rec[Q_ENV_LEN]) = (o, l);
        let (o, l) = pool.put(self.cwd.as_bytes())?;
        (rec[Q_CWD_OFF], rec[Q_CWD_LEN]) = (o, l);
        let (o, l) = pool.put(self.user.as_bytes())?;
        (rec[Q_USER_OFF], rec[Q_USER_LEN]) = (o, l);
        let (mode, nums): (u32, &[u32]) = match &self.seccomp {
            Seccomp::None => (0, &[]),
            Seccomp::Default => (1, &[]),
            Seccomp::Deny(v) => (2, v),
            Seccomp::Allow(v) => (3, v),
        };
        let nums: Vec<String> = nums.iter().map(u32::to_string).collect();
        let (o, l) = pool.list(&nums)?;
        rec[Q_SECCOMP] = mode;
        (rec[Q_SECCOMP_OFF], rec[Q_SECCOMP_LEN]) = (o, l);
        let (o, l) = pool.list(&self.paths)?;
        (rec[Q_PATHS_OFF], rec[Q_PATHS_LEN]) = (o, l);
        if self.stdin == Stream::Same || self.stdout == Stream::Same {
            return Err(EncodeError::BadStream);
        }
        for (s, kind, a, b) in [
            (&self.stdin, Q_STDIN_KIND, Q_STDIN_A, Q_STDIN_B),
            (&self.stdout, Q_STDOUT_KIND, Q_STDOUT_A, Q_STDOUT_B),
            (&self.stderr, Q_STDERR_KIND, Q_STDERR_A, Q_STDERR_B),
        ] {
            match s {
                Stream::Path(p) => {
                    let (o, l) = pool.put(p.as_bytes())?;
                    (rec[kind], rec[a], rec[b]) = (STREAM_PATH, o, l);
                }
                Stream::Fd(n) => (rec[kind], rec[a]) = (STREAM_FD, *n),
                Stream::Same => rec[kind] = STREAM_SAME,
            }
        }
        rec[Q_UMASK] = self.umask;
        for (r, limit) in self.rlimits.iter().enumerate() {
            if let Some(v) = limit {
                rec[Q_RLIMIT_MASK] |= 1 << r;
                // Low word, then high word.
                #[allow(clippy::cast_possible_truncation)]
                {
                    rec[Q_RLIMIT_BASE + 2 * r] = *v as u32;
                    rec[Q_RLIMIT_BASE + 2 * r + 1] = (*v >> 32) as u32;
                }
            }
        }
        rec[Q_CAPS_LO] =
            u32::try_from(self.caps & 0xffff_ffff).map_err(|_| EncodeError::TooLarge)?;
        rec[Q_CAPS_HI] = u32::try_from(self.caps >> 32).map_err(|_| EncodeError::TooLarge)?;
        rec[Q_SECUREBITS] = match self.securebits {
            Securebits::None => 0,
            Securebits::Noroot => 1,
            Securebits::NorootLocked => 2,
        };
        rec[Q_NNP] = u32::from(self.nnp);
        rec[Q_NS] = self.ns;
        rec[Q_USER_MAP] = u32::from(self.user_map == UserMap::Range);
        rec[Q_INSIDE_UID] = self.inside_uid;
        rec[Q_INSIDE_GID] = self.inside_gid;
        match self.ready_fd {
            None => rec[Q_READY_KIND] = READY_NONE,
            Some(fd) => (rec[Q_READY_KIND], rec[Q_READY_FD]) = (READY_PIPE, fd),
        }
        rec[Q_FLAGS] = if self.die_with_parent {
            FLAG_DIE_WITH_PARENT
        } else {
            0
        };
        rec[Q_DEADLINE_MS] = self.deadline_ms;
        let fixed = 4 * (HEADER_WORDS + REQ_WORDS);
        let total = fixed + pool.0.len();
        if total > MAX_REQUEST {
            return Err(EncodeError::TooLarge);
        }
        let n32 = |x: usize| u32::try_from(x).map_err(|_| EncodeError::TooLarge);
        let header = [
            LAUNCH_MAGIC,
            LAUNCH_VERSION,
            n32(total)?,
            n32(fixed)?,
            n32(pool.0.len())?,
        ];
        let mut out: Vec<u8> = header
            .iter()
            .chain(rec.iter())
            .flat_map(|w| w.to_le_bytes())
            .collect();
        out.extend_from_slice(&pool.0);
        Ok(out)
    }
}
