// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The launch request as a value, its byte layout and the builder from the database model
//! (spec §6, R15).
use qinit_db::{Model, Node, Ready, Route};
pub use qinit_db::{Seccomp, Securebits};
use qinit_overseer_core::{
    FLAG_DIE_WITH_PARENT, HEADER_WORDS, LAUNCH_MAGIC, LAUNCH_VERSION, MAX_REQUEST, Q_ARGV_LEN,
    Q_ARGV_OFF, Q_CAPS_HI, Q_CAPS_LO, Q_CWD_LEN, Q_CWD_OFF, Q_DEADLINE_MS, Q_ENV_LEN, Q_ENV_OFF,
    Q_FLAGS, Q_LANDLOCK_LEN, Q_LANDLOCK_OFF, Q_NNP, Q_NOFILE, Q_NS, Q_READY_FD, Q_READY_KIND,
    Q_SECCOMP, Q_SECCOMP_LEN, Q_SECCOMP_OFF, Q_SECUREBITS, Q_STDERR_A, Q_STDERR_B, Q_STDERR_KIND,
    Q_STDIN_A, Q_STDIN_B, Q_STDIN_KIND, Q_STDOUT_A, Q_STDOUT_B, Q_STDOUT_KIND, Q_UMASK, Q_USER_LEN,
    Q_USER_OFF, READY_NONE, READY_PIPE, REQ_WORDS, STREAM_FD, STREAM_PATH, STREAM_SAME,
};

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
    pub nofile: u32,
    pub user: String,
    pub caps: u64,
    pub securebits: Securebits,
    pub nnp: bool,
    pub ns: u32,
    pub seccomp: Seccomp,
    pub landlock: Vec<String>,
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
            nofile: 0,
            user: String::new(),
            caps: 0,
            securebits: Securebits::None,
            nnp: true,
            ns: 0,
            seccomp: Seccomp::None,
            landlock: Vec::new(),
            stdin: Stream::Path("/dev/null".into()),
            stdout: Stream::Path("/dev/null".into()),
            stderr: Stream::Same,
            ready_fd: None,
            die_with_parent: false,
            deadline_ms: 30_000,
        }
    }
}

/// Why a request could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// A pipe route or readiness pipe has no descriptor in [`Routed`].
    MissingFd,
    /// The node is a brood: it has no credentials and nothing to launch.
    NoCredentials,
    /// The request is longer than `MAX_REQUEST`.
    TooLarge,
    /// Standard input or output was [`Stream::Same`].
    BadStream,
}

/// The descriptor numbers the launcher routes in, by role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Routed {
    pub stdin: Option<u32>,
    pub stdout: Option<u32>,
    pub stderr: Option<u32>,
    pub ready: Option<u32>,
}

/// The pool under construction.
struct Pool(Vec<u8>);

impl Pool {
    fn put(&mut self, bytes: &[u8]) -> Result<(u32, u32), BuildError> {
        let off = u32::try_from(self.0.len()).map_err(|_| BuildError::TooLarge)?;
        let len = u32::try_from(bytes.len()).map_err(|_| BuildError::TooLarge)?;
        self.0.extend_from_slice(bytes);
        Ok((off, len))
    }

    fn list(&mut self, items: &[String]) -> Result<(u32, u32), BuildError> {
        self.put(items.join("\0").as_bytes())
    }
}

impl RequestSpec {
    /// Lays the request out: header, record and pool.
    ///
    /// # Errors
    /// [`BuildError::TooLarge`] past `MAX_REQUEST`, [`BuildError::BadStream`] for a `Same`
    /// standard input or output. Nothing else is checked here: `decode` is the judge.
    pub fn bytes(&self) -> Result<Vec<u8>, BuildError> {
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
        let (o, l) = pool.list(&self.landlock)?;
        (rec[Q_LANDLOCK_OFF], rec[Q_LANDLOCK_LEN]) = (o, l);
        if self.stdin == Stream::Same || self.stdout == Stream::Same {
            return Err(BuildError::BadStream);
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
        rec[Q_NOFILE] = self.nofile;
        rec[Q_CAPS_LO] =
            u32::try_from(self.caps & 0xffff_ffff).map_err(|_| BuildError::TooLarge)?;
        rec[Q_CAPS_HI] = u32::try_from(self.caps >> 32).map_err(|_| BuildError::TooLarge)?;
        rec[Q_SECUREBITS] = match self.securebits {
            Securebits::None => 0,
            Securebits::Noroot => 1,
            Securebits::NorootLocked => 2,
        };
        rec[Q_NNP] = u32::from(self.nnp);
        rec[Q_NS] = self.ns;
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
            return Err(BuildError::TooLarge);
        }
        let n32 = |x: usize| u32::try_from(x).map_err(|_| BuildError::TooLarge);
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

fn stream(route: &Route, fd: Option<u32>) -> Result<Stream, BuildError> {
    match route {
        Route::Path(p) => Ok(Stream::Path(p.clone())),
        Route::Pipe(_) => fd.map(Stream::Fd).ok_or(BuildError::MissingFd),
    }
}

/// The request for `node` of `model`. A pipe route needs its descriptor in `routed`; an
/// `errors` route equal to the `output` route is standard error following standard output.
///
/// # Errors
/// [`BuildError::NoCredentials`] for a brood, [`BuildError::MissingFd`] for a pipe route or
/// pipe readiness without its descriptor.
pub fn from_model(
    node: &Node,
    model: &Model,
    routed: &Routed,
    deadline_ms: u32,
) -> Result<RequestSpec, BuildError> {
    let cred = &model.creds[node.cred.ok_or(BuildError::NoCredentials)? as usize];
    let route = |i: u32| &model.routes[i as usize];
    let stdout = match node.output {
        None => Stream::Path("/dev/null".into()),
        Some(r) => stream(route(r), routed.stdout)?,
    };
    let stderr = match node.errors {
        None => Stream::Same,
        Some(r) if node.output.is_some_and(|o| route(o) == route(r)) => Stream::Same,
        Some(r) => stream(route(r), routed.stderr)?,
    };
    let ready_fd = match node.ready {
        Ready::Pipe => Some(routed.ready.ok_or(BuildError::MissingFd)?),
        _ => None,
    };
    Ok(RequestSpec {
        argv: node.exec.clone(),
        env: node.env.clone(),
        cwd: node.cwd.clone(),
        umask: node.umask,
        nofile: node.rlimit_nofile,
        user: cred.user.clone(),
        caps: cred.caps,
        securebits: cred.securebits,
        nnp: cred.nnp,
        ns: cred.ns,
        seccomp: cred.seccomp.clone(),
        landlock: cred.landlock.clone(),
        stdin: routed
            .stdin
            .map_or_else(|| Stream::Path("/dev/null".into()), Stream::Fd),
        stdout,
        stderr,
        ready_fd,
        die_with_parent: false,
        deadline_ms,
    })
}
