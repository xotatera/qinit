// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The launch request as a value, built from the database model (spec §6, R15). The value and
//! its byte layout are `qinit-launch`.
use qinit_db::{Model, Node, Ready, Route};
pub use qinit_launch::{EncodeError, RequestSpec, Seccomp, Securebits, Stream};

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

impl From<EncodeError> for BuildError {
    fn from(e: EncodeError) -> Self {
        match e {
            EncodeError::TooLarge => BuildError::TooLarge,
            EncodeError::BadStream => BuildError::BadStream,
        }
    }
}

/// The descriptor numbers the launcher routes in, by role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Routed {
    pub stdin: Option<u32>,
    pub stdout: Option<u32>,
    pub stderr: Option<u32>,
    pub ready: Option<u32>,
}

fn stream(route: &Route, fd: Option<u32>) -> Result<Stream, BuildError> {
    match route {
        Route::Path(p) => Ok(Stream::Path(p.clone())),
        Route::Pipe(_) => fd.map(Stream::Fd).ok_or(BuildError::MissingFd),
    }
}

/// The standard output and error of `node`: its routes, or the descriptors in `routed`. With
/// `replace`, a descriptor in `routed` takes the place of the node's route (a caller's stream
/// for an instance); without it, a descriptor only serves a pipe route.
fn streams(
    node: &Node,
    model: &Model,
    routed: &Routed,
    replace: bool,
) -> Result<(Stream, Stream), BuildError> {
    let route = |i: u32| &model.routes[i as usize];
    let stdout = match (replace, routed.stdout, node.output) {
        (true, Some(fd), _) => Stream::Fd(fd),
        (_, _, None) => Stream::Path("/dev/null".into()),
        (_, fd, Some(r)) => stream(route(r), fd)?,
    };
    let stderr = match (replace, routed.stderr, node.errors) {
        (true, Some(fd), _) => Stream::Fd(fd),
        (_, _, None) => Stream::Same,
        (_, _, Some(r)) if node.output.is_some_and(|o| route(o) == route(r)) => Stream::Same,
        (_, fd, Some(r)) => stream(route(r), fd)?,
    };
    Ok((stdout, stderr))
}

fn build(
    node: &Node,
    model: &Model,
    routed: &Routed,
    deadline_ms: u32,
    replace: bool,
) -> Result<RequestSpec, BuildError> {
    let cred = &model.creds[node.cred.ok_or(BuildError::NoCredentials)? as usize];
    let (stdout, stderr) = streams(node, model, routed, replace)?;
    let ready_fd = match node.ready {
        Ready::Pipe => Some(routed.ready.ok_or(BuildError::MissingFd)?),
        _ => None,
    };
    Ok(RequestSpec {
        argv: node.exec.clone(),
        env: node.env.clone(),
        cwd: node.cwd.clone(),
        umask: node.umask,
        rlimits: node.rlimits,
        user: cred.user.clone(),
        caps: cred.caps,
        securebits: match cred.securebits {
            qinit_db::Securebits::None => Securebits::None,
            qinit_db::Securebits::Noroot => Securebits::Noroot,
            qinit_db::Securebits::NorootLocked => Securebits::NorootLocked,
        },
        nnp: cred.nnp,
        ns: cred.ns,
        seccomp: match &cred.seccomp {
            qinit_db::Seccomp::None => Seccomp::None,
            qinit_db::Seccomp::Default => Seccomp::Default,
            qinit_db::Seccomp::Deny(v) => Seccomp::Deny(v.clone()),
            qinit_db::Seccomp::Allow(v) => Seccomp::Allow(v.clone()),
        },
        paths: cred.paths.clone(),
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
    build(node, model, routed, deadline_ms, false)
}

/// The request for an instance of the launchable forager `node`: [`from_model`] with the
/// caller's additions. `argv_tail` follows the frame's argv, and `env_add` overrides the
/// frame's entries of the same key (the result stays sorted by key). A descriptor in `routed`
/// replaces the frame's route for that stream: stdin from the caller instead of `/dev/null`,
/// stdout or stderr to the caller instead of a path or the logger.
///
/// # Errors
/// As [`from_model`].
pub fn from_instance(
    node: &Node,
    model: &Model,
    routed: &Routed,
    argv_tail: &[String],
    env_add: &[(String, String)],
    deadline_ms: u32,
) -> Result<RequestSpec, BuildError> {
    let mut spec = build(node, model, routed, deadline_ms, true)?;
    spec.argv.extend(argv_tail.iter().cloned());
    let key = |e: &str| {
        e.split_once('=')
            .map_or(e.to_owned(), |(k, _)| k.to_owned())
    };
    for (k, v) in env_add {
        spec.env.retain(|e| key(e) != *k);
        spec.env.push(format!("{k}={v}"));
    }
    spec.env.sort_by_key(|e| key(e));
    Ok(spec)
}
