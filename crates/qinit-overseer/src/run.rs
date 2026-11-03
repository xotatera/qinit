// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The step runner: decode the request on fd 3, resolve the identity, and perform the proved
//! plan one step at a time (spec §4). A failing step writes its `(step, errno)` record on
//! fd 4 and ends the process with 127.
use crate::identity::{self, Identity, IdentityError};
use crate::output::open_route;
use crate::request::RequestSpec;
use crate::status::{STEP_DECODE, STEP_IDENTITY, Status};
use crate::supervisor::supervise;
use qinit_overseer_core::{
    DEFAULT_DENY, Insn, MAX_BPF, MAX_REQUEST, MAX_STEPS, Q_ARGV_LEN, Q_ARGV_OFF, Q_CAPS_HI,
    Q_CAPS_LO, Q_CWD_LEN, Q_CWD_OFF, Q_ENV_LEN, Q_ENV_OFF, Q_LANDLOCK_LEN, Q_LANDLOCK_OFF,
    Q_SECCOMP, Q_SECCOMP_LEN, Q_SECCOMP_OFF, Q_STDERR_A, Q_STDERR_B, Q_STDERR_KIND, Q_STDOUT_A,
    Q_STDOUT_B, Q_STDOUT_KIND, Q_UMASK, Q_USER_LEN, Q_USER_OFF, STREAM_FD, STREAM_PATH, Step,
    decode, plan, pool, program, req,
};
use qinit_sys::landlock::{
    LANDLOCK_ACCESS_FS_ALL_V3, LANDLOCK_ACCESS_FS_READ, add_path_rule, restrict_self, ruleset,
};
use qinit_sys::limits::{RLIMIT_CORE, RLIMIT_NOFILE, chdir, set_rlimit, umask};
use qinit_sys::{Errno, Result, cred, fd, memfd, ns, proc, seccomp, spawn, timer};
use std::ffi::{CStr, CString};
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};

/// The sealed request.
pub const REQUEST_FD: RawFd = 3;
/// The close-on-exec status pipe.
pub const STATUS_FD: RawFd = 4;
/// Where the service finds its readiness pipe (`QINIT_READY_FD=3`).
pub const READY_FD: RawFd = 3;

const BASE_PATH: &str = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// The environment of R8: `PATH`, `HOME`, `USER`, `LOGNAME`, `QINIT_READY_FD` with a readiness
/// pipe, then the frame's entries, a later entry replacing an earlier one with the same key.
fn build_env(ready: bool, frame: &[&str], user: &str, id: &Identity) -> Vec<CString> {
    let mut env: Vec<String> = vec![
        BASE_PATH.to_owned(),
        format!("HOME={}", id.home),
        format!("USER={user}"),
        format!("LOGNAME={user}"),
    ];
    if ready {
        env.push(format!("QINIT_READY_FD={READY_FD}"));
    }
    for entry in frame {
        let key = entry.split('=').next().unwrap_or_default();
        env.retain(|e| e.split('=').next() != Some(key));
        env.push((*entry).to_owned());
    }
    env.into_iter()
        .filter_map(|e| CString::new(e).ok())
        .collect()
}

/// The environment of `spec` for `id`.
#[must_use]
pub fn envp(spec: &RequestSpec, id: &Identity) -> Vec<CString> {
    let frame: Vec<&str> = spec.env.iter().map(String::as_str).collect();
    build_env(spec.ready_fd.is_some(), &frame, &spec.user, id)
}

/// The NUL-separated items of a pool list; an empty list has none.
fn items(list: &str) -> Vec<&str> {
    if list.is_empty() {
        Vec::new()
    } else {
        list.split('\0').collect()
    }
}

fn cstring(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Errno(libc::EINVAL))
}

fn fd_number(n: u32) -> Result<RawFd> {
    RawFd::try_from(n).map_err(|_| Errno(libc::EINVAL))
}

/// One accepted request being performed.
struct Run<'a> {
    b: &'a [u8],
    id: &'a Identity,
    user: &'a str,
    ruleset: Option<OwnedFd>,
}

impl<'a> Run<'a> {
    fn text(&self, off: usize, len: usize) -> Result<&'a str> {
        std::str::from_utf8(pool(self.b, req(self.b, off), req(self.b, len)))
            .map_err(|_| Errno(libc::EINVAL))
    }

    fn list(&self, off: usize, len: usize) -> Result<Vec<&'a str>> {
        Ok(items(self.text(off, len)?))
    }

    fn caps(&self) -> u64 {
        u64::from(req(self.b, Q_CAPS_LO)) | (u64::from(req(self.b, Q_CAPS_HI)) << 32)
    }

    /// Places stream `kind` on `target`: a path is opened by file type, a descriptor copied.
    fn stream(&self, kind: usize, a: usize, b: usize, target: RawFd) -> Result<()> {
        match req(self.b, kind) {
            STREAM_PATH => {
                // The file is created under the request's umask, which the plan sets later.
                let old = umask(req(self.b, Q_UMASK));
                let opened = open_route(&cstring(self.text(a, b)?)?);
                let _ = umask(old);
                fd::dup2(opened?.as_fd(), target)
            }
            STREAM_FD => fd::dup2_raw(fd_number(req(self.b, a))?, target),
            _ => fd::dup2_raw(1, target),
        }
    }

    fn seccomp(&self) -> Result<()> {
        let mode = req(self.b, Q_SECCOMP);
        let mut numbers = Vec::new();
        if mode != 3 {
            numbers.extend_from_slice(&DEFAULT_DENY);
        }
        if mode >= 2 {
            for n in self.list(Q_SECCOMP_OFF, Q_SECCOMP_LEN)? {
                numbers.push(n.parse::<u32>().map_err(|_| Errno(libc::EINVAL))?);
            }
        }
        let mut out = Box::new(
            [Insn {
                code: 0,
                jt: 0,
                jf: 0,
                k: 0,
            }; MAX_BPF],
        );
        let n = program(mode, &numbers, &mut out);
        let insns: Vec<seccomp::Insn> = out[..n]
            .iter()
            .map(|i| seccomp::Insn {
                code: i.code,
                jt: i.jt,
                jf: i.jf,
                k: i.k,
            })
            .collect();
        seccomp::install(&insns)
    }

    fn landlock_rule(&self, i: u32) -> Result<()> {
        let list = self.list(Q_LANDLOCK_OFF, Q_LANDLOCK_LEN)?;
        let entry = list.get(i as usize).ok_or(Errno(libc::EINVAL))?;
        let (access, path) = if let Some(p) = entry.strip_prefix("ro:") {
            (LANDLOCK_ACCESS_FS_READ, p)
        } else if let Some(p) = entry.strip_prefix("rw:") {
            (LANDLOCK_ACCESS_FS_ALL_V3, p)
        } else {
            return Err(Errno(libc::EINVAL));
        };
        let rs = self.ruleset.as_ref().ok_or(Errno(libc::EBADF))?;
        add_path_rule(rs.as_fd(), &cstring(path)?, access)
    }

    fn exec(&self) -> Errno {
        let argv: Vec<&str> = match self.list(Q_ARGV_OFF, Q_ARGV_LEN) {
            Ok(a) if !a.is_empty() => a,
            _ => return Errno(libc::EINVAL),
        };
        let Ok(frame) = self.list(Q_ENV_OFF, Q_ENV_LEN) else {
            return Errno(libc::EINVAL);
        };
        let ready =
            req(self.b, qinit_overseer_core::Q_READY_KIND) == qinit_overseer_core::READY_PIPE;
        let env = build_env(ready, &frame, self.user, self.id);
        let converted: Result<Vec<CString>> = argv.iter().map(|a| cstring(a)).collect();
        let Ok(words) = converted else {
            return Errno(libc::EINVAL);
        };
        let argv_refs: Vec<&CStr> = words.iter().map(CString::as_c_str).collect();
        let env_refs: Vec<&CStr> = env.iter().map(CString::as_c_str).collect();
        spawn::exec_in_place(&words[0], &argv_refs, &env_refs)
    }

    fn perform(&mut self, step: Step) -> Result<()> {
        match step {
            Step::Setsid => proc::setsid(),
            Step::Unshare(flags) => {
                ns::unshare(libc::c_int::try_from(flags).map_err(|_| Errno(libc::EINVAL))?)
            }
            Step::MountSlaveRoot => ns::mount_slave_rec_root(),
            Step::MountTmp => ns::mount_private_tmp(),
            Step::LoopbackUp => ns::loopback_up(),
            Step::Fork => Err(Errno(libc::EINVAL)),
            Step::ArmDeadline(ms) => timer::arm_alarm(ms),
            Step::OpenStdin => {
                let null = fd::open_cloexec(c"/dev/null", libc::O_RDONLY, 0)?;
                fd::dup2(null.as_fd(), 0)
            }
            Step::OpenStdout => self.stream(Q_STDOUT_KIND, Q_STDOUT_A, Q_STDOUT_B, 1),
            Step::OpenStderr => self.stream(Q_STDERR_KIND, Q_STDERR_A, Q_STDERR_B, 2),
            Step::RouteReady(n) => fd::dup2_raw(fd_number(n)?, READY_FD),
            Step::Umask(m) => {
                let _ = umask(m);
                Ok(())
            }
            Step::RlimitNofile(n) => set_rlimit(RLIMIT_NOFILE, u64::from(n), u64::from(n)),
            Step::RlimitCore0 => set_rlimit(RLIMIT_CORE, 0, 0),
            Step::Setgroups => cred::setgroups(&self.id.groups),
            Step::Setgid => cred::setresgid(self.id.gid),
            Step::Securebits(bits) => cred::set_securebits(bits),
            Step::DropBounding(cap) => match cred::capbset_drop(cap) {
                // A kernel that does not know the capability has nothing to drop.
                Err(Errno(libc::EINVAL)) => Ok(()),
                r => r,
            },
            Step::Setuid => cred::setresuid(self.id.uid),
            Step::Capset => {
                let caps = self.caps();
                cred::capset(caps, caps, caps)
            }
            Step::AmbientRaise(cap) => cred::ambient_raise(cap),
            Step::Pdeathsig => cred::set_pdeathsig(libc::SIGKILL),
            Step::NoNewPrivs => cred::set_no_new_privs(),
            Step::Chdir => chdir(&cstring(self.text(Q_CWD_OFF, Q_CWD_LEN)?)?),
            Step::LandlockRuleset => {
                self.ruleset = Some(ruleset(LANDLOCK_ACCESS_FS_ALL_V3)?);
                Ok(())
            }
            Step::LandlockRule(i) => self.landlock_rule(i),
            Step::LandlockRestrict => {
                let rs = self.ruleset.take().ok_or(Errno(libc::EBADF))?;
                restrict_self(rs.as_fd())
            }
            Step::Seccomp => self.seccomp(),
            Step::CloseRange => fd::close_from(5),
            Step::Exec => Err(self.exec()),
        }
    }
}

fn identity_errno(e: IdentityError) -> i32 {
    match e {
        IdentityError::Unknown => libc::ENOENT,
        IdentityError::RootAlias => libc::EPERM,
        IdentityError::Io(Errno(n)) => n,
        IdentityError::BadName | IdentityError::Ambiguous | IdentityError::Malformed(_) => {
            libc::EINVAL
        }
    }
}

/// The pid-namespace fork (spec §3, M2): the first child is the namespace's init and the
/// second its only child, which goes on to run the service. The original process and the init
/// each become a supervisor of the child they forked, so a signal reaches the service from a
/// process inside its namespace and the init reaps what the service orphans.
fn fork_supervised(id: &Identity, status: &mut Option<OwnedFd>) -> Result<()> {
    for outside in [true, false] {
        match proc::fork()? {
            0 => {}
            child => match status.take() {
                Some(pipe) => supervise(child, id, pipe, outside),
                None => proc::exit_now(127),
            },
        }
    }
    Ok(())
}

fn die(status: &OwnedFd, step: u32, errno: i32) -> ! {
    Status { step, errno }.write(status.as_fd());
    proc::exit_now(127)
}

/// Performs the launch described by the request on fd 3. Never returns: the process becomes
/// the service, or ends with 127 after writing its failure record to fd 4, or (as the
/// supervisor of a pid namespace) with the status of the service.
pub fn launch() -> ! {
    let Ok(status) = fd::inherit(STATUS_FD) else {
        proc::exit_now(127)
    };
    let _ = fd::set_cloexec_raw(STATUS_FD);
    let Ok(request) = fd::inherit(REQUEST_FD) else {
        die(&status, STEP_DECODE, libc::EBADF)
    };
    let _ = fd::set_cloexec_raw(REQUEST_FD);
    let bytes = match memfd::read_all(request.as_fd(), MAX_REQUEST) {
        Ok(b) => b,
        Err(e) => die(&status, STEP_DECODE, e.0),
    };
    // The number stays occupied (close-on-exec) until a readiness pipe replaces it.
    let _ = request.as_raw_fd();
    std::mem::forget(request);
    if decode(&bytes).is_err() {
        die(&status, STEP_DECODE, libc::EINVAL);
    }
    let mut run = Run {
        b: &bytes,
        id: &Identity {
            uid: 0,
            gid: 0,
            groups: Vec::new(),
            home: String::new(),
        },
        user: "",
        ruleset: None,
    };
    let user = match run.text(Q_USER_OFF, Q_USER_LEN) {
        Ok(u) => u,
        Err(e) => die(&status, STEP_DECODE, e.0),
    };
    let id = match identity::resolve(user) {
        Ok(i) => i,
        Err(e) => die(&status, STEP_IDENTITY, identity_errno(e)),
    };
    run.id = &id;
    run.user = user;
    let mut steps = [Step::Setsid; MAX_STEPS];
    let n = plan(&bytes, &mut steps);
    let mut status = Some(status);
    for (i, step) in steps[..n].iter().enumerate() {
        let index = u32::try_from(i).unwrap_or(u32::MAX);
        let result = if *step == Step::Fork {
            fork_supervised(&id, &mut status)
        } else {
            run.perform(*step)
        };
        if let Err(e) = result {
            match status.as_ref() {
                Some(pipe) => die(pipe, index, e.0),
                None => proc::exit_now(127),
            }
        }
    }
    // `Exec` is the last step and does not return success.
    match status.as_ref() {
        Some(pipe) => die(pipe, u32::try_from(n).unwrap_or(u32::MAX), libc::ENOEXEC),
        None => proc::exit_now(127),
    }
}
