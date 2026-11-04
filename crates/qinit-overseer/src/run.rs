// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The step runner: decode the request on fd 3, resolve the identity, and perform the proved
//! plan one step at a time (spec §4). A failing step writes its `(step, errno)` record on
//! fd 4 and ends the process with 127.
use crate::identity::{self, Identity, IdentityError};
use crate::output::{open_input, open_route};
use crate::request::RequestSpec;
use crate::status::{STEP_DECODE, STEP_IDENTITY, Status};
use crate::supervisor::supervise;
use crate::userns;
use crate::view;
use qinit_overseer_core::{
    DEFAULT_DENY, Insn, MAX_BPF, MAX_REQUEST, MAX_STEPS, Q_ARGV_LEN, Q_ARGV_OFF, Q_CAPS_HI,
    Q_CAPS_LO, Q_CWD_LEN, Q_CWD_OFF, Q_ENV_LEN, Q_ENV_OFF, Q_INSIDE_GID, Q_INSIDE_UID, Q_NS,
    Q_PATHS_LEN, Q_PATHS_OFF, Q_SECCOMP, Q_SECCOMP_LEN, Q_SECCOMP_OFF, Q_STDERR_A, Q_STDERR_B,
    Q_STDERR_KIND, Q_STDIN_A, Q_STDIN_B, Q_STDIN_KIND, Q_STDOUT_A, Q_STDOUT_B, Q_STDOUT_KIND,
    Q_UMASK, Q_USER_LEN, Q_USER_MAP, Q_USER_OFF, STREAM_FD, STREAM_PATH, Step, decode, plan, pool,
    program, req,
};
use qinit_sys::fs::{Kind, lstat_kind};
use qinit_sys::landlock::{
    LANDLOCK_ACCESS_FS_ALL_V3, LANDLOCK_ACCESS_FS_READ, add_path_rule, restrict_self, ruleset,
};
use qinit_sys::limits::{RLIMIT_CORE, chdir, set_rlimit, umask};
use qinit_sys::timer::{Alarm, arm_alarm_at, now_monotonic_ns};
use qinit_sys::{Errno, Result, cred, fd, memfd, ns, proc, seccomp, spawn};
use std::ffi::{CStr, CString};
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::path::Path;

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
    /// The argument and environment vectors of the exec, built before the filter is installed
    /// (a filter that allows no `brk` or `mmap` would end the allocation).
    prepared: Option<(Vec<CString>, Vec<CString>)>,
    /// Whether the capabilities above `CAP_LAST` of a newer kernel are out of the bounding set.
    extra_dropped: bool,
    /// The deadline as an absolute `CLOCK_MONOTONIC` instant, kept so that the process after a
    /// pid-namespace fork can arm the same instant again.
    deadline_ns: u64,
    /// The armed deadline timer; a pid-namespace fork leaves it with the supervisor outside.
    alarm: Option<Alarm>,
    /// The host's `/proc/self`, for the map writer, from `ProcSelf` until the user namespace.
    proc_self: Option<OwnedFd>,
}

impl<'a> Run<'a> {
    fn text(&self, off: usize, len: usize) -> Result<&'a str> {
        std::str::from_utf8(pool(self.b, req(self.b, off), req(self.b, len)))
            .map_err(|_| Errno(libc::EINVAL))
    }

    fn list(&self, off: usize, len: usize) -> Result<Vec<&'a str>> {
        Ok(items(self.text(off, len)?))
    }

    /// Runs `f` with the mask cleared: the view's directories and mount points are made with
    /// the modes the view wants, not the service's mask.
    fn unmasked<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
        let old = umask(0);
        let r = f();
        let _ = umask(old);
        r
    }

    /// The service runs in a user namespace of its own: its ids are the inside ones.
    fn in_user_namespace(&self) -> bool {
        req(self.b, Q_NS) & 32 != 0
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
                fd::place(opened?, target)
            }
            STREAM_FD => fd::dup2_raw(fd_number(req(self.b, a))?, target),
            _ => fd::dup2_raw(1, target),
        }
    }

    fn seccomp(&mut self) -> Result<()> {
        if self.prepared.is_none() {
            self.prepared = Some(self.exec_vectors()?);
        }
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
        let list = self.list(Q_PATHS_OFF, Q_PATHS_LEN)?;
        let entry = list.get(i as usize).ok_or(Errno(libc::EINVAL))?;
        let (mode, path) = view::split(entry)?;
        let access = if mode.read_only() {
            LANDLOCK_ACCESS_FS_READ
        } else {
            LANDLOCK_ACCESS_FS_ALL_V3
        };
        // A symlink entry is a link in the view: what it points to is reachable only if that
        // is listed too, so it gets no rule (`O_PATH` would follow it).
        if lstat_kind(Path::new(path))? == Kind::Symlink {
            return Ok(());
        }
        let rs = self.ruleset.as_ref().ok_or(Errno(libc::EBADF))?;
        add_path_rule(rs.as_fd(), &cstring(path)?, access)
    }

    /// The argument and environment vectors of the exec.
    fn exec_vectors(&self) -> Result<(Vec<CString>, Vec<CString>)> {
        let argv = self.list(Q_ARGV_OFF, Q_ARGV_LEN)?;
        if argv.is_empty() {
            return Err(Errno(libc::EINVAL));
        }
        let frame = self.list(Q_ENV_OFF, Q_ENV_LEN)?;
        let ready =
            req(self.b, qinit_overseer_core::Q_READY_KIND) == qinit_overseer_core::READY_PIPE;
        let env = build_env(ready, &frame, self.user, self.id);
        let words = argv
            .iter()
            .map(|a| cstring(a))
            .collect::<Result<Vec<CString>>>()?;
        Ok((words, env))
    }

    fn exec(&mut self) -> Errno {
        let (words, env) = match self.prepared.take() {
            Some(v) => v,
            None => match self.exec_vectors() {
                Ok(v) => v,
                Err(e) => return e,
            },
        };
        let argv_refs: Vec<&CStr> = words.iter().map(CString::as_c_str).collect();
        let env_refs: Vec<&CStr> = env.iter().map(CString::as_c_str).collect();
        spawn::exec_in_place(&words[0], &argv_refs, &env_refs)
    }

    /// Takes every capability a newer kernel has beyond `CAP_LAST` out of the bounding set,
    /// before the first of the plan's drops (the last of which, `CAP_SETPCAP`, is needed here).
    fn drop_newer_capabilities(&mut self) -> Result<()> {
        if self.extra_dropped {
            return Ok(());
        }
        self.extra_dropped = true;
        for cap in cred::CAP_LAST + 1..=cred::cap_last()? {
            cred::capbset_drop(cap)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // one arm per plan step
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
            // The helper user namespace of the idmapped entries arrives with the idmapped mounts.
            Step::IdmapNamespace => Err(Errno(libc::ENOSYS)),
            Step::ViewRoot => Self::unmasked(view::root),
            Step::ViewDev => Self::unmasked(view::dev),
            Step::ViewTmp => Self::unmasked(view::tmp),
            Step::ViewEntry(i) => {
                let list = self.list(Q_PATHS_OFF, Q_PATHS_LEN)?;
                let entry = list.get(i as usize).ok_or(Errno(libc::EINVAL))?;
                let above = view::writable_ancestor(&list, i as usize)
                    .map(|j| view::split(list[j]).map(|(_, p)| Path::new(p)))
                    .transpose()?;
                Self::unmasked(|| view::entry(entry, req(self.b, Q_NS) & 2 != 0, above))
            }
            Step::ViewPivot => Self::unmasked(view::pivot),
            Step::ViewSeal => view::seal(),
            Step::ArmDeadline(ms) => {
                self.deadline_ns = now_monotonic_ns().saturating_add(u64::from(ms) * 1_000_000);
                self.alarm = Some(arm_alarm_at(self.deadline_ns)?);
                Ok(())
            }
            Step::RearmDeadline => {
                // Timers are not inherited across a fork: this is a new one at the same instant.
                self.alarm = Some(arm_alarm_at(self.deadline_ns)?);
                Ok(())
            }
            Step::OpenStdin => match req(self.b, Q_STDIN_KIND) {
                STREAM_PATH => {
                    let opened = open_input(&cstring(self.text(Q_STDIN_A, Q_STDIN_B)?)?);
                    fd::place(opened?, 0)
                }
                _ => fd::dup2_raw(fd_number(req(self.b, Q_STDIN_A))?, 0),
            },
            Step::OpenStdout => self.stream(Q_STDOUT_KIND, Q_STDOUT_A, Q_STDOUT_B, 1),
            Step::OpenStderr => self.stream(Q_STDERR_KIND, Q_STDERR_A, Q_STDERR_B, 2),
            Step::RouteReady(n) => fd::dup2_raw(fd_number(n)?, READY_FD),
            Step::Umask(m) => {
                let _ = umask(m);
                Ok(())
            }
            Step::Rlimit(r, v) => set_rlimit(
                libc::c_int::try_from(r).map_err(|_| Errno(libc::EINVAL))?,
                v,
                v,
            ),
            Step::RlimitCore0 => set_rlimit(RLIMIT_CORE, 0, 0),
            Step::Setgroups => cred::setgroups(&self.id.groups),
            Step::Setgid => cred::setresgid(if self.in_user_namespace() {
                req(self.b, Q_INSIDE_GID)
            } else {
                self.id.gid
            }),
            Step::Securebits(bits) => cred::set_securebits(bits),
            Step::DropBounding(cap) => {
                self.drop_newer_capabilities()?;
                match cred::capbset_drop(cap) {
                    // A kernel that does not know the capability has nothing to drop.
                    Err(Errno(libc::EINVAL)) => Ok(()),
                    r => r,
                }
            }
            Step::Setuid => cred::setresuid(if self.in_user_namespace() {
                req(self.b, Q_INSIDE_UID)
            } else {
                self.id.uid
            }),
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
            Step::LandlockViewRules => {
                let rs = self.ruleset.as_ref().ok_or(Errno(libc::EBADF))?;
                view::landlock_rules(rs.as_fd())
            }
            Step::LandlockRule(i) => self.landlock_rule(i),
            Step::LandlockRestrict => {
                let rs = self.ruleset.take().ok_or(Errno(libc::EBADF))?;
                restrict_self(rs.as_fd())
            }
            Step::ProcSelf => {
                self.proc_self = Some(userns::proc_self()?);
                Ok(())
            }
            Step::ClearGroups => cred::setgroups(&[]),
            Step::UserNamespace => {
                let dir = self.proc_self.take().ok_or(Errno(libc::EBADF))?;
                userns::enter(
                    &dir,
                    self.id,
                    req(self.b, Q_USER_MAP) == 1,
                    (req(self.b, Q_INSIDE_UID), req(self.b, Q_INSIDE_GID)),
                )
            }
            Step::UnshareOwned(flags) => {
                ns::unshare(libc::c_int::try_from(flags).map_err(|_| Errno(libc::EINVAL))?)
            }
            Step::Seccomp => self.seccomp(),
            Step::CloseRange => fd::close_from(5),
            Step::Exec => Err(self.exec()),
        }
    }
}

fn identity_errno(e: IdentityError) -> i32 {
    match e {
        IdentityError::Unknown | IdentityError::SubidMissing => libc::ENOENT,
        IdentityError::InsideRange => libc::ERANGE,
        IdentityError::RootAlias | IdentityError::RootGroup | IdentityError::SubidOverlap => {
            libc::EPERM
        }
        IdentityError::Io(Errno(n)) => n,
        IdentityError::BadName
        | IdentityError::Ambiguous
        | IdentityError::Malformed(_)
        | IdentityError::SubidAmbiguous
        | IdentityError::SubidMalformed(_) => libc::EINVAL,
    }
}

/// The pid-namespace fork (spec §3, M2): the first child is the namespace's init and the
/// second its only child, which goes on to run the service. The original process and the init
/// each become a supervisor of the child they forked, so a signal reaches the service from a
/// process inside its namespace and the init reaps what the service orphans.
fn fork_supervised(
    id: &Identity,
    status: &mut Option<OwnedFd>,
    step: u32,
    alarm: &mut Option<Alarm>,
) -> Result<()> {
    for outside in [true, false] {
        match proc::fork()? {
            0 => {}
            child => match status.take() {
                Some(pipe) => supervise(child, id, pipe, step, outside, alarm.take()),
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
            subuid: None,
            subgid: None,
        },
        user: "",
        ruleset: None,
        prepared: None,
        extra_dropped: false,
        deadline_ns: 0,
        alarm: None,
        proc_self: None,
    };
    let user = match run.text(Q_USER_OFF, Q_USER_LEN) {
        Ok(u) => u,
        Err(e) => die(&status, STEP_DECODE, e.0),
    };
    let range = req(&bytes, Q_USER_MAP) == 1;
    let id = match identity::resolve(user, range).and_then(|id| {
        identity::check_inside(
            &id,
            range,
            (req(&bytes, Q_INSIDE_UID), req(&bytes, Q_INSIDE_GID)),
        )
        .map(|()| id)
    }) {
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
            fork_supervised(&id, &mut status, index, &mut run.alarm)
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
