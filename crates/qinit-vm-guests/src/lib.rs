// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! `qinit-vm-guests`: the guest side of qinit's VM suites (spec 2026-10-27 §6.1 tier 3). Each
//! suite is a binary booted as `/init`. It mounts proc, sys, cgroup2, devtmpfs and tmpfs, runs
//! its cases, prints `QINIT-VM <suite> <case> PASS|FAIL <detail>` and `QINIT-VM <suite> END <case-count>` on
//! the console and powers the guest off from a child. The same binary is the helper program
//! the cases spawn: `/init --qinit-helper <role> <args…>`.
#![allow(clippy::missing_errors_doc)] // every fallible function returns one string naming the step and its cause
use qinit_cell::{CellId, Cells, Notice, ReadyMode, Report};
use qinit_event::{Loop, Ready, Token};
use qinit_overseer::request::RequestSpec;
use qinit_overseer::status::Status;
use std::ffi::{CString, OsStr, OsString};
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd, RawFd};
use std::path::Path;
use std::time::Duration;

/// One case: its name and its body.
pub type Case = (&'static str, fn() -> Result<(), String>);

pub const HELPER_FLAG: &str = "--qinit-helper";
/// The test comb: cells live directly under it.
pub const COMB: &str = "/sys/fs/cgroup/qinit-test";
/// A hang guard for each wait (cases assert order, never durations).
pub const HANG_GUARD: Duration = Duration::from_secs(60);
/// The grace of a stop that must reach its kill deadline: long enough for a TERM-noting
/// helper to write its one-byte note before the kill. A margin, not an expectation.
pub const NOTE_GRACE: Duration = Duration::from_secs(5);

/// The suite's whole body. Never returns: the guest powers off.
pub fn run(suite: &'static str, cases: &[Case]) -> ! {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some(HELPER_FLAG) {
        let role = args.next().unwrap_or_default();
        std::process::exit(helper(&role, &args.collect::<Vec<String>>()));
    }
    let setup = if qinit_sys::proc::pid() == 1 {
        enter_tmpfs_root().and_then(|()| setup())
    } else {
        Ok(())
    };
    for (name, body) in cases {
        let r = match &setup {
            Err(e) => Err(format!("guest setup failed: {e}")),
            Ok(()) => std::panic::catch_unwind(*body).unwrap_or_else(|p| Err(panic_text(&p))),
        };
        console(&match r {
            Ok(()) => format!("QINIT-VM {suite} {name} PASS"),
            Err(e) => format!(
                "QINIT-VM {suite} {name} FAIL {}",
                e.replace(['\n', '\r'], " ")
            ),
        });
    }
    console(&format!("QINIT-VM {suite} END {}", cases.len()));
    qinit_sys::mount::power_off_from_child()
}

fn panic_text(p: &Box<dyn std::any::Any + Send>) -> String {
    p.downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| p.downcast_ref::<String>().cloned())
        .map_or_else(|| "panicked".to_string(), |s| format!("panicked: {s}"))
}

fn console(line: &str) {
    if let Ok(mut c) = std::fs::OpenOptions::new().write(true).open("/dev/console") {
        let _ = writeln!(c, "{line}");
    }
}

/// Copies the directory `from` into `to`, leaving out the entries named in `skip`.
fn copy_tree(from: &Path, to: &Path, skip: &[&Path]) -> std::io::Result<()> {
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let path = entry.path();
        if skip.contains(&path.as_path()) {
            continue;
        }
        let target = to.join(entry.file_name());
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.is_dir() {
            std::fs::create_dir(&target)?;
            std::fs::set_permissions(&target, meta.permissions())?;
            copy_tree(&path, &target, skip)?;
        } else if meta.file_type().is_symlink() {
            std::os::unix::fs::symlink(std::fs::read_link(&path)?, &target)?;
        } else {
            std::fs::copy(&path, &target)?;
        }
    }
    Ok(())
}

/// Moves the guest from the initramfs root onto a tmpfs root (what `switch_root` does):
/// `pivot_root`, which the executor's path view needs, refuses to run when the root is the
/// initramfs itself.
fn enter_tmpfs_root() -> Result<(), String> {
    use qinit_sys::mount::{chroot, mkdir, mount, mount_move};
    let new = Path::new("/.root");
    mkdir(new, 0o755).map_err(|x| format!("mkdir /.root: {x}"))?;
    mount("tmpfs", new, "tmpfs", 0).map_err(|x| format!("mount the new root: {x}"))?;
    let skip = [
        new,
        Path::new("/proc"),
        Path::new("/sys"),
        Path::new("/dev"),
    ];
    copy_tree(Path::new("/"), new, &skip).map_err(|x| format!("copy the root: {x}"))?;
    for d in ["dev", "proc", "sys"] {
        mkdir(&new.join(d), 0o755).map_err(|x| format!("mkdir /{d}: {x}"))?;
    }
    std::env::set_current_dir(new).map_err(|x| format!("enter the new root: {x}"))?;
    mount_move(Path::new("."), Path::new("/")).map_err(|x| format!("move the new root: {x}"))?;
    chroot(Path::new(".")).map_err(|x| format!("chroot: {x}"))?;
    std::env::set_current_dir("/").map_err(|x| format!("chdir /: {x}"))
}

fn setup() -> Result<(), String> {
    use qinit_sys::mount::{mkdir, mount};
    for d in ["/dev", "/proc", "/sys", "/tmp", "/run"] {
        let _ = mkdir(Path::new(d), 0o755);
    }
    let m = |src: &str, dst: &str, fs: &str| {
        mount(src, Path::new(dst), fs, 0).map_err(|e| format!("mount {fs} on {dst}: {e}"))
    };
    m("devtmpfs", "/dev", "devtmpfs")?;
    m("proc", "/proc", "proc")?;
    m("sysfs", "/sys", "sysfs")?;
    m("cgroup2", "/sys/fs/cgroup", "cgroup2")?;
    m("tmpfs", "/tmp", "tmpfs")?;
    // The writable directory of a host whose root may be read-only; the view is built below it.
    m("tmpfs", "/run", "tmpfs")?;
    mkdir(Path::new(COMB), 0o755).map_err(|e| format!("mkdir {COMB}: {e}"))?;
    // The home of the `svc` account of the initrd's /etc/passwd.
    let _ = mkdir(Path::new("/home"), 0o755);
    mkdir(Path::new("/home/svc"), 0o700).map_err(|e| format!("mkdir /home/svc: {e}"))?;
    qinit_sys::fd::chown(c"/home/svc", 1000, 1000).map_err(|e| format!("chown /home/svc: {e}"))
}

fn sys<T>(r: qinit_sys::Result<T>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("{what}: {e}"))
}

/// Any displayable error as a case's `String` error.
pub fn e<T, E: std::fmt::Display>(r: Result<T, E>) -> Result<T, String> {
    r.map_err(|x| x.to_string())
}

/// The cells of the test comb.
pub fn cells() -> Result<Cells, String> {
    Cells::open(Path::new(COMB)).map_err(|x| format!("open the cells: {x}"))
}

/// `/init --qinit-helper <role> <args…>` as a cell's main process (readiness pipe at fd 3).
#[must_use]
pub fn helper_cmd(role: &str, role_args: &[&str]) -> qinit_cell::Command {
    let mut argv = vec![
        OsString::from("/init"),
        OsString::from(HELPER_FLAG),
        OsString::from(role),
    ];
    argv.extend(role_args.iter().map(OsString::from));
    qinit_cell::Command {
        path: "/init".into(),
        argv,
        env: Vec::new(),
        fds: Vec::new(),
        ready_fd: 3,
    }
}

/// The executor in the initrd.
pub const OVERSEER: &str = "/overseer";

/// A launch through the executor: its cell and the read end of its status pipe.
pub struct Launched {
    pub id: CellId,
    pub status: OwnedFd,
}

/// Spawns the executor into a new cell `name` with `spec` (the request at fd 3 and the status
/// pipe at fd 4 are added here); `extra` are routed descriptors the spec names (5 and up).
/// `ready` chooses the cell's readiness mode: `Pipe` routes the pipe at fd 5, so the spec
/// must say `ready_fd: Some(5)`.
pub fn launch(
    cells: &mut Cells,
    name: &str,
    spec: &RequestSpec,
    extra: Vec<(OwnedFd, RawFd)>,
    ready: ReadyMode,
) -> Result<Launched, String> {
    let bytes = e(spec.bytes().map_err(|x| format!("{x:?}")))?;
    let request = sys(qinit_sys::memfd::sealed(c"req", &bytes), "seal the request")?;
    launch_fd(cells, name, request, extra, ready)
}

/// As [`launch`], with the sealed request already in a memfd (what a `Run` passes on).
pub fn launch_fd(
    cells: &mut Cells,
    name: &str,
    request: OwnedFd,
    extra: Vec<(OwnedFd, RawFd)>,
    ready: ReadyMode,
) -> Result<Launched, String> {
    let (status_r, status_w) = sys(qinit_sys::fd::pipe(libc::O_CLOEXEC), "status pipe")?;
    let id = e(cells.create(name))?;
    let mut fds = vec![(request, 3), (status_w, 4)];
    fds.extend(extra);
    let cmd = qinit_cell::Command {
        path: OVERSEER.into(),
        argv: vec![OsString::from("overseer")],
        env: Vec::new(),
        fds,
        ready_fd: 5,
    };
    e(cells.spawn(id, cmd, ready))?;
    Ok(Launched {
        id,
        status: status_r,
    })
}

/// The failure record of a launch, once its executor exited or reported ready; `None` is EOF,
/// the service's exec.
#[must_use]
pub fn status_of(l: &Launched) -> Option<Status> {
    Status::read(l.status.as_fd())
}

/// The request for `/init --qinit-helper <role> <args…>` as `user`, a ten-second deadline;
/// the caller sets the streams.
#[must_use]
pub fn spec(user: &str, role: &str, args: &[&str]) -> RequestSpec {
    let mut command = vec![
        "/init".to_string(),
        HELPER_FLAG.to_string(),
        role.to_string(),
    ];
    command.extend(args.iter().map(ToString::to_string));
    RequestSpec {
        argv: command,
        user: user.to_string(),
        deadline_ms: 10_000,
        ..RequestSpec::default()
    }
}

/// A pipe for a helper's standard output: (read end, write end), the write end to route at
/// fd 6 with `Stream::Fd(6)`.
///
/// # Panics
/// When the kernel refuses a pipe.
#[must_use]
pub fn capture() -> (OwnedFd, OwnedFd) {
    qinit_sys::fd::pipe(libc::O_CLOEXEC).expect("pipe")
}

/// Everything written to a capture pipe, once every writer is gone.
#[must_use]
pub fn read_all(fd: OwnedFd) -> String {
    let mut text = String::new();
    let _ = std::fs::File::from(fd).read_to_string(&mut text);
    text
}

/// The calls the static musl helper needs under an allowlist, with their `x86_64` numbers (a
/// host test checks the pairs against the syscall table). `execve` and `close_range` are the
/// executor's own last calls before the service starts.
pub const ALLOW_MIN: &[(&str, u32)] = &[
    ("read", 0),
    ("write", 1),
    ("writev", 20),
    ("close", 3),
    ("fstat", 5),
    ("newfstatat", 262),
    ("lseek", 8),
    ("mmap", 9),
    ("munmap", 11),
    ("mprotect", 10),
    ("brk", 12),
    ("rt_sigaction", 13),
    ("rt_sigprocmask", 14),
    ("rt_sigreturn", 15),
    ("ioctl", 16),
    ("pread64", 17),
    ("poll", 7),
    ("madvise", 28),
    ("exit", 60),
    ("exit_group", 231),
    ("futex", 202),
    ("set_tid_address", 218),
    ("set_robust_list", 273),
    ("rseq", 334),
    ("clock_gettime", 228),
    ("getrandom", 318),
    ("sigaltstack", 131),
    ("prlimit64", 302),
    ("arch_prctl", 158),
    ("openat", 257),
    ("readlinkat", 267),
    ("statx", 332),
    ("membarrier", 324),
    ("sched_getaffinity", 204),
    ("getpid", 39),
    ("gettid", 186),
    ("tgkill", 234),
    ("kill", 62),
    ("execve", 59),
    ("close_range", 436),
];

/// A stream socket bound to `path` and listening with `backlog`.
pub fn stream_listener(
    path: &str,
    backlog: i32,
) -> Result<std::os::unix::net::UnixListener, String> {
    let c = CString::new(path).map_err(|x| x.to_string())?;
    let fd = sys(qinit_sys::sock::listen_unix(&c, backlog), "listen")?;
    Ok(std::os::unix::net::UnixListener::from(fd))
}

/// `n` connected clients of the listener at `path`, none accepted: they fill its backlog.
pub fn queue_connections(
    path: &str,
    n: usize,
) -> Result<Vec<std::os::unix::net::UnixStream>, String> {
    (0..n)
        .map(|_| e(std::os::unix::net::UnixStream::connect(path)))
        .collect()
}

/// What a launch left behind once its cell was empty.
pub struct Outcome {
    /// Everything the service wrote to its captured standard output.
    pub out: String,
    /// The wait status of the main process (the executor or, after its exec, the service).
    pub exit: Option<i32>,
    /// The executor's failure record, if it left one.
    pub failure: Option<Status>,
    /// The request as bytes, for naming the failing step.
    pub request: Vec<u8>,
}

impl Outcome {
    /// The exit code of the main process; an error when it was killed by a signal.
    pub fn code(&self) -> Result<i32, String> {
        match self.exit {
            Some(st) if libc::WIFEXITED(st) => Ok(libc::WEXITSTATUS(st)),
            other => Err(format!(
                "main status {other:?}, want a normal exit; {:?}",
                self.failure
            )),
        }
    }

    /// The signal that killed the main process; an error when it exited.
    pub fn signal(&self) -> Result<i32, String> {
        match self.exit {
            Some(st) if libc::WIFSIGNALED(st) => Ok(libc::WTERMSIG(st)),
            other => Err(format!("main status {other:?}, want a death by signal")),
        }
    }
}

/// Launches `request` in a new cell `name` (`ReadyMode::Exit`), waits for the cell to empty,
/// and collects its captured standard output (when `capture_stdout`, which routes it at
/// fd 6), the main's status and the executor's record.
pub fn run_to_end(
    name: &str,
    mut request: RequestSpec,
    capture_stdout: bool,
) -> Result<Outcome, String> {
    let mut cells = cells()?;
    let (reader, writer) = capture();
    let mut extra = Vec::new();
    if capture_stdout {
        request.stdout = qinit_overseer::request::Stream::Fd(6);
        extra.push((writer, 6));
    }
    let l = launch(&mut cells, name, &request, extra, ReadyMode::Exit)?;
    let seen = expect(&mut cells, l.id, Report::Empty)?;
    // In exit mode a status 0 is the `Ready` report; any other status is `MainExited`.
    let exit = reports_of(&seen, l.id).iter().find_map(|r| match r {
        Report::MainExited(st) => *st,
        Report::Ready => Some(0),
        _ => None,
    });
    let failure = status_of(&l);
    remove(&mut cells, l.id)?;
    Ok(Outcome {
        out: if capture_stdout {
            read_all(reader)
        } else {
            String::new()
        },
        exit,
        failure,
        request: e(request.bytes().map_err(|x| format!("{x:?}")))?,
    })
}

/// Runs the request in the sealed memfd `request` through the executor in a new cell `name`
/// and waits for the cell to empty: the main's status and the executor's record.
pub fn run_fd_to_end(name: &str, request: OwnedFd) -> Result<Outcome, String> {
    let bytes = sys(
        qinit_sys::memfd::read_all(request.as_fd(), 65536),
        "read the request",
    )?;
    let mut cells = cells()?;
    let l = launch_fd(&mut cells, name, request, Vec::new(), ReadyMode::Exit)?;
    let seen = expect(&mut cells, l.id, Report::Empty)?;
    let exit = reports_of(&seen, l.id).iter().find_map(|r| match r {
        Report::MainExited(st) => *st,
        Report::Ready => Some(0),
        _ => None,
    });
    let failure = status_of(&l);
    remove(&mut cells, l.id)?;
    Ok(Outcome {
        out: String::new(),
        exit,
        failure,
        request: bytes,
    })
}

/// Reads notices until `id` reports `want`: every notice seen, in order, up to the end of the
/// batch that brought `want`. A report of `id` after which `want` can no longer come
/// (`Failed`, `Empty`, `Removed`, other than `want`) ends the wait with an error.
pub fn expect(cells: &mut Cells, id: CellId, want: Report) -> Result<Vec<Notice>, String> {
    let mut seen = Vec::new();
    loop {
        let batch = cells.next().map_err(|x| format!("next notices: {x}"))?;
        let from = seen.len();
        seen.extend(batch);
        for n in &seen[from..] {
            match *n {
                Notice::Cell(i, r) if i == id && r == want => return Ok(seen),
                Notice::Cell(i, r @ (Report::Failed(_) | Report::Empty | Report::Removed))
                    if i == id =>
                {
                    return Err(format!(
                        "the cell reported {r:?} while waiting for {want:?}; seen {seen:?}"
                    ));
                }
                _ => {}
            }
        }
    }
}

/// The reports of `id` among `seen`, in order.
#[must_use]
pub fn reports_of(seen: &[Notice], id: CellId) -> Vec<Report> {
    seen.iter()
        .filter_map(|n| match n {
            Notice::Cell(i, r) if *i == id => Some(*r),
            _ => None,
        })
        .collect()
}

/// Removes cell `id` and waits for its `Removed`.
pub fn remove(cells: &mut Cells, id: CellId) -> Result<(), String> {
    e(cells.remove(id))?;
    expect(cells, id, Report::Removed).map(|_| ())
}

#[must_use]
pub fn exists(path: &str) -> bool {
    Path::new(path).exists()
}

/// Reaps every exited child of this process: their wait statuses. Only for children no
/// `Cells` tracks (a cell's main process re-parented grandchildren, once the cell is empty).
pub fn reap_exited() -> Result<Vec<i32>, String> {
    let mut statuses = Vec::new();
    while let Some((_, status)) = sys(qinit_sys::proc::reap_any(), "reap")? {
        statuses.push(status);
    }
    Ok(statuses)
}

/// Blocks for `count` untracked children (or ECHILD), returning their wait statuses.
/// Use after Empty when presence is asserted: cgroup exit precedes waitability.
pub fn reap_expected(count: usize) -> Result<Vec<i32>, String> {
    let mut statuses = Vec::new();
    while statuses.len() < count {
        let Some((_, status)) = sys(qinit_sys::proc::wait_any(), "wait for child")? else {
            break;
        };
        statuses.push(status);
    }
    Ok(statuses)
}

/// Whether wait status `status` is a death by SIGKILL.
#[must_use]
pub fn killed(status: i32) -> bool {
    libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL
}

/// The comb's directory descriptor.
pub fn comb() -> Result<OwnedFd, String> {
    sys(
        qinit_sys::cgroup::open_dir(Path::new(COMB)),
        "open the comb",
    )
}

/// Makes cell `name`: its directory and its open `cgroup.events`.
pub fn make_cell(name: &str) -> Result<(OwnedFd, OwnedFd), String> {
    let comb = comb()?;
    let c = CString::new(name).map_err(|e| e.to_string())?;
    sys(
        qinit_sys::cgroup::mkdir_at(&comb, &c, 0o755),
        "mkdir the cell",
    )?;
    let dir = sys(qinit_sys::cgroup::open_dir_at(&comb, &c), "open the cell")?;
    let events = sys(
        qinit_sys::cgroup::open_file_at(&dir, c"cgroup.events", libc::O_RDONLY),
        "open cgroup.events",
    )?;
    Ok((dir, events))
}

/// Spawns `/init --qinit-helper <role>` straight into `cell`, waiting for its exec.
pub fn spawn_helper(cell: BorrowedFd<'_>, role: &str) -> Result<(libc::pid_t, OwnedFd), String> {
    spawn_helper_routed(cell, role, &[])
}

/// [`spawn_helper`] with descriptor routes `(source, target number)` into the helper.
pub fn spawn_helper_routed(
    cell: BorrowedFd<'_>,
    role: &str,
    routes: &[(BorrowedFd<'_>, RawFd)],
) -> Result<(libc::pid_t, OwnedFd), String> {
    spawn_with(Some(cell), &[role], routes)
}

/// Starts a ready helper in `cell`, waiting until it has blocked TERM.
pub fn spawn_ready_helper(
    cell: BorrowedFd<'_>,
    role: &str,
) -> Result<(libc::pid_t, OwnedFd), String> {
    let (r, w) = e(qinit_sys::fd::pipe(libc::O_CLOEXEC))?;
    let child = spawn_helper_routed(cell, role, &[(w.as_fd(), 3)])?;
    drop(w);
    let mut byte = [0u8; 1];
    e(std::fs::File::from(r).read_exact(&mut byte))?;
    Ok(child)
}

/// Spawns `/init --qinit-helper <role_args…>`, in `cell` when given, with only `routes`,
/// waiting for its exec.
fn spawn_with(
    cell: Option<BorrowedFd<'_>>,
    role_args: &[&str],
    routes: &[(BorrowedFd<'_>, RawFd)],
) -> Result<(libc::pid_t, OwnedFd), String> {
    let mut argv = vec![OsStr::new("/init"), OsStr::new(HELPER_FLAG)];
    argv.extend(role_args.iter().map(OsStr::new));
    let p = sys(
        qinit_sys::spawn::Prepared::new(Path::new("/init"), &argv, &[], routes),
        "prepare",
    )?;
    let (r, w) = sys(qinit_sys::fd::pipe(libc::O_CLOEXEC), "pipe")?;
    let child = sys(qinit_sys::spawn::spawn(&p, cell, w.as_fd()), "clone3")?;
    drop(w);
    let mut bytes = Vec::new();
    std::fs::File::from(r)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if !bytes.is_empty() {
        return Err(format!("exec of the helper failed: {bytes:?}"));
    }
    Ok(child)
}

/// `(populated, frozen)` from `cgroup.events`, re-read from its start.
pub fn read_events(events: BorrowedFd<'_>) -> Result<(bool, bool), String> {
    let mut buf = [0u8; 128];
    let n = sys(
        qinit_sys::cgroup::read_from_start(events, &mut buf),
        "read cgroup.events",
    )?;
    qinit_cell::text::parse_events(&buf[..n]).ok_or_else(|| {
        format!(
            "cgroup.events without populated and frozen: {:?}",
            String::from_utf8_lossy(&buf[..n])
        )
    })
}

/// Waits on `l` (whose source `token` watches `events`) until `events` shows the wanted
/// values; a `HANG_GUARD` deadline token `token + 1000` ends the wait with an error. Lenient:
/// a state already reached when it is called is accepted without any notification, so it
/// proves the state, never that a notification announced it (that is [`await_notified`]).
pub fn await_events(
    l: &mut Loop,
    token: Token,
    events: BorrowedFd<'_>,
    populated: Option<bool>,
    frozen: Option<bool>,
) -> Result<(), String> {
    wait_for(l, token, events, (populated, frozen), false)
}

/// Like [`await_events`], but strict: the wanted state is accepted only when read after a
/// `Ready::Priority` or `Ready::Inotify` for `token`. For a probe of the notification
/// itself: read `events` (clearing its pending priority state), register the watch, then
/// trigger the change. EPOLLPRI is level-triggered and inotify queues, so a notification
/// raised before this call stays pending.
pub fn await_notified(
    l: &mut Loop,
    token: Token,
    events: BorrowedFd<'_>,
    populated: Option<bool>,
    frozen: Option<bool>,
) -> Result<(), String> {
    wait_for(l, token, events, (populated, frozen), true)
}

fn wait_for(
    l: &mut Loop,
    token: Token,
    events: BorrowedFd<'_>,
    (populated, frozen): (Option<bool>, Option<bool>),
    strict: bool,
) -> Result<(), String> {
    let guard = token + 1000;
    l.add_deadline(HANG_GUARD, guard)
        .map_err(|e| e.to_string())?;
    let wanted =
        |(p, f): (bool, bool)| populated.is_none_or(|w| w == p) && frozen.is_none_or(|w| w == f);
    if !strict && wanted(read_events(events)?) {
        l.remove(guard).map_err(|e| e.to_string())?;
        return Ok(());
    }
    loop {
        for r in l.wait().map_err(|e| e.to_string())? {
            match r {
                Ready::Deadline(t) if t == guard => {
                    return Err(format!(
                        "no notification brought populated {populated:?} frozen {frozen:?}"
                    ));
                }
                Ready::Priority(t) if t == token => {}
                Ready::Inotify(t, _) if t == token => {}
                _ => continue,
            }
            if wanted(read_events(events)?) {
                l.remove(guard).map_err(|e| e.to_string())?;
                return Ok(());
            }
        }
    }
}

/// Writes one byte to descriptor 3 (a readiness pipe), which stays open. Through the
/// descriptor itself: `/proc/self/fd/3` of a pipe made by root is closed to another user.
fn write_ready() -> bool {
    use std::os::fd::IntoRawFd;
    let Ok(fd) = qinit_sys::fd::inherit(3) else {
        return false;
    };
    let mut file = std::fs::File::from(fd);
    let written = file.write_all(b"\n").is_ok();
    let _ = OwnedFd::from(file).into_raw_fd();
    written
}

/// Blocks until SIGTERM (blocked, read from a signalfd) arrives; with `ignore`, forever.
/// With `ready`, writes to descriptor 3 once SIGTERM is blocked, so a TERM sent after the
/// readiness byte is always caught. With `note`, writes that file at each TERM before going
/// on (the helper's own evidence that TERM reached it).
fn wait_for_term(ignore: bool, ready: bool, note: Option<&str>) -> i32 {
    let Ok(mut l) = Loop::new() else { return 2 };
    if l.add_signal(&[libc::SIGTERM], 1).is_err() {
        return 2;
    }
    if ready && !write_ready() {
        return 2;
    }
    loop {
        match l.wait() {
            Ok(rs) if rs.iter().any(|r| matches!(r, Ready::Signal(1, _))) => {
                if note.is_some_and(|f| std::fs::write(f, b"T").is_err()) {
                    return 2;
                }
                if !ignore {
                    return 0;
                }
            }
            Ok(_) => {}
            Err(_) => return 2,
        }
    }
}

fn reexec(role: &str) -> i32 {
    use std::os::unix::process::CommandExt;
    let e = std::process::Command::new("/init")
        .args([HELPER_FLAG, role])
        .exec();
    eprintln!("exec {role}: {e}");
    2
}

/// Starts `/init --qinit-helper <role_args…>` with a pipe at its descriptor 3 and waits for
/// the byte a `ready` helper writes there once it has blocked TERM: a TERM sent later is
/// always caught. The child is never waited for.
fn start_ready(role_args: &[&str]) -> bool {
    let Ok((r, w)) = qinit_sys::fd::pipe(libc::O_CLOEXEC) else {
        return false;
    };
    if spawn_with(None, role_args, &[(w.as_fd(), 3)]).is_err() {
        return false;
    }
    drop(w);
    let mut byte = [0u8; 1];
    std::fs::File::from(r).read_exact(&mut byte).is_ok()
}

/// The double fork's middle: a new session, a `ready <file>` child handed this process's own
/// descriptor 3 (so the grandchild's readiness byte reaches whoever waits on it), and exit 0
/// without waiting: the child is orphaned.
fn setsid_fork(file: &str) -> i32 {
    if qinit_sys::proc::setsid().is_err() {
        return 2;
    }
    let Ok(own) = std::fs::OpenOptions::new()
        .write(true)
        .open("/proc/self/fd/3")
    else {
        return 2;
    };
    let fd = OwnedFd::from(own);
    match spawn_with(None, &["ready", file], &[(fd.as_fd(), 3)]) {
        Ok(_) => 0,
        Err(_) => 2,
    }
}

/// Copies `/proc/self/cgroup` to descriptor 3: the helper's first action after the role
/// dispatch, so it shows the cgroup the program started in.
fn report_cgroup() -> i32 {
    let copied = std::fs::read("/proc/self/cgroup").and_then(|text| {
        std::fs::OpenOptions::new()
            .write(true)
            .open("/proc/self/fd/3")
            .and_then(|mut f| f.write_all(&text))
    });
    if copied.is_ok() { 0 } else { 2 }
}

/// The helper programs (exit codes: 0 done, 2 helper failure). `[file]` is a file the helper
/// writes when TERM reaches it; `<prefix>` names such files for a helper and its children.
fn helper(role: &str, args: &[String]) -> i32 {
    let a0 = args.first().map(String::as_str);
    match role {
        "report-cgroup" => report_cgroup(),
        "wait-term" => wait_for_term(false, false, None),
        "ignore-term" => wait_for_term(true, false, None),
        // `ready [file]`: blocks TERM, writes the readiness byte, exits 0 at TERM.
        "ready" => wait_for_term(false, true, a0),
        // `ready-ignore-term [file]`: as `ready`, but goes on after each TERM.
        "ready-ignore-term" => wait_for_term(true, true, a0),
        // `family <prefix>`: a ready child noting to `<prefix>-child`, then `ready <prefix>-main`.
        "family" => match a0 {
            Some(p) if start_ready(&["ready", &format!("{p}-child")]) => {
                wait_for_term(false, true, Some(&format!("{p}-main")))
            }
            _ => 2,
        },
        // `escape <prefix>`: a double-forked, setsid grandchild noting to `<prefix>-escapee`,
        // then `ready <prefix>-main`.
        "escape" => match a0 {
            Some(p) if start_ready(&["setsid-fork", &format!("{p}-escapee")]) => {
                wait_for_term(false, true, Some(&format!("{p}-main")))
            }
            _ => 2,
        },
        "setsid-fork" => a0.map_or(2, setsid_fork),
        // `orphan-parent [file]`: a ready child noting to `[file]`, then exit 0: it is orphaned.
        "orphan-parent" => {
            let child: Vec<&str> = std::iter::once("ready").chain(a0).collect();
            if start_ready(&child) { 0 } else { 2 }
        }
        "subreaper-host" => match subreaper_host() {
            Ok(()) => 0,
            Err(x) => {
                eprintln!("subreaper-host: {x}");
                console(&format!("subreaper-host: {x}"));
                1
            }
        },
        "ready-close" => {
            // Close fd 3 without writing by exec'ing with it close-on-exec, and keep running.
            if qinit_sys::fd::set_cloexec_raw(3).is_err() {
                return 2;
            }
            reexec("wait-term")
        }
        "fds" => {
            let open: Vec<String> = (0..64)
                .filter(|n| Path::new(&format!("/proc/self/fd/{n}")).exists())
                .map(|n| n.to_string())
                .collect();
            let line = open.join(" ");
            // Through standard output itself: a pipe made by root is closed to another user
            // by way of `/proc/self/fd/1`.
            if writeln!(std::io::stdout(), "{line}").is_ok() {
                0
            } else {
                2
            }
        }
        "exit-0" => 0,
        "exit-3" => 3,
        _ => launch_helper(role, args).unwrap_or(2),
    }
}

/// The helpers of the executor suites: they report what a launch gave them on standard output
/// or by exit code. `None` for a role this function does not know.
#[allow(clippy::too_many_lines)] // one arm per helper role
fn launch_helper(role: &str, args: &[String]) -> Option<i32> {
    let a0 = args.first().map(String::as_str);
    Some(match role {
        // `show`: identity, directory, mask, environment, capability sets and flags of this
        // process, one `key: value` line each, on standard output.
        "show" => show(),
        // `ready-show`: `show`, then the readiness byte, then waits for TERM.
        "ready-show" => {
            if show() != 0 {
                return Some(2);
            }
            wait_for_term(false, true, None)
        }
        // `cat`: standard input to standard output, until its end.
        "cat" => {
            let copied = std::io::copy(&mut std::io::stdin(), &mut std::io::stdout());
            if copied.is_ok() { 0 } else { 2 }
        }
        // `say <words…>`: the words and a newline on standard output.
        "say" => {
            if writeln!(std::io::stdout(), "{}", args.join(" ")).is_ok() {
                0
            } else {
                2
            }
        }
        // `probe-path <path> <r|w>`: exit 0 when the open works, the errno otherwise.
        "probe-path" => match (a0, args.get(1).map(String::as_str)) {
            (Some(p), Some(mode)) => {
                let mut o = std::fs::OpenOptions::new();
                if mode == "w" {
                    o.write(true).create(true);
                } else {
                    o.read(true);
                }
                o.open(p)
                    .map_or_else(|x| x.raw_os_error().unwrap_or(2), |_| 0)
            }
            _ => 2,
        },
        // `probe-owner <path>`: the owner of the file as `<uid> <gid>` on standard output.
        "probe-owner" => a0.map_or(2, |p| match std::fs::metadata(p) {
            Ok(m) => {
                let ids = format!(
                    "{} {}",
                    std::os::unix::fs::MetadataExt::uid(&m),
                    std::os::unix::fs::MetadataExt::gid(&m)
                );
                if writeln!(std::io::stdout(), "{ids}").is_ok() {
                    0
                } else {
                    2
                }
            }
            Err(x) => x.raw_os_error().unwrap_or(2),
        }),
        // `probe-after-go <path>`: says `started` on standard output, waits for a line on
        // standard input, then exits 0 when the file can be opened for reading, the errno
        // otherwise.
        "probe-after-go" => a0.map_or(2, |p| {
            let mut line = String::new();
            if writeln!(std::io::stdout(), "started").is_err()
                || std::io::stdout().flush().is_err()
                || std::io::stdin().read_line(&mut line).is_err()
            {
                return 2;
            }
            std::fs::File::open(p).map_or_else(|x| x.raw_os_error().unwrap_or(2), |_| 0)
        }),
        // `probe-statvfs <path>`: 0 when the mount holding the path is read-only, 1 when not,
        // the errno when the path cannot be examined.
        "probe-statvfs" => a0.map_or(2, |p| match qinit_sys::fs::is_readonly(Path::new(p)) {
            Ok(true) => 0,
            Ok(false) => 1,
            Err(e) => e.0,
        }),
        // `probe-kind <path>`: 10 for a symlink, 11 for a directory, 12 for a regular file,
        // 13 for anything else, the errno when the path cannot be examined (no link followed).
        "probe-kind" => a0.map_or(2, |p| match qinit_sys::fs::lstat_kind(Path::new(p)) {
            Ok(qinit_sys::fs::Kind::Symlink) => 10,
            Ok(qinit_sys::fs::Kind::Dir) => 11,
            Ok(qinit_sys::fs::Kind::File) => 12,
            Ok(qinit_sys::fs::Kind::Other) => 13,
            Err(e) => e.0,
        }),
        // `probe-propagation`: `0` when no mount in `/proc/self/mountinfo` takes part in a peer
        // group (a `shared:` or `master:` optional field), else those lines joined by ` | `.
        "probe-propagation" => {
            let lines = std::fs::read_to_string("/proc/self/mountinfo").map_or_else(
                |_| vec!["unreadable".to_string()],
                |t| {
                    t.lines()
                        .filter(|l| {
                            l.split(" - ").next().is_some_and(|head| {
                                head.split(' ')
                                    .skip(6)
                                    .any(|f| f.starts_with("shared:") || f.starts_with("master:"))
                            })
                        })
                        .map(ToString::to_string)
                        .collect()
                },
            );
            let text = if lines.is_empty() {
                "0".to_string()
            } else {
                lines.join(" | ")
            };
            if writeln!(std::io::stdout(), "{text}").is_ok() {
                0
            } else {
                2
            }
        }
        // `probe-procs`: the number of process directories in `/proc`, on standard output.
        "probe-procs" => {
            let n = std::fs::read_dir("/proc").map_or(0, |d| {
                d.filter_map(Result::ok)
                    .filter(|e| {
                        e.file_name()
                            .to_string_lossy()
                            .bytes()
                            .all(|b| b.is_ascii_digit())
                    })
                    .count()
            });
            if writeln!(std::io::stdout(), "{n}").is_ok() {
                0
            } else {
                2
            }
        }
        // `probe-syscall <getppid|ptrace|unshare-net|clone3>`: `ok` or the errno, on stdout.
        "probe-syscall" => {
            let r: qinit_sys::Result<()> = match a0 {
                Some("getppid") => qinit_sys::proc::getppid_raw().map(|_| ()),
                Some("ptrace") => qinit_sys::proc::ptrace_probe(),
                Some("unshare-net") => qinit_sys::ns::unshare(libc::CLONE_NEWNET),
                Some("clone3") => qinit_sys::proc::clone3_probe(),
                Some("mount") => qinit_sys::mount::mount("tmpfs", Path::new("/tmp"), "tmpfs", 0),
                _ => return Some(2),
            };
            let line = r.map_or_else(|x| x.0.to_string(), |()| "ok".to_string());
            if writeln!(std::io::stdout(), "{line}").is_ok() {
                0
            } else {
                2
            }
        }
        "pid" => {
            if writeln!(std::io::stdout(), "{}", qinit_sys::proc::pid()).is_ok() {
                0
            } else {
                2
            }
        }
        // `hostname-set`: sets the hostname to `inside` and prints what the kernel reports.
        "hostname-set" => {
            if qinit_sys::ns::sethostname("inside").is_err() {
                return Some(2);
            }
            let name = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
            if write!(std::io::stdout(), "{name}").is_ok() {
                0
            } else {
                2
            }
        }
        // `ifaces`: one `<name> up|down` line per interface of this network namespace.
        "ifaces" => {
            let dev = std::fs::read_to_string("/proc/net/dev").unwrap_or_default();
            let mut out = String::new();
            for line in dev.lines().skip(2) {
                let name = line.split(':').next().unwrap_or_default().trim();
                let up = qinit_sys::ns::interface_is_up(name).unwrap_or(false);
                let _ = writeln!(out, "{name} {}", if up { "up" } else { "down" });
            }
            if write!(std::io::stdout(), "{out}").is_ok() {
                0
            } else {
                2
            }
        }
        // `userns-show`: this process's uid and gid, then `uid_map`, `gid_map` and `setgroups`
        // of its user namespace, on standard output.
        "userns-show" => {
            let read =
                |f: &str| std::fs::read_to_string(format!("/proc/self/{f}")).unwrap_or_default();
            let words = |t: String| t.split_whitespace().collect::<Vec<_>>().join(" ");
            let out = format!(
                "ids {} {}\nuid_map {}\ngid_map {}\nsetgroups {}\n",
                qinit_sys::cred::getuid(),
                qinit_sys::cred::getgid(),
                words(read("uid_map")),
                words(read("gid_map")),
                read("setgroups").trim()
            );
            if write!(std::io::stdout(), "{out}").is_ok() {
                0
            } else {
                2
            }
        }
        // `setuid-1`: `setresuid(1, 1, 1)`: `ok` or the errno, on standard output.
        "setuid-1" => {
            let line = qinit_sys::cred::setresuid(1)
                .map_or_else(|x| x.0.to_string(), |()| "ok".to_string());
            if writeln!(std::io::stdout(), "{line}").is_ok() {
                0
            } else {
                2
            }
        }
        // `loosen <dir>`: tries to remount `<dir>` writable and to unmount it, on standard
        // output as `remount <errno|ok> umount <errno|ok>`.
        "loosen" => a0.map_or(2, |dir| {
            let path = Path::new(dir);
            let word =
                |r: qinit_sys::Result<()>| r.map_or_else(|x| x.0.to_string(), |()| "ok".into());
            let remount = qinit_sys::mount::mount_data(
                "none",
                path,
                "",
                libc::MS_REMOUNT | libc::MS_BIND,
                None,
            );
            let umount = qinit_sys::mount::umount_detach(path);
            if writeln!(
                std::io::stdout(),
                "remount {} umount {}",
                word(remount),
                word(umount)
            )
            .is_ok()
            {
                0
            } else {
                2
            }
        }),
        "raise-usr1" => {
            let _ = qinit_sys::proc::kill(qinit_sys::proc::pid(), libc::SIGUSR1);
            2
        }
        _ => return None,
    })
}

/// The resource names of `show`'s `rlimit_<name>` lines, by kernel resource number.
pub const RLIMIT_NAMES: [&str; 16] = [
    "cpu",
    "fsize",
    "data",
    "stack",
    "core",
    "rss",
    "nproc",
    "nofile",
    "memlock",
    "as",
    "locks",
    "sigpending",
    "msgqueue",
    "nice",
    "rtprio",
    "rttime",
];

/// The `show` helper: what the launch gave this process.
fn show() -> i32 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return 2;
    };
    let mut out = String::new();
    for key in [
        "Uid",
        "Gid",
        "Groups",
        "Umask",
        "CapBnd",
        "CapAmb",
        "CapEff",
        "CapPrm",
        "NoNewPrivs",
        "Seccomp",
    ] {
        let line = status.lines().find(|l| l.starts_with(&format!("{key}:")));
        out.push_str(line.unwrap_or("missing"));
        out.push('\n');
    }
    let cwd = std::env::current_dir().map(|p| p.display().to_string());
    let _ = writeln!(out, "cwd: {}", cwd.unwrap_or_default());
    let bits = qinit_sys::cred::get_securebits().unwrap_or(u32::MAX);
    let _ = writeln!(out, "SecBits:\t{bits:#x}");
    let mut env: Vec<String> = std::env::vars().map(|(k, v)| format!("{k}={v}")).collect();
    env.sort();
    for entry in env {
        let _ = writeln!(out, "env: {entry}");
    }
    for (r, name) in RLIMIT_NAMES.iter().enumerate() {
        let resource = libc::c_int::try_from(r).unwrap_or(-1);
        let (soft, hard) = qinit_sys::limits::get_rlimit(resource).unwrap_or((0, 0));
        let text = |v: u64| {
            if v == u64::MAX {
                "inf".to_string()
            } else {
                v.to_string()
            }
        };
        let _ = writeln!(out, "rlimit_{name}: {} {}", text(soft), text(hard));
    }
    eprintln!("err");
    if std::io::stdout().write_all(out.as_bytes()).is_ok() {
        0
    } else {
        2
    }
}

/// Runs as a subreaper that is not PID 1: the grandchild a cell's main process orphans is
/// reaped and reported as an orphan with its own status, and the main process is not.
fn subreaper_host() -> Result<(), String> {
    use qinit_cell::Polite;
    let mut cells = cells()?;
    e(cells.subreaper())?;
    let id = e(cells.create("orph"))?;
    // The main process starts a ready child and exits 0: ready by exit, the child orphaned.
    e(cells.spawn(id, helper_cmd("orphan-parent", &[]), ReadyMode::Exit))?;
    let main = cells.main_pid(id).ok_or("no main pid after the spawn")?;
    let mut seen = expect(&mut cells, id, Report::Ready)?;
    e(cells.stop(id, Polite::Cell, HANG_GUARD, HANG_GUARD))?;
    seen.extend(expect(&mut cells, id, Report::Empty)?);
    // The orphan's SIGCHLD and the cell's last notification arrive in either order.
    while !seen.iter().any(|n| matches!(n, Notice::Orphan { .. })) {
        seen.extend(e(cells.next())?);
    }
    remove(&mut cells, id)?;
    let orphans: Vec<(libc::pid_t, i32)> = seen
        .iter()
        .filter_map(|n| match *n {
            Notice::Orphan { pid, status } => Some((pid, status)),
            Notice::Cell(..) => None,
        })
        .collect();
    match orphans.as_slice() {
        [(pid, 0)] if *pid != main => Ok(()),
        _ => Err(format!(
            "orphans (pid, status) {orphans:?}, want one with status 0 that is not main {main}; seen {seen:?}"
        )),
    }
}
