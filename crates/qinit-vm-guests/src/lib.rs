// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! `qinit-vm-guests`: the guest side of qinit's VM suites (spec 2026-10-27 §6.1 tier 3). Each
//! suite is a binary booted as `/init`. It mounts proc, sys, cgroup2, devtmpfs and tmpfs, runs
//! its cases, prints `QINIT-VM <suite> <case> PASS|FAIL <detail>` and `QINIT-VM <suite> END <case-count>` on
//! the console and powers the guest off from a child. The same binary is the helper program
//! the cases spawn: `/init --qinit-helper <role> <args…>`.
// Every fallible function returns one string naming the step and its cause; a per-function
// `# Errors` section would only repeat that.
#![allow(clippy::missing_errors_doc)]
use qinit_cell::{CellId, Cells, Notice, Report};
use qinit_event::{Loop, Ready, Token};
use std::ffi::{CString, OsStr, OsString};
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd, RawFd};
use std::path::Path;
use std::time::Duration;

/// One case: its name and its body.
pub type Case = (&'static str, fn() -> Result<(), String>);

pub const HELPER_FLAG: &str = "--qinit-helper";
/// The test comb: cells live directly under it.
pub const COMB: &str = "/sys/fs/cgroup/qinit-test";
/// A hang guard for each wait (cases assert order, never durations: spec R7).
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
        setup()
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

fn setup() -> Result<(), String> {
    use qinit_sys::mount::{mkdir, mount};
    for d in ["/dev", "/proc", "/sys", "/tmp"] {
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
    mkdir(Path::new(COMB), 0o755).map_err(|e| format!("mkdir {COMB}: {e}"))
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

/// Writes one byte to descriptor 3 (a readiness pipe).
fn write_ready() -> bool {
    std::fs::OpenOptions::new()
        .write(true)
        .open("/proc/self/fd/3")
        .and_then(|mut f| f.write_all(b"\n"))
        .is_ok()
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
            let written = std::fs::OpenOptions::new()
                .write(true)
                .open("/proc/self/fd/1")
                .and_then(|mut f| writeln!(f, "{line}"));
            if written.is_ok() { 0 } else { 2 }
        }
        "exit-0" => 0,
        "exit-3" => 3,
        _ => 2,
    }
}

/// Runs as a subreaper that is not PID 1: the grandchild a cell's main process orphans is
/// reaped and reported as an orphan with its own status, and the main process is not.
fn subreaper_host() -> Result<(), String> {
    use qinit_cell::{Polite, ReadyMode};
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
