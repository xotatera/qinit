// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! `qinit-vm-guests`: the guest side of qinit's VM suites (spec 2026-10-27 §6.1 tier 3). Each
//! suite is a binary booted as `/init`. It mounts proc, sys, cgroup2, devtmpfs and tmpfs, runs
//! its cases, prints `QINIT-VM <suite> <case> PASS|FAIL <detail>` and `QINIT-VM <suite> END` on
//! the console and powers the guest off from a child. The same binary is the helper program
//! the cases spawn: `/init --qinit-helper <role>`.
// Every fallible function returns one string naming the step and its cause; a per-function
// `# Errors` section would only repeat that.
#![allow(clippy::missing_errors_doc)]
use qinit_event::{Loop, Ready, Token};
use std::ffi::CString;
use std::io::Write;
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

/// The suite's whole body. Never returns: the guest powers off.
pub fn run(suite: &'static str, cases: &[Case]) -> ! {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some(HELPER_FLAG) {
        let role = args.next().unwrap_or_default();
        std::process::exit(helper(&role));
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
    console(&format!("QINIT-VM {suite} END"));
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
    use std::ffi::OsStr;
    use std::io::Read;
    let argv = [
        OsStr::new("/init"),
        OsStr::new(HELPER_FLAG),
        OsStr::new(role),
    ];
    let p = sys(
        qinit_sys::spawn::Prepared::new(Path::new("/init"), &argv, &[], routes),
        "prepare",
    )?;
    let (r, w) = sys(qinit_sys::fd::pipe(libc::O_CLOEXEC), "pipe")?;
    let child = sys(qinit_sys::spawn::spawn(&p, Some(cell), w.as_fd()), "clone3")?;
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
/// readiness byte is always caught.
fn wait_for_term(ignore: bool, ready: bool) -> i32 {
    let Ok(mut l) = Loop::new() else { return 2 };
    if l.add_signal(&[libc::SIGTERM], 1).is_err() {
        return 2;
    }
    if ready && !write_ready() {
        return 2;
    }
    loop {
        match l.wait() {
            Ok(rs) if !ignore && rs.iter().any(|r| matches!(r, Ready::Signal(1, _))) => return 0,
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

/// Starts `/init --qinit-helper <role>` and exits without waiting: the child is orphaned.
fn spawn_role(role: &str) -> i32 {
    match std::process::Command::new("/init")
        .args([HELPER_FLAG, role])
        .spawn()
    {
        Ok(child) => {
            std::mem::forget(child);
            0
        }
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

/// The helper programs (exit codes: 0 done, 2 helper failure).
fn helper(role: &str) -> i32 {
    match role {
        "report-cgroup" => report_cgroup(),
        "wait-term" => wait_for_term(false, false),
        "ignore-term" => wait_for_term(true, false),
        "ready" => wait_for_term(false, true),
        "ready-ignore-term" => wait_for_term(true, true),
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
        "escape" => spawn_role("setsid-wait"),
        "setsid-wait" => {
            if qinit_sys::proc::setsid().is_err() {
                return 2;
            }
            wait_for_term(false, false)
        }
        "orphan-parent" => spawn_role("wait-term"),
        "exit-0" => 0,
        "exit-3" => 3,
        _ => 2,
    }
}
