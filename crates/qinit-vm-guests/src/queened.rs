// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Guests whose PID 1 is queen. The guest's init (the suite binary) prepares the machine as a
//! real boot would find it, forks the driver (the cases) and becomes queen. Colony, the
//! executor, zero's stand-in and the rescue program are files at the paths queen uses. Nothing
//! here sleeps: a wait is an event (a file changing, the kernel log, a socket appearing, a
//! process ending) or a bounded spin, with a hang guard.
use crate::{Case, HANG_GUARD, HELPER_FLAG, e, run};
use qinit_client::Client;
use qinit_db::Model;
use qinit_event::{Loop, Ready as LoopReady};
use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// Colony's syslog, received by the driver: bound before queen starts, so no line is lost.
static LOG: OnceLock<UnixDatagram> = OnceLock::new();
/// Every line colony has sent, oldest first.
static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Where the initrd puts queen.
pub const QUEEN: &str = "/usr/lib/qinit/queen";
/// Where zero's stand-in is, and the file it appends its command line to.
pub const ZERO: &str = "/usr/lib/qinit/zero";
pub const ZERO_LOG: &str = "/tmp/zero-log";
/// The rescue program (the suite binary again), what it should do and what it wrote.
pub const RESCUE: &str = "/etc/qinit/rescue";
pub const RESCUE_ROLE: &str = "/tmp/rescue-role";
pub const RESCUE_LOG: &str = "/tmp/rescue-log";
/// The database the `repair` role of rescue puts in place.
pub const REPAIRED: &str = "/tmp/repaired.db";
/// Colony's control socket and database, at their defaults.
pub const SOCKET: &str = "/run/qinit/colony";
pub const DB: &str = "/etc/qinit/colony.db";
/// Colony's comb, at its default.
pub const COMB: &str = "/sys/fs/cgroup/qinit";

/// The guest's PID 1 (and the rescue program): never returns.
pub fn boot(cases: &'static [Case], suite: &'static str, first: &Model) -> ! {
    let mut args = std::env::args();
    let argv0 = args.next().unwrap_or_default();
    if argv0.rsplit('/').next() == Some("rescue") {
        std::process::exit(rescue());
    }
    if args.next().as_deref() == Some(HELPER_FLAG) || qinit_sys::proc::pid() != 1 {
        run(suite, cases)
    }
    if let Err(why) = prepare(first) {
        eprintln!("queened: {why}");
        qinit_sys::mount::power_off_from_child()
    }
    match qinit_sys::proc::fork() {
        Ok(0) => run(suite, cases),
        Ok(_) => {
            let err = qinit_sys::spawn::exec_in_place(c"/usr/lib/qinit/queen", &[c"queen"], &[]);
            eprintln!("queened: cannot exec queen: {err}");
            qinit_sys::mount::power_off_from_child()
        }
        Err(err) => {
            eprintln!("queened: fork: {err}");
            qinit_sys::mount::power_off_from_child()
        }
    }
}

/// The machine as zero would leave it for queen: the mounts, colony's comb with its controllers,
/// and the database.
fn prepare(first: &Model) -> Result<(), String> {
    crate::boot_root()?;
    e(std::fs::write(
        "/sys/fs/cgroup/cgroup.subtree_control",
        "+memory +pids",
    ))?;
    // The kernel rate-limits what userspace writes to /dev/kmsg (five lines in five seconds by
    // default): the cases count queen's lines, so none may be dropped.
    e(std::fs::write("/proc/sys/kernel/printk_devkmsg", "on\n")
        .map_err(|x| format!("printk_devkmsg: {x}")))?;
    e(std::fs::create_dir_all(COMB))?;
    e(std::fs::create_dir_all("/etc/qinit"))?;
    // The limits the cases run under: a rescue minimum short enough to wait out.
    limits(300_000, 5_000, 300)?;
    // A datagram socket holds ten datagrams by default: colony's lines would fall back to the
    // console while the driver is busy, and the cases count them.
    e(std::fs::write(
        "/proc/sys/net/unix/max_dgram_qlen",
        "10000\n",
    ))?;
    let log = e(UnixDatagram::bind("/dev/log"))?;
    e(log.set_nonblocking(true))?;
    let _ = LOG.set(log);
    write_db(first)
}

/// Writes `model` as the database colony starts from.
pub fn write_db(model: &Model) -> Result<(), String> {
    let bytes = qinit_db::write(model).map_err(|x| format!("write the database: {x:?}"))?;
    e(std::fs::write(DB, bytes))
}

/// Waits 400 ms, then exits 0: a rescue that ran long enough to count.
fn late() -> i32 {
    let Ok(t) = qinit_sys::event::timer(std::time::Duration::from_millis(400)) else {
        return 2;
    };
    let Ok(mut l) = Loop::new() else { return 2 };
    if l.add_fd(t.as_fd(), 1).is_err() {
        return 2;
    }
    match l.wait() {
        Ok(_) => 0,
        Err(_) => 2,
    }
}

/// The rescue program: logs its session, pid and controlling terminal, then does what
/// `/tmp/rescue-role` says: `late` (waits 400 ms, exits 0), `repair` (copies `REPAIRED` over the database, then as `late`),
/// `now` (exits 0) or `fail` (exits 3).
fn rescue() -> i32 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let rest = stat.rsplit_once(')').map_or("", |x| x.1);
    let f: Vec<&str> = rest.split_whitespace().collect();
    // After the `)`: state(0) ppid(1) pgrp(2) session(3) tty_nr(4).
    let line = format!(
        "{} {} {}\n",
        f.get(3).copied().unwrap_or("?"),
        std::process::id(),
        f.get(4).copied().unwrap_or("?")
    );
    let _ = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(RESCUE_LOG)
        .and_then(|mut l| std::io::Write::write_all(&mut l, line.as_bytes()));
    match std::fs::read_to_string(RESCUE_ROLE)
        .unwrap_or_default()
        .trim()
    {
        "now" => 0,
        "late" => late(),
        // What an administrator does in rescue: puts a repaired database where colony reads it.
        "repair" => {
            if std::fs::copy(REPAIRED, DB).is_err() {
                return 2;
            }
            late()
        }
        _ => 3,
    }
}

/// Waits until `check` gives something, watching `dirs` for changes, with the hang guard.
pub fn wait_until<T>(
    what: &str,
    dirs: &[&str],
    mut check: impl FnMut() -> Option<T>,
) -> Result<T, String> {
    let mut l = e(Loop::new())?;
    for (i, d) in dirs.iter().enumerate() {
        e(l.add_inotify(
            Path::new(d),
            libc::IN_CREATE
                | libc::IN_MODIFY
                | libc::IN_ATTRIB
                | libc::IN_DELETE
                | libc::IN_MOVED_TO,
            10 + u64::try_from(i).unwrap_or(0),
        ))?;
    }
    e(l.add_deadline(HANG_GUARD, 2))?;
    loop {
        if let Some(v) = check() {
            return Ok(v);
        }
        for r in e(l.wait())? {
            if matches!(r, LoopReady::Deadline(2)) {
                return Err(format!("never: {what}"));
            }
        }
    }
}

/// As [`wait_until`] for a state no event announces (a process table entry): a bounded spin.
pub fn spin_until<T>(what: &str, mut check: impl FnMut() -> Option<T>) -> Result<T, String> {
    let end = Instant::now() + HANG_GUARD;
    loop {
        if let Some(v) = check() {
            return Ok(v);
        }
        if Instant::now() > end {
            return Err(format!("never: {what}"));
        }
        std::thread::yield_now();
    }
}

/// Colony's client: waits for its socket to take a connection.
pub fn client() -> Result<Client, String> {
    // Colony's log queue is only as long as its datagram buffer: drain it as the cases go.
    let _ = log_history();
    e(std::fs::create_dir_all("/run/qinit"))?;
    wait_until("colony's socket", &["/run/qinit"], || {
        Client::connect(Path::new(SOCKET)).ok()
    })
}

/// The lines zero's stand-in has appended.
#[must_use]
pub fn zero_lines() -> Vec<String> {
    std::fs::read_to_string(ZERO_LOG)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Waits until zero has been run `n` times; the lines.
pub fn await_zero_lines(n: usize) -> Result<Vec<String>, String> {
    wait_until(&format!("{n} lines of zero's log"), &["/tmp"], || {
        let l = zero_lines();
        (l.len() >= n).then_some(l)
    })
    .map_err(|why| {
        let said: Vec<String> = kmsg_timed()
            .unwrap_or_default()
            .into_iter()
            .filter(|l| l.contains("queen:"))
            .collect();
        let tail = said.len().saturating_sub(12);
        let up = std::fs::read_to_string("/proc/uptime").unwrap_or_default();
        format!(
            "{why}; zero ran {} times; uptime {}; queen said {:?}",
            zero_lines().len(),
            up.trim(),
            &said[tail..]
        )
    })
}

/// A new colony on `model`: it is asked to halt (the stand-in zero starts queen over), and the
/// database is `model` when queen starts. Returns the new colony's client.
pub fn fresh(model: &Model) -> Result<Client, String> {
    let before = zero_lines().len();
    write_db(model)?;
    let mut c = client()?;
    e(c.shutdown(qinit_client::Mode::Halt, qinit_client::Wait::Now))?;
    drop(c);
    await_zero_lines(before + 1)?;
    client()
}

/// The kernel log's messages, one string per record.
pub fn kmsg() -> Result<Vec<String>, String> {
    crate::colonyd::kmsg()
}

/// The kernel log's records as `<seconds since boot>: <text>`.
fn kmsg_timed() -> Result<Vec<String>, String> {
    let mut f = e(std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/dev/kmsg"))?;
    let mut out = Vec::new();
    let mut buf = vec![0u8; 8192];
    while let Ok(n) = f.read(&mut buf) {
        if n == 0 {
            break;
        }
        let rec = String::from_utf8_lossy(&buf[..n]).into_owned();
        if let Some((head, text)) = rec.split_once(';') {
            let ts: u64 = head
                .split(',')
                .nth(2)
                .and_then(|t| t.parse().ok())
                .unwrap_or(0);
            out.push(format!(
                "{}.{:03}: {}",
                ts / 1_000_000,
                ts / 1000 % 1000,
                text.trim_end()
            ));
        }
    }
    Ok(out)
}

/// How many kernel log messages contain `text`.
pub fn kmsg_count(text: &str) -> Result<usize, String> {
    Ok(kmsg()?.iter().filter(|l| l.contains(text)).count())
}

/// Waits until at least `n` kernel log messages contain `text` (an event wait on `/dev/kmsg`).
pub fn await_kmsg(text: &str, n: usize) -> Result<(), String> {
    let f = e(std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/dev/kmsg"))?;
    let fd: OwnedFd = f.into();
    let ms = i32::try_from(HANG_GUARD.as_millis()).unwrap_or(i32::MAX);
    let mut file = std::fs::File::from(fd.try_clone().map_err(|x| x.to_string())?);
    let mut seen = 0;
    let mut buf = vec![0u8; 8192];
    loop {
        while let Ok(len) = file.read(&mut buf) {
            if len == 0 {
                break;
            }
            if String::from_utf8_lossy(&buf[..len]).contains(text) {
                seen += 1;
            }
        }
        if seen >= n {
            return Ok(());
        }
        if !e(qinit_ipc::poll_readable(fd.as_fd(), ms))? {
            return Err(format!("the kernel log never showed {text:?} {n} times"));
        }
    }
}

/// Tells what rescue does next: `late`, `repair`, `now` or `fail`.
pub fn rescue_role(role: &str) -> Result<(), String> {
    e(std::fs::write(RESCUE_ROLE, role))
}

/// The limits queen reads when it next starts (see `qinit-queen`'s `testing` feature).
pub fn limits(shutdown_ms: u64, kill_wait_ms: u64, rescue_min_ms: u64) -> Result<(), String> {
    e(std::fs::write(
        "/run/queen-test",
        format!("{shutdown_ms} {kill_wait_ms} {rescue_min_ms}"),
    ))
}

/// Colony's pid: the process whose command line is `colony --queen-fd 3`.
#[must_use]
pub fn colony_pid() -> Option<i32> {
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<i32>().ok())
        else {
            continue;
        };
        let cmd = std::fs::read(entry.path().join("cmdline")).unwrap_or_default();
        if cmd.starts_with(b"colony\0--queen-fd\0") {
            return Some(pid);
        }
    }
    None
}

/// SIGKILLs colony; its pid.
pub fn kill_colony() -> Result<i32, String> {
    let pid = colony_pid().ok_or("no colony runs")?;
    e(qinit_sys::proc::kill(pid, libc::SIGKILL))?;
    Ok(pid)
}

/// Waits for a colony other than `old`, and for its socket.
pub fn await_colony_restart(old: i32) -> Result<Client, String> {
    spin_until("a new colony", || colony_pid().filter(|p| *p != old))?;
    client()
}

/// Sends PID 1 `sig`.
pub fn signal_queen(sig: libc::c_int) -> Result<(), String> {
    e(qinit_sys::proc::kill(1, sig))
}

/// Kills every cell of colony's comb and removes it, best effort: for a case that left workers
/// behind (queen killed their colony).
pub fn clear_comb() {
    let Ok(entries) = std::fs::read_dir(COMB) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let path = entry.path();
        let _ = std::fs::write(path.join("cgroup.kill"), b"1");
        let _ = spin_until("a removable cell", || std::fs::remove_dir(&path).ok());
    }
}

/// Takes what colony has logged into the history; the history.
fn log_history() -> Vec<String> {
    let mut lines = LINES.lock().map(|g| g.clone()).unwrap_or_default();
    let mut buf = [0u8; 1024];
    if let Some(log) = LOG.get() {
        while let Ok(n) = log.recv(&mut buf) {
            lines.push(String::from_utf8_lossy(&buf[..n]).into_owned());
        }
    }
    if let Ok(mut g) = LINES.lock() {
        g.clone_from(&lines);
    }
    lines
}

/// How many lines colony has logged that contain `text`.
#[must_use]
pub fn log_count(text: &str) -> usize {
    log_history().iter().filter(|l| l.contains(text)).count()
}

/// Waits until colony has logged `n` lines containing `text` (an event wait on its syslog).
pub fn await_log(text: &str, n: usize) -> Result<Vec<String>, String> {
    let log = LOG.get().ok_or("no syslog receiver")?;
    let ms = i32::try_from(HANG_GUARD.as_millis()).unwrap_or(i32::MAX);
    loop {
        let lines = log_history();
        if lines.iter().filter(|l| l.contains(text)).count() >= n {
            return Ok(lines);
        }
        if !e(qinit_ipc::poll_readable(log.as_fd(), ms))? {
            return Err(format!("colony never logged {text:?} {n} times"));
        }
    }
}

/// The last `n` lines colony logged, to say what happened when a case fails.
#[must_use]
pub fn log_tail(n: usize) -> Vec<String> {
    let lines = log_history();
    let from = lines.len().saturating_sub(n);
    lines[from..].to_vec()
}
