// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The sandbox on a real kernel: Landlock, the seccomp filters and the namespaces (spec
//! 2026-11-03 §4 steps 3, 9 and 10, §3).
use qinit_cell::{Polite, ReadyMode, Report};
use qinit_overseer::request::{RequestSpec, Seccomp, Stream};
use qinit_vm_guests::{
    ALLOW_MIN, HANG_GUARD, capture, cells, e, expect, launch, read_all, remove, reports_of, run,
    run_to_end, spec, status_of,
};

/// `CAP_SYS_ADMIN`, for the calls the kernel would otherwise refuse the `svc` user.
const SYS_ADMIN: u64 = 1 << 21;
/// Namespace bits of the request: mount, pid, ipc, uts, net.
const NS_PID: u32 = 1 << 1;
const NS_UTS: u32 = 1 << 3;
const NS_NET: u32 = 1 << 4;

#[allow(clippy::needless_pass_by_value)] // call sites pass fresh values; a reference would only add noise
fn want<T: PartialEq + std::fmt::Debug>(got: T, expected: T, what: &str) -> Result<(), String> {
    if got == expected {
        Ok(())
    } else {
        Err(format!("{what}: {got:?}, want {expected:?}"))
    }
}

fn probe_path(name: &str, path: &str, mode: &str, landlock: &[&str]) -> Result<i32, String> {
    let mut request = spec("svc", "probe-path", &[path, mode]);
    request.landlock = landlock.iter().map(ToString::to_string).collect();
    let o = run_to_end(name, request, false)?;
    if let Some(f) = o.failure {
        return Err(format!("launch failed: {f:?}"));
    }
    o.code()
}

fn landlock() -> Result<(), String> {
    e(std::fs::create_dir_all("/tmp/ll"))?;
    e(qinit_sys::fd::chown(c"/tmp/ll", 1000, 1000).map_err(|x| x.to_string()))?;
    let rules = ["ro:/etc", "rw:/tmp/ll", "ro:/init"];
    let eacces = libc::EACCES;
    want(
        probe_path("ll1", "/etc/passwd", "r", &rules)?,
        0,
        "read of /etc/passwd",
    )?;
    want(
        probe_path("ll2", "/etc/passwd", "w", &rules)?,
        eacces,
        "write of /etc/passwd",
    )?;
    want(
        probe_path("ll3", "/tmp/ll/x", "w", &rules)?,
        0,
        "write of /tmp/ll/x",
    )?;
    want(
        probe_path("ll4", "/proc/self/status", "r", &rules)?,
        eacces,
        "read of /proc",
    )
}

fn syscall(name: &str, seccomp: Seccomp, caps: u64, call: &str) -> Result<String, String> {
    let mut request = spec("svc", "probe-syscall", &[call]);
    request.seccomp = seccomp;
    request.caps = caps;
    let o = run_to_end(name, request, true)?;
    if let Some(f) = o.failure {
        return Err(format!("launch failed: {f:?}"));
    }
    want(o.code()?, 0, "the helper's exit")?;
    Ok(o.out.trim().to_string())
}

fn errno(n: i32) -> String {
    n.to_string()
}

fn default_denylist() -> Result<(), String> {
    let d = Seccomp::Default;
    want(
        syscall("sd1", d.clone(), SYS_ADMIN, "ptrace")?,
        errno(libc::EPERM),
        "ptrace",
    )?;
    want(
        syscall("sd2", d.clone(), SYS_ADMIN, "unshare-net")?,
        errno(libc::EPERM),
        "unshare",
    )?;
    want(
        syscall("sd3", d.clone(), SYS_ADMIN, "clone3")?,
        errno(libc::ENOSYS),
        "clone3",
    )?;
    want(
        syscall("sd4", d, SYS_ADMIN, "getppid")?,
        "ok".to_string(),
        "getppid",
    )
}

fn deny_list() -> Result<(), String> {
    let d = || Seccomp::Deny(vec![110]);
    want(
        syscall("sx1", d(), 0, "getppid")?,
        errno(libc::EPERM),
        "getppid",
    )?;
    want(
        syscall("sx2", d(), 0, "ptrace")?,
        errno(libc::EPERM),
        "ptrace",
    )
}

fn allow_list() -> Result<(), String> {
    let list: Vec<u32> = ALLOW_MIN.iter().map(|(_, n)| *n).collect();
    want(
        syscall("sa1", Seccomp::Allow(list), 0, "getppid")?,
        errno(libc::EPERM),
        "getppid under the allowlist",
    )
}

fn pid_request(role: &str) -> RequestSpec {
    let mut request = spec("svc", role, &[]);
    request.ns = NS_PID;
    request
}

fn pid_namespace() -> Result<(), String> {
    let o = run_to_end("pn1", pid_request("pid"), true)?;
    want(o.out.trim(), "2", "the service's pid")?;
    want(o.code()?, 0, "exit status relayed")?;
    // The supervisor relays a polite stop: TERM reaches the service through two processes.
    let mut cells = cells()?;
    let (reader, writer) = capture();
    let mut request = pid_request("ready-show");
    request.stdout = Stream::Fd(6);
    request.ready_fd = Some(5);
    let l = launch(
        &mut cells,
        "pn2",
        &request,
        vec![(writer, 6)],
        ReadyMode::Pipe,
    )?;
    expect(&mut cells, l.id, Report::Ready)?;
    e(cells.stop(l.id, Polite::Main, HANG_GUARD, HANG_GUARD))?;
    let seen = expect(&mut cells, l.id, Report::Empty)?;
    // A clean exit (status 0) is not reported on its own: any `MainExited` is a failure.
    let reports = reports_of(&seen, l.id);
    if let Some(r) = reports.iter().find(|r| matches!(r, Report::MainExited(_))) {
        return Err(format!("the main did not exit cleanly after a stop: {r:?}"));
    }
    want(status_of(&l), None, "the status record")?;
    remove(&mut cells, l.id)?;
    let _ = read_all(reader);
    // A signal death of the service is seen as the same signal.
    let o = run_to_end("pn3", pid_request("raise-usr1"), false)?;
    want(o.signal()?, libc::SIGUSR1, "the relayed signal")
}

/// Starts a ready-show service in a pid namespace, stops it politely and waits for the cell to
/// empty. A supervisor that misses its child's exit leaves the stop to time out.
fn start_and_stop(name: &str) -> Result<(), String> {
    let mut cells = cells()?;
    let (reader, writer) = capture();
    let mut request = pid_request("ready-show");
    request.stdout = Stream::Fd(6);
    request.ready_fd = Some(5);
    let l = launch(
        &mut cells,
        name,
        &request,
        vec![(writer, 6)],
        ReadyMode::Pipe,
    )?;
    expect(&mut cells, l.id, Report::Ready)?;
    e(cells.stop(l.id, Polite::Main, HANG_GUARD, HANG_GUARD))?;
    expect(&mut cells, l.id, Report::Empty)?;
    remove(&mut cells, l.id)?;
    let _ = read_all(reader);
    Ok(())
}

fn supervisor_sees_every_exit() -> Result<(), String> {
    // The exit lands right after the forwarded TERM: the window between reaping and waiting.
    let started = std::time::Instant::now();
    for i in 0..30 {
        start_and_stop(&format!("ps{i}"))?;
    }
    let took = started.elapsed();
    if took < std::time::Duration::from_secs(20) {
        Ok(())
    } else {
        Err(format!("30 starts and stops took {took:?}, a stop hung"))
    }
}

fn supervisors_drop_the_parents_descriptors() -> Result<(), String> {
    let mut cells = cells()?;
    let (out_r, out_w) = capture();
    // A pipe the request does not mention, routed anyway: only a holder that never closed it
    // keeps its read end from reaching EOF.
    let (held_r, held_w) = capture();
    let mut request = pid_request("ready-show");
    request.stdout = Stream::Fd(6);
    request.ready_fd = Some(5);
    let l = launch(
        &mut cells,
        "pd1",
        &request,
        vec![(out_w, 6), (held_w, 9)],
        ReadyMode::Pipe,
    )?;
    expect(&mut cells, l.id, Report::Ready)?;
    // Blocks until the last write end is closed; the harness's hang guard ends a holder that
    // never lets go.
    let mut file = std::fs::File::from(held_r);
    let eof = matches!(std::io::Read::read(&mut file, &mut [0u8; 1]), Ok(0));
    e(cells.stop(l.id, Polite::Main, HANG_GUARD, HANG_GUARD))?;
    expect(&mut cells, l.id, Report::Empty)?;
    remove(&mut cells, l.id)?;
    let _ = read_all(out_r);
    if eof {
        Ok(())
    } else {
        Err("a supervisor still holds a descriptor of its parent".into())
    }
}

fn hostname() -> Result<(), String> {
    let before = e(std::fs::read_to_string("/proc/sys/kernel/hostname"))?;
    let mut request = spec("svc", "hostname-set", &[]);
    request.ns = NS_UTS;
    request.caps = SYS_ADMIN;
    let o = run_to_end("uts", request, true)?;
    want(o.out.trim(), "inside", "the hostname inside")?;
    let after = e(std::fs::read_to_string("/proc/sys/kernel/hostname"))?;
    want(after, before, "the guest's own hostname")
}

fn loopback() -> Result<(), String> {
    let mut request = spec("svc", "ifaces", &[]);
    request.ns = NS_NET;
    let o = run_to_end("net", request, true)?;
    want(o.out.trim(), "lo up", "interfaces")
}

fn main() {
    run(
        "sandbox",
        &[
            ("landlock_grants_ro_and_rw_and_denies_the_rest", landlock),
            ("the_default_denylist_returns_eperm", default_denylist),
            ("a_deny_list_adds_to_the_default", deny_list),
            ("an_allow_list_permits_only_its_calls", allow_list),
            (
                "a_pid_namespace_has_a_supervisor_that_relays_signals_and_status",
                pid_namespace,
            ),
            (
                "a_supervisor_sees_every_exit_of_its_child",
                supervisor_sees_every_exit,
            ),
            (
                "supervisors_hold_no_descriptor_of_their_parent",
                supervisors_drop_the_parents_descriptors,
            ),
            ("uts_isolation_hides_a_hostname_change", hostname),
            ("net_isolation_leaves_only_loopback_up", loopback),
        ],
    )
}
