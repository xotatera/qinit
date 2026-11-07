// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! A fatal signal or a panic parks the process instead of ending it. Each case runs in a child:
//! the test binary re-runs itself with `QINIT_SYS_ROLE` set, and `child_roles` dispatches the
//! role. The child's standard output is the park descriptor, so the parent reads the line the
//! handler wrote and then inspects the parked process.
use qinit_sys::{proc, signal};
use std::io::{BufRead, BufReader};
use std::os::fd::AsFd;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn start(role: &str) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_roles", "--nocapture"])
        .env("QINIT_SYS_ROLE", role)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap()
}

fn state_of(pid: i32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit(')').next()?.trim().chars().next()
}

/// Asserts the role parks: it writes its line, stays alive, and sleeps.
fn parks(role: &str, line_starts: &str) {
    let mut child = start(role);
    let pid = i32::try_from(child.id()).unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    // The test harness may print its own lines first; read until the park line arrives.
    loop {
        line.clear();
        assert!(
            out.read_line(&mut line).unwrap() > 0,
            "{role} ended without a line"
        );
        if line.starts_with(line_starts) {
            break;
        }
    }
    let end = Instant::now() + Duration::from_secs(10);
    while state_of(pid) != Some('S') {
        assert!(Instant::now() < end, "{role}: state {:?}", state_of(pid));
        std::thread::yield_now();
    }
    proc::kill(pid, 0).unwrap();
    assert!(child.try_wait().unwrap().is_none(), "{role} ended");
    child.kill().unwrap();
    child.wait().unwrap();
}

#[allow(unconditional_recursion, clippy::cast_possible_truncation)] // the overflow is the point
fn grow(n: u64) -> u64 {
    let pad = [n as u8; 256];
    std::hint::black_box(&pad);
    grow(std::hint::black_box(n) + 1) + u64::from(pad[0])
}

/// The child half: with `QINIT_SYS_ROLE` set it runs the role; otherwise it passes.
#[test]
fn child_roles() {
    let Ok(role) = std::env::var("QINIT_SYS_ROLE") else {
        return;
    };
    let out = std::io::stdout();
    signal::set_park_fd(out.as_fd());
    signal::install_fault_park().unwrap();
    match role.as_str() {
        "sigsegv" => proc::kill_thread_self(libc::SIGSEGV).unwrap(),
        "overflow" => {
            std::hint::black_box(grow(0));
        }
        "abort" => std::process::abort(),
        "panic" => {
            std::panic::set_hook(Box::new(|_| signal::park(b"<2>queen: panic\n")));
            panic!("on purpose");
        }
        other => panic!("unknown role {other}"),
    }
    std::process::exit(0);
}

#[test]
fn a_fault_parks_instead_of_ending() {
    parks("sigsegv", "<2>queen: fatal signal");
}

#[test]
fn a_stack_overflow_parks() {
    parks("overflow", "<2>queen: fatal signal");
}

#[test]
fn an_abort_parks() {
    parks("abort", "<2>queen: fatal signal");
}

#[test]
fn a_panic_hook_can_park() {
    parks("panic", "<2>queen: panic");
}
