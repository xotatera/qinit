// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! `watch::wait_until`: woken by events, bounded by its deadline.
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use xtask::watch::{self, WatchMask};

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!("xtask-watch-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

/// Long enough never to decide a passing test: only a failure waits it out.
const DEADLINE: Duration = Duration::from_secs(20);

#[test]
fn a_check_that_already_holds_returns_at_once() {
    let s = scratch("held");
    let mut calls = 0;
    let held = watch::wait_until(&s.0, WatchMask::CREATE, DEADLINE, &mut || {
        calls += 1;
        true
    });
    assert!(held.unwrap());
    assert_eq!(calls, 1);
}

#[test]
fn an_event_after_the_watch_wakes_the_wait() {
    // The first check runs with the watch in place; the file it creates
    // there can only be seen again through the event.
    let s = scratch("event");
    let mut calls = 0;
    let held = watch::wait_until(&s.0, WatchMask::CREATE, DEADLINE, &mut || {
        calls += 1;
        if calls == 1 {
            fs::write(s.0.join("arrived"), "").unwrap();
            return false;
        }
        true
    });
    assert!(held.unwrap());
    assert_eq!(calls, 2);
}

#[test]
fn without_an_event_the_deadline_ends_the_wait() {
    let s = scratch("quiet");
    let mut calls = 0;
    let held = watch::wait_until(
        &s.0,
        WatchMask::CREATE,
        Duration::from_millis(50),
        &mut || {
            calls += 1;
            false
        },
    );
    assert!(!held.unwrap());
    assert_eq!(calls, 1, "no event, so no second check");
}

#[test]
fn a_path_that_cannot_be_watched_is_an_error() {
    let s = scratch("missing");
    let held = watch::wait_until(
        &s.0.join("absent"),
        WatchMask::MODIFY,
        DEADLINE,
        &mut || false,
    );
    assert!(held.is_err());
}

#[test]
fn a_removed_path_ends_the_wait() {
    // Removing the watched directory queues `IN_IGNORED` before the wait
    // removes its own watch: the reader must still end.
    let s = scratch("removed");
    let dir = s.0.join("gone");
    fs::create_dir(&dir).unwrap();
    let mut calls = 0;
    let held = watch::wait_until(&dir, WatchMask::DELETE_SELF, DEADLINE, &mut || {
        calls += 1;
        if calls == 1 {
            fs::remove_dir(&dir).unwrap();
            return false;
        }
        true
    });
    assert!(held.unwrap());
}

const FROZEN_CHILD: &str = "XTASK_WATCH_FROZEN_CHILD";

/// A budget survives a freeze: the child waits with 3 s of budget, the
/// parent stops it (SIGSTOP, as atc's fallback freezes; a cgroup freeze
/// stops it the same way) for longer than that, resumes it and then sends.
/// The child still gets the message: the stopped time cost one slice. A
/// single `recv_timeout(3 s)` would have timed out on resume. The margin
/// left (about 3 s less what passed before the stop) absorbs a loaded host.
#[test]
fn a_budget_does_not_count_time_frozen() {
    use std::io::{BufRead as _, Write as _};
    if std::env::var_os(FROZEN_CHILD).is_some() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = std::io::stdin().lock().read_line(&mut line);
            let _ = tx.send(());
        });
        println!("waiting");
        std::io::stdout().flush().unwrap();
        let got = watch::Budget::new(Duration::from_secs(3)).recv(&rx);
        println!("{got:?}");
        return;
    }
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "a_budget_does_not_count_time_frozen",
            "--exact",
            "--nocapture",
            "--quiet",
        ])
        .env(FROZEN_CHILD, "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    while line.trim() != "waiting" {
        line.clear();
        assert!(
            out.read_line(&mut line).unwrap() > 0,
            "the child never waited"
        );
    }
    let pid = child.id().to_string();
    let signal = |sig: &str| {
        assert!(
            // The shell's `kill` (a POSIX built-in): a base system without
            // procps has no `kill` binary.
            std::process::Command::new("sh")
                .args(["-c", "kill -s \"$1\" -- \"$2\"", "sh", sig, &pid])
                .status()
                .unwrap()
                .success()
        );
    };
    signal("STOP");
    // The freeze itself: real time on purpose, the child's budget and more.
    let (_keep, never) = std::sync::mpsc::channel::<()>();
    let _ = never.recv_timeout(Duration::from_millis(3500));
    signal("CONT");
    writeln!(child.stdin.take().unwrap(), "go").unwrap();
    let mut rest = String::new();
    std::io::Read::read_to_string(&mut out, &mut rest).unwrap();
    assert!(child.wait().unwrap().success());
    assert!(rest.contains("Ok(())"), "{rest}");
}

#[test]
fn a_budget_is_spent_by_messages_and_work_too_and_takes_one_waiting_at_the_end() {
    let (tx, rx) = std::sync::mpsc::channel();
    let mut budget = watch::Budget::new(Duration::ZERO);
    tx.send(1).unwrap();
    assert_eq!(
        budget.recv(&rx),
        Ok(1),
        "a spent budget takes a waiting message"
    );
    tx.send(2).unwrap();
    assert_eq!(
        budget.recv(&rx),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout),
        "only one"
    );
    drop(tx);
    assert_eq!(watch::Budget::new(Duration::from_secs(1)).recv(&rx), Ok(2));
    assert_eq!(
        watch::Budget::new(Duration::from_secs(1)).recv(&rx),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
    );
    // Messages every few ms that never satisfy the waiter: the budget
    // still runs out, rather than waiting as long as they keep coming.
    let (tx, rx) = std::sync::mpsc::channel();
    let feeder = std::thread::spawn(move || {
        while tx.send(()).is_ok() {
            let (_keep, pace) = std::sync::mpsc::channel::<()>();
            let _ = pace.recv_timeout(Duration::from_millis(5));
        }
    });
    let mut budget = watch::Budget::new(Duration::from_millis(200));
    while budget.recv(&rx).is_ok() {}
    drop(rx);
    feeder.join().unwrap();
    // Messages already waiting each time, behind a waiter whose work takes
    // 20 ms: the work is charged, so the budget runs out within a few
    // dozen calls rather than never.
    let (tx, rx) = std::sync::mpsc::channel();
    for _ in 0..1000 {
        tx.send(()).unwrap();
    }
    let mut budget = watch::Budget::new(Duration::from_millis(200));
    let mut calls = 0;
    while budget.recv(&rx).is_ok() {
        calls += 1;
        assert!(calls < 100, "the waiter's work is never charged");
        let (_keep, work) = std::sync::mpsc::channel::<()>();
        let _ = work.recv_timeout(Duration::from_millis(20));
    }
}
