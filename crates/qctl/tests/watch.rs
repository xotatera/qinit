// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qctl watch` against the real server on a thread: `qctl` runs on its own thread and writes
//! into a pipe, which the test reads line by line (each line is the handshake for the next
//! step).
mod common;
#[path = "../../qinit-client/tests/common/served.rs"]
mod served;

use common::TempDir;
use served::common::database;
use served::{Served, instant};
use std::io::{BufRead, BufReader};
use std::os::fd::OwnedFd;
use std::sync::mpsc;
use std::time::Duration;

fn qctl(args: &[&str]) -> (i32, String, String) {
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = qctl::run(&args, &mut out, &mut err);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

/// How long a test waits for the next line before it fails (rather than hanging).
const LINE_TIMEOUT: Duration = Duration::from_secs(10);

/// The lines written to a pipe, read on a thread so the test can wait for each with a bound.
struct Lines(mpsc::Receiver<String>);

impl Lines {
    fn new(r: OwnedFd) -> Lines {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut r = BufReader::new(std::fs::File::from(r));
            loop {
                let mut l = String::new();
                match r.read_line(&mut l) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if tx.send(l.trim_end_matches('\n').to_owned()).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Lines(rx)
    }
}

/// `qctl <args>` on a thread, its output on the returned lines; the thread's result is the
/// exit code and the error text.
fn spawn(args: &[&str]) -> (Lines, std::thread::JoinHandle<(i32, String)>) {
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let (r, w) = qinit_sys::fd::pipe(0o2_000_000).unwrap();
    let thread = std::thread::spawn(move || {
        let mut out = std::fs::File::from(w);
        let mut err = Vec::new();
        let code = qctl::run(&args, &mut out, &mut err);
        (code, String::from_utf8(err).unwrap())
    });
    (Lines::new(r), thread)
}

/// The next line, or None at the end of the output; panics after [`LINE_TIMEOUT`] without one.
fn line(r: &mut Lines) -> Option<String> {
    match r.0.recv_timeout(LINE_TIMEOUT) {
        Ok(l) => Some(l),
        Err(mpsc::RecvTimeoutError::Disconnected) => None,
        Err(mpsc::RecvTimeoutError::Timeout) => panic!("no line from qctl in {LINE_TIMEOUT:?}"),
    }
}

#[test]
fn watch_prints_current_then_the_change_and_ends_on_superseded() {
    let s = Served::start(&["db"], true, instant(None));
    let path = s.path.to_str().unwrap().to_owned();
    let (mut lines, thread) = spawn(&["--socket", &path, "watch", "db"]);
    // The current state comes first: the watch is in place before the change.
    assert_eq!(line(&mut lines).as_deref(), Some("node db current ready"));
    let (code, _, err) = qctl(&["--socket", &path, "stop", "db"]);
    assert_eq!(code, 0, "{err}");
    let mut seen = Vec::new();
    loop {
        let l = line(&mut lines).expect("the watch ended before the stop");
        let done = l == "node db stopped off";
        seen.push(l);
        if done {
            break;
        }
    }
    // A database without `db` ends the watch: the node is gone.
    let dir = TempDir::new("watch");
    let db = dir.join("without-db.db");
    let frames = "[forager.backup]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/backup\"]\n";
    std::fs::write(&db, database(frames, &[])).unwrap();
    let (code, _, err) = qctl(&["--socket", &path, "refresh", db.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}");
    let mut last = None;
    while let Some(l) = line(&mut lines) {
        seen.push(l.clone());
        last = Some(l);
    }
    assert_eq!(last.as_deref(), Some("ended off"), "{seen:?}");
    let (code, err) = thread.join().unwrap();
    assert_eq!(code, 0, "{err}");
}

#[test]
fn an_instance_watch_ends_at_the_exit() {
    let s = Served::start(&[], true, instant(Some(5 << 8)));
    let path = s.path.to_str().unwrap().to_owned();
    let (code, out, err) = qctl(&["--socket", &path, "launch", "backup"]);
    assert_eq!(code, 5, "{err}");
    let target = out
        .lines()
        .find_map(|l| l.strip_prefix("started "))
        .expect("the instance is named")
        .to_owned();
    let (mut lines, thread) = spawn(&["--socket", &path, "watch", &target]);
    let mut seen = Vec::new();
    while let Some(l) = line(&mut lines) {
        seen.push(l);
    }
    // Colony sends an already-exited instance's exit (report 5, with the status), then the
    // end in the instance's state words.
    assert_eq!(
        seen,
        [
            format!("instance {target} exited exited status=1280"),
            "ended exited".to_owned()
        ]
    );
    assert_eq!(thread.join().unwrap().0, 0);
}

#[test]
fn an_instance_watch_in_json_ends_in_the_instance_state() {
    use serde_json::json;
    let s = Served::start(&[], true, instant(Some(5 << 8)));
    let path = s.path.to_str().unwrap().to_owned();
    let (code, out, err) = qctl(&["--socket", &path, "launch", "backup"]);
    assert_eq!(code, 5, "{err}");
    let target = out
        .lines()
        .find_map(|l| l.strip_prefix("started "))
        .expect("the instance is named")
        .to_owned();
    let (frame, id) = target.split_once('#').unwrap();
    let id: u64 = id.parse().unwrap();
    let (mut lines, thread) = spawn(&["--socket", &path, "--json", "watch", &target]);
    let mut seen = Vec::new();
    while let Some(l) = line(&mut lines) {
        seen.push(serde_json::from_str::<serde_json::Value>(&l).unwrap());
    }
    assert_eq!(
        seen,
        [
            json!({"kind": "instance", "name": frame, "id": id, "report": "exited",
                   "state": "exited", "status": 1280}),
            json!({"kind": "ended", "state": "exited"}),
        ]
    );
    assert_eq!(thread.join().unwrap().0, 0);
    // The end of an instance's watch has the instance's state words, never a detail.
    assert_eq!(
        qctl::json::ended_instance(5),
        json!({"kind": "ended", "state": "stopping"})
    );
    assert_eq!(
        qctl::json::ended_instance(9),
        json!({"kind": "ended", "state": "state9"})
    );
}

#[test]
fn a_watch_of_an_unknown_target_exits_1() {
    let s = Served::start(&["db"], true, instant(None));
    let path = s.path.to_str().unwrap().to_owned();
    let (code, out, err) = qctl(&["--socket", &path, "watch", "nope"]);
    assert_eq!((code, out.as_str()), (1, ""));
    assert!(err.contains("colony refused: UnknownNode"), "{err}");
}

#[test]
fn a_watch_whose_server_goes_away_exits_1() {
    let s = Served::start(&["db"], true, instant(None));
    let path = s.path.to_str().unwrap().to_owned();
    let (mut lines, thread) = spawn(&["--socket", &path, "watch", "db"]);
    // The current state: the watch is in place (only a targeted watch gets one).
    assert_eq!(line(&mut lines).as_deref(), Some("node db current ready"));
    drop(s.finish());
    while line(&mut lines).is_some() {}
    let (code, err) = thread.join().unwrap();
    assert_eq!(code, 1);
    assert_eq!(
        err,
        "qctl: the stream ended: colony closed it or sent a reply that is not a notice\n"
    );
}

#[test]
fn watch_all_goes_on_after_an_instance_exit() {
    let s = Served::start(&["db"], true, instant(Some(0)));
    let path = s.path.to_str().unwrap().to_owned();
    // A watch of everything gets no current lines, so the test makes the watcher itself:
    // `watch` returns after `Accepted`, with the watch in place. `follow` is qctl's loop.
    let w = qinit_client::Client::connect(&s.path)
        .unwrap()
        .watch(qinit_client::Scope::All)
        .unwrap();
    let (r, wr) = qinit_sys::fd::pipe(0o2_000_000).unwrap();
    let thread = std::thread::spawn(move || {
        let mut out = std::fs::File::from(wr);
        let mut err = Vec::new();
        let code = qctl::watch::follow(w, false, qctl::json::Output::Text, &mut out, &mut err);
        (code, String::from_utf8(err).unwrap())
    });
    let mut lines = Lines::new(r);
    let (code, out, err) = qctl(&["--socket", &path, "launch", "backup"]);
    assert_eq!(code, 0, "{err}");
    let target = out
        .lines()
        .find_map(|l| l.strip_prefix("started "))
        .unwrap()
        .to_owned();
    let exited = format!("instance {target} exited exited status=0");
    let mut seen = Vec::new();
    while seen.last() != Some(&exited) {
        seen.push(line(&mut lines).expect("the watch ended before the exit"));
    }
    // The line after the exit still arrives: the watch goes on.
    let (code, _, err) = qctl(&["--socket", &path, "stop", "db"]);
    assert_eq!(code, 0, "{err}");
    while seen.last().map(String::as_str) != Some("node db stopped off") {
        seen.push(line(&mut lines).unwrap_or_else(|| panic!("the watch ended: {seen:?}")));
    }
    // It ends only when the server goes away.
    drop(s.finish());
    while line(&mut lines).is_some() {}
    let (code, err) = thread.join().unwrap();
    assert_eq!(
        (code, err.as_str()),
        (
            1,
            "qctl: the stream ended: colony closed it or sent a reply that is not a notice\n"
        )
    );
}

#[test]
fn watch_json_lines() {
    use serde_json::json;
    let s = Served::start(&["db"], true, instant(None));
    let path = s.path.to_str().unwrap().to_owned();
    let (mut lines, thread) = spawn(&["--socket", &path, "--json", "watch", "db"]);
    let next = |l: &mut Lines| -> serde_json::Value {
        let t = line(l).expect("the watch ended early");
        serde_json::from_str(&t).unwrap_or_else(|e| panic!("{t:?}: {e}"))
    };
    assert_eq!(
        next(&mut lines),
        json!({"kind": "node", "name": "db", "report": "current", "state": "ready"})
    );
    let (code, _, err) = qctl(&["--socket", &path, "stop", "db"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        next(&mut lines),
        json!({"kind": "node", "name": "db", "report": "stopped", "state": "off"})
    );
    let dir = TempDir::new("watchjson");
    let db = dir.join("without-db.db");
    let frames = "[forager.backup]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/backup\"]\n";
    std::fs::write(&db, database(frames, &[])).unwrap();
    let (code, _, err) = qctl(&["--socket", &path, "refresh", db.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}");
    let mut last = None;
    while let Some(l) = line(&mut lines) {
        last = Some(serde_json::from_str::<serde_json::Value>(&l).unwrap());
    }
    assert_eq!(last, Some(json!({"kind": "ended", "state": "off"})));
    let (code, err) = thread.join().unwrap();
    assert_eq!(code, 0, "{err}");
}

#[test]
fn watch_notice_shapes() {
    use qinit_client::{Event, Report, StateWord};
    use serde_json::json;
    let ev = Event::Instance {
        frame: "backup".into(),
        id: 4,
        report: Report::Exited,
        state: 4,
        status: Some(256),
    };
    assert_eq!(
        qctl::json::notice(&ev),
        json!({"kind": "instance", "name": "backup", "id": 4, "report": "exited",
               "state": "exited", "status": 256})
    );
    let ev = Event::Node {
        name: "db".into(),
        report: Report::Failed,
        state: StateWord {
            state: 1,
            detail: 1,
        },
        status: None,
    };
    assert_eq!(
        qctl::json::notice(&ev),
        json!({"kind": "node", "name": "db", "report": "failed",
               "state": "waiting", "detail": "backoff"})
    );
    assert_eq!(
        qctl::json::notice(&Event::Swapped),
        json!({"kind": "swapped"})
    );
    assert_eq!(
        qctl::json::notice(&Event::ShutdownComplete { still_populated: 2 }),
        json!({"kind": "shutdown_complete", "still_populated": 2})
    );
}
