// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qctl watch` against the real server on a thread: `qctl` runs on its own thread and writes
//! into a pipe, which the test reads line by line (each line is the handshake for the next
//! step).
#[path = "../../qinit-client/tests/common/served.rs"]
mod served;

use served::common::database;
use served::{Served, instant};
use std::io::{BufRead, BufReader};

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

/// `qctl <args>` on a thread, its output on the returned reader; the thread's result is the
/// exit code and the error text.
fn spawn(
    args: &[&str],
) -> (
    BufReader<std::fs::File>,
    std::thread::JoinHandle<(i32, String)>,
) {
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let (r, w) = qinit_sys::fd::pipe(0o2_000_000).unwrap();
    let thread = std::thread::spawn(move || {
        let mut out = std::fs::File::from(w);
        let mut err = Vec::new();
        let code = qctl::run(&args, &mut out, &mut err);
        (code, String::from_utf8(err).unwrap())
    });
    (BufReader::new(std::fs::File::from(r)), thread)
}

fn line(r: &mut BufReader<std::fs::File>) -> Option<String> {
    let mut l = String::new();
    match r.read_line(&mut l).unwrap() {
        0 => None,
        _ => Some(l.trim_end_matches('\n').to_owned()),
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
    let dir = std::env::temp_dir().join(format!("qctl-watch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("without-db.db");
    let frames = "[forager.backup]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/backup\"]\n";
    std::fs::write(&db, database(frames, &[])).unwrap();
    let (code, _, err) = qctl(&["--socket", &path, "refresh", db.to_str().unwrap()]);
    let _ = std::fs::remove_dir_all(&dir);
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
    // The exit, if the watch saw it, then the end in the instance's state words.
    assert_eq!(
        seen.last().map(String::as_str),
        Some("ended exited"),
        "{seen:?}"
    );
    assert!(
        seen.len() == 1 || seen[0] == format!("instance {target} exited exited status=1280"),
        "{seen:?}"
    );
    assert_eq!(thread.join().unwrap().0, 0);
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
    assert_eq!(err, "qctl: colony closed the stream\n");
}
