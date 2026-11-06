// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The path watcher against real inotify in a temporary directory.
use qinit_colonyd::watch::{Want, Watcher};
use qinit_event::{Loop, Ready};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

/// A temporary directory removed when it goes out of scope.
struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Tmp {
        let d = std::env::temp_dir().join(format!("qinit-watch-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Tmp(d)
    }

    fn at(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const TOKEN: u64 = 3;

fn rig() -> (Loop, Watcher) {
    let mut l = Loop::new().unwrap();
    let w = Watcher::new(&mut l, TOKEN).unwrap();
    (l, w)
}

/// Feeds every inotify event that is ready now to the watcher; the ids it reports.
fn pump(l: &mut Loop, w: &mut Watcher) -> Vec<u64> {
    let mut seen = Vec::new();
    loop {
        let batch = l.poll().unwrap();
        if batch.is_empty() {
            return seen;
        }
        for r in batch {
            if let Ready::InotifySet(TOKEN, evs) = r {
                seen.extend(w.on_events(l, &evs));
            }
        }
    }
}

fn make(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, b"x").unwrap();
}

#[test]
fn an_existing_path_is_satisfied_at_once() {
    let t = Tmp::new("exists");
    make(&t.at("a/b"));
    let (mut l, mut w) = rig();
    assert_eq!(w.add(&mut l, 1, &t.at("a/b"), Want::Exists), Ok(true));
    assert_eq!(w.pending(), 0, "nothing left to watch");
    assert_eq!(pump(&mut l, &mut w), []);
}

#[test]
fn a_path_three_levels_down_is_seen_when_made() {
    let t = Tmp::new("deep");
    let (mut l, mut w) = rig();
    assert_eq!(w.add(&mut l, 1, &t.at("a/b/c"), Want::Exists), Ok(false));
    std::fs::create_dir_all(t.at("a/b")).unwrap();
    assert_eq!(pump(&mut l, &mut w), [], "the directories alone are not it");
    std::fs::write(t.at("a/b/c"), b"x").unwrap();
    assert_eq!(pump(&mut l, &mut w), [1]);
    assert_eq!(pump(&mut l, &mut w), [], "reported once");
    assert_eq!(w.pending(), 0);
}

#[test]
fn a_path_created_after_the_watch_and_before_the_check_is_seen_once() {
    let t = Tmp::new("window");
    let (mut l, mut w) = rig();
    let path = t.at("a/b/c");
    let made = path.clone();
    w.between = Some(Box::new(move || make(&made)));
    assert_eq!(w.add(&mut l, 1, &path, Want::Exists), Ok(true));
    assert_eq!(
        pump(&mut l, &mut w),
        [],
        "the queued event does not report it again"
    );
    assert_eq!(w.pending(), 0);
}

#[test]
fn a_removed_ancestor_is_climbed_back() {
    let t = Tmp::new("climb");
    let (mut l, mut w) = rig();
    assert_eq!(w.add(&mut l, 1, &t.at("a/b/c"), Want::Exists), Ok(false));
    std::fs::create_dir_all(t.at("a/b")).unwrap();
    assert_eq!(pump(&mut l, &mut w), []);
    std::fs::remove_dir_all(t.at("a")).unwrap();
    assert_eq!(pump(&mut l, &mut w), [], "climbed, not satisfied");
    make(&t.at("a/b/c"));
    assert_eq!(pump(&mut l, &mut w), [1]);
}

#[test]
fn a_stale_file_is_not_created() {
    let t = Tmp::new("stale");
    let path = t.at("run/x.pid");
    make(&path);
    let (mut l, mut w) = rig();
    assert_eq!(w.add(&mut l, 1, &path, Want::Created), Ok(false));
    assert_eq!(pump(&mut l, &mut w), [], "the old file does not count");
    std::fs::remove_file(&path).unwrap();
    assert_eq!(pump(&mut l, &mut w), [], "removing it does not either");
    std::fs::write(&path, b"1").unwrap();
    assert_eq!(pump(&mut l, &mut w), [1], "a new one does");
}

#[test]
fn a_stale_socket_is_not_created_and_a_fresh_bind_is() {
    let t = Tmp::new("sock");
    let path = t.at("run/s.sock");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let old = UnixListener::bind(&path).unwrap();
    let (mut l, mut w) = rig();
    assert_eq!(w.add(&mut l, 1, &path, Want::CreatedSocket), Ok(false));
    let plain = t.at("run/plain.sock");
    assert_eq!(w.add(&mut l, 2, &plain, Want::CreatedSocket), Ok(false));
    assert_eq!(pump(&mut l, &mut w), [], "the old socket does not count");
    // A regular file where a socket is expected is not the socket.
    std::fs::write(&plain, b"not a socket").unwrap();
    assert_eq!(pump(&mut l, &mut w), []);
    assert_eq!(w.pending(), 2);
    drop(old);
    std::fs::remove_file(&path).unwrap();
    let _fresh = UnixListener::bind(&path).unwrap();
    assert_eq!(pump(&mut l, &mut w), [1]);
    assert_eq!(w.pending(), 1, "the plain-file watch is still waiting");
}

#[test]
fn removing_an_entry_ends_its_watch_and_a_shared_directory_keeps_the_other() {
    let t = Tmp::new("remove");
    let (mut l, mut w) = rig();
    assert_eq!(w.add(&mut l, 1, &t.at("d/one"), Want::Exists), Ok(false));
    assert_eq!(w.add(&mut l, 2, &t.at("d/two"), Want::Exists), Ok(false));
    w.remove(&mut l, 1);
    assert_eq!(w.pending(), 1);
    std::fs::create_dir_all(t.at("d")).unwrap();
    assert_eq!(pump(&mut l, &mut w), []);
    make(&t.at("d/one"));
    make(&t.at("d/two"));
    assert_eq!(pump(&mut l, &mut w), [2], "only the entry still wanted");
}

#[test]
fn a_relative_path_is_refused() {
    let (mut l, mut w) = rig();
    assert!(w.add(&mut l, 1, Path::new("run/x"), Want::Exists).is_err());
    assert_eq!(w.pending(), 0);
}
