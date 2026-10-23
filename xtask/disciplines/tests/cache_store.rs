// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use xtask::cache::store::{DIR_NAME, KEEP, Store, ago};

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!("xtask-store-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

fn git(dir: &Path, args: &[&str]) {
    let ok = xtask::git::command()
        .args(["-c", "user.name=t", "-c", "user.email=t@t"])
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap()
        .status
        .success();
    assert!(ok, "git {args:?}");
}

#[test]
fn record_then_hit_and_miss() {
    let s = scratch("hit");
    let store = Store::at(s.0.join("cache"));
    assert_eq!(store.hit("fmt", "k1"), Ok(None));
    store.record("fmt", "k1", 1_700_000_000).unwrap();
    assert_eq!(store.hit("fmt", "k1"), Ok(Some(1_700_000_000)));
    assert_eq!(store.hit("lint", "k1"), Ok(None), "entries are per gate");
}

#[test]
fn a_corrupt_entry_is_an_error_not_a_hit() {
    let s = scratch("corrupt");
    let store = Store::at(s.0.join("cache"));
    fs::create_dir_all(store.dir().join("fmt")).unwrap();
    fs::write(store.dir().join("fmt/k1"), "garbage").unwrap();
    assert!(store.hit("fmt", "k1").unwrap_err().contains("corrupt"));
}

#[test]
fn record_prunes_to_keep_newest() {
    let s = scratch("prune");
    let store = Store::at(s.0.join("cache"));
    for i in 0..KEEP + 5 {
        store.record("test", &format!("k{i}"), 1).unwrap();
    }
    let kept = fs::read_dir(store.dir().join("test")).unwrap().count();
    assert_eq!(kept, KEEP);
    assert_eq!(
        store.hit("test", &format!("k{}", KEEP + 4)),
        Ok(Some(1)),
        "the newest survives"
    );
}

#[test]
fn clear_removes_everything_and_tolerates_absence() {
    let s = scratch("clear");
    let store = Store::at(s.0.join("cache"));
    store.clear().unwrap();
    store.record("fmt", "k", 1).unwrap();
    store.clear().unwrap();
    assert!(!store.dir().exists());
}

#[test]
fn open_uses_the_common_dir_shared_by_linked_worktrees() {
    let s = scratch("open");
    let repo = s.0.join("repo");
    fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["commit", "-q", "--allow-empty", "-m", "init"]);
    git(&repo, &["worktree", "add", "-q", "-b", "feat/w", "../wt"]);
    let main = Store::open(&repo).unwrap();
    let linked = Store::open(&s.0.join("wt")).unwrap();
    assert_eq!(main.dir(), linked.dir());
    assert!(main.dir().ends_with(Path::new(".git").join(DIR_NAME)));
}

#[test]
fn ages_read_naturally() {
    assert_eq!(ago(100, 130), "30 s ago");
    assert_eq!(ago(0, 600), "10 min ago");
    assert_eq!(ago(0, 3 * 3600), "3 h ago");
    assert_eq!(ago(0, 3 * 86_400), "3 days ago");
    assert_eq!(ago(200, 100), "0 s ago", "a clock that went backwards");
}

#[test]
fn record_keeps_the_entry_just_written() {
    let s = scratch("fresh");
    let store = Store::at(s.0.join("cache"));
    for i in 0..KEEP + 5 {
        store.record("test", &format!("k{i}"), 1).unwrap();
    }
    store.record("test", "fresh", 2).unwrap();
    assert_eq!(store.hit("test", "fresh"), Ok(Some(2)));
    assert_eq!(
        fs::read_dir(store.dir().join("test")).unwrap().count(),
        KEEP
    );
}

#[test]
fn record_keeps_the_entry_just_written_when_all_mtimes_tie() {
    let s = scratch("fresh-tie");
    let store = Store::at(s.0.join("cache"));
    for i in 0..KEEP + 5 {
        store.record("test", &format!("k{i}"), 1).unwrap();
    }
    // Existing entries share one mtime in the future, so the fresh entry is
    // the oldest by mtime and an mtime-only prune would delete it.
    let future = SystemTime::now() + Duration::from_secs(3600);
    for entry in fs::read_dir(store.dir().join("test")).unwrap() {
        let file = fs::File::options()
            .write(true)
            .open(entry.unwrap().path())
            .unwrap();
        file.set_modified(future).unwrap();
    }
    store.record("test", "fresh", 2).unwrap();
    assert_eq!(store.hit("test", "fresh"), Ok(Some(2)));
    assert_eq!(
        fs::read_dir(store.dir().join("test")).unwrap().count(),
        KEEP
    );
}

#[test]
fn bad_names_are_rejected_before_touching_the_disk() {
    let s = scratch("names");
    let store = Store::at(s.0.join("cache"));
    store.record("fmt", "k", 1).unwrap();
    assert!(store.record("..", "k", 1).is_err());
    assert!(store.hit("..", "k").is_err());
    assert!(store.record("fmt", "../escape", 1).is_err());
    assert!(store.hit("fmt", "").is_err());
    assert_eq!(
        fs::read_dir(&s.0).unwrap().count(),
        1,
        "only the cache dir exists"
    );
}

#[test]
fn durations_round_trip_and_overwrite() {
    let s = scratch("durations");
    let store = Store::at(s.0.join("c"));
    assert!(store.durations().is_empty());
    store.record_duration("proof:a", 12).unwrap();
    store.record_duration("proof:b", 3).unwrap();
    store.record_duration("proof:a", 40).unwrap();
    let d = store.durations();
    assert_eq!(d.get("proof:a"), Some(&40));
    assert_eq!(d.get("proof:b"), Some(&3));
}

#[test]
fn durations_tolerate_garbage() {
    let s = scratch("durations-bad");
    let store = Store::at(s.0.join("c"));
    fs::create_dir_all(store.dir()).unwrap();
    fs::write(
        store.dir().join("proof-durations"),
        "proof:a x\n\n\u{fffd}\nproof:b 7\n",
    )
    .unwrap();
    let d = store.durations();
    assert_eq!(d.get("proof:b"), Some(&7));
    assert_eq!(d.len(), 1);
}

#[test]
fn record_prunes_stale_temp_files_but_not_fresh_ones() {
    let s = scratch("stale-tmp");
    let store = Store::at(s.0.join("cache"));
    store.record("g", "k1", 1).unwrap();
    let gate_dir = s.0.join("cache").join("g");
    let stale = gate_dir.join(".tmp-old-1");
    let fresh = gate_dir.join(".tmp-new-2");
    std::fs::write(&stale, "").unwrap();
    std::fs::write(&fresh, "").unwrap();
    let old = SystemTime::now() - Duration::from_hours(2);
    std::fs::File::options()
        .write(true)
        .open(&stale)
        .unwrap()
        .set_modified(old)
        .unwrap();
    store.record("g", "k2", 2).unwrap();
    assert!(!stale.exists(), "a temp file over an hour old is removed");
    assert!(
        fresh.exists(),
        "a recent temp file may be another run's write"
    );
}
