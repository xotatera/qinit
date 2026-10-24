// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! `watch::wait_until` ends its reader thread when `check` panics. The
//! reader owns the inotify descriptor and drops it before it returns, and
//! the join waits for that, so an open inotify descriptor after the call
//! means a reader still running. Its own binary with one test, so every
//! descriptor counted is this test's. (Threads are not counted: a joined
//! thread's `/proc/self/task` entry can outlive the join.)
use std::time::Duration;

use xtask::watch::{self, WatchMask};

fn inotify_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .flatten()
        .filter(|e| {
            std::fs::read_link(e.path()).is_ok_and(|l| l.to_string_lossy() == "anon_inode:inotify")
        })
        .count()
}

#[test]
fn a_panicking_check_leaves_no_reader_behind() {
    let dir = std::env::temp_dir().join(format!("xtask-watch-panic-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let before = inotify_fds();
    let unwound = std::panic::catch_unwind(|| {
        watch::wait_until(
            &dir,
            WatchMask::CREATE,
            Duration::from_secs(20),
            &mut || panic!("check failed"),
        )
    });
    let after = inotify_fds();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(unwound.is_err());
    assert_eq!(after, before, "the reader thread outlived the panic");
}
