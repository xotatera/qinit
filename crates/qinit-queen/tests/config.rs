// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The bounds the kernel command line sets: `qinit.shutdown_ms=` and `qinit.heartbeat_ms=`.
use qinit_queen::configured;
use qinit_queen_core::machine::{ALIVE_MS, LIMITS, MIN_HEARTBEAT_MS};

#[test]
fn a_command_line_without_settings_leaves_the_spec_limits() {
    let (l, refused) = configured(LIMITS, "console=ttyS0 root=/dev/vda rw quiet");
    assert_eq!(l, LIMITS);
    assert!(refused.is_empty());
}

#[test]
fn the_shutdown_bound_and_the_heartbeat_are_set() {
    let (l, refused) = configured(
        LIMITS,
        "ro qinit.shutdown_ms=45000 qinit.heartbeat_ms=12000 x",
    );
    assert_eq!(l.shutdown_ms, 45_000);
    assert_eq!(l.heartbeat_ms, 12_000);
    assert_eq!(
        (l.window_ms, l.kill_wait_ms),
        (LIMITS.window_ms, LIMITS.kill_wait_ms)
    );
    assert!(refused.is_empty());
}

#[test]
fn the_last_setting_wins() {
    let (l, _) = configured(LIMITS, "qinit.shutdown_ms=1000 qinit.shutdown_ms=2000");
    assert_eq!(l.shutdown_ms, 2_000);
}

#[test]
fn a_heartbeat_of_zero_turns_the_watch_off() {
    let (l, refused) = configured(LIMITS, "qinit.heartbeat_ms=0");
    assert_eq!(l.heartbeat_ms, 0);
    assert!(refused.is_empty());
}

#[test]
fn a_value_that_is_not_allowed_is_refused_by_name_and_the_default_kept() {
    for (word, value) in [
        ("qinit.shutdown_ms=abc", "shutdown"),
        ("qinit.shutdown_ms=", "shutdown"),
        ("qinit.shutdown_ms=0", "shutdown"),
        ("qinit.shutdown_ms=-5", "shutdown"),
        ("qinit.shutdown_ms=86400001", "shutdown"),
        ("qinit.heartbeat_ms=1", "heartbeat"),
        ("qinit.heartbeat_ms=x", "heartbeat"),
        ("qinit.heartbeat_ms=86400001", "heartbeat"),
    ] {
        let (l, refused) = configured(LIMITS, word);
        assert_eq!(l, LIMITS, "{word}");
        assert_eq!(refused.len(), 1, "{word}: {refused:?}");
        assert!(refused[0].contains(word), "{word}: {refused:?}");
        assert!(refused[0].contains(value), "{word}: {refused:?}");
    }
}

#[test]
fn the_edges_are_allowed() {
    let (l, refused) = configured(
        LIMITS,
        &format!("qinit.shutdown_ms=1 qinit.heartbeat_ms={MIN_HEARTBEAT_MS}"),
    );
    assert_eq!((l.shutdown_ms, l.heartbeat_ms), (1, MIN_HEARTBEAT_MS));
    assert!(refused.is_empty());
    let (l, refused) = configured(
        LIMITS,
        "qinit.shutdown_ms=86400000 qinit.heartbeat_ms=86400000",
    );
    assert_eq!((l.shutdown_ms, l.heartbeat_ms), (86_400_000, 86_400_000));
    assert!(refused.is_empty());
}

#[test]
fn a_word_that_only_looks_like_a_setting_is_not_one() {
    let (l, refused) = configured(
        LIMITS,
        "xqinit.shutdown_ms=5 qinit.shutdown_msx=5 qinit.other=1",
    );
    assert_eq!(l, LIMITS);
    assert!(refused.is_empty());
}

/// The smallest heartbeat period leaves room for four beats.
const _: () = assert!(MIN_HEARTBEAT_MS >= 4 * ALIVE_MS);
