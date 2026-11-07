// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! A flood of one signal logs once a minute.
use qinit_queen::quiet::Quiet;

#[test]
fn a_signal_logs_once_a_minute() {
    let mut q = Quiet::new();
    assert!(q.log(15, 1_000));
    assert!(!q.log(15, 1_001));
    assert!(!q.log(15, 60_999));
    assert!(q.log(15, 61_000));
    assert!(!q.log(15, 61_001));
}

#[test]
fn two_signals_log_apart() {
    let mut q = Quiet::new();
    assert!(q.log(15, 5));
    assert!(q.log(1, 6));
    assert!(!q.log(15, 7));
    assert!(!q.log(1, 8));
}

#[test]
fn a_huge_signal_number_cannot_index_out_of_bounds() {
    let mut q = Quiet::new();
    assert!(q.log(u32::MAX, 0));
    assert!(!q.log(u32::MAX, 1));
}
