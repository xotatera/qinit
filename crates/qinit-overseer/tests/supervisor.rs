// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! What the supervisor decodes from an exit code (spec §3, M2).
use qinit_overseer::supervisor::death_signal;

#[test]
fn an_exit_code_above_128_names_a_terminating_signal() {
    assert_eq!(death_signal(128 + libc::SIGKILL), Some(libc::SIGKILL));
    assert_eq!(death_signal(128 + libc::SIGTERM), Some(libc::SIGTERM));
    assert_eq!(death_signal(128 + libc::SIGSEGV), Some(libc::SIGSEGV));
}

#[test]
fn an_ordinary_exit_code_names_no_signal() {
    for code in [0, 1, 2, 127, 128, 160, 255] {
        assert_eq!(death_signal(code), None, "{code}");
    }
}

#[test]
fn the_stopping_signals_are_not_decoded_so_the_supervisor_never_stops_itself() {
    for sig in [libc::SIGSTOP, libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU] {
        assert_eq!(death_signal(128 + sig), None, "{sig}");
    }
}
