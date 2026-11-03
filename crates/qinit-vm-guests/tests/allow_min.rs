// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The allowlist the sandbox suite installs names its calls by number, because the guest has
//! no table: the host checks every pair against the `x86_64` table of `qinit-frames`.
use qinit_frames::syscalls::number;
use qinit_vm_guests::ALLOW_MIN;

#[test]
fn allow_min_numbers_match_the_table() {
    for (name, nr) in ALLOW_MIN {
        assert_eq!(number(name), Some(*nr), "{name}");
    }
}

#[test]
fn allow_min_has_no_duplicates_and_leaves_getppid_out() {
    let mut numbers: Vec<u32> = ALLOW_MIN.iter().map(|(_, n)| *n).collect();
    numbers.sort_unstable();
    let len = numbers.len();
    numbers.dedup();
    assert_eq!(numbers.len(), len);
    assert!(!ALLOW_MIN.iter().any(|(name, _)| *name == "getppid"));
}
