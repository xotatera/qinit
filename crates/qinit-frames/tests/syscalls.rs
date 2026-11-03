// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The `x86_64` syscall table: pinned numbers, order and the names the default denylist uses.
use qinit_frames::syscalls::{SYSCALLS, name, number};

#[test]
fn known_numbers_are_pinned() {
    for (n, nr) in [
        ("read", 0),
        ("write", 1),
        ("clone", 56),
        ("ptrace", 101),
        ("getppid", 110),
        ("exit_group", 231),
        ("unshare", 272),
        ("setns", 308),
        ("clone3", 435),
        ("openat2", 437),
        ("mount_setattr", 442),
        ("landlock_create_ruleset", 444),
    ] {
        assert_eq!(number(n), Some(nr), "{n}");
        assert_eq!(name(nr), Some(n), "{nr}");
    }
    assert_eq!(number("vm86"), None);
    assert_eq!(number(""), None);
    assert_eq!(name(511), None);
}

#[test]
fn the_table_is_sorted_unique_and_below_the_limit() {
    let mut last = None;
    for (n, nr) in SYSCALLS {
        assert!(last.is_none_or(|l| l < *nr), "{n} {nr} after {last:?}");
        assert!(*nr < qinit_db_core::MAX_SYSCALL);
        last = Some(*nr);
    }
    assert!(SYSCALLS.len() > 300);
}

/// The names of the overseer's default denylist (spec §7) and the numbers it must carry;
/// `qinit-overseer-core` checks its `DEFAULT_DENY` against this table.
pub const DEFAULT_DENY_NAMES: &[(&str, u32)] = &[
    ("ptrace", 101),
    ("process_vm_readv", 310),
    ("process_vm_writev", 311),
    ("kcmp", 312),
    ("mount", 165),
    ("umount2", 166),
    ("pivot_root", 155),
    ("chroot", 161),
    ("open_tree", 428),
    ("move_mount", 429),
    ("fsopen", 430),
    ("fsconfig", 431),
    ("fsmount", 432),
    ("fspick", 433),
    ("mount_setattr", 442),
    ("open_tree_attr", 467),
    ("swapon", 167),
    ("swapoff", 168),
    ("reboot", 169),
    ("kexec_load", 246),
    ("kexec_file_load", 320),
    ("init_module", 175),
    ("finit_module", 313),
    ("delete_module", 176),
    ("acct", 163),
    ("settimeofday", 164),
    ("clock_settime", 227),
    ("clock_adjtime", 305),
    ("adjtimex", 159),
    ("sethostname", 170),
    ("setdomainname", 171),
    ("bpf", 321),
    ("perf_event_open", 298),
    ("userfaultfd", 323),
    ("add_key", 248),
    ("request_key", 249),
    ("keyctl", 250),
    ("lookup_dcookie", 212),
    ("personality", 135),
    ("vhangup", 153),
    ("iopl", 172),
    ("ioperm", 173),
    ("nfsservctl", 180),
    ("quotactl", 179),
    ("quotactl_fd", 443),
    ("setns", 308),
    ("clone", 56),
    ("unshare", 272),
    ("clone3", 435),
];

#[test]
fn the_default_denylist_names_are_in_the_table_with_their_numbers() {
    for (n, nr) in DEFAULT_DENY_NAMES {
        assert_eq!(number(n), Some(*nr), "{n}");
    }
}
