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

/// The names of the overseer's default denylist (spec 2026-11-03 §7), with the numbers they
/// must carry. `setns`, `clone3`, `clone` and `unshare` are not here: the generated program
/// gives them a rule of their own.
const DEFAULT_DENY_NAMES: &[(&str, u32)] = &[
    ("ptrace", 101),
    ("uselib", 134),
    ("sysfs", 139),
    ("modify_ldt", 154),
    ("pivot_root", 155),
    ("_sysctl", 156),
    ("adjtimex", 159),
    ("acct", 163),
    ("settimeofday", 164),
    ("mount", 165),
    ("umount2", 166),
    ("swapon", 167),
    ("swapoff", 168),
    ("reboot", 169),
    ("iopl", 172),
    ("ioperm", 173),
    ("create_module", 174),
    ("init_module", 175),
    ("delete_module", 176),
    ("get_kernel_syms", 177),
    ("query_module", 178),
    ("nfsservctl", 180),
    ("clock_settime", 227),
    ("kexec_load", 246),
    ("add_key", 248),
    ("request_key", 249),
    ("keyctl", 250),
    ("perf_event_open", 298),
    ("clock_adjtime", 305),
    ("process_vm_readv", 310),
    ("process_vm_writev", 311),
    ("finit_module", 313),
    ("kexec_file_load", 320),
    ("bpf", 321),
    ("userfaultfd", 323),
    ("open_tree", 428),
    ("move_mount", 429),
    ("fsopen", 430),
    ("fsconfig", 431),
    ("fsmount", 432),
    ("fspick", 433),
    ("mount_setattr", 442),
];

#[test]
fn the_default_denylist_names_are_in_the_table_with_their_numbers() {
    for (n, nr) in DEFAULT_DENY_NAMES {
        assert_eq!(number(n), Some(*nr), "{n}");
        assert_eq!(name(*nr), Some(*n), "{nr}");
    }
}

#[test]
fn the_default_denylist_names_match_the_core_numbers() {
    let numbers: Vec<u32> = DEFAULT_DENY_NAMES.iter().map(|(_, nr)| *nr).collect();
    let mut core: Vec<u32> = qinit_overseer_core::DEFAULT_DENY.to_vec();
    core.sort_unstable();
    let mut named = numbers;
    named.sort_unstable();
    assert_eq!(
        named, core,
        "the documented names and the core's numbers differ"
    );
}

#[test]
fn the_calls_with_their_own_rule_are_named_by_the_core_constants() {
    use qinit_overseer_core::{NR_CLONE, NR_CLONE3, NR_SETNS, NR_UNSHARE};
    assert_eq!(number("clone"), Some(NR_CLONE));
    assert_eq!(number("unshare"), Some(NR_UNSHARE));
    assert_eq!(number("setns"), Some(NR_SETNS));
    assert_eq!(number("clone3"), Some(NR_CLONE3));
}
