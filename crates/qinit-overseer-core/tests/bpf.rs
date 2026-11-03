// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The seccomp program generator, checked by running its output on a small BPF interpreter.
use qinit_overseer_core::*;

const EPERM: u32 = RET_ERRNO | 1;
const ENOSYS: u32 = RET_ERRNO | 0x26;

fn build(mode: u32, list: &[u32]) -> Vec<Insn> {
    let mut out = [Insn {
        code: 0,
        jt: 0,
        jf: 0,
        k: 0,
    }; MAX_BPF];
    let n = program(mode, list, &mut out);
    out[..n].to_vec()
}

/// Runs `p` on a system call with `arch`, number `nr` and first argument `arg0`.
fn run(p: &[Insn], arch: u32, nr: u32, arg0: u32) -> u32 {
    let (mut pc, mut a) = (0usize, 0u32);
    loop {
        let i = p[pc];
        match i.code {
            0x20 => {
                a = match i.k {
                    0 => nr,
                    4 => arch,
                    16 => arg0,
                    k => panic!("load of offset {k}"),
                };
                pc += 1;
            }
            0x15 => pc += 1 + usize::from(if a == i.k { i.jt } else { i.jf }),
            0x45 => pc += 1 + usize::from(if a & i.k != 0 { i.jt } else { i.jf }),
            0x35 => pc += 1 + usize::from(if a >= i.k { i.jt } else { i.jf }),
            0x06 => return i.k,
            c => panic!("opcode {c:#x}"),
        }
    }
}

fn verdict(p: &[Insn], nr: u32, arg0: u32) -> u32 {
    run(p, AUDIT_ARCH_X86_64, nr, arg0)
}

#[test]
fn the_arch_check_comes_first_and_kills_other_archs() {
    for mode in 1..=3 {
        let p = build(mode, &[101]);
        assert_eq!(
            p[0],
            Insn {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 4
            }
        );
        assert_eq!(
            p[1],
            Insn {
                code: 0x15,
                jt: 1,
                jf: 0,
                k: AUDIT_ARCH_X86_64
            }
        );
        assert_eq!(
            p[2],
            Insn {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: RET_KILL_PROCESS
            }
        );
        assert_eq!(
            p[3],
            Insn {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0
            }
        );
        for arch in [0x4000_0028, 0x4000_00b7, 0, 0xC000_003F] {
            assert_eq!(
                run(&p, arch, 101, 0),
                RET_KILL_PROCESS,
                "mode {mode} arch {arch:#x}"
            );
            assert_eq!(run(&p, arch, 0, 0), RET_KILL_PROCESS);
        }
    }
}

#[test]
fn a_denylist_program_returns_eperm_for_listed_numbers_only() {
    let list = [101, 310, 0, 511];
    for mode in [1, 2] {
        let p = build(mode, &list);
        for nr in list {
            assert_eq!(verdict(&p, nr, 0), EPERM, "listed {nr}");
        }
        for nr in [1, 2, 39, 60, 102, 231, 435 + 1, 500] {
            assert_eq!(verdict(&p, nr, 0), RET_ALLOW, "unlisted {nr}");
        }
    }
}

#[test]
fn an_allowlist_program_allows_listed_numbers_only() {
    let list = [0, 1, 231, 511];
    let p = build(3, &list);
    for nr in list {
        assert_eq!(verdict(&p, nr, 0), RET_ALLOW, "listed {nr}");
    }
    for nr in [2, 56, 101, 272, 308, 435, 510] {
        assert_eq!(verdict(&p, nr, 0), EPERM, "unlisted {nr}");
    }
    assert_eq!(verdict(&p, 0x4000_0000, 0), EPERM);
}

#[test]
fn clone_with_a_new_namespace_flag_is_denied_and_clone3_is_enosys() {
    for mode in [1, 2] {
        let p = build(mode, &[101]);
        for flag in [
            0x0002_0000,
            0x0400_0000,
            0x0800_0000,
            0x1000_0000,
            0x2000_0000,
            0x4000_0000,
            0x0200_0000,
            0x80,
        ] {
            assert_eq!(verdict(&p, NR_CLONE, flag | 0x11), EPERM, "clone {flag:#x}");
            assert_eq!(verdict(&p, NR_UNSHARE, flag), EPERM, "unshare {flag:#x}");
        }
        // Plain thread creation and fork stay possible.
        assert_eq!(verdict(&p, NR_CLONE, 0x003d_0f00), RET_ALLOW);
        assert_eq!(verdict(&p, NR_CLONE, 0x11), RET_ALLOW);
        assert_eq!(verdict(&p, NR_UNSHARE, 0x0000_0200), RET_ALLOW);
        assert_eq!(verdict(&p, NR_SETNS, 0), EPERM);
        assert_eq!(verdict(&p, NR_CLONE3, 0), ENOSYS);
        assert_eq!(
            CLONE_NEW_ANY,
            0x0002_0000
                | 0x0400_0000
                | 0x0800_0000
                | 0x1000_0000
                | 0x2000_0000
                | 0x4000_0000
                | 0x0200_0000
                | 0x80
        );
    }
}

#[test]
fn an_allowlist_does_not_special_case_clone() {
    let p = build(3, &[NR_CLONE, 0]);
    assert_eq!(verdict(&p, NR_CLONE, 0x2000_0000), RET_ALLOW);
    assert_eq!(verdict(&p, NR_CLONE3, 0), EPERM);
}

#[test]
fn a_denylist_kills_the_x32_number_range() {
    let p = build(1, &[]);
    for nr in [0x4000_0000, 0x4000_0000 + 101, 0x7fff_ffff, u32::MAX] {
        assert_eq!(verdict(&p, nr, 0), RET_KILL_PROCESS, "{nr:#x}");
    }
    assert_eq!(verdict(&p, 0x3fff_ffff, 0), RET_ALLOW);
}

#[test]
fn every_jump_target_is_inside_the_program() {
    for (mode, list) in [
        (1, vec![]),
        (2, vec![1, 2, 3]),
        (3, vec![0]),
        (3, (0..576).collect::<Vec<_>>()),
        (2, (0..576).collect::<Vec<_>>()),
    ] {
        let p = build(mode, &list);
        assert!(p.len() <= MAX_BPF);
        assert_eq!(p.last().map(|i| i.code), Some(0x06), "ends in RET");
        for (pc, i) in p.iter().enumerate() {
            assert!(
                matches!(i.code, 0x20 | 0x15 | 0x45 | 0x35 | 0x06),
                "opcode {:#x}",
                i.code
            );
            if matches!(i.code, 0x15 | 0x45 | 0x35) {
                assert!(
                    pc + 1 + usize::from(i.jt) < p.len() && pc + 1 + usize::from(i.jf) < p.len()
                );
            }
        }
    }
}

#[test]
fn the_longest_programs_fit_max_bpf() {
    let list: Vec<u32> = (0..u32::try_from(MAX_FILTER_LIST).unwrap()).collect();
    assert_eq!(build(2, &list).len(), 4 + 16 + 2 * list.len() + 1);
    assert_eq!(build(3, &list).len(), 4 + 2 * list.len() + 1);
    assert_eq!(MAX_BPF, 4 + 2 * MAX_FILTER_LIST + 16 + 1);
    assert!(DEFAULT_DENY.len() + MAX_SECCOMP_LIST <= MAX_FILTER_LIST);
}

#[test]
fn the_default_denylist_has_no_duplicates_and_is_sorted() {
    assert!(
        DEFAULT_DENY.windows(2).all(|w| w[0] < w[1]),
        "{DEFAULT_DENY:?}"
    );
    assert!(DEFAULT_DENY.iter().all(|nr| *nr < 512));
    for special in [NR_CLONE, NR_UNSHARE, NR_SETNS, NR_CLONE3] {
        assert!(
            !DEFAULT_DENY.contains(&special),
            "{special} has its own block"
        );
    }
    assert_eq!(DEFAULT_DENY.len(), 42);
}

#[test]
fn the_default_program_denies_every_default_entry() {
    let p = build(1, &DEFAULT_DENY);
    for nr in &DEFAULT_DENY {
        assert_eq!(verdict(&p, *nr, 0), EPERM, "{nr}");
    }
    for nr in [0, 1, 2, 3, 9, 12, 39, 57, 59, 60, 231, 257, 262] {
        assert_eq!(verdict(&p, nr, 0), RET_ALLOW, "{nr}");
    }
}
