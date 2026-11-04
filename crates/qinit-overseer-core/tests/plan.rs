// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The launch plan: the step list a request resolves to.
mod common;

use common::*;
use qinit_overseer_core::*;

fn steps(spec: &ReqSpec) -> Vec<Step> {
    let b = build(spec);
    assert_eq!(decode(&b), Ok(()), "the request must be valid");
    let mut out = [Step::Exec; MAX_STEPS];
    let n = plan(&b, &mut out);
    out[..n].to_vec()
}

fn pos(s: &[Step], x: Step) -> usize {
    s.iter()
        .position(|y| *y == x)
        .unwrap_or_else(|| panic!("{x:?} missing from {s:?}"))
}

fn drops(from: u32, to: u32) -> impl Iterator<Item = Step> {
    (from..=to).map(Step::DropBounding)
}

#[test]
fn the_plan_of_a_minimal_request_is_the_fixed_skeleton() {
    let mut want = vec![
        Step::Setsid,
        Step::ArmDeadline(1000),
        Step::OpenStdin,
        Step::OpenStdout,
        Step::OpenStderr,
        Step::Umask(0o27),
        Step::RlimitCore0,
        Step::Setgroups,
        Step::Setgid,
        Step::Securebits(16),
    ];
    // CAP_SETPCAP (8) goes last among the drops.
    want.extend(drops(0, 7));
    want.extend(drops(9, 40));
    want.push(Step::DropBounding(8));
    want.extend([
        Step::Setuid,
        Step::Capset,
        Step::NoNewPrivs,
        Step::Chdir,
        Step::CloseRange,
        Step::Exec,
    ]);
    assert_eq!(steps(&minimal()), want);
}

#[test]
fn a_pid_namespace_puts_fork_before_the_deadline_and_outputs() {
    let mut spec = minimal();
    spec.ns = 0b00011; // mount + pid
    let s = steps(&spec);
    let flags = 0x0002_0000 | 0x2000_0000;
    assert_eq!(
        &s[..5],
        &[
            Step::Setsid,
            Step::Unshare(flags),
            Step::MountSlaveRoot,
            Step::MountTmp,
            Step::Fork,
        ]
    );
    assert!(pos(&s, Step::Fork) < pos(&s, Step::ArmDeadline(1000)));
    assert!(pos(&s, Step::ArmDeadline(1000)) < pos(&s, Step::OpenStdout));
    assert!(!s.contains(&Step::LoopbackUp));
}

#[test]
fn a_network_namespace_brings_loopback_up() {
    let mut spec = minimal();
    spec.ns = 0b11100; // ipc + uts + net
    let s = steps(&spec);
    let flags = 0x0800_0000 | 0x0400_0000 | 0x4000_0000;
    assert!(s.contains(&Step::Unshare(flags)));
    assert!(s.contains(&Step::LoopbackUp));
    assert!(!s.contains(&Step::Fork) && !s.contains(&Step::MountTmp));
    assert!(pos(&s, Step::Unshare(flags)) < pos(&s, Step::LoopbackUp));
}

#[test]
fn caps_are_raised_after_setuid_and_not_dropped() {
    let mut spec = minimal();
    spec.caps = (1 << 10) | (1 << 12);
    let s = steps(&spec);
    assert!(!s.contains(&Step::DropBounding(10)) && !s.contains(&Step::DropBounding(12)));
    for c in (0..=40).filter(|c| *c != 10 && *c != 12) {
        assert!(s.contains(&Step::DropBounding(c)), "drop {c}");
    }
    assert!(pos(&s, Step::Setuid) < pos(&s, Step::Capset));
    assert!(pos(&s, Step::Capset) < pos(&s, Step::AmbientRaise(10)));
    assert!(pos(&s, Step::AmbientRaise(10)) < pos(&s, Step::AmbientRaise(12)));
    assert!(pos(&s, Step::DropBounding(8)) < pos(&s, Step::Setuid));
    assert!(!s.contains(&Step::AmbientRaise(11)));
}

#[test]
fn a_high_capability_comes_from_the_second_word() {
    let mut spec = minimal();
    spec.caps = 1 << 40;
    let s = steps(&spec);
    assert!(s.contains(&Step::AmbientRaise(40)) && !s.contains(&Step::DropBounding(40)));
    assert!(s.contains(&Step::DropBounding(39)));
}

#[test]
fn landlock_entries_follow_nnp_and_precede_seccomp() {
    let mut spec = minimal();
    spec.paths = "ro:/etc\0rw:/run/x\0ro:/usr";
    spec.seccomp = 1;
    let s = steps(&spec);
    let i = pos(&s, Step::LandlockRuleset);
    assert_eq!(
        &s[i..i + 5],
        &[
            Step::LandlockRuleset,
            Step::LandlockRule(0),
            Step::LandlockRule(1),
            Step::LandlockRule(2),
            Step::LandlockRestrict,
        ]
    );
    assert!(pos(&s, Step::NoNewPrivs) < i);
    assert!(
        pos(&s, Step::Chdir) < i,
        "chdir is done as the user, before the ruleset"
    );
    assert!(pos(&s, Step::LandlockRestrict) < pos(&s, Step::Seccomp));
    assert!(pos(&s, Step::Seccomp) < pos(&s, Step::CloseRange));
}

#[test]
fn no_landlock_list_means_no_landlock_steps() {
    let s = steps(&minimal());
    assert!(!s.contains(&Step::LandlockRuleset) && !s.contains(&Step::LandlockRestrict));
    assert!(!s.contains(&Step::Seccomp));
}

#[test]
fn pdeathsig_follows_the_last_credential_step() {
    let mut spec = minimal();
    spec.flags = FLAG_DIE_WITH_PARENT;
    spec.caps = 1 << 10;
    let s = steps(&spec);
    assert!(pos(&s, Step::AmbientRaise(10)) < pos(&s, Step::Pdeathsig));
    assert!(pos(&s, Step::Pdeathsig) < pos(&s, Step::NoNewPrivs));
    assert!(!steps(&minimal()).contains(&Step::Pdeathsig));
}

#[test]
fn nnp_off_omits_the_step_and_securebits_carry_the_preset() {
    let mut spec = minimal();
    spec.nnp = 0;
    spec.securebits = 1;
    let s = steps(&spec);
    assert!(!s.contains(&Step::NoNewPrivs));
    assert!(s.contains(&Step::Securebits(16 | 1)));
    spec.securebits = 2;
    assert!(steps(&spec).contains(&Step::Securebits(16 | 1 | 2)));
}

#[test]
fn rlimits_umask_ready_and_deadline_come_from_the_request() {
    let mut spec = minimal();
    spec.rlimits[7] = Some(64);
    spec.umask = 0o077;
    spec.deadline_ms = 250;
    spec.ready = Some(7);
    let s = steps(&spec);
    for x in [
        Step::Rlimit(7, 64),
        Step::Umask(0o077),
        Step::ArmDeadline(250),
        Step::RouteReady(7),
        Step::RlimitCore0,
    ] {
        assert!(s.contains(&x), "{x:?}");
    }
    assert!(
        !steps(&minimal())
            .iter()
            .any(|x| matches!(x, Step::Rlimit(..) | Step::RouteReady(_)))
    );
}

#[test]
fn exec_is_last_and_occurs_once() {
    let mut spec = minimal();
    spec.paths = "ro:/etc";
    spec.seccomp = 1;
    spec.ns = 0b11111;
    let s = steps(&spec);
    assert_eq!(s.last(), Some(&Step::Exec));
    assert_eq!(s.iter().filter(|x| **x == Step::Exec).count(), 1);
    assert_eq!(s[s.len() - 2], Step::CloseRange);
}

#[test]
fn the_plan_never_exceeds_max_steps() {
    let paths: &'static str = Box::leak(
        (0..64)
            .map(|i| format!("ro:/p{i}"))
            .collect::<Vec<_>>()
            .join("\0")
            .into_boxed_str(),
    );
    let mut spec = minimal();
    spec.caps = (1u64 << 41) - 1;
    spec.paths = paths;
    spec.seccomp = 1;
    spec.ns = 0b11111;
    spec.flags = FLAG_DIE_WITH_PARENT;
    spec.rlimits = std::array::from_fn(|r| (r != 4).then_some(if r == 7 { 10 } else { 1 }));
    spec.ready = Some(5);
    spec.stdout = Stream::Fd(6);
    spec.nnp = 0;
    spec.caps |= 1 << 21;
    let s = steps(&spec);
    assert!(s.len() < MAX_STEPS, "{}", s.len());
    assert_eq!(
        s.iter()
            .filter(|x| matches!(x, Step::LandlockRule(_)))
            .count(),
        64
    );
    assert_eq!(
        s.iter()
            .filter(|x| matches!(x, Step::AmbientRaise(_)))
            .count(),
        41
    );
    assert!(!s.iter().any(|x| matches!(x, Step::DropBounding(_))));
}

#[test]
fn plan_emits_one_step_per_set_limit_in_resource_order() {
    let mut spec = minimal();
    spec.rlimits[14] = Some(7);
    spec.rlimits[3] = Some(u64::MAX);
    spec.rlimits[7] = Some((1 << 32) + 5);
    let s = steps(&spec);
    let limits: Vec<Step> = s
        .iter()
        .copied()
        .filter(|x| matches!(x, Step::Rlimit(..) | Step::RlimitCore0))
        .collect();
    assert_eq!(
        limits,
        [
            Step::Rlimit(3, u64::MAX),
            Step::Rlimit(7, (1 << 32) + 5),
            Step::Rlimit(14, 7),
            Step::RlimitCore0
        ]
    );
    assert!(pos(&s, Step::Umask(0o027)) < pos(&s, Step::Rlimit(3, u64::MAX)));
    assert!(pos(&s, Step::RlimitCore0) < pos(&s, Step::Setgroups));
}

#[test]
fn plan_without_limits_has_only_core0() {
    let s = steps(&minimal());
    assert!(!s.iter().any(|x| matches!(x, Step::Rlimit(..))));
    assert!(s.contains(&Step::RlimitCore0));
}
