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
fn a_pid_namespace_rearms_after_the_fork() {
    let mut spec = minimal();
    spec.ns = 0b00011; // mount + pid
    let s = steps(&spec);
    let flags = 0x0002_0000 | 0x2000_0000;
    assert_eq!(
        &s[..12],
        &[
            Step::Setsid,
            Step::ArmDeadline(1000),
            Step::OpenStdin,
            Step::OpenStdout,
            Step::OpenStderr,
            Step::Umask(0o27),
            Step::RlimitCore0,
            Step::Unshare(flags),
            Step::MountSlaveRoot,
            Step::MountTmp,
            Step::Fork,
            Step::RearmDeadline,
        ]
    );
    assert!(!s.contains(&Step::LoopbackUp));
}

#[test]
fn no_pid_namespace_means_no_rearm() {
    let mut spec = minimal();
    spec.ns = 0b00100;
    assert!(!steps(&spec).contains(&Step::RearmDeadline));
}

#[test]
fn the_deadline_precedes_every_output() {
    let mut spec = minimal();
    spec.ns = 0b11111;
    spec.ready = Some(7);
    let s = steps(&spec);
    let arm = pos(&s, Step::ArmDeadline(1000));
    assert!(arm < pos(&s, Step::OpenStdin));
    assert!(arm < pos(&s, Step::OpenStdout));
    assert!(arm < pos(&s, Step::OpenStderr));
    assert!(arm < pos(&s, Step::RouteReady(7)));
    assert_eq!(arm, 1, "only setsid comes before the deadline");
}

#[test]
fn outputs_and_rlimits_precede_every_unshare() {
    let mut spec = minimal();
    spec.ns = 0b11111;
    spec.rlimits[7] = Some(64);
    let s = steps(&spec);
    let unshare = s
        .iter()
        .position(|x| matches!(x, Step::Unshare(_)))
        .expect("an unshare");
    for early in [
        Step::OpenStdin,
        Step::OpenStdout,
        Step::OpenStderr,
        Step::Umask(0o27),
        Step::Rlimit(7, 64),
        Step::RlimitCore0,
    ] {
        assert!(pos(&s, early) < unshare, "{early:?}");
    }
}

#[test]
fn mount_without_paths_keeps_the_host_copy() {
    let mut spec = minimal();
    spec.ns = 1;
    let s = steps(&spec);
    assert!(pos(&s, Step::MountSlaveRoot) < pos(&s, Step::MountTmp));
    // With a list the view builds /tmp itself.
    spec.paths = "ro:/bin";
    spec.argv = "/bin/true";
    let s = steps(&spec);
    assert!(s.contains(&Step::MountSlaveRoot) && !s.contains(&Step::MountTmp));
}

#[test]
fn loopback_follows_every_namespace_step() {
    let mut spec = minimal();
    spec.ns = 0b11111;
    let s = steps(&spec);
    let lo = pos(&s, Step::LoopbackUp);
    for x in [
        Step::MountSlaveRoot,
        Step::MountTmp,
        Step::Fork,
        Step::RearmDeadline,
    ] {
        assert!(pos(&s, x) < lo, "{x:?}");
    }
    assert!(
        s.iter()
            .position(|x| matches!(x, Step::Unshare(_)))
            .unwrap()
            < lo
    );
    assert!(lo < pos(&s, Step::Setgid));
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
    spec.argv = "/etc/x";
    spec.ns = 1;
    spec.seccomp = 1;
    let s = steps(&spec);
    let i = pos(&s, Step::LandlockRuleset);
    assert_eq!(
        &s[i..i + 6],
        &[
            Step::LandlockRuleset,
            Step::LandlockViewRules,
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
    assert!(!s.contains(&Step::LandlockViewRules));
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
    spec.argv = "/etc/x";
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
            .map(|i| format!("ro:/p{i:02}"))
            .collect::<Vec<_>>()
            .join("\0")
            .into_boxed_str(),
    );
    let mut spec = minimal();
    spec.caps = (1u64 << 41) - 1;
    spec.paths = paths;
    spec.argv = "/p00/x";
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

fn listed() -> ReqSpec {
    ReqSpec {
        ns: 0b00011,
        argv: "/etc/x",
        paths: "ro:/etc\0rw:/run/x\0ro:/usr",
        ..minimal()
    }
}

fn is_view(x: &Step) -> bool {
    matches!(
        x,
        Step::ViewRoot
            | Step::ViewDev
            | Step::ViewTmp
            | Step::ViewEntry(_)
            | Step::ViewPivot
            | Step::ViewSeal
    )
}

#[test]
fn view_steps_follow_the_fork_and_precede_the_credentials() {
    let s = steps(&listed());
    let first = s.iter().position(is_view).unwrap();
    let last = s.iter().rposition(is_view).unwrap();
    assert!(pos(&s, Step::RearmDeadline) < first);
    assert!(last < pos(&s, Step::Setgroups));
    assert!(last < pos(&s, Step::LandlockRuleset));
    assert_eq!(s[first], Step::ViewRoot);
    assert_eq!(
        &s[first..first + 3],
        &[Step::ViewRoot, Step::ViewDev, Step::ViewTmp]
    );
}

#[test]
fn the_pivot_follows_every_entry_and_precedes_the_seal() {
    let s = steps(&listed());
    for i in 0..3 {
        assert!(pos(&s, Step::ViewEntry(i)) < pos(&s, Step::ViewPivot));
    }
    assert!(pos(&s, Step::ViewPivot) < pos(&s, Step::ViewSeal));
    assert!(pos(&s, Step::ViewTmp) < pos(&s, Step::ViewEntry(0)));
    assert!(pos(&s, Step::ViewEntry(0)) < pos(&s, Step::ViewEntry(1)));
}

#[test]
fn one_view_entry_per_path() {
    let s = steps(&listed());
    let entries: Vec<_> = s
        .iter()
        .filter(|x| matches!(x, Step::ViewEntry(_)))
        .collect();
    assert_eq!(
        entries,
        [
            &Step::ViewEntry(0),
            &Step::ViewEntry(1),
            &Step::ViewEntry(2)
        ]
    );
    // Landlock follows the pivot, one rule per entry.
    assert!(pos(&s, Step::ViewSeal) < pos(&s, Step::LandlockRuleset));
}

#[test]
fn no_view_without_a_list() {
    for ns in [0, 1, 0b00011, 0b11111] {
        let mut spec = minimal();
        spec.ns = ns;
        assert!(!steps(&spec).iter().any(is_view), "ns {ns:#b}");
    }
}

#[test]
fn landlock_view_rules_iff_a_list() {
    let s = steps(&listed());
    assert!(pos(&s, Step::LandlockRuleset) < pos(&s, Step::LandlockViewRules));
    assert!(pos(&s, Step::LandlockViewRules) < pos(&s, Step::LandlockRule(0)));
    assert!(pos(&s, Step::LandlockRule(2)) < pos(&s, Step::LandlockRestrict));
    assert!(!steps(&minimal()).contains(&Step::LandlockViewRules));
}

fn userns() -> ReqSpec {
    ReqSpec {
        ns: 0b11_1111,
        user: "svc",
        ..minimal()
    }
}

fn is_user_step(x: &Step) -> bool {
    matches!(
        x,
        Step::ProcSelf | Step::ClearGroups | Step::UserNamespace | Step::UnshareOwned(_)
    )
}

#[test]
fn user_steps_iff_the_bit() {
    assert!(!steps(&minimal()).iter().any(is_user_step));
    let mut spec = minimal();
    spec.ns = 0b01_1111;
    assert!(!steps(&spec).iter().any(is_user_step));
    for ns in [32, 0b11_1111, 32 | 1, 32 | 16] {
        spec.ns = ns;
        let s = steps(&spec);
        for want in [Step::ProcSelf, Step::ClearGroups, Step::UserNamespace] {
            assert_eq!(s.iter().filter(|x| **x == want).count(), 1, "{want:?}");
        }
        assert_eq!(
            s.iter()
                .filter(|x| matches!(x, Step::UnshareOwned(_)))
                .count(),
            1
        );
    }
}

#[test]
fn clear_groups_precedes_the_user_namespace_which_precedes_the_owned_unshare() {
    let s = steps(&userns());
    let owned = s
        .iter()
        .position(|x| matches!(x, Step::UnshareOwned(_)))
        .unwrap();
    assert!(pos(&s, Step::ClearGroups) < pos(&s, Step::UserNamespace));
    assert!(pos(&s, Step::UserNamespace) < owned);
    // Every view step and the host-owned unshare precede the user namespace.
    assert!(pos(&s, Step::RearmDeadline) < pos(&s, Step::ClearGroups));
    assert!(owned < pos(&s, Step::LoopbackUp));
    assert!(owned < pos(&s, Step::Setgid));
    // No setgroups: the groups were cleared in the host.
    assert!(!s.contains(&Step::Setgroups));
}

#[test]
fn net_uts_ipc_move_to_the_owned_unshare() {
    let (ns, uts, ipc, net) = (
        0x0002_0000_u32,
        0x0400_0000_u32,
        0x0800_0000_u32,
        0x4000_0000_u32,
    );
    let pid = 0x2000_0000_u32;
    let s = steps(&userns());
    assert!(s.contains(&Step::Unshare(ns | pid)));
    assert!(s.contains(&Step::UnshareOwned(ns | uts | ipc | net)));
    // Without the mount and pid bits there is no host-owned unshare at all.
    let mut spec = minimal();
    spec.ns = 32 | 16;
    let s = steps(&spec);
    assert!(!s.iter().any(|x| matches!(x, Step::Unshare(_))));
    assert!(s.contains(&Step::UnshareOwned(net)));
    // Without the user bit the old arrangement stands.
    spec.ns = 16 | 8;
    let s = steps(&spec);
    assert!(s.contains(&Step::Unshare(net | uts)));
    assert!(!s.iter().any(|x| matches!(x, Step::UnshareOwned(_))));
}

#[test]
fn proc_self_precedes_the_pivot() {
    let mut spec = userns();
    spec.argv = "/etc/x";
    spec.paths = "ro:/etc";
    let s = steps(&spec);
    assert!(pos(&s, Step::ProcSelf) < pos(&s, Step::ViewPivot));
    assert!(pos(&s, Step::ViewEntry(0)) < pos(&s, Step::ProcSelf));
    assert!(pos(&s, Step::ViewSeal) < pos(&s, Step::ClearGroups));
    // Without a view the descriptor is still opened, before the user namespace.
    let s = steps(&userns());
    assert!(pos(&s, Step::ProcSelf) < pos(&s, Step::ClearGroups));
}
