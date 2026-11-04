// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The policy tables: one record per rule and at most one header record.
mod common;

use common::*;
use qinit_db_core::*;

fn tid(t: usize) -> u8 {
    u8::try_from(t).unwrap()
}

fn with_policy(rules: Vec<RuleSpec>) -> DbSpec {
    DbSpec {
        policy: rules,
        policy_head: Some(head()),
        ..minimal_spec()
    }
}

fn rule_consistency(record: u32) -> Result<(), DbError> {
    Err(DbError::Consistency {
        table: tid(T_POLICY),
        record,
    })
}

fn rule_enum(record: u32) -> Result<(), DbError> {
    Err(DbError::Enum {
        table: tid(T_POLICY),
        record,
    })
}

#[test]
fn a_policy_with_rules_and_a_head_is_valid() {
    let mut r = rule("sshd");
    r.users = "sshd\0svc_2-x";
    r.users_any = 0;
    r.caps = (1 << 40) | 1;
    r.require_nnp = 1;
    r.require_seccomp = 1;
    r.allow_userns = 2;
    r.rlimits[7] = Some(4096);
    r.rlimits[0] = Some(u64::MAX);
    let mut spec = with_policy(vec![r, rule("~job@*"), rule("*")]);
    spec.policy_head.as_mut().unwrap().allow = 1;
    spec.policy_head.as_mut().unwrap().rlimits[7] = Some(1024);
    assert_eq!(check(&build(&spec)), Ok(()));
    // No policy at all, and a head without rules, are valid too.
    assert_eq!(check(&build(&minimal_spec())), Ok(()));
    assert_eq!(check(&build(&with_policy(vec![]))), Ok(()));
}

#[test]
fn a_rule_without_a_head_is_consistency() {
    let spec = DbSpec {
        policy: vec![rule("a")],
        policy_head: None,
        ..minimal_spec()
    };
    assert_eq!(check(&build(&spec)), rule_consistency(0));
}

#[test]
fn two_heads_are_count() {
    let spec = with_policy(vec![rule("a")]);
    let db = with(&build(&spec), |w| w[5 + 2 * T_POLICY_HEAD] = 2);
    assert_eq!(check(&db), Err(DbError::Count(tid(T_POLICY_HEAD))));
}

#[test]
fn a_pattern_with_a_slash_is_consistency() {
    for bad in ["a/b", "", "a b", "a?", "a[b]", "é"] {
        let spec = with_policy(vec![rule("ok"), rule(bad)]);
        assert_eq!(check(&build(&spec)), rule_consistency(1), "{bad:?}");
    }
    let long: &'static str = Box::leak("a".repeat(129).into_boxed_str());
    assert_eq!(
        check(&build(&with_policy(vec![rule(long)]))),
        rule_consistency(0)
    );
    let fits: &'static str = Box::leak("a".repeat(128).into_boxed_str());
    assert_eq!(check(&build(&with_policy(vec![rule(fits)]))), Ok(()));
    for ok in ["~backup", "ssh@tty1:x+y.z-w_1", "a*", "*", "~*"] {
        assert_eq!(
            check(&build(&with_policy(vec![rule(ok)]))),
            Ok(()),
            "{ok:?}"
        );
    }
}

#[test]
fn users_any_with_a_list_is_consistency() {
    let mut r = rule("a");
    r.users = "svc";
    assert_eq!(
        check(&build(&with_policy(vec![r.clone()]))),
        rule_consistency(0)
    );
    // Not any, and no users: a rule nobody matches, and valid.
    r.users = "";
    r.users_any = 0;
    assert_eq!(check(&build(&with_policy(vec![r]))), Ok(()));
}

#[test]
fn a_bad_user_name_is_consistency() {
    for bad in ["Root", "0day", "a b", "x".repeat(33).leak(), "ok\0Bad"] {
        let mut r = rule("a");
        r.users = bad;
        r.users_any = 0;
        assert_eq!(
            check(&build(&with_policy(vec![r]))),
            rule_consistency(0),
            "{bad:?}"
        );
    }
}

#[test]
fn allow_userns_3_is_enum() {
    let mut r = rule("a");
    r.allow_userns = 3;
    assert_eq!(check(&build(&with_policy(vec![r]))), rule_enum(0));
    for ok in [0, 1, 2] {
        let mut r = rule("a");
        r.allow_userns = ok;
        assert_eq!(check(&build(&with_policy(vec![r]))), Ok(()));
    }
}

#[test]
fn flags_and_caps_are_bounded() {
    for (f, v) in [
        (P_REQUIRE_NNP, 2),
        (P_REQUIRE_SECCOMP, 2),
        (P_CAPS_HI, 0x200),
    ] {
        let db = with(&build(&with_policy(vec![rule("a")])), |w| {
            let i = at(w, T_POLICY, 0, f);
            w[i] = v;
        });
        assert_eq!(check(&db), rule_enum(0), "word {f}");
    }
    let db = with(&build(&with_policy(vec![])), |w| {
        let i = at(w, T_POLICY_HEAD, 0, PH_ALLOW);
        w[i] = 2;
    });
    assert_eq!(
        check(&db),
        Err(DbError::Enum {
            table: tid(T_POLICY_HEAD),
            record: 0
        })
    );
}

#[test]
fn ceilings_follow_the_node_limit_rules() {
    // Resource 4 (core) never has a limit; nofile 0 and infinity are refused; nice above 40 too.
    let mut bad: Vec<RuleSpec> = Vec::new();
    for (r, v) in [(4, 1), (7, 0), (7, u64::MAX), (13, 41), (14, 100)] {
        let mut x = rule("a");
        x.rlimits[r] = Some(v);
        bad.push(x);
    }
    for x in bad {
        let spec = with_policy(vec![x]);
        let got = check(&build(&spec));
        assert!(
            matches!(
                got,
                Err(DbError::Enum { table, .. } | DbError::Consistency { table, .. }) if table == tid(T_POLICY)
            ),
            "{got:?}"
        );
    }
    let mut ok = rule("a");
    ok.rlimits[13] = Some(40);
    ok.rlimits[14] = Some(99);
    ok.rlimits[7] = Some(1);
    assert_eq!(check(&build(&with_policy(vec![ok]))), Ok(()));
    // The header's ceilings follow the same rules.
    let mut spec = with_policy(vec![]);
    spec.policy_head.as_mut().unwrap().rlimits[7] = Some(0);
    assert!(matches!(
        check(&build(&spec)),
        Err(DbError::Enum { table, .. } | DbError::Consistency { table, .. }) if table == tid(T_POLICY_HEAD)
    ));
}
