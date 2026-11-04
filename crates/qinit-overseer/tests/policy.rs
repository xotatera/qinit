// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The proved policy check over a database with a policy table.
use qinit_db::{Model, Policy, PolicyRule, Userns, write};
use qinit_overseer::request::{RequestSpec, Seccomp, UserMap};
use qinit_overseer_core::{Denial, check_policy};

fn db(policy: Option<Policy>) -> Vec<u8> {
    write(&Model {
        policy,
        ..Model::default()
    })
    .expect("writes")
}

fn rule(pattern: &str) -> PolicyRule {
    PolicyRule {
        pattern: pattern.into(),
        users: None,
        caps_max: 0,
        require_nnp: false,
        require_seccomp: false,
        allow_userns: Userns::No,
        rlimits: [None; 16],
    }
}

#[allow(clippy::unnecessary_wraps)] // the database takes an optional policy
fn policy(allow: bool, rules: Vec<PolicyRule>) -> Option<Policy> {
    Some(Policy {
        allow_by_default: allow,
        ceiling: [None; 16],
        rules,
    })
}

fn req(f: impl FnOnce(&mut RequestSpec)) -> Vec<u8> {
    let mut r = RequestSpec {
        argv: vec!["/x".into()],
        user: "svc".into(),
        ..RequestSpec::default()
    };
    f(&mut r);
    r.bytes().expect("encodes")
}

/// A request that holds privilege, so that a rule has something to say.
fn root() -> Vec<u8> {
    req(|r| r.user = "root".into())
}

fn check(db: &[u8], name: &str, request: &[u8]) -> Result<(), Denial> {
    check_policy(db, name.as_bytes(), request)
}

#[test]
fn no_policy_denies() {
    assert_eq!(check(&db(None), "a", &root()), Err(Denial::NoPolicy));
    // Even a request that needs no rule: there is nothing to judge it by.
    assert_eq!(check(&db(None), "a", &req(|_| ())), Err(Denial::NoPolicy));
}

#[test]
fn frame_rules_never_match_a_run_name() {
    let d = db(policy(false, vec![rule("backup")]));
    assert_eq!(check(&d, "backup", &root()), Ok(()));
    assert_eq!(check(&d, "~backup", &root()), Err(Denial::Default));
}

#[test]
fn a_star_rule_matches_a_run_name() {
    let d = db(policy(false, vec![rule("*")]));
    assert_eq!(check(&d, "~backup", &root()), Ok(()));
    let d = db(policy(false, vec![rule("~*")]));
    assert_eq!(check(&d, "~backup", &root()), Ok(()));
    assert_eq!(check(&d, "backup", &root()), Err(Denial::Default));
}

#[test]
fn an_unprivileged_request_needs_no_rule() {
    let d = db(policy(false, vec![]));
    assert_eq!(check(&d, "~job", &req(|_| ())), Ok(()));
    // Not even a matching rule that would refuse it is consulted.
    let mut r = rule("~job");
    r.users = Some(vec!["other".into()]);
    let d = db(policy(false, vec![r]));
    assert_eq!(check(&d, "~job", &req(|_| ())), Ok(()));
}

#[test]
fn limits_above_the_head_ceiling_are_privileged() {
    let mut ceiling = [None; 16];
    ceiling[7] = Some(1024);
    let p = Some(Policy {
        allow_by_default: false,
        ceiling,
        rules: vec![],
    });
    let d = db(p);
    assert_eq!(
        check(&d, "~job", &req(|r| r.rlimits[7] = Some(1024))),
        Ok(())
    );
    assert_eq!(
        check(&d, "~job", &req(|r| r.rlimits[7] = Some(1025))),
        Err(Denial::Default)
    );
    // A limit with no ceiling at all is above it.
    assert_eq!(
        check(&d, "~job", &req(|r| r.rlimits[9] = Some(1))),
        Err(Denial::Default)
    );
}

#[test]
fn the_user_clause() {
    let mut r = rule("*");
    r.users = Some(vec!["svc".into(), "other".into()]);
    let d = db(policy(false, vec![r]));
    let privileged = |u: &str| {
        req(|q| {
            q.user = u.into();
            q.nnp = false;
            q.caps = 1 << 21;
        })
    };
    assert_eq!(check(&d, "a", &privileged("other")), Err(Denial::Caps));
    assert_eq!(check(&d, "a", &privileged("nobody")), Err(Denial::User));
    let mut r = rule("*");
    r.users = Some(vec![]);
    let d = db(policy(false, vec![r]));
    assert_eq!(check(&d, "a", &root()), Err(Denial::User));
}

#[test]
fn the_caps_clause() {
    let mut r = rule("*");
    r.caps_max = (1 << 10) | (1 << 40);
    let d = db(policy(false, vec![r]));
    let with = |caps: u64| req(|q| q.caps = caps);
    assert_eq!(check(&d, "a", &with((1 << 10) | (1 << 40))), Ok(()));
    assert_eq!(check(&d, "a", &with(1 << 11)), Err(Denial::Caps));
    assert_eq!(check(&d, "a", &with(1 << 39)), Err(Denial::Caps));
}

#[test]
fn the_nnp_and_seccomp_clauses() {
    let mut r = rule("*");
    r.require_nnp = true;
    let d = db(policy(false, vec![r]));
    assert_eq!(check(&d, "a", &req(|q| q.user = "root".into())), Ok(()));
    assert_eq!(check(&d, "a", &req(|q| q.nnp = false)), Err(Denial::Nnp));
    let mut r = rule("*");
    r.require_seccomp = true;
    let d = db(policy(false, vec![r]));
    assert_eq!(check(&d, "a", &root()), Err(Denial::Seccomp));
    assert_eq!(
        check(
            &d,
            "a",
            &req(|q| {
                q.user = "root".into();
                q.seccomp = Seccomp::Default;
            })
        ),
        Ok(())
    );
}

#[test]
fn the_userns_clause() {
    let user_ns = |map: UserMap| {
        req(move |q| {
            q.ns = 32;
            q.user_map = map;
        })
    };
    for (allow, own, range) in [
        (Userns::No, false, false),
        (Userns::Own, true, false),
        (Userns::Range, true, true),
    ] {
        let mut r = rule("*");
        r.allow_userns = allow;
        let d = db(policy(false, vec![r]));
        let got = |m| check(&d, "a", &user_ns(m));
        assert_eq!(got(UserMap::Own).is_ok(), own, "{allow:?} own");
        assert_eq!(got(UserMap::Range).is_ok(), range, "{allow:?} range");
        if !own {
            assert_eq!(got(UserMap::Own), Err(Denial::Userns));
        }
    }
    // Without a matching rule a user namespace is privilege: the default decides.
    let d = db(policy(false, vec![]));
    assert_eq!(check(&d, "a", &user_ns(UserMap::Own)), Err(Denial::Default));
    let d = db(policy(true, vec![]));
    assert_eq!(check(&d, "a", &user_ns(UserMap::Own)), Ok(()));
}

#[test]
fn the_limit_clause_falls_back_rule_then_head() {
    let mut ceiling = [None; 16];
    ceiling[7] = Some(100);
    ceiling[9] = Some(5);
    let mut r = rule("*");
    r.rlimits[7] = Some(1000);
    let d = db(Some(Policy {
        allow_by_default: false,
        ceiling,
        rules: vec![r],
    }));
    let with = |nofile: u64, a: u64| {
        req(move |q| {
            q.rlimits[7] = Some(nofile);
            q.rlimits[9] = Some(a);
        })
    };
    assert_eq!(check(&d, "a", &with(1000, 5)), Ok(()));
    assert_eq!(check(&d, "a", &with(1001, 5)), Err(Denial::Limit));
    assert_eq!(check(&d, "a", &with(1000, 6)), Err(Denial::Limit));
}

#[test]
fn the_first_failing_clause_is_reported_in_order() {
    let mut r = rule("*");
    r.users = Some(vec!["other".into()]);
    r.require_nnp = true;
    r.require_seccomp = true;
    let d = db(policy(false, vec![r]));
    let bad = req(|q| {
        q.user = "root".into();
        q.nnp = false;
        q.caps = 1 << 21;
    });
    assert_eq!(check(&d, "a", &bad), Err(Denial::User));
}

#[test]
fn the_first_matching_rule_decides() {
    let mut deny = rule("~j*");
    deny.users = Some(vec!["nobody".into()]);
    let d = db(policy(false, vec![deny, rule("*")]));
    assert_eq!(check(&d, "~job", &root()), Err(Denial::User));
    assert_eq!(check(&d, "other", &root()), Ok(()));
}
