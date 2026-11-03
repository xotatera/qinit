// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Credential policy: rules, ceilings, glob matching and file errors.
mod common;

use common::{TempDir, ok};
use qinit_db::Model;
use qinit_frames::error::{Code, Error};
use qinit_frames::policy::{Policy, check, glob_match, load_policy};
use std::path::PathBuf;

fn policy(tag: &str, body: &str) -> Result<Policy, Vec<Error>> {
    let dir = TempDir::new(tag);
    let path = dir.join("policy.toml");
    std::fs::write(&path, body).expect("write");
    load_policy(&path)
}

fn pol(tag: &str, body: &str) -> Policy {
    policy(tag, body).expect("policy loads")
}

fn model(src: &str) -> Model {
    ok(src).model
}

const SSHD: &str = r#"
    [worker.sshd]
    exec = ["/sshd"]
    credentials = { uid = "sshd", caps = ["net_bind_service"], nnp = true }
"#;

const RULE: &str = r#"
    default = "deny"
    [[rule]]
    match = "sshd"
    users = ["sshd"]
    caps_max = ["net_bind_service"]
    require_nnp = true
"#;

#[test]
fn a_worker_within_its_rule_passes() {
    assert_eq!(check(&pol("pass", RULE), &model(SSHD)), Ok(()));
}

#[test]
fn a_user_outside_the_rule_is_a_policy_error() {
    let m = model(&SSHD.replace("\"sshd\", caps", "\"root\", caps"));
    let es = check(&pol("user", RULE), &m).expect_err("refused");
    assert_eq!(es.len(), 1);
    assert_eq!(es[0].code, Code::Policy);
    assert_eq!(es[0].key, "worker.sshd.credentials");
    assert_eq!(es[0].layer, None);
    assert!(es[0].detail.contains("root"), "{}", es[0].detail);
}

#[test]
fn a_capability_above_the_ceiling_is_a_policy_error() {
    let m = model(&SSHD.replace(
        "[\"net_bind_service\"]",
        "[\"net_bind_service\", \"sys_admin\", \"chown\"]",
    ));
    let es = check(&pol("caps", RULE), &m).expect_err("refused");
    assert_eq!(es.len(), 1);
    assert_eq!(es[0].code, Code::Policy);
    assert!(es[0].detail.contains("sys_admin"), "{}", es[0].detail);
    assert!(es[0].detail.contains("chown"), "{}", es[0].detail);
    assert!(
        !es[0].detail.contains("net_bind_service"),
        "{}",
        es[0].detail
    );
}

#[test]
fn nnp_off_where_required_is_a_policy_error() {
    let m = model(&SSHD.replace("nnp = true", "nnp = false"));
    let es = check(&pol("nnp", RULE), &m).expect_err("refused");
    assert_eq!(es.len(), 1);
    assert!(es[0].detail.contains("nnp required"), "{}", es[0].detail);
}

#[test]
fn the_first_matching_rule_wins() {
    let p = pol(
        "first",
        r#"
        default = "deny"
        [[rule]]
        match = "ss*"
        users = ["nobody"]
        [[rule]]
        match = "sshd"
        users = ["sshd"]
        caps_max = ["net_bind_service"]
        "#,
    );
    let es = check(&p, &model(SSHD)).expect_err("first rule refuses");
    assert_eq!(es[0].code, Code::Policy);
}

#[test]
fn glob_star_matches_a_run_and_nothing_else() {
    assert!(glob_match("getty@*", "getty@tty1"));
    assert!(!glob_match("getty@*", "agetty"));
    assert!(!glob_match("getty@*", "agetty@tty1"));
    assert!(glob_match("*", ""));
    assert!(glob_match("*", "anything"));
    assert!(glob_match("a*b*c", "aXXbYYc"));
    assert!(glob_match("a*b*c", "abc"));
    assert!(!glob_match("a*b*c", "aXXbYY"));
    assert!(glob_match("sshd", "sshd"));
    assert!(!glob_match("sshd", "sshd2"));
    assert!(!glob_match("", "x"));
    assert!(glob_match("", ""));
    assert!(glob_match("a.b", "a.b"));
    assert!(!glob_match("a.b", "aXb"));
    assert!(glob_match("**a", "ba"));
    let long = "a".repeat(20_000);
    assert!(!glob_match("*a*a*a*a*b", &long));
}

#[test]
fn no_matching_rule_follows_the_default() {
    let deny = pol("dd", "default = \"deny\"\n");
    let es = check(&deny, &model(SSHD)).expect_err("denied");
    assert_eq!(es[0].code, Code::Policy);
    assert_eq!(es[0].key, "worker.sshd.credentials");
    let allow = pol("da", "default = \"allow\"\n");
    assert_eq!(check(&allow, &model(SSHD)), Ok(()));
}

/// A worker with no `credentials` is unprivileged by contract (not root, no capabilities,
/// no-new-privileges on), so it needs no rule and passes even under `default = "deny"`.
#[test]
fn a_non_root_worker_without_capabilities_needs_no_rule() {
    let m = model("[worker.plain]\ncredentials = { uid = \"svc\" }\nexec = [\"/p\"]\n");
    assert_eq!(check(&pol("nocred", "default = \"deny\"\n"), &m), Ok(()));
    // Also when a rule matches it: there is nothing for the rule to bound.
    let p = pol(
        "nocred2",
        "default = \"deny\"\n[[rule]]\nmatch = \"*\"\nusers = []\nrequire_nnp = true\n",
    );
    assert_eq!(check(&p, &m), Ok(()));
}

#[test]
fn a_root_worker_without_capabilities_still_needs_a_rule() {
    let m = model("[worker.su]\ncredentials = { uid = \"root\" }\nexec = [\"/s\"]\n");
    let es = check(&pol("root-deny", "default = \"deny\"\n"), &m).expect_err("refused");
    assert_eq!(es.len(), 1, "{es:?}");
    assert_eq!(es[0].code, Code::Policy);
    let p = pol(
        "root-rule",
        "default = \"deny\"\n[[rule]]\nmatch = \"su\"\nusers = [\"root\"]\n",
    );
    assert_eq!(check(&p, &m), Ok(()));
}

#[test]
fn a_declared_root_worker_is_checked_against_the_ceiling() {
    let m = model(
        r#"
        [worker.r]
        exec = ["/r"]
        credentials = { uid = "root", caps = ["sys_admin", "net_raw"], nnp = true }
        "#,
    );
    let p = pol(
        "root-ceil",
        "default = \"allow\"\n[[rule]]\nmatch = \"r\"\nusers = [\"root\"]\ncaps_max = [\"net_raw\"]\n",
    );
    let es = check(&p, &m).expect_err("refused");
    assert_eq!(es.len(), 1, "{es:?}");
    assert_eq!(es[0].key, "worker.r.credentials");
    assert!(es[0].detail.contains("sys_admin"), "{}", es[0].detail);
    assert!(!es[0].detail.contains("net_raw"), "{}", es[0].detail);
    // Without a matching rule, `default = "deny"` refuses it, unlike an undeclared worker.
    assert!(check(&pol("root-deny", "default = \"deny\"\n"), &m).is_err());
}

#[test]
fn every_offending_worker_is_reported() {
    let m = model(
        r#"
        [worker.a]
        exec = ["/a"]
        credentials = { uid = "root" }
        [worker.b]
        exec = ["/b"]
        credentials = { uid = "y", caps = ["net_raw"] }
        "#,
    );
    let es = check(&pol("all", "default = \"deny\"\n"), &m).expect_err("denied");
    let keys: Vec<_> = es.iter().map(|e| e.key.as_str()).collect();
    assert_eq!(keys, ["worker.a.credentials", "worker.b.credentials"]);
}

#[test]
fn instances_match_by_their_expanded_name() {
    let m = model(
        r#"
        [worker.getty]
        exec = ["/agetty", "%i"]
        instances = ["tty1", "tty2"]
        credentials = { uid = "root" }
        "#,
    );
    let p = pol(
        "inst",
        "default = \"deny\"\n[[rule]]\nmatch = \"getty@*\"\nusers = [\"root\"]\n",
    );
    assert_eq!(check(&p, &m), Ok(()));
    let p = pol(
        "inst2",
        "default = \"deny\"\n[[rule]]\nmatch = \"getty\"\nusers = [\"root\"]\n",
    );
    assert_eq!(check(&p, &m).expect_err("denied").len(), 2);
}

#[test]
fn a_missing_default_is_a_bad_value() {
    let es = policy("nodef", "[[rule]]\nmatch = \"x\"\n").expect_err("refused");
    assert_eq!(es[0].code, Code::BadValue);
    assert_eq!(es[0].key, "default");
    assert!(es[0].file.is_some());
    let es = policy("baddef", "default = \"maybe\"\n").expect_err("refused");
    assert_eq!(es[0].code, Code::BadValue);
    let es = policy(
        "badcap",
        "default = \"deny\"\n[[rule]]\nmatch = \"x\"\ncaps_max = [\"nope\"]\n",
    )
    .expect_err("refused");
    assert_eq!(es[0].code, Code::BadValue);
    assert_eq!(es[0].key, "rule[0].caps_max");
}

#[test]
fn an_unknown_policy_key_is_an_unknown_key() {
    let es = policy("unk", "default = \"deny\"\nbogus = 1\n").expect_err("refused");
    assert_eq!(es[0].code, Code::UnknownKey);
    assert_eq!(es[0].key, "bogus");
    assert!(es[0].file.is_some());
    let es = policy(
        "unk2",
        "default = \"deny\"\n[[rule]]\nmatch = \"x\"\nbogus = 1\n",
    )
    .expect_err("refused");
    assert_eq!(es[0].code, Code::UnknownKey);
    assert_eq!(es[0].key, "rule[0].bogus");
    let es = policy("syn", "default = \n").expect_err("refused");
    assert_eq!(es[0].code, Code::Parse);
}

#[test]
fn a_missing_policy_file_is_an_io_error() {
    let path = PathBuf::from("/nonexistent/qinit/policy.toml");
    let es = load_policy(&path).expect_err("refused");
    assert_eq!(es[0].code, Code::Io);
    assert_eq!(es[0].file.as_deref(), Some(path.as_path()));
}

#[test]
fn shape_errors_name_the_rule_and_field() {
    let key = |tag: &str, body: &str| {
        let es = policy(tag, body).expect_err("refused");
        assert_eq!(es.len(), 1, "{es:?}");
        assert_eq!(es[0].code, Code::BadValue, "{es:?}");
        es[0].key.clone()
    };
    assert_eq!(key("sh-def", "default = 3\n"), "default");
    let two = "default = \"deny\"\n[[rule]]\nmatch = \"a\"\n[[rule]]\nmatch = \"b\"\n";
    assert_eq!(
        key("sh-users", &format!("{two}users = \"root\"\n")),
        "rule[1].users"
    );
    assert_eq!(
        key("sh-match", "default = \"deny\"\n[[rule]]\nmatch = 3\n"),
        "rule[0].match"
    );
    assert_eq!(
        key("sh-miss", "default = \"deny\"\n[[rule]]\nusers = []\n"),
        "rule[0].match"
    );
    // Never an empty key, even for a shape the line scan cannot place.
    assert!(!key("sh-inline", "default = \"deny\"\nrule = 3\n").is_empty());
}

#[test]
fn the_first_matching_rule_decides_and_later_rules_are_not_tried() {
    // `ssh*` matches first and does not list the user; the later exact rule would allow it.
    let p = pol(
        "nofall",
        "default = \"allow\"\n\
         [[rule]]\nmatch = \"ssh*\"\nusers = [\"other\"]\ncaps_max = [\"net_bind_service\"]\n\
         [[rule]]\nmatch = \"sshd\"\nusers = [\"sshd\"]\ncaps_max = [\"net_bind_service\"]\n",
    );
    let es = check(&p, &model(SSHD)).expect_err("refused");
    assert_eq!(es.len(), 1, "{es:?}");
    assert_eq!(es[0].code, Code::Policy);
    assert!(es[0].detail.contains("`ssh*`"), "{}", es[0].detail);
}

#[test]
fn an_empty_users_list_allows_no_user_but_omitting_users_allows_any() {
    let rule = |users: &str| {
        format!(
            "default = \"deny\"\n[[rule]]\nmatch = \"sshd\"\n{users}caps_max = [\"net_bind_service\"]\n"
        )
    };
    let es = check(&pol("users-empty", &rule("users = []\n")), &model(SSHD)).expect_err("refused");
    assert_eq!(es[0].code, Code::Policy);
    assert!(es[0].detail.contains("sshd"), "{}", es[0].detail);
    assert_eq!(check(&pol("users-any", &rule("")), &model(SSHD)), Ok(()));
}

#[test]
fn require_seccomp_is_satisfied_by_default_deny_and_allow_lists() {
    let p = pol(
        "req-sec",
        "default = \"deny\"\n[[rule]]\nmatch = \"a\"\nusers = [\"root\"]\nrequire_seccomp = true\n",
    );
    for seccomp in [
        "\"default\"",
        "{ deny = [\"ptrace\"] }",
        "{ allow = [\"read\", \"write\", \"exit_group\"] }",
    ] {
        let m = model(&format!(
            "[worker.a]\nexec = [\"/a\"]\ncredentials = {{ uid = \"root\" }}\nsandbox = {{ seccomp = {seccomp} }}\n"
        ));
        assert_eq!(check(&p, &m), Ok(()), "{seccomp}");
    }
}

#[test]
fn require_seccomp_refuses_none() {
    let p = pol(
        "req-sec-none",
        "default = \"deny\"\n[[rule]]\nmatch = \"a\"\nusers = [\"root\"]\nrequire_seccomp = true\n",
    );
    let m = model("[worker.a]\nexec = [\"/a\"]\ncredentials = { uid = \"root\" }\n");
    let es = check(&p, &m).expect_err("refused");
    assert_eq!(es.len(), 1, "{es:?}");
    assert_eq!(es[0].code, Code::Policy);
    assert!(
        es[0].detail.contains("seccomp required by rule `a`"),
        "{}",
        es[0].detail
    );
    let e = policy(
        "req-sec-shape",
        "default = \"deny\"\n[[rule]]\nmatch = \"a\"\nrequire_seccomp = 1\n",
    )
    .expect_err("refused");
    assert_eq!(e[0].key, "rule[0].require_seccomp");
}
