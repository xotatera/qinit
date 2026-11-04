// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Inside ids: the ids a service runs as inside its user namespace. `sandbox.inside_uid` and
//! `sandbox.inside_gid` default to 0, need the `user` namespace when non-zero, and need a policy
//! rule with `allow_inside_ids = true`.
mod common;

use common::{TempDir, errs, node, ok};
use qinit_frames::error::Code;
use qinit_frames::policy::{check, load_policy};

fn worker(namespaces: &str, ids: &str) -> String {
    format!(
        r#"
        [worker.box]
        exec = ["/box"]
        credentials = {{ uid = "svc" }}
        sandbox = {{ namespaces = [{namespaces}]{ids} }}
    "#
    )
}

#[test]
fn inside_ids_default_to_zero_and_need_the_user_namespace() {
    let r = ok(&worker(r#""user""#, ""));
    let m = &r.model;
    let c = &m.creds[node(m, "box").cred.expect("cred") as usize];
    assert_eq!((c.inside_uid, c.inside_gid), (0, 0));

    let r = ok(&worker(
        r#""user""#,
        ", inside_uid = 1000, inside_gid = 1001",
    ));
    let m = &r.model;
    let c = &m.creds[node(m, "box").cred.expect("cred") as usize];
    assert_eq!((c.inside_uid, c.inside_gid), (1000, 1001));

    for ids in [", inside_uid = 1000", ", inside_gid = 1"] {
        let es = errs(&worker(r#""pid""#, ids));
        assert_eq!(es.len(), 1, "{ids}: {es:?}");
        let key = if ids.contains("uid") {
            "worker.box.sandbox.inside_uid"
        } else {
            "worker.box.sandbox.inside_gid"
        };
        assert_eq!((es[0].code, es[0].key.as_str()), (Code::BadValue, key));
    }
    // Zero without the user namespace is the default and fine.
    ok(&worker(r#""pid""#, ", inside_uid = 0, inside_gid = 0"));
}

#[test]
fn inside_id_4294967295_is_refused() {
    ok(&worker(r#""user""#, ", inside_uid = 4294967294"));
    for (ids, key) in [
        (", inside_uid = 4294967295", "worker.box.sandbox.inside_uid"),
        (", inside_gid = 4294967295", "worker.box.sandbox.inside_gid"),
        (", inside_uid = 4294967296", "worker.box.sandbox.inside_uid"),
        (", inside_uid = -1", "worker.box.sandbox.inside_uid"),
    ] {
        let es = errs(&worker(r#""user""#, ids));
        assert_eq!(es.len(), 1, "{ids}: {es:?}");
        assert_eq!(es[0].key, key, "{ids}");
    }
}

fn pol(tag: &str, rule: &str) -> qinit_frames::policy::Policy {
    let dir = TempDir::new(tag);
    let path = dir.join("policy.toml");
    std::fs::write(
        &path,
        format!("default = \"deny\"\n[[rule]]\nmatch = \"box\"\nallow_userns = true\n{rule}\n"),
    )
    .expect("write");
    load_policy(&path).expect("policy loads")
}

#[test]
fn a_nonzero_inside_id_needs_allow_inside_ids() {
    let m = ok(&worker(r#""user""#, ", inside_uid = 1000")).model;
    let es = check(&pol("ii-no", ""), &m).expect_err("refused");
    assert_eq!(es.len(), 1, "{es:?}");
    assert_eq!(
        (es[0].code, es[0].key.as_str()),
        (Code::Policy, "rule[0].allow_inside_ids")
    );
    assert!(es[0].detail.contains("worker `box`"), "{}", es[0].detail);
    let es = check(&pol("ii-false", "allow_inside_ids = false"), &m).expect_err("refused");
    assert_eq!(es[0].key, "rule[0].allow_inside_ids");
    // Inside id 0 needs no such permission.
    let zero = ok(&worker(r#""user""#, "")).model;
    assert_eq!(check(&pol("ii-zero", ""), &zero), Ok(()));
}

#[test]
fn allow_inside_ids_true_passes() {
    let m = ok(&worker(
        r#""user""#,
        ", inside_uid = 1000, inside_gid = 1000",
    ))
    .model;
    assert_eq!(check(&pol("ii-yes", "allow_inside_ids = true"), &m), Ok(()));
}

#[test]
fn a_bad_allow_inside_ids_is_a_bad_value() {
    let dir = TempDir::new("ii-bad");
    let path = dir.join("policy.toml");
    std::fs::write(
        &path,
        "default = \"deny\"\n[[rule]]\nmatch = \"box\"\nallow_inside_ids = 1\n",
    )
    .expect("write");
    let es = load_policy(&path).expect_err("refused");
    assert_eq!(es.len(), 1, "{es:?}");
    assert_eq!(
        (es[0].code, es[0].key.as_str()),
        (Code::BadValue, "rule[0].allow_inside_ids")
    );
}

#[test]
fn an_idmapped_entry_needs_allow_idmap() {
    let src = r#"
        [worker.box]
        exec = ["/bin/box"]
        credentials = { uid = "svc" }
        sandbox = { namespaces = ["user"], paths = ["ro:/bin", "wi:/data"] }
    "#;
    let m = ok(src).model;
    let es = check(&pol("im-no", ""), &m).expect_err("refused");
    assert_eq!(es.len(), 1, "{es:?}");
    assert_eq!(
        (es[0].code, es[0].key.as_str()),
        (Code::Policy, "rule[0].allow_idmap")
    );
    assert_eq!(check(&pol("im-yes", "allow_idmap = true"), &m), Ok(()));
    // A plain writable entry needs nothing.
    let plain = ok(&src.replace("wi:", "rw:")).model;
    assert_eq!(check(&pol("im-plain", ""), &plain), Ok(()));
}
