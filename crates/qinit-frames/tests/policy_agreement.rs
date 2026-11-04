// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The frames compiler's policy check and the proved check over the compiled database give the
//! same verdict on the same policy and the same credentials.
mod common;

use common::{TempDir, run};
use qinit_frames::layers::Enable;
use qinit_frames::policy::{check, glob_match, load_policy, to_model};
use qinit_overseer::request::{Routed, from_model};
use qinit_overseer_core::{check_policy, glob_exec};

const POLICIES: &[(&str, &str)] = &[
    (
        "ssh",
        "default = \"deny\"\n[[rule]]\nmatch = \"sshd\"\nusers = [\"sshd\"]\ncaps_max = [\"net_bind_service\"]\nrequire_nnp = true\n",
    ),
    ("allow", "default = \"allow\"\n"),
    ("bare-deny", "default = \"deny\"\n"),
    (
        "userns-own",
        "default = \"deny\"\n[[rule]]\nmatch = \"*\"\nallow_userns = true\n",
    ),
    (
        "userns-range",
        "default = \"deny\"\n[[rule]]\nmatch = \"*\"\nallow_userns = \"range\"\n",
    ),
    (
        "limits",
        "default = \"deny\"\nrlimits_max = { nofile = 2048 }\n[[rule]]\nmatch = \"w*\"\nrlimits_max = { nofile = 4096 }\n",
    ),
    (
        "seccomp",
        "default = \"deny\"\n[[rule]]\nmatch = \"*\"\nrequire_seccomp = true\ncaps_max = [\"chown\"]\n",
    ),
    (
        "first-wins",
        "default = \"allow\"\n[[rule]]\nmatch = \"s*\"\nusers = [\"nobody\"]\n[[rule]]\nmatch = \"*\"\n",
    ),
    (
        "tilde",
        "default = \"allow\"\n[[rule]]\nmatch = \"~*\"\nusers = [\"nobody\"]\n",
    ),
];

/// A worker named `name` under `creds` and `sandbox`/`rlimits` (TOML inline bodies).
fn frame(name: &str, creds: &str, extra: &str) -> String {
    format!("[worker.{name}]\nexec = [\"/{name}\"]\ncredentials = {{ {creds} }}\n{extra}\n")
}

fn frames() -> Vec<String> {
    let mut v = Vec::new();
    for name in ["sshd", "w1", "svc2", "other"] {
        for creds in [
            "uid = \"svc\"",
            "uid = \"root\"",
            "uid = \"sshd\", caps = [\"net_bind_service\"]",
            "uid = \"sshd\", caps = [\"net_bind_service\", \"chown\"]",
            "uid = \"svc\", nnp = false",
            "uid = \"svc\", caps = [\"chown\"]",
            "uid = \"nobody\", caps = [\"chown\"], nnp = false",
        ] {
            v.push(frame(name, creds, ""));
            v.push(frame(name, creds, "sandbox = { seccomp = \"default\" }"));
        }
        for sandbox in [
            "sandbox = { namespaces = [\"user\"] }",
            "sandbox = { namespaces = [\"user\"], user_map = \"range\" }",
        ] {
            v.push(frame(name, "uid = \"svc\"", sandbox));
        }
        for nofile in [1000, 2048, 3000, 4096, 5000] {
            v.push(frame(
                name,
                "uid = \"svc\"",
                &format!("rlimits = {{ nofile = {nofile} }}"),
            ));
        }
        v.push(frame(name, "uid = \"svc\"", "rlimits = { nice = 1 }"));
        v.push(frame(name, "uid = \"svc\"", "rlimits = { memlock = 100 }"));
    }
    v
}

#[test]
fn the_two_checks_agree_on_every_pair() {
    let dir = TempDir::new("agree");
    let mut pairs = 0;
    for (pname, ptext) in POLICIES {
        let path = dir.join(format!("{pname}.toml"));
        std::fs::write(&path, ptext).expect("write");
        let policy = load_policy(&path).expect("policy loads");
        for src in frames() {
            // Combinations the compiler refuses on their own (nnp off with seccomp) are skipped.
            let Ok(resolved) = run(&src, &Enable::default()) else {
                continue;
            };
            let mut model = resolved.model;
            let frames_ok = check(&policy, &model).is_ok();
            model.policy = Some(to_model(&policy));
            let bytes = qinit_db::write(&model).expect("writes");
            let db = qinit_db::open(&bytes).expect("opens");
            let node = &db.decode().nodes[0];
            let request = from_model(
                node,
                &model,
                &Routed {
                    stdin: None,
                    stdout: None,
                    stderr: None,
                    ready: Some(5),
                },
                30_000,
            )
            .expect("builds")
            .bytes()
            .expect("encodes");
            let proved = check_policy(&bytes, node.name.as_bytes(), &request);
            assert_eq!(
                frames_ok,
                proved.is_ok(),
                "policy {pname}, frame:\n{src}\nframes {frames_ok}, proved {proved:?}"
            );
            pairs += 1;
        }
    }
    assert!(pairs > 700, "{pairs}");
}

#[test]
fn glob_matches_the_frames_matcher() {
    for (p, n) in [
        ("", ""),
        ("", "a"),
        ("*", ""),
        ("*", "abc"),
        ("a*", "a"),
        ("a*b", "ab"),
        ("a*b", "axxb"),
        ("a*b", "axxbc"),
        ("*a*", "xxaxx"),
        ("**", "x"),
        ("a*b*c", "abc"),
        ("a*b*c", "acb"),
        ("~*", "~x"),
        ("~*", "x"),
        ("a", "A"),
        ("ab*", "a"),
        ("*ab", "xab"),
        ("*ab", "xa"),
    ] {
        assert_eq!(
            glob_exec(p.as_bytes(), n.as_bytes()),
            glob_match(p, n),
            "{p:?} {n:?}"
        );
    }
}
