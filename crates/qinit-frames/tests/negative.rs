// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Named negative controls (spec §9): each refused tree gives the exact code and key.
mod common;

use common::{Tree, ok};
use qinit_frames::compile::compile;
use qinit_frames::error::{Code, Error};

/// Compile one `vendor` layer holding `frames` as `f.toml`; it must be refused.
fn refuse(tag: &str, frames: &str) -> Vec<Error> {
    let t = Tree::new(tag);
    t.file("vendor", "f.toml", frames);
    compile(&t.input(&["vendor"])).expect_err("refused")
}

/// Exactly one error, with `code` and `key`.
fn one(es: &[Error], code: Code, key: &str) {
    assert_eq!(es.len(), 1, "{es:?}");
    assert_eq!(es[0].code, code, "{es:?}");
    assert_eq!(es[0].key, key, "{es:?}");
}

#[test]
fn a_self_loop_is_a_cycle() {
    let es = refuse(
        "neg-self",
        "[worker.a]\ncredentials = { uid = \"svc\" }\nexec = [\"/a\"]\n\
         deps = [{ group = \"require_all\", edges = [{ to = \"a\" }] }]\n",
    );
    one(&es, Code::Cycle, "worker.a");
    assert_eq!(es[0].detail, "a -> a");
    assert_eq!(es[0].layer.as_deref(), Some("vendor"));
}

#[test]
fn a_two_node_ordering_cycle_is_a_cycle() {
    let es = refuse(
        "neg-two",
        "[worker.b]\ncredentials = { uid = \"svc\" }\nexec = [\"/b\"]\n\
         deps = [{ group = \"optional_all\", edges = [{ to = \"a\" }] }]\n\
         [worker.a]\ncredentials = { uid = \"svc\" }\nexec = [\"/a\"]\n\
         deps = [{ group = \"require_any\", edges = [{ to = \"b\" }] }]\n",
    );
    one(&es, Code::Cycle, "worker.a");
    assert_eq!(es[0].detail, "a -> b -> a");
}

#[test]
fn a_parallel_soft_edge_cannot_hide_a_start_cycle() {
    // a -> b may stop in parallel, but the start order still needs b before a and a before b.
    let es = refuse(
        "neg-par",
        "[worker.a]\ncredentials = { uid = \"svc\" }\nexec = [\"/a\"]\n\
         deps = [{ group = \"require_all\", edges = [\
           { to = \"b\", mode = \"async\", deadline = \"1s\", stop = \"parallel\" }] }]\n\
         [worker.b]\ncredentials = { uid = \"svc\" }\nexec = [\"/b\"]\n\
         deps = [{ group = \"require_all\", edges = [{ to = \"a\" }] }]\n",
    );
    one(&es, Code::Cycle, "worker.a");
    assert_eq!(es[0].detail, "a -> b -> a");
}

#[test]
fn a_missing_require_all_target_is_missing_target() {
    let es = refuse(
        "neg-miss",
        "[worker.a]\ncredentials = { uid = \"svc\" }\nexec = [\"/a\"]\n\
         deps = [{ group = \"require_all\", edges = [{ to = \"nope\" }] }]\n",
    );
    one(&es, Code::MissingTarget, "worker.a.deps[0].edges[0].to");
}

#[test]
fn stop_parallel_on_a_hard_edge_is_hard_parallel() {
    let es = refuse(
        "neg-hard",
        "[brood.b]\n[worker.a]\ncredentials = { uid = \"svc\" }\nexec = [\"/a\"]\n\
         deps = [{ group = \"require_all\", edges = [{ to = \"b\", stop = \"parallel\" }] }]\n",
    );
    one(&es, Code::HardParallel, "worker.a.deps[0].edges[0].stop");
}

#[test]
fn more_than_the_node_limit_is_a_limit_error() {
    use std::fmt::Write as _;
    let mut src = String::new();
    for i in 0..=qinit_db_core::MAX_NODES {
        let _ = write!(
            src,
            "[worker.w{i}]\ncredentials = {{ uid = \"svc\" }}\nexec = [\"/w\"]\n"
        );
    }
    let es = refuse("neg-limit", &src);
    assert_eq!(es.len(), 1, "{es:?}");
    assert_eq!(es[0].code, Code::Limit);
}

#[test]
fn a_policy_violation_is_a_policy_error_with_the_frame_key() {
    let t = Tree::new("neg-policy");
    t.file(
        "vendor",
        "sshd.toml",
        "[worker.sshd]\nexec = [\"/sshd\"]\n\
         credentials = { uid = \"root\", caps = [\"sys_admin\"] }\n",
    );
    t.file(
        "policy",
        "policy.toml",
        "default = \"deny\"\n[[rule]]\nmatch = \"sshd\"\nusers = [\"sshd\"]\n",
    );
    let mut input = t.input(&["vendor"]);
    input.policy = Some(t.root.join("policy/policy.toml"));
    let es = compile(&input).expect_err("refused");
    assert!(!es.is_empty());
    assert!(es.iter().all(|e| e.code == Code::Policy), "{es:?}");
    assert!(
        es.iter().all(|e| e.key == "worker.sshd.credentials"),
        "{es:?}"
    );
}

#[test]
fn removing_an_absent_list_item_is_a_list_op_error() {
    let t = Tree::new("neg-listop");
    t.file(
        "vendor",
        "a.toml",
        "[worker.a]\ncredentials = { uid = \"svc\" }\nexec = [\"/a\", \"-v\"]\n",
    );
    t.file(
        "etc",
        "a.toml",
        "[worker.a]\ncredentials = { uid = \"svc\" }\nexec = { remove = [\"-q\"] }\n",
    );
    let es = compile(&t.input(&["vendor", "etc"])).expect_err("refused");
    one(&es, Code::ListOp, "worker.a.exec");
    assert_eq!(es[0].layer.as_deref(), Some("etc"));
}

#[test]
fn a_duplicate_instance_name_is_an_instance_error() {
    let es = refuse(
        "neg-inst",
        "[worker.g]\ncredentials = { uid = \"svc\" }\nexec = [\"/g\", \"%i\"]\ninstances = [\"tty1\", \"tty1\"]\n",
    );
    assert_eq!(es.len(), 1, "{es:?}");
    assert_eq!(es[0].code, Code::Instance);
}

#[test]
fn an_unknown_key_is_an_unknown_key_error() {
    let es = refuse(
        "neg-unk",
        "[worker.a]\ncredentials = { uid = \"svc\" }\nexec = [\"/a\"]\ncolour = \"red\"\n",
    );
    one(&es, Code::UnknownKey, "worker.a.colour");
}

#[test]
fn a_worker_is_its_own_logger_is_a_cycle() {
    // The implicit logger edge would point at the producer itself.
    let es = refuse(
        "neg-ownlog",
        "[worker.a]\ncredentials = { uid = \"svc\" }\nexec = [\"/a\"]\noutput = { pipe = \"a\" }\n",
    );
    one(&es, Code::Cycle, "worker.a.output");
}

#[test]
fn a_logger_that_depends_on_its_producer_is_a_cycle() {
    // App pipes to log (implicit app -> log), and log requires app.
    let es = refuse(
        "neg-backlog",
        "[worker.app]\ncredentials = { uid = \"svc\" }\nexec = [\"/app\"]\nerrors = { pipe = \"log\" }\n\
         [worker.log]\ncredentials = { uid = \"svc\" }\nexec = [\"/log\"]\n\
         deps = [{ group = \"require_all\", edges = [{ to = \"app\", mode = \"async\" }] }]\n",
    );
    one(&es, Code::Cycle, "worker.app");
    assert_eq!(es[0].detail, "app -> log -> app");
}

#[test]
fn a_worker_without_credentials_is_refused() {
    let es = refuse("neg-nocred", "[worker.a]\nexec = [\"/a\"]\n");
    one(&es, Code::BadValue, "worker.a.credentials.uid");
}

#[test]
fn a_sandbox_only_worker_is_refused() {
    let es = refuse(
        "neg-sandbox",
        "[worker.a]\nexec = [\"/a\"]\nsandbox = { namespaces = [\"mount\"] }\n",
    );
    one(&es, Code::BadValue, "worker.a.credentials.uid");
}

#[test]
fn a_forager_without_credentials_is_refused() {
    let es = refuse("neg-nocred-f", "[forager.a]\nexec = [\"/a\"]\n");
    one(&es, Code::BadValue, "forager.a.credentials.uid");
}

#[test]
fn an_unknown_syscall_name_is_refused() {
    let es = refuse(
        "neg-sys",
        "[worker.a]\nexec = [\"/a\"]\ncredentials = { uid = \"svc\" }\nsandbox = { seccomp = { deny = [\"frobnicate\"] } }\n",
    );
    one(&es, Code::BadValue, "worker.a.sandbox.seccomp");
    assert!(es[0].detail.contains("frobnicate"), "{}", es[0].detail);
}

#[test]
fn an_empty_seccomp_list_is_refused() {
    let es = refuse(
        "neg-sys-empty",
        "[worker.a]\nexec = [\"/a\"]\ncredentials = { uid = \"svc\" }\nsandbox = { seccomp = { deny = [] } }\n",
    );
    one(&es, Code::BadValue, "worker.a.sandbox.seccomp");
}

#[test]
fn an_unknown_seccomp_word_is_refused() {
    let es = refuse(
        "neg-sys-word",
        "[worker.a]\nexec = [\"/a\"]\ncredentials = { uid = \"svc\" }\nsandbox = { seccomp = \"strict\" }\n",
    );
    one(&es, Code::BadValue, "worker.a.sandbox.seccomp");
}

#[test]
fn nnp_off_with_a_sandbox_needs_sys_admin() {
    let body = |caps: &str, sandbox: &str| {
        format!(
            "[worker.a]\nexec = [\"/a\"]\ncredentials = {{ uid = \"root\", nnp = false{caps} }}\nsandbox = {{ {sandbox} }}\n"
        )
    };
    for sandbox in ["paths = [\"ro:/a\"]", "seccomp = \"default\""] {
        let es = refuse("neg-nnp", &body("", sandbox));
        one(&es, Code::BadValue, "worker.a.credentials.nnp");
        ok(&body(", caps = [\"sys_admin\"]", sandbox));
    }
    // Namespaces alone need nothing.
    ok(&body("", "namespaces = [\"uts\"]"));
}
