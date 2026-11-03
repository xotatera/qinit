// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Resolution of node fields and credentials, limits, and the proved-validator round trip.
mod common;

use common::{enable, errs, idx, node, ok, run};
use qinit_db::{Kind, Ready, RestartPolicy, Seccomp, Securebits};
use qinit_frames::error::Code;

#[test]
fn credentials_and_sandbox_merge_into_one_cred() {
    let r = ok(r#"
        [worker.a]
        exec = ["/a"]
        credentials = { uid = "sshd", caps = ["chown", "net_bind_service", "checkpoint_restore"], nnp = true, securebits = "noroot-locked" }
        sandbox = { namespaces = ["mount", "net"], landlock = ["ro:/etc", "rw:/run/a"], seccomp = "default" }
        [worker.b]
credentials = { uid = "svc" }
        exec = ["/b"]
        sandbox = { namespaces = ["pid"] }
        [worker.c]
credentials = { uid = "svc" }
        exec = ["/c"]
    "#);
    let m = &r.model;
    let a = &m.creds[node(m, "a").cred.expect("cred") as usize];
    assert_eq!(a.user, "sshd");
    assert_eq!(a.caps, 1 | (1 << 10) | (1 << 40));
    assert!(a.nnp);
    assert_eq!(a.securebits, Securebits::NorootLocked);
    assert_eq!(a.ns, 0b1_0001);
    assert_eq!(a.seccomp, Seccomp::Default);
    assert_eq!(a.landlock, ["ro:/etc", "rw:/run/a"]);
    // A sandbox next to a bare user: the identity's defaults (no caps, no-new-privileges on)
    // and the sandbox in one record.
    let b = &m.creds[node(m, "b").cred.expect("cred") as usize];
    assert_eq!((b.user.as_str(), b.caps, b.ns), ("svc", 0, 0b10));
    assert!(b.nnp);
    assert_eq!(b.securebits, Securebits::None);
    let bare = &m.creds[node(m, "c").cred.expect("cred") as usize];
    assert_eq!((bare.user.as_str(), bare.caps, bare.ns), ("svc", 0, 0));
}

#[test]
fn declared_credentials_default_nnp_on_when_omitted() {
    let r = ok(r#"
        [worker.a]
        exec = ["/a"]
        credentials = { uid = "sshd" }
        sandbox = { namespaces = ["pid"] }
    "#);
    let m = &r.model;
    let a = &m.creds[node(m, "a").cred.expect("cred") as usize];
    assert_eq!((a.user.as_str(), a.caps, a.nnp), ("sshd", 0, true));
}

#[test]
fn bad_credential_strings_are_bad_values() {
    let es = errs(
        r#"
        [worker.a]
        exec = ["/a"]
        credentials = { uid = "" }
        [worker.b]
        exec = ["/b"]
        credentials = { uid = "b", securebits = "high" }
        [worker.c]
credentials = { uid = "svc" }
        exec = ["/c"]
        sandbox = { landlock = ["/etc"], seccomp = "strict" }
    "#,
    );
    let keys: Vec<_> = es.iter().map(|e| (e.code, e.key.as_str())).collect();
    assert_eq!(
        keys,
        [
            (Code::BadValue, "worker.a.credentials.uid"),
            (Code::BadValue, "worker.b.credentials.securebits"),
            (Code::BadValue, "worker.c.sandbox.landlock"),
            (Code::BadValue, "worker.c.sandbox.seccomp"),
        ]
    );
}

#[test]
fn exec_rules_are_bad_values() {
    let es = errs(
        r#"
        [worker.a]
credentials = { uid = "svc" }
        [forager.b]
credentials = { uid = "svc" }
        exec = []
        [worker.c]
credentials = { uid = "svc" }
        exec = ["/c", ""]
        [worker.d]
credentials = { uid = "svc" }
        exec = ["/d", "x\u0000y"]
    "#,
    );
    assert_eq!(es.len(), 4, "{es:?}");
    assert!(
        es.iter()
            .all(|e| e.code == Code::BadValue && e.key.rsplit('.').next() == Some("exec"))
    );
}

#[test]
fn node_fields_are_converted() {
    let r = ok(r#"
        [worker.a]
credentials = { uid = "svc" }
        exec = ["/a"]
        ready = { socket = "/run/a.sock" }
        restart = { policy = "on-failure", max = 5, window = "60s" }
        cell = { memory_max = "512M", pids_max = 256 }
        [forager.f]
credentials = { uid = "svc" }
        exec = ["/f"]
        [brood.g]
        [worker.p]
credentials = { uid = "svc" }
        exec = ["/p"]
    "#);
    let m = &r.model;
    let a = node(m, "a");
    assert_eq!(a.kind, Kind::Worker);
    assert_eq!(a.ready, Ready::Socket("/run/a.sock".into()));
    assert_eq!(a.restart.policy, RestartPolicy::OnFailure);
    assert_eq!((a.restart.max, a.restart.window_ms), (5, 60_000));
    assert_eq!((a.memory_max_kib, a.pids_max), (512 * 1024, 256));
    assert_eq!(node(m, "p").ready, Ready::Pipe);
    assert_eq!(node(m, "f").ready, Ready::Exit);
    assert_eq!(node(m, "f").restart.policy, RestartPolicy::Never);
    assert!(node(m, "g").exec.is_empty());
    assert_eq!(node(m, "a").instance_of, None);
}

#[test]
fn more_edges_in_a_group_than_the_limit_is_a_limit_error() {
    let edges: Vec<String> = (0..65).map(|_| "{ to = \"a\" }".to_string()).collect();
    let src = format!(
        "[brood.a]\n[brood.b]\ndeps = [{{ group = \"require_all\", edges = [{}] }}]\n",
        edges.join(", ")
    );
    let es = errs(&src);
    assert_eq!(es[0].code, Code::Limit);
    assert!(es[0].detail.contains("edges per group"), "{}", es[0].detail);
    assert_eq!(es[0].key, "brood.b");
}

#[test]
fn a_resolved_tree_passes_the_proved_validator() {
    let src = r#"
        [template.daemon]
        restart = { policy = "on-failure", max = 5, window = "60s" }
        output = { pipe = "logger" }
        [template.tty]
        exec = ["/sbin/agetty", "%i"]
        instances = ["tty1", "tty2"]
        restart = { policy = "always" }
        [worker.getty]
credentials = { uid = "svc" }
        template = "tty"
        deps = [{ group = "require_all", edges = [{ to = "local-fs" }] }]
        [worker.logger]
credentials = { uid = "svc" }
        exec = ["/usr/bin/logger-d"]
        output = "/dev/console"
        deps = [{ group = "require_all", edges = [{ to = "local-fs" }] }]
        [worker.syslog-ng]
credentials = { uid = "svc" }
        exec = ["/usr/bin/syslog-ng", "-F"]
        template = "daemon"
        [worker.sshd]
        exec = ["/usr/bin/sshd", "-D"]
        template = "daemon"
        ready = "pipe"
        errors = "/dev/console"
        cell = { memory_max = "512M", pids_max = 256 }
        credentials = { uid = "sshd", caps = ["net_bind_service"], securebits = "noroot-locked" }
        sandbox = { namespaces = ["mount", "pid"], landlock = ["ro:/etc/ssh"], seccomp = "default" }
        deps = [
          { group = "require_all", edges = [
              { to = "firewall", mode = "sync" },
              { to = "network", mode = "async", deadline = "1s", restart_on = "error" } ] },
          { group = "require_all", edges = [{ to = "syslog-ng" }] },
          { group = "exclude_all", edges = [ { to = "rescue" } ] },
          { group = "optional_all", edges = [ { to = "absent" }, { path = "/run/ready", stop = "parallel" } ] },
        ]
        [forager.firewall]
credentials = { uid = "svc" }
        exec = ["/usr/bin/nft", "-f", "/etc/nftables.conf"]
        ready = "exit"
        deps = [{ group = "require_all", edges = [{ to = "local-fs" }] }]
        [forager.network]
credentials = { uid = "svc" }
        exec = ["/usr/bin/net-up"]
        [brood.local-fs]
        [brood.rescue]
        [brood.multi-user]
        deps = [{ group = "require_all", edges = [{ to = "sshd" }, { to = "getty@tty1" }, { to = "getty@tty2" }] }]
    "#;
    let r = run(src, &enable(&["multi-user"], &["syslog-ng"])).expect("resolves");
    assert_eq!(r.warnings.len(), 1, "{:?}", r.warnings);
    let m = &r.model;
    assert!(!m.presyslog.is_empty());
    assert!(m.presyslog.contains(&idx(m, "logger")));
    let bytes = qinit_db::write(m).expect("writes");
    let db = qinit_db::open(&bytes).expect("the proved validator accepts it");
    assert_eq!(&db.decode(), m);
}

#[test]
fn a_worker_that_is_its_own_logger_through_output_is_a_cycle() {
    let es = errs(
        "[worker.a]\ncredentials = { uid = \"svc\" }\nexec = [\"/a\"]\noutput = { pipe = \"a\" }\n",
    );
    assert_eq!(es[0].code, Code::Cycle);
    assert_eq!(es[0].key, "worker.a.output");
}

#[test]
fn a_producer_piping_to_the_syslog_worker_is_not_presyslog() {
    let src = r#"
        [worker.syslog-ng]
credentials = { uid = "svc" }
        exec = ["/s"]
        [worker.app]
credentials = { uid = "svc" }
        exec = ["/app"]
        output = { pipe = "syslog-ng" }
        [worker.early]
credentials = { uid = "svc" }
        exec = ["/e"]
        [brood.boot]
        deps = [{ group = "require_all", edges = [{ to = "app" }, { to = "early" }, { to = "syslog-ng" }] }]
    "#;
    let r = run(src, &enable(&["boot"], &["syslog-ng"])).expect("resolves");
    // `app` reaches the syslog worker over its implicit logger edge, so it is not listed.
    assert_eq!(r.model.presyslog, [idx(&r.model, "early")]);
}

#[test]
fn stop_parallel_on_a_sync_require_path_edge_is_hard_parallel() {
    // The check also fires for a path target, which is stricter than the validator (a path
    // edge has no node to stop in parallel); this is deliberate and documented.
    let src = |mode: &str, group: &str| {
        format!(
            "[worker.b]\ncredentials = {{ uid = \"svc\" }}\nexec = [\"/b\"]\ndeps = [{{ group = \"{group}\", edges = \
             [{{ path = \"/run/x\", stop = \"parallel\"{mode} }}] }}]\n"
        )
    };
    let es = errs(&src("", "require_all"));
    assert_eq!(es[0].code, Code::HardParallel);
    assert_eq!(es[0].key, "worker.b.deps[0].edges[0].stop");
    ok(&src(", mode = \"async\"", "require_all"));
    ok(&src("", "optional_all"));
}

#[test]
fn launch_fields_resolve_with_their_defaults() {
    let r = ok("[worker.a]\nexec = [\"/a\"]\ncredentials = { uid = \"svc\" }\n");
    let n = node(&r.model, "a");
    assert_eq!((n.cwd.as_str(), n.umask, n.rlimit_nofile), ("/", 0o027, 0));
    assert!(n.env.is_empty());
    let r = ok(
        "[worker.a]\nexec = [\"/a\"]\ncredentials = { uid = \"svc\" }\nenv = { B = \"2\", A = \"1\", C = \"\" }\ncwd = \"/srv\"\numask = 0o077\nrlimits = { nofile = 4096 }\n",
    );
    let n = node(&r.model, "a");
    assert_eq!(n.env, ["A=1", "B=2", "C="]);
    assert_eq!(
        (n.cwd.as_str(), n.umask, n.rlimit_nofile),
        ("/srv", 0o077, 4096)
    );
}

#[test]
fn a_template_env_merges_under_the_frame_env() {
    let r = ok(
        "[template.t]\nenv = { A = \"t\", B = \"t\" }\ncwd = \"/t\"\n[worker.a]\ntemplate = \"t\"\nexec = [\"/a\"]\ncredentials = { uid = \"svc\" }\nenv = { A = \"f\" }\n",
    );
    let n = node(&r.model, "a");
    assert_eq!(n.env, ["A=f", "B=t"]);
    assert_eq!(n.cwd, "/t");
}

#[test]
fn seccomp_lists_resolve_to_numbers() {
    let r = ok(
        "[worker.a]\nexec = [\"/a\"]\ncredentials = { uid = \"svc\" }\nsandbox = { seccomp = { deny = [\"ptrace\", \"getppid\"] } }\n",
    );
    let c = &r.model.creds[node(&r.model, "a").cred.unwrap() as usize];
    assert_eq!(c.seccomp, Seccomp::Deny(vec![101, 110]));
    let r = ok(
        "[worker.a]\nexec = [\"/a\"]\ncredentials = { uid = \"svc\" }\nsandbox = { seccomp = { allow = [\"read\", \"write\", \"exit_group\"] } }\n",
    );
    let c = &r.model.creds[node(&r.model, "a").cred.unwrap() as usize];
    assert_eq!(c.seccomp, Seccomp::Allow(vec![0, 1, 231]));
}

#[test]
fn a_deny_list_cannot_name_a_call_the_default_program_already_answers() {
    for name in ["clone", "unshare", "clone3", "setns"] {
        let es = errs(&format!(
            r#"
        [worker.a]
        exec = ["/a"]
        credentials = {{ uid = "svc" }}
        sandbox = {{ seccomp = {{ deny = ["{name}", "fork"] }} }}
    "#
        ));
        let keys: Vec<_> = es.iter().map(|e| (e.code, e.key.as_str())).collect();
        assert_eq!(
            keys,
            [(Code::BadValue, "worker.a.sandbox.seccomp")],
            "{name}"
        );
        assert!(es[0].detail.contains(name), "{}", es[0].detail);
    }
}

#[test]
fn an_allow_list_may_name_them() {
    let r = ok(r#"
        [worker.a]
        exec = ["/a"]
        credentials = { uid = "svc" }
        sandbox = { seccomp = { allow = ["clone", "read"] } }
    "#);
    assert_eq!(r.model.creds.len(), 1);
}
