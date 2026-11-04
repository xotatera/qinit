// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The `reload` key and the forager `[launch]` table, and their negative controls.
mod common;

use common::{errs, node, ok};
use qinit_db::{Launch, Reload};
use qinit_db_core::{FD_STDERR, FD_STDIN, FD_STDOUT};
use qinit_frames::error::Code;

fn forager(launch: &str) -> String {
    format!(
        "[forager.backup]\nexec = [\"/bin/backup\"]\ncredentials = {{ uid = \"svc\" }}\n\
         [forager.backup.launch]\n{launch}\n"
    )
}

fn refused(src: &str, key: &str) {
    let es = errs(src);
    assert_eq!(es.len(), 1, "{es:?}");
    assert_eq!(es[0].code, Code::BadValue, "{es:?}");
    assert_eq!(es[0].key, key, "{es:?}");
}

#[test]
fn a_launch_table_compiles_into_the_node() {
    let r = ok(&forager(
        "concurrency = 4\nargv_tail = 8\nenv = [\"VERBOSE\", \"TARGET\"]\nfds = [\"stdin\", \"stdout\", \"stderr\"]",
    ));
    assert_eq!(
        node(&r.model, "backup").launch,
        Some(Launch {
            concurrency: 4,
            argv_tail: 8,
            env: vec!["TARGET".into(), "VERBOSE".into()],
            fds: FD_STDIN | FD_STDOUT | FD_STDERR,
        })
    );
}

#[test]
fn a_launch_table_has_defaults() {
    let r = ok(&forager("concurrency = 1"));
    assert_eq!(
        node(&r.model, "backup").launch,
        Some(Launch {
            concurrency: 1,
            argv_tail: 0,
            env: Vec::new(),
            fds: 0,
        })
    );
    let r = ok("[forager.plain]\nexec = [\"/p\"]\ncredentials = { uid = \"svc\" }\n");
    assert_eq!(node(&r.model, "plain").launch, None);
}

#[test]
fn reload_names_a_signal() {
    for (name, want) in [
        ("SIGHUP", Reload::Hup),
        ("SIGUSR1", Reload::Usr1),
        ("SIGUSR2", Reload::Usr2),
    ] {
        let r = ok(&format!(
            "[worker.a]\nexec = [\"/a\"]\ncredentials = {{ uid = \"svc\" }}\nreload = \"{name}\"\n"
        ));
        assert_eq!(node(&r.model, "a").reload, Some(want));
    }
    let r = ok("[worker.a]\nexec = [\"/a\"]\ncredentials = { uid = \"svc\" }\n");
    assert_eq!(node(&r.model, "a").reload, None);
}

#[test]
fn reload_sigkill_is_an_error() {
    refused(
        "[worker.a]\nexec = [\"/a\"]\ncredentials = { uid = \"svc\" }\nreload = \"SIGKILL\"\n",
        "worker.a.reload",
    );
}

#[test]
fn reload_on_a_brood_is_an_error() {
    refused("[brood.a]\nreload = \"SIGHUP\"\n", "brood.a.reload");
}

#[test]
fn concurrency_0_and_65_are_errors() {
    refused(
        &forager("concurrency = 0"),
        "forager.backup.launch.concurrency",
    );
    refused(
        &forager("concurrency = 65"),
        "forager.backup.launch.concurrency",
    );
}

#[test]
fn a_launch_table_needs_a_concurrency() {
    refused(
        &forager("argv_tail = 1"),
        "forager.backup.launch.concurrency",
    );
}

#[test]
fn argv_tail_above_64_is_an_error() {
    refused(
        &forager("concurrency = 1\nargv_tail = 65"),
        "forager.backup.launch.argv_tail",
    );
}

#[test]
fn launch_on_a_worker_is_an_error() {
    refused(
        "[worker.a]\nexec = [\"/a\"]\ncredentials = { uid = \"svc\" }\n[worker.a.launch]\nconcurrency = 1\n",
        "worker.a.launch",
    );
}

#[test]
fn a_reserved_env_key_is_an_error() {
    for key in ["PATH", "HOME", "USER", "LOGNAME", "QINIT_READY_FD"] {
        refused(
            &forager(&format!("concurrency = 1\nenv = [\"{key}\"]")),
            "forager.backup.launch.env",
        );
    }
}

#[test]
fn duplicate_env_keys_are_an_error() {
    refused(
        &forager("concurrency = 1\nenv = [\"A\", \"A\"]"),
        "forager.backup.launch.env",
    );
}

#[test]
fn an_env_key_that_is_not_a_name_is_an_error() {
    refused(
        &forager("concurrency = 1\nenv = [\"A=1\"]"),
        "forager.backup.launch.env",
    );
}

#[test]
fn an_unknown_fd_role_is_an_error() {
    refused(
        &forager("concurrency = 1\nfds = [\"stdwhat\"]"),
        "forager.backup.launch.fds",
    );
}

#[test]
fn a_name_with_a_hash_is_an_error() {
    let es = errs("[forager.\"a#1\"]\nexec = [\"/a\"]\ncredentials = { uid = \"svc\" }\n");
    assert!(!es.is_empty(), "{es:?}");
}
