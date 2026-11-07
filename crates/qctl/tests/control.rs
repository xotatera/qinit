// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The control commands against the real server on a thread, over a real socket.
mod common;
#[path = "../../qinit-client/tests/common/served.rs"]
mod served;

use common::TempDir;
use served::common::database;
use served::{Served, frames, instant};

fn qctl(args: &[&str]) -> (i32, String, String) {
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = qctl::run(&args, &mut out, &mut err);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn sock(s: &Served) -> String {
    s.path.to_str().unwrap().to_owned()
}

#[test]
fn status_and_list_print_names_and_states() {
    let s = Served::start(&["db"], true, instant(None));
    let path = sock(&s);
    let (code, out, _) = qctl(&["--socket", &path, "status", "db"]);
    assert_eq!(code, 0);
    assert!(out.contains("state: ready"), "{out}");
    assert!(
        out.contains("name: db") && out.contains("kind: worker"),
        "{out}"
    );
    let (code, out, _) = qctl(&["--socket", &path, "list"]);
    assert_eq!(code, 0);
    assert!(out.lines().any(|l| l == "worker db ready"), "{out}");
    let (_, out, _) = qctl(&["--socket", &path, "list", "foragers"]);
    assert!(out.lines().all(|l| l.starts_with("forager ")), "{out}");
    let (code, _, err) = qctl(&["--socket", &path, "status", "nope"]);
    assert_eq!(code, 1);
    assert!(err.contains("colony refused: UnknownNode"), "{err}");
}

#[test]
fn stop_with_wait_prints_settled() {
    let s = Served::start(&["db"], true, instant(None));
    let path = sock(&s);
    let (code, out, err) = qctl(&["--socket", &path, "stop", "db", "--wait", "5000"]);
    assert_eq!((code, out.as_str()), (0, "settled off\n"), "{err}");
}

#[test]
fn a_refused_request_exits_1_with_the_server_error() {
    let s = Served::start(&["db"], false, instant(None));
    let path = sock(&s);
    let (code, out, err) = qctl(&["--socket", &path, "stop", "db"]);
    assert_eq!(code, 1);
    assert_eq!(out, "");
    assert!(err.starts_with("qctl: colony refused: Denied ("), "{err}");
}

#[test]
fn a_missing_socket_is_a_transport_error_and_a_bad_wait_is_usage() {
    let (code, _, err) = qctl(&["--socket", "/nonexistent/qctl-sock", "list"]);
    assert_eq!(code, 1);
    assert!(
        err.starts_with("qctl: ") && !err.contains("refused"),
        "{err}"
    );
    for w in ["0", "600001"] {
        let (code, _, err) = qctl(&["--socket", "/nonexistent/x", "stop", "db", "--wait", w]);
        assert_eq!(code, 2, "{err}");
    }
}

#[test]
fn refresh_passes_the_database_and_halt_without_wait_prints_accepted() {
    let s = Served::start(&["db"], true, instant(None));
    let path = sock(&s);
    let dir = TempDir::new("control");
    let db = dir.join("expected.db");
    let changed = frames().replace("/bin/db", "/bin/db2");
    std::fs::write(&db, database(&changed, &["db"])).unwrap();
    let (code, out, err) = qctl(&["--socket", &path, "refresh", db.to_str().unwrap()]);
    assert_eq!((code, out.as_str()), (0, "accepted\n"), "{err}");
    let (code, out, err) = qctl(&["--socket", &path, "halt"]);
    assert_eq!((code, out.as_str()), (0, "accepted\n"), "{err}");
    let (code, _, err) = qctl(&["--socket", "/nonexistent/x", "refresh", "/nonexistent/db"]);
    assert_eq!(code, 1);
    assert!(err.starts_with("qctl: "), "{err}");
}

#[test]
fn state_names_carry_their_detail() {
    use qctl::text::state;
    use qinit_client::StateWord;
    let w = |state, detail| StateWord { state, detail };
    assert_eq!(state(w(1, 1)), "waiting/backoff");
    assert_eq!(state(w(1, 0)), "waiting/dependency");
    assert_eq!(state(w(6, 0)), "quarantined/breaker");
    assert_eq!(state(w(6, 1)), "quarantined/cascade");
    assert_eq!(state(w(6, 2)), "quarantined/start-timeout");
    assert_eq!(state(w(6, 3)), "quarantined/stop-failed");
    assert_eq!(state(w(3, 0)), "ready");
    // A word the table does not know prints as its number.
    assert_eq!(state(w(6, 4)), "quarantined/4");
    assert_eq!(state(w(1, 2)), "waiting/2");
    assert_eq!(state(w(7, 0)), "state7/0");
    assert_eq!(qctl::text::kind(3), "kind3");
    assert_eq!(qctl::text::instance_state(1), "state1");
}

#[test]
fn a_command_that_is_not_a_control_command_is_an_error_not_a_panic() {
    let mut err = Vec::new();
    let code = qctl::control::run(
        &qctl::args::Command::Watch {
            all: true,
            target: String::new(),
        },
        std::path::Path::new("/nonexistent/qctl-sock"),
        qctl::json::Output::Text,
        &mut Vec::new(),
        &mut err,
    );
    let err = String::from_utf8(err).unwrap();
    assert_eq!(code, 1, "{err}");
    assert!(err.starts_with("qctl: "), "{err}");
}

fn json_lines(out: &str) -> Vec<serde_json::Value> {
    out.lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{l:?}: {e}")))
        .collect()
}

#[test]
fn status_and_list_in_json() {
    use serde_json::json;
    let s = Served::start(&["db"], true, instant(None));
    let path = sock(&s);
    let (code, out, err) = qctl(&["--socket", &path, "--json", "status", "db"]);
    assert_eq!(code, 0, "{err}");
    let lines = json_lines(&out);
    assert_eq!(lines.len(), 1, "{out}");
    let o = lines[0].as_object().unwrap();
    // The dynamic numbers are read back; every other field is compared whole.
    let expected = json!({
        "name": "db", "kind": "worker", "state": "ready",
        "backoff_ms": o["backoff_ms"], "since_ms": o["since_ms"], "restarts": o["restarts"],
    });
    let mut expected = expected.as_object().unwrap().clone();
    if let Some(pid) = o.get("pid") {
        expected.insert("pid".into(), pid.clone());
    }
    assert_eq!(*o, expected);
    let (code, out, err) = qctl(&["list", "--json", "--socket", &path]);
    assert_eq!(code, 0, "{err}");
    assert!(
        json_lines(&out).contains(&json!({"kind": "worker", "name": "db", "state": "ready"})),
        "{out}"
    );
    // The text form is untouched.
    let (_, out, _) = qctl(&["--socket", &path, "list"]);
    assert!(out.lines().any(|l| l == "worker db ready"), "{out}");
}

#[test]
fn change_results_in_json() {
    use serde_json::json;
    let s = Served::start(&["db"], true, instant(None));
    let path = sock(&s);
    let (code, out, err) = qctl(&["--socket", &path, "stop", "db", "--wait", "5000", "--json"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        json_lines(&out),
        [json!({"result": "settled", "state": "off"})]
    );
    let (code, out, err) = qctl(&["--socket", &path, "--json", "halt"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(json_lines(&out), [json!({"result": "accepted"})]);
}

#[test]
fn a_state_with_a_detail_splits_in_json() {
    use qinit_client::StateWord;
    use serde_json::json;
    let w = |state, detail| StateWord { state, detail };
    assert_eq!(
        qctl::json::entry(&qinit_client::Entry {
            name: "x".into(),
            kind: 0,
            state: w(1, 1)
        }),
        json!({"kind": "worker", "name": "x", "state": "waiting", "detail": "backoff"})
    );
    assert_eq!(
        qctl::json::change(qinit_client::Outcome::Pending(w(6, 3))),
        json!({"result": "pending", "state": "quarantined", "detail": "stop-failed"})
    );
}

#[test]
fn an_absent_optional_field_is_absent() {
    use qinit_client::{InstanceInfo, NodeInfo, StateWord};
    use serde_json::json;
    let node = NodeInfo {
        name: "db".into(),
        kind: 0,
        state: StateWord {
            state: 0,
            detail: 0,
        },
        blocking: None,
        backoff_ms: 0,
        since_ms: 5,
        restarts: 1,
        pid: None,
    };
    assert_eq!(
        qctl::json::status(&node),
        json!({"name": "db", "kind": "worker", "state": "off",
               "backoff_ms": 0, "since_ms": 5, "restarts": 1})
    );
    let blocked = NodeInfo {
        blocking: Some((2, "worker.x".into())),
        pid: Some(77),
        ..node
    };
    assert_eq!(
        qctl::json::status(&blocked),
        json!({"name": "db", "kind": "worker", "state": "off",
               "blocking": {"group": 2, "target": "worker.x"},
               "backoff_ms": 0, "since_ms": 5, "restarts": 1, "pid": 77})
    );
    let inst = InstanceInfo {
        frame: "backup".into(),
        id: 4,
        state: 3,
        status: None,
        pid: None,
    };
    assert_eq!(
        qctl::json::instance_status(&inst),
        json!({"frame": "backup", "id": 4, "state": "running"})
    );
    let done = InstanceInfo {
        state: 4,
        status: Some(256),
        pid: Some(9),
        ..inst
    };
    assert_eq!(
        qctl::json::instance_status(&done),
        json!({"frame": "backup", "id": 4, "state": "exited", "status": 256, "pid": 9})
    );
}

#[test]
fn json_is_a_usage_error_for_compile_show_and_fill() {
    for cmd in ["compile", "show", "fill"] {
        let (code, out, err) = qctl(&[cmd, "--json"]);
        assert_eq!((code, out.as_str()), (2, ""), "{cmd}: {err}");
        assert!(err.contains("--json") && err.contains(cmd), "{err}");
    }
    let (code, _, err) = qctl(&["--json", "compile"]);
    assert_eq!(code, 2, "{err}");
    let (code, _, err) = qctl(&["status", "db", "--json=1"]);
    assert_eq!(code, 2, "{err}");
}

#[test]
fn a_refusal_stays_text_on_stderr() {
    let s = Served::start(&["db"], false, instant(None));
    let path = sock(&s);
    let (code, out, err) = qctl(&["--socket", &path, "--json", "stop", "db"]);
    assert_eq!(code, 1);
    assert_eq!(out, "");
    assert!(err.starts_with("qctl: colony refused: Denied ("), "{err}");
}
