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
    assert_eq!(state(w(3, 0)), "ready");
}
