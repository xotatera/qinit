// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qctl launch` and `qctl run` against the real server on a thread, over a real socket.
#[path = "../../qinit-client/tests/common/served.rs"]
mod served;

use served::{Served, instant};

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
fn launch_exits_with_the_instance_status() {
    // The script's status is a wait status: exit code 3.
    let s = Served::start(&[], true, instant(Some(3 << 8)));
    let path = sock(&s);
    let (code, out, err) = qctl(&["--socket", &path, "launch", "backup", "--wait", "5000"]);
    assert_eq!(code, 3, "{out}{err}");
    assert!(out.contains("backup#"), "{out}");
}

#[test]
fn a_signalled_instance_exits_128_plus_the_signal() {
    let s = Served::start(&[], true, instant(Some(9)));
    let path = sock(&s);
    let (code, _, err) = qctl(&["--socket", &path, "launch", "backup", "--", "a", "b"]);
    assert_eq!(code, 137, "{err}");
}

#[test]
fn launch_with_pidfd_exits_with_the_status() {
    // The sim stands a pipe in for the pidfd; the kernel cannot read a status from it, so the
    // reply's status counts.
    let (pipe_r, _pipe_w) = qinit_sys::fd::pipe(0o2_000_000).unwrap();
    let s = Served::start_with(&[], true, instant(Some(4 << 8)), vec![pipe_r]);
    let path = sock(&s);
    let (code, out, err) = qctl(&["--socket", &path, "launch", "backup", "--pidfd"]);
    assert_eq!(code, 4, "{out}{err}");
}

#[test]
fn launch_pending_prints_the_id_and_exits_0() {
    // The virtual clock moves 1 s at each wake-up of the server, so the 100 ms wait elapses
    // while the instance runs on.
    let s = Served::start_ticking(&[], true, instant(None), Vec::new(), None, 1000);
    let path = sock(&s);
    let (code, out, err) = qctl(&["--socket", &path, "launch", "backup", "--wait", "100"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.lines().any(|l| l.starts_with("still running: backup#")),
        "{out}"
    );
}

#[test]
fn a_refused_launch_and_a_bad_wait() {
    let s = Served::start(&[], false, instant(Some(0)));
    let path = sock(&s);
    let (code, _, err) = qctl(&["--socket", &path, "launch", "backup"]);
    assert_eq!(code, 1);
    assert!(err.starts_with("qctl: colony refused: Denied"), "{err}");
    let (code, _, _) = qctl(&["--socket", &path, "launch", "backup", "--wait", "0"]);
    assert_eq!(code, 2);
}

/// A request file in its own directory, removed on drop.
struct Request(std::path::PathBuf);

impl Request {
    fn new(tag: &str, text: &str) -> Request {
        let dir = std::env::temp_dir().join(format!("qctl-request-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("request.toml"), text).unwrap();
        Request(dir)
    }

    fn path(&self) -> String {
        self.0.join("request.toml").to_str().unwrap().to_owned()
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn run_sends_a_request_file() {
    let s = Served::start_policy(
        &[],
        true,
        instant(Some(0)),
        Vec::new(),
        Some("default = \"allow\"\n"),
    );
    let path = sock(&s);
    let req = Request::new("run", "argv = [\"/bin/job\"]\nuser = \"svc\"\n");
    let (code, out, err) = qctl(&[
        "--socket",
        &path,
        "run",
        &req.path(),
        "--name",
        "job",
        "--wait",
        "5000",
    ]);
    assert_eq!(code, 0, "{out}{err}");
    let target = out
        .lines()
        .find_map(|l| l.strip_prefix("started "))
        .expect("the instance is named");
    assert!(target.starts_with("~job#"), "{out}");
    assert_eq!(out, format!("started {target}\nexited {target} code=0\n"));
}

#[test]
fn run_refuses_a_bad_request_file_before_it_connects() {
    let req = Request::new("bad", "argv = [\"/bin/job\"]\nnope = 1\n");
    let (code, out, err) = qctl(&[
        "--socket",
        "/nonexistent/qctl-sock",
        "run",
        &req.path(),
        "--name",
        "job",
    ]);
    assert_eq!((code, out.as_str()), (1, ""));
    assert!(err.contains("unknown field `nope`"), "{err}");
    let (code, _, err) = qctl(&["run", "/nonexistent/request.toml", "--name", "job"]);
    assert_eq!(code, 1);
    assert!(err.contains("/nonexistent/request.toml"), "{err}");
}

#[test]
fn a_wait_status_maps_to_the_exit_code() {
    use qctl::launch::exit_code;
    assert_eq!(exit_code(3 << 8), Some(3));
    assert_eq!(exit_code(9), Some(137));
    assert_eq!(
        exit_code(0x80 + 11),
        Some(139),
        "a core dump is still the signal"
    );
    assert_eq!(exit_code(-1), None, "the exit was not seen");
    assert_eq!(exit_code((19 << 8) + 0x7f), None, "a stop is no end");
}

#[test]
fn fds_routes_the_named_streams_and_only_those() {
    // The instance runs on (the 100 ms wait elapses), so its routed descriptors stay with it.
    let routed = |fds: Option<&str>| {
        let s = Served::start_ticking(&[], true, instant(None), Vec::new(), None, 1000);
        let path = sock(&s);
        let mut args = vec!["--socket", &path, "launch", "backup", "--wait", "100"];
        args.extend(fds.map(|f| ["--fds", f]).into_iter().flatten());
        let (code, out, err) = qctl(&args);
        let colony = s.finish();
        let counts: Vec<usize> = colony.effects.instance_fds.values().map(Vec::len).collect();
        (code, out, err, counts)
    };
    let (code, _, err, counts) = routed(None);
    assert_eq!((code, counts), (0, vec![0]), "{err}");
    let (code, _, err, counts) = routed(Some("stdout"));
    assert_eq!((code, counts), (0, vec![1]), "{err}");
    // backup's launch table routes stdout only: colony refuses stdin, and nothing starts.
    let (code, out, err, counts) = routed(Some("stdin"));
    assert_eq!(code, 1, "{out}{err}");
    assert!(err.starts_with("qctl: colony refused: "), "{err}");
    assert!(counts.is_empty(), "{counts:?}");
}

fn json_lines(out: &str) -> Vec<serde_json::Value> {
    out.lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{l:?}: {e}")))
        .collect()
}

/// The `name` of the first object, which must be a `started` event.
fn started_name(lines: &[serde_json::Value]) -> String {
    assert_eq!(lines[0]["event"], "started", "{lines:?}");
    lines[0]["name"].as_str().unwrap().to_owned()
}

#[test]
fn launch_events_in_json() {
    use serde_json::json;
    let s = Served::start(&[], true, instant(Some(3 << 8)));
    let path = sock(&s);
    let (code, out, err) = qctl(&[
        "--socket", &path, "launch", "backup", "--json", "--wait", "5000",
    ]);
    assert_eq!(code, 3, "{out}{err}");
    let lines = json_lines(&out);
    let name = started_name(&lines);
    assert!(name.starts_with("backup#"), "{name}");
    assert_eq!(
        lines,
        [
            json!({"event": "started", "name": name}),
            json!({"event": "exited", "name": name, "code": 3}),
        ]
    );
    let s = Served::start(&[], true, instant(Some(9)));
    let path = sock(&s);
    let (code, out, err) = qctl(&["--socket", &path, "--json", "launch", "backup"]);
    assert_eq!(code, 137, "{err}");
    let lines = json_lines(&out);
    let name = started_name(&lines);
    assert_eq!(
        lines[1],
        json!({"event": "killed", "name": name, "signal": 9})
    );
}

#[test]
fn launch_pending_in_json() {
    use serde_json::json;
    let s = Served::start_ticking(&[], true, instant(None), Vec::new(), None, 1000);
    let path = sock(&s);
    let (code, out, err) = qctl(&[
        "--socket", &path, "--json", "launch", "backup", "--wait", "100",
    ]);
    assert_eq!(code, 0, "{err}");
    let lines = json_lines(&out);
    let name = started_name(&lines);
    assert_eq!(lines[1], json!({"event": "still_running", "name": name}));
    assert_eq!(lines.len(), 2);
}

#[test]
fn run_events_in_json() {
    use serde_json::json;
    let s = Served::start_policy(
        &[],
        true,
        instant(Some(0)),
        Vec::new(),
        Some("default = \"allow\"\n"),
    );
    let path = sock(&s);
    let req = Request::new("runjson", "argv = [\"/bin/job\"]\nuser = \"svc\"\n");
    let (code, out, err) = qctl(&[
        "--socket",
        &path,
        "run",
        &req.path(),
        "--name",
        "job",
        "--wait",
        "5000",
        "--json",
    ]);
    assert_eq!(code, 0, "{out}{err}");
    let lines = json_lines(&out);
    let name = started_name(&lines);
    assert!(name.starts_with("~job#"), "{name}");
    assert_eq!(
        lines[1],
        json!({"event": "exited", "name": name, "code": 0})
    );
}

#[test]
fn a_launch_failure_stays_text_in_json_mode() {
    let s = Served::start(&[], false, instant(Some(0)));
    let path = sock(&s);
    let (code, out, err) = qctl(&["--socket", &path, "--json", "launch", "backup"]);
    assert_eq!(code, 1);
    assert_eq!(out, "");
    assert!(err.starts_with("qctl: colony refused: Denied"), "{err}");
}
