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

/// The lower layers `run --frame` compiles over, and the user's frame file, in a scratch tree
/// removed on drop.
struct Tree {
    dir: std::path::PathBuf,
    defaults: qctl::compile::Defaults,
}

/// The vendor layer: a logger and a forager the user's frame may amend.
const VENDOR: &str = "\
[worker.logd]
credentials = { uid = \"svc\" }
exec = [\"/bin/logd\"]

[forager.job]
credentials = { uid = \"svc\" }
exec = [\"/bin/job\"]
env = { A = \"1\" }
";

impl Tree {
    fn new(tag: &str) -> Tree {
        let dir = std::env::temp_dir().join(format!("qctl-frame-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("vendor")).unwrap();
        std::fs::create_dir_all(dir.join("user")).unwrap();
        std::fs::write(dir.join("vendor/base.toml"), VENDOR).unwrap();
        let defaults = qctl::compile::Defaults {
            vendor: dir.join("vendor"),
            etc: dir.join("etc-absent"),
            policy: dir.join("policy-absent.toml"),
            euid: 1000,
        };
        Tree { dir, defaults }
    }

    /// Write the user's frame file; its path.
    fn frame(&self, text: &str) -> String {
        let path = self.dir.join("user/frame.toml");
        std::fs::write(&path, text).unwrap();
        path.to_str().unwrap().to_owned()
    }

    fn qctl(&self, args: &[&str]) -> (i32, String, String) {
        let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = qctl::run_with(&args, &mut out, &mut err, &self.defaults);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    /// The model of the vendor layer and the frame file as one more layer, compiled here.
    fn model(&self) -> qinit_db::Model {
        use qinit_frames::compile::{CompileInput, compile};
        use qinit_frames::layers::LayerInput;
        let input = CompileInput {
            layers: vec![
                LayerInput {
                    name: "vendor".into(),
                    dir: self.dir.join("vendor"),
                    only: None,
                },
                LayerInput {
                    name: "run".into(),
                    dir: self.dir.join("user"),
                    only: Some(self.dir.join("user/frame.toml")),
                },
            ],
            policy: None,
        };
        compile(&input).expect("compiles").resolved.model
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A server whose policy allows any `Run`, with `script` for its instances.
fn served_for_run(script: qinit_colony::sim::Script) -> Served {
    Served::start_policy(&[], true, script, Vec::new(), Some("default = \"allow\"\n"))
}

/// The request bytes of the one instance the server started.
fn sent_request(colony: &mut qinit_colony::Colony<qinit_colony::sim::Sim>) -> Vec<u8> {
    use std::io::Read;
    let fd = colony
        .effects
        .instance_requests
        .drain()
        .map(|(_, fd)| fd)
        .next()
        .expect("one request");
    let mut bytes = Vec::new();
    std::fs::File::from(fd).read_to_end(&mut bytes).unwrap();
    bytes
}

/// What `from_model` makes of node `name` of `model`, with no stream given.
fn request_of(model: &qinit_db::Model, name: &str, ready: Option<u32>) -> Vec<u8> {
    use qinit_overseer::request::{Routed, from_model};
    let node = model.nodes.iter().find(|n| n.name == name).expect("node");
    let routed = Routed {
        stdin: None,
        stdout: None,
        stderr: None,
        ready,
    };
    let deadline = qinit_overseer::request::deadline_ms(node.start_timeout_ms);
    from_model(node, model, &routed, deadline)
        .expect("builds")
        .bytes()
        .expect("encodes")
}

const ONCE: &str = "\
[forager.once]
credentials = { uid = \"svc\" }
exec = [\"/bin/once\", \"--x\"]
cwd = \"/work\"
env = { LANG = \"C\" }
start_timeout = \"5s\"
";

#[test]
fn a_frame_file_runs_as_its_request() {
    let tree = Tree::new("runs");
    let file = tree.frame(ONCE);
    let s = served_for_run(instant(Some(0)));
    let path = sock(&s);
    let (code, out, err) =
        tree.qctl(&["--socket", &path, "run", "--frame", &file, "--wait", "5000"]);
    assert_eq!(code, 0, "{out}{err}");
    let target = out
        .lines()
        .find_map(|l| l.strip_prefix("started "))
        .expect("the instance is named");
    assert!(target.starts_with("~once#"), "the frame's name: {out}");
    assert_eq!(out, format!("started {target}\nexited {target} code=0\n"));
    let mut colony = s.finish();
    let sent = sent_request(&mut colony);
    let model = tree.model();
    assert_eq!(sent, request_of(&model, "once", None));
    let once = model.nodes.iter().find(|n| n.name == "once").unwrap();
    assert_eq!(
        once.start_timeout_ms, 5000,
        "the request's deadline is the frame's"
    );
    // --name takes the place of the frame's name.
    let s = served_for_run(instant(Some(0)));
    let path = sock(&s);
    let (code, out, err) = tree.qctl(&[
        "--socket", &path, "run", "--frame", &file, "--name", "other", "--json",
    ]);
    assert_eq!(code, 0, "{out}{err}");
    let lines = json_lines(&out);
    assert!(started_name(&lines).starts_with("~other#"), "{out}");
}

#[test]
fn the_deadline_is_the_start_timeout_capped_at_30_s() {
    use qinit_overseer::request::deadline_ms;
    assert_eq!(deadline_ms(0), 30_000, "no start timeout");
    assert_eq!(deadline_ms(5_000), 5_000);
    assert_eq!(deadline_ms(90_000), 30_000);
}

/// What the server started its one instance with: the node spec colony made of the `Run`.
fn started_node(colony: &qinit_colony::Colony<qinit_colony::sim::Sim>) -> qinit_colony::NodeSpec {
    let mut nodes: Vec<_> = colony.effects.instance_nodes.values().cloned().collect();
    assert_eq!(nodes.len(), 1, "{nodes:?}");
    nodes.remove(0)
}

#[test]
fn options_override_the_frame() {
    use qinit_colony::StopMode;
    let tree = Tree::new("override");
    let file = tree.frame(
        "[forager.once]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/once\"]\n\
         cell = { memory_max = \"64M\", pids_max = 10 }\nstop = { mode = \"cell\", grace = \"2s\" }\n",
    );
    let started = |extra: &[&str]| {
        let s = served_for_run(instant(Some(0)));
        let path = sock(&s);
        let mut args = vec!["--socket", &path, "run", "--frame", &file];
        args.extend_from_slice(extra);
        let (code, out, err) = tree.qctl(&args);
        assert_eq!(code, 0, "{out}{err}");
        started_node(&s.finish())
    };
    let n = started(&[]);
    let model = tree.model();
    let once = model.nodes.iter().find(|n| n.name == "once").unwrap();
    assert_eq!(
        (n.memory_max_kib, n.pids_max, n.stop, n.grace_ms),
        (once.memory_max_kib, once.pids_max, StopMode::Cell, 2000),
        "the frame's"
    );
    assert_eq!(once.memory_max_kib, 64 * 1024);
    let n = started(&[
        "--memory-max",
        "1024",
        "--pids-max",
        "3",
        "--stop-mode",
        "main",
        "--stop-grace",
        "500",
    ]);
    assert_eq!(
        (n.memory_max_kib, n.pids_max, n.stop, n.grace_ms),
        (1024, 3, StopMode::Main, 500),
        "the options'"
    );
}

#[test]
fn request_and_frame_together_are_a_usage_error() {
    let tree = Tree::new("usage");
    let file = tree.frame(ONCE);
    let (code, out, err) = tree.qctl(&["run", &file, "--frame", &file, "--name", "x"]);
    assert_eq!((code, out.as_str()), (2, ""), "{err}");
    assert!(err.contains("--frame"), "{err}");
    let (code, _, err) = tree.qctl(&["run", "--name", "x"]);
    assert_eq!(code, 2, "neither: {err}");
    let (code, _, err) = tree.qctl(&["run", &file]);
    assert_eq!(code, 2, "a request file still needs --name: {err}");
}

/// `run --frame` of `text`, which must be refused before anything is sent: the error text.
fn refused(tag: &str, text: &str) -> (String, String) {
    let tree = Tree::new(tag);
    let file = tree.frame(text);
    let (code, out, err) = tree.qctl(&[
        "--socket",
        "/nonexistent/qctl-sock",
        "run",
        "--frame",
        &file,
    ]);
    assert_eq!((code, out.as_str()), (1, ""), "{err}");
    assert!(
        !err.contains("qctl-sock"),
        "refused before it connects: {err}"
    );
    (err, file)
}

#[test]
fn a_frame_that_cannot_run_is_refused_naming_its_key() {
    let cases = [
        (
            "logger",
            "[forager.x]\ncredentials = { uid = \"svc\" }\nexec = [\"/x\"]\n\
             output = { pipe = \"logd\" }\n",
            "forager.x.output",
            4,
        ),
        (
            "logger-errors",
            "[forager.x]\ncredentials = { uid = \"svc\" }\nexec = [\"/x\"]\n\
             errors = { pipe = \"logd\" }\n",
            "forager.x.errors",
            4,
        ),
        (
            "socket",
            "[worker.x]\ncredentials = { uid = \"svc\" }\nexec = [\"/x\"]\n\
             ready = { socket = \"/run/x.sock\" }\n",
            "worker.x.ready",
            4,
        ),
        (
            "path",
            "[worker.x]\ncredentials = { uid = \"svc\" }\nexec = [\"/x\"]\n\
             ready = { path = \"/run/x\" }\n",
            "worker.x.ready",
            4,
        ),
        (
            "launch",
            "[forager.x]\ncredentials = { uid = \"svc\" }\nexec = [\"/x\"]\n\
             [forager.x.launch]\nconcurrency = 1\n",
            "forager.x.launch",
            4,
        ),
        ("brood", "\n[brood.x]\n", "brood.x", 2),
        (
            "instances",
            "[worker.x]\ncredentials = { uid = \"svc\" }\nexec = [\"/x\", \"%i\"]\n\
             instances = [\"a\", \"b\"]\n",
            "worker.x.instances",
            4,
        ),
    ];
    for (tag, text, key, line) in cases {
        let (err, file) = refused(tag, text);
        assert!(
            err.contains(&format!("{file}:{line}: {key}: ")),
            "{tag}: {err}"
        );
    }
}

#[test]
fn a_refusal_for_a_key_a_lower_layer_set_names_that_layers_file_and_line() {
    let tree = Tree::new("lower-key");
    let lower = tree.dir.join("vendor/logged.toml");
    std::fs::write(
        &lower,
        "[forager.logged]\ncredentials = { uid = \"svc\" }\nexec = [\"/x\"]\n\
         output = { pipe = \"logd\" }\n",
    )
    .unwrap();
    // The file amends the frame and leaves its output alone.
    let file = tree.frame("[forager.logged]\nenv = { B = \"2\" }\n");
    let (code, out, err) = tree.qctl(&[
        "--socket",
        "/nonexistent/qctl-sock",
        "run",
        "--frame",
        &file,
    ]);
    assert_eq!((code, out.as_str()), (1, ""), "{err}");
    let want = format!(
        "{}:4: forager.logged.output: a Run has no logger",
        lower.display()
    );
    assert!(err.contains(&want), "{err}");
    assert!(!err.contains(&file), "the frame file did not set it: {err}");
}

#[test]
fn a_frame_over_64_kib_is_refused_in_the_request_checks_words() {
    let big = "v".repeat(70_000);
    let (err, file) = refused(
        "big",
        &format!(
            "[forager.x]\ncredentials = {{ uid = \"svc\" }}\nexec = [\"/x\"]\nenv = {{ K = \"{big}\" }}\n"
        ),
    );
    let words = qinit_launch::CheckError::TooLarge.to_string();
    assert!(
        err.contains(&format!("qctl: {file}: forager.x: {words}")),
        "{err}"
    );
}

#[test]
fn a_file_with_no_frame_or_two_is_refused() {
    let (err, file) = refused("none", "# nothing here\n");
    assert!(err.contains(&file) && err.contains("no frame"), "{err}");
    let (err, file) = refused(
        "two",
        "[forager.a]\ncredentials = { uid = \"svc\" }\nexec = [\"/a\"]\n\
         [forager.b]\ncredentials = { uid = \"svc\" }\nexec = [\"/b\"]\n",
    );
    assert!(err.contains(&file), "{err}");
    assert!(
        err.contains("forager.a") && err.contains("forager.b"),
        "{err}"
    );
}

#[test]
fn a_frame_over_a_lower_one_merges_as_a_layer() {
    // forager.job is the vendor layer's; the file amends it as a layer would.
    let tree = Tree::new("over");
    let file = tree.frame(
        "[forager.job]\nexec = { replace = [\"/bin/other\", \"--y\"] }\nenv = { B = \"2\" }\n",
    );
    let s = served_for_run(instant(Some(0)));
    let path = sock(&s);
    let (code, out, err) = tree.qctl(&["--socket", &path, "run", "--frame", &file]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.starts_with("started ~job#"), "{out}");
    let sent = sent_request(&mut s.finish());
    let model = tree.model();
    let job = model.nodes.iter().find(|n| n.name == "job").unwrap();
    assert_eq!(job.exec, ["/bin/other", "--y"]);
    assert_eq!(
        job.env,
        ["A=1", "B=2"],
        "the vendor key stays, the file's joins it"
    );
    assert_eq!(sent, request_of(&model, "job", None));
}

#[test]
fn its_compile_error_names_the_file_and_line() {
    // A plain array over the vendor layer's list is the merge's error, in the user's file.
    let (err, file) = refused("line", "[forager.job]\n\nexec = [\"/bin/x\"]\n");
    assert!(
        err.contains(&format!("{file}:3: forager.job.exec: ")),
        "{err}"
    );
    // A value the schema refuses, the same.
    let (err, file) = refused("bad", "[forager.job]\nstart_timeout = \"soon\"\n");
    assert!(
        err.contains(&format!("{file}:2: forager.job.start_timeout: ")),
        "{err}"
    );
}

#[test]
fn ready_pipe_waits_for_ready() {
    let tree = Tree::new("ready");
    let file = tree.frame(
        "[worker.svc]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/svc\"]\nready = \"pipe\"\n",
    );
    let script = qinit_colony::sim::Script {
        ready_after_ms: Some(0),
        exit_after: None,
        ..qinit_colony::sim::Script::default()
    };
    let s = served_for_run(script.clone());
    let path = sock(&s);
    let (code, out, err) = tree.qctl(&[
        "--socket",
        &path,
        "run",
        "--frame",
        &file,
        "--fds",
        "stdout,stderr",
        "--wait",
        "5000",
    ]);
    assert_eq!(code, 0, "{out}{err}");
    let target = out
        .lines()
        .find_map(|l| l.strip_prefix("started "))
        .expect("started");
    assert_eq!(out, format!("started {target}\nready {target}\n"));
    let colony = s.finish();
    // The same run in JSON: the readiness is the `ready` event.
    let s = served_for_run(script);
    let path = sock(&s);
    let (code, out, err) = tree.qctl(&[
        "--socket", &path, "--json", "run", "--frame", &file, "--wait", "5000",
    ]);
    assert_eq!(code, 0, "{out}{err}");
    let lines = json_lines(&out);
    let name = started_name(&lines);
    assert_eq!(
        lines,
        [
            serde_json::json!({"event": "started", "name": name}),
            serde_json::json!({"event": "ready", "name": name}),
        ]
    );
    drop(s.finish());
    let ready: Vec<_> = colony.effects.instance_ready.iter().map(|r| r.1).collect();
    assert_eq!(ready, [Some(qctl::frame_run::READY_FD)]);
    let counts: Vec<usize> = colony.effects.instance_fds.values().map(Vec::len).collect();
    assert_eq!(counts, [2], "stdout and stderr went with it");
    // --wait-ready on a frame without a readiness pipe is an error.
    let file = tree.frame(ONCE);
    let (code, _, err) = tree.qctl(&[
        "--socket",
        "/nonexistent/s",
        "run",
        "--frame",
        &file,
        "--wait-ready",
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("ready"), "{err}");
}

#[test]
fn every_stream_and_the_readiness_pipe_get_numbers_colony_accepts() {
    // A `Run`'s streams arrive as 5, 6 and 7 (docs/control-protocol.md); the readiness pipe
    // takes a number none of them uses.
    use qctl::args::Fds;
    use qctl::frame_run::{READY_FD, routed};
    let all = routed(Fds {
        stdin: true,
        stdout: true,
        stderr: true,
    });
    assert_eq!(
        (all.stdin, all.stdout, all.stderr),
        (Some(5), Some(6), Some(7))
    );
    assert!(!(5..=7).contains(&READY_FD) && (5..=37).contains(&READY_FD));
    let some = routed(Fds {
        stdin: false,
        stdout: false,
        stderr: true,
    });
    assert_eq!(
        (some.stdin, some.stdout, some.stderr),
        (None, None, Some(7))
    );
}

#[test]
fn a_stream_given_takes_the_place_of_the_frames_route() {
    // forager.x routes stdout to the logger; given --fds stdout, the caller's stream replaces
    // it and no logger is needed.
    let tree = Tree::new("replace");
    let file = tree.frame(
        "[forager.x]\ncredentials = { uid = \"svc\" }\nexec = [\"/x\"]\noutput = { pipe = \"logd\" }\n",
    );
    let s = served_for_run(instant(Some(0)));
    let path = sock(&s);
    let (code, out, err) = tree.qctl(&[
        "--socket", &path, "run", "--frame", &file, "--fds", "stdout",
    ]);
    assert_eq!(code, 0, "{out}{err}");
    let sent = sent_request(&mut s.finish());
    let model = tree.model();
    let x = model.nodes.iter().find(|n| n.name == "x").unwrap();
    let routed = qinit_overseer::request::Routed {
        stdin: None,
        stdout: Some(6),
        stderr: None,
        ready: None,
    };
    let want =
        qinit_overseer::request::from_instance(x, &model, &routed, &[], &[], 30_000).unwrap();
    assert_eq!(want.stdout, qinit_launch::Stream::Fd(6));
    assert_eq!(sent, want.bytes().unwrap());
    // Without the stream the logger is needed, and there is none.
    let (code, _, err) = tree.qctl(&[
        "--socket",
        "/nonexistent/s",
        "run",
        "--frame",
        &file,
        "--fds",
        "stderr",
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("forager.x.output"), "{err}");
}

#[test]
fn colony_takes_every_stream_with_the_readiness_pipe() {
    // The request `run --frame` makes with all three streams and a readiness pipe, sent with
    // three descriptors: the real colony accepts it. The control: the readiness pipe on
    // descriptor 5, where stdin arrives, is refused.
    use qctl::args::Fds;
    use qctl::frame_run::{routed, spec};
    use qinit_client::{Begun, Client, RunArgs};
    use std::os::fd::AsFd;
    let tree = Tree::new("allfds");
    let file = tree.frame(
        "[worker.svc]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/svc\"]\nready = \"pipe\"\n",
    );
    let all = Fds {
        stdin: true,
        stdout: true,
        stderr: true,
    };
    let framed = spec(
        std::path::Path::new(&file),
        &tree.defaults,
        routed(all),
        &mut Vec::new(),
    )
    .expect("runs");
    let (r, w) = qinit_sys::fd::pipe(0o2_000_000).unwrap();
    let send = |request: &qinit_launch::RequestSpec| {
        let s = served_for_run(qinit_colony::sim::Script {
            ready_after_ms: Some(0),
            exit_after: None,
            ..qinit_colony::sim::Script::default()
        });
        let args = RunArgs {
            stdin: Some(r.as_fd()),
            stdout: Some(w.as_fd()),
            stderr: Some(w.as_fd()),
            wait_ready: true,
            ..RunArgs::default()
        };
        let mut c = Client::connect(&s.path).unwrap();
        c.begin_run(
            "svc",
            request,
            &args,
            false,
            std::time::Duration::from_secs(5),
        )
    };
    assert!(
        matches!(send(&framed.run.spec), Ok(Begun::Started(_))),
        "{:?}",
        framed.run.spec
    );
    let mut on_stdin = framed.run.spec.clone();
    on_stdin.ready_fd = Some(5);
    assert!(
        matches!(
            send(&on_stdin),
            Err(qinit_client::ClientError::Server(
                qinit_client::ErrorCode::Invalid,
                4
            ))
        ),
        "the control does not decode: two roles on one number"
    );
}
