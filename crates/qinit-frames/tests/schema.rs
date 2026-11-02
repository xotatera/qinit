// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Strict frame schema.
use qinit_frames::error::Code;
use qinit_frames::schema::{Output, Ready, parse_frame};

fn parse(kind: &str, src: &str) -> Result<qinit_frames::schema::Frame, qinit_frames::error::Error> {
    let v = toml::Value::Table(src.parse::<toml::Table>().expect("test toml"));
    parse_frame(kind, "t", &v)
}

const SSHD: &str = r#"
exec        = ["/usr/bin/sshd", "-D"]
template    = "daemon"
ready       = "pipe"
restart     = { policy = "on-failure", max = 5, window = "60s" }
output      = "/dev/log"
errors      = "/dev/console"
cell        = { memory_max = "512M", pids_max = 256 }
credentials = { uid = "sshd", caps = ["net_bind_service"], nnp = false, securebits = "noroot-locked" }
sandbox     = { namespaces = ["mount", "pid"], landlock = [], seccomp = "default" }
deps = [
  { group = "require_all", edges = [
      { to = "firewall", mode = "sync" },
      { to = "network", mode = "async", deadline = "1s", restart_on = "error" } ] },
  { group = "exclude_all", edges = [ { to = "rescue" } ] },
]
"#;

#[test]
fn the_spec_sshd_example_parses() {
    let f = parse("worker", SSHD).expect("sshd parses");
    assert_eq!(f.exec.as_deref().map(<[String]>::len), Some(2));
    assert_eq!(f.deps.as_ref().map(Vec::len), Some(2));
    assert!(matches!(f.ready, Some(Ready::Kind(ref k)) if k == "pipe"));
}

#[test]
fn an_unknown_key_is_rejected() {
    let e = parse("worker", "exec = [\"/x\"]\ncolour = 1").unwrap_err();
    assert_eq!(e.code, Code::UnknownKey);
}

#[test]
fn an_unknown_key_inside_a_table_is_rejected() {
    let e = parse("worker", "exec = [\"/x\"]\ncell = { colour = 1 }").unwrap_err();
    assert_eq!(e.code, Code::UnknownKey);
}

#[test]
fn a_bad_ready_kind_is_a_bad_value() {
    let e = parse("worker", "exec = [\"/x\"]\nready = \"banana\"").unwrap_err();
    assert_eq!(e.code, Code::BadValue);
    assert_eq!(e.key, "worker.t.ready");
}

#[test]
fn ready_socket_and_path_parse() {
    let f = parse("worker", "ready = { socket = \"/run/x\" }").unwrap();
    assert!(matches!(f.ready, Some(Ready::Socket { .. })));
    let f = parse("worker", "ready = { path = \"/run/y\" }").unwrap();
    assert!(matches!(f.ready, Some(Ready::Path { .. })));
}

#[test]
fn output_pipe_and_path_both_parse() {
    let f = parse("worker", "output = { pipe = \"logger\" }").unwrap();
    assert!(matches!(f.output, Some(Output::Pipe { .. })));
    let f = parse("worker", "output = \"/dev/log\"").unwrap();
    assert!(matches!(f.output, Some(Output::Path(_))));
}

#[test]
fn restart_on_a_forager_is_a_bad_value() {
    let e = parse("forager", "restart = { policy = \"always\" }").unwrap_err();
    assert_eq!(e.code, Code::BadValue);
}

#[test]
fn exec_on_a_brood_is_a_bad_value() {
    let e = parse("brood", "exec = [\"/x\"]").unwrap_err();
    assert_eq!(e.code, Code::BadValue);
}

#[test]
fn a_brood_with_runtime_keys_is_a_bad_value() {
    for k in [
        "ready = \"pipe\"",
        "output = \"/dev/log\"",
        "credentials = { uid = \"a\" }",
    ] {
        let e = parse("brood", k).unwrap_err();
        assert_eq!(e.code, Code::BadValue, "{k}");
    }
}

#[test]
fn a_brood_with_only_deps_parses() {
    let f = parse(
        "brood",
        "deps = [ { group = \"require_all\", edges = [ { to = \"a\" } ] } ]",
    );
    assert!(f.is_ok());
}

#[test]
fn an_edge_needs_exactly_one_of_to_and_path() {
    let none = "deps = [ { group = \"require_all\", edges = [ { mode = \"sync\" } ] } ]";
    let both = "deps = [ { group = \"require_all\", edges = [ { to = \"a\", path = \"/p\" } ] } ]";
    assert_eq!(parse("worker", none).unwrap_err().code, Code::BadValue);
    assert_eq!(parse("worker", both).unwrap_err().code, Code::BadValue);
}

#[test]
fn a_deadline_needs_async_mode_and_stop_must_be_parallel() {
    let d = "deps = [ { group = \"require_all\", edges = [ { to = \"a\", deadline = \"1s\" } ] } ]";
    let s = "deps = [ { group = \"require_all\", edges = [ { to = \"a\", stop = \"serial\" } ] } ]";
    let ok =
        "deps = [ { group = \"optional_all\", edges = [ { to = \"a\", stop = \"parallel\" } ] } ]";
    assert_eq!(parse("worker", d).unwrap_err().code, Code::BadValue);
    assert_eq!(parse("worker", s).unwrap_err().code, Code::BadValue);
    assert!(parse("worker", ok).is_ok());
}

#[test]
fn a_bad_unit_string_is_a_bad_value() {
    let e = parse(
        "worker",
        "restart = { policy = \"always\", window = \"1.5s\" }",
    )
    .unwrap_err();
    assert_eq!(e.code, Code::BadValue);
    let e = parse("worker", "cell = { memory_max = \"lots\" }").unwrap_err();
    assert_eq!(e.code, Code::BadValue);
}

#[test]
fn a_wrong_type_is_a_bad_value() {
    let e = parse("worker", "exec = \"/bin/x\"").unwrap_err();
    assert_eq!(e.code, Code::BadValue);
}

#[test]
fn a_template_accepts_defaults_of_any_kind() {
    assert!(parse("template", SSHD).is_ok());
}
