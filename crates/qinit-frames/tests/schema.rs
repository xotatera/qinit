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
    assert_eq!(e.key, "forager.t.restart");
}

#[test]
fn exec_on_a_brood_is_a_bad_value() {
    let e = parse("brood", "exec = [\"/x\"]").unwrap_err();
    assert_eq!(e.code, Code::BadValue);
    assert_eq!(e.key, "brood.t.exec");
}

#[test]
fn a_brood_with_runtime_keys_is_a_bad_value() {
    for (k, key) in [
        ("ready = \"pipe\"", "ready"),
        ("output = \"/dev/log\"", "output"),
        ("credentials = { uid = \"a\" }", "credentials"),
    ] {
        let e = parse("brood", k).unwrap_err();
        assert_eq!(e.code, Code::BadValue, "{k}");
        assert_eq!(e.key, format!("brood.t.{key}"));
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
    for src in [none, both] {
        let e = parse("worker", src).unwrap_err();
        assert_eq!(e.code, Code::BadValue);
        assert_eq!(e.key, "worker.t.deps[0].edges[0]");
    }
}

#[test]
fn a_deadline_needs_async_mode_and_stop_must_be_parallel() {
    let d = "deps = [ { group = \"require_all\", edges = [ { to = \"a\", deadline = \"1s\" } ] } ]";
    let s = "deps = [ { group = \"require_all\", edges = [ { to = \"a\", stop = \"serial\" } ] } ]";
    let ok =
        "deps = [ { group = \"optional_all\", edges = [ { to = \"a\", stop = \"parallel\" } ] } ]";
    let e = parse("worker", d).unwrap_err();
    assert_eq!(
        (e.code, e.key.as_str()),
        (Code::BadValue, "worker.t.deps[0].edges[0].deadline")
    );
    let e = parse("worker", s).unwrap_err();
    assert_eq!(
        (e.code, e.key.as_str()),
        (Code::BadValue, "worker.t.deps[0].edges[0].stop")
    );
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

#[test]
fn credentials_no_longer_carry_sandbox_keys() {
    for k in [
        "namespaces = [\"mount\"]",
        "seccomp = \"default\"",
        "landlock = []",
    ] {
        let src = format!("credentials = {{ uid = \"x\", {k} }}");
        let e = parse("worker", &src).unwrap_err();
        assert_eq!(e.code, Code::UnknownKey, "{k}");
    }
}

#[test]
fn sandbox_keys_parse_and_unknown_sandbox_keys_are_unknown_keys() {
    let f = parse(
        "worker",
        "sandbox = { namespaces = [\"net\"], seccomp = \"default\", landlock = [\"ro:/etc\"] }",
    )
    .unwrap();
    assert!(f.sandbox.is_some());
    let e = parse("worker", "sandbox = { colour = 1 }").unwrap_err();
    assert_eq!(e.code, Code::UnknownKey);
}

#[test]
fn an_unknown_key_names_the_field_in_the_key_path() {
    let e = parse("worker", "colour = 1").unwrap_err();
    assert_eq!(
        (e.code, e.key.as_str()),
        (Code::UnknownKey, "worker.t.colour")
    );
    assert!(e.detail.contains("colour"));
}

#[test]
fn a_message_that_merely_mentions_unknown_field_is_a_bad_value() {
    let e = parse("worker", "exec = \"unknown field\"").unwrap_err();
    assert_eq!((e.code, e.key.as_str()), (Code::BadValue, "worker.t"));
}

#[test]
fn an_unknown_key_inside_an_untagged_enum_is_a_bad_value() {
    // Serde cannot tell which variant was meant, so it reports no matching variant.
    for src in [
        "ready = { socket = \"/x\", x = 1 }",
        "output = { pipe = \"l\", x = 1 }",
    ] {
        assert_eq!(
            parse("worker", src).unwrap_err().code,
            Code::BadValue,
            "{src}"
        );
    }
}

#[test]
fn an_unknown_key_in_a_nested_table_names_its_true_path() {
    let key = |src: &str| {
        let e = parse("worker", src).unwrap_err();
        assert_eq!(e.code, Code::UnknownKey, "{src}");
        e.key
    };
    assert_eq!(
        key("restart = { policy = \"never\", bogus = 1 }"),
        "worker.t.restart.bogus"
    );
    assert_eq!(
        key("credentials = { uid = \"u\", bogus = 1 }"),
        "worker.t.credentials.bogus"
    );
    assert_eq!(
        key("sandbox = { seccomp = \"default\", bogus = 1 }"),
        "worker.t.sandbox.bogus"
    );
    assert_eq!(key("cell = { bogus = 1 }"), "worker.t.cell.bogus");
    assert_eq!(
        key(
            "deps = [{ group = \"require_all\", edges = [{ to = \"a\" }, { to = \"b\", bogus = 1 }] }]"
        ),
        "worker.t.deps[0].edges[1].bogus"
    );
    assert_eq!(
        key("deps = [{ group = \"require_all\", edges = [{ to = \"a\" }], bogus = 1 }]"),
        "worker.t.deps[0].bogus"
    );
    // `max` is a restart key, so only the edge holding it is a candidate.
    assert_eq!(
        key("restart = { policy = \"never\", max = 1 }\n\
             deps = [{ group = \"require_all\", edges = [{ to = \"a\", max = 1 }] }]"),
        "worker.t.deps[0].edges[0].max"
    );
}

#[test]
fn an_unknown_key_in_two_tables_is_keyed_on_the_frame() {
    let e = parse(
        "worker",
        "restart = { policy = \"never\", bogus = 1 }\ncell = { bogus = 1 }",
    )
    .unwrap_err();
    assert_eq!((e.code, e.key.as_str()), (Code::UnknownKey, "worker.t"));
    assert!(e.detail.contains("could not be told"), "{}", e.detail);
}

#[test]
fn an_empty_require_group_is_a_bad_value() {
    for g in ["require_all", "require_any"] {
        let src = format!("deps = [{{ group = \"{g}\", edges = [] }}]");
        let e = parse("worker", &src).unwrap_err();
        assert_eq!(
            (e.code, e.key.as_str()),
            (Code::BadValue, "worker.t.deps[0].edges"),
            "{g}"
        );
    }
    for g in ["optional_all", "exclude_all"] {
        let src = format!("deps = [{{ group = \"{g}\", edges = [] }}]");
        assert!(parse("worker", &src).is_ok(), "{g}");
    }
}
