// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qctl show`: the effective frame or policy as TOML with origins (spec 2026-11-05 §4.3).
use qctl::compile::Defaults;
use qinit_frames::compile::{CompileInput, compile};
use qinit_frames::layers::LayerInput;
use std::path::{Path, PathBuf};

const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../qinit-frames/tests/golden");

/// Every frame of the golden tree that is a node or expands to nodes, as `kind.name`, from the
/// merged frames of the compiled tree (templates left out: they are resolved into the frames).
fn golden_frames() -> Vec<String> {
    let layer = |name: &str| LayerInput {
        name: name.into(),
        dir: PathBuf::from(format!("{GOLDEN}/{name}")),
        only: None,
    };
    let input = CompileInput {
        layers: vec![layer("vendor"), layer("etc")],
        policy: None,
    };
    let c = compile(&input).expect("golden compiles");
    let mut out = Vec::new();
    for (kind, frames) in &c.merged.table {
        if kind == "template" {
            continue;
        }
        for name in frames.as_table().expect("a kind is a table").keys() {
            out.push(format!("{kind}.{name}"));
        }
    }
    out
}

/// A scratch directory, removed on drop (also when the test panics).
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let d = std::env::temp_dir().join(format!("qctl-show-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Self(d)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run `qctl` as a user other than root, so the ownership check does not judge the temp tree.
fn qctl(args: &[&str]) -> (i32, String, String) {
    qctl_as(args, 1000)
}

/// Run `qctl` with the effective user id `euid`.
fn qctl_as(args: &[&str], euid: u32) -> (i32, String, String) {
    let defaults = Defaults {
        vendor: "/nonexistent/vendor".into(),
        etc: "/nonexistent/etc".into(),
        policy: "/nonexistent/policy.toml".into(),
        euid,
    };
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = qctl::run_with(&args, &mut out, &mut err, &defaults);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn show(targets: &[&str]) -> String {
    let vendor = format!("vendor={GOLDEN}/vendor");
    let etc = format!("etc={GOLDEN}/etc");
    let mut args = vec!["show", "--layer", &vendor, "--layer", &etc, "--no-policy"];
    args.extend(targets);
    let (code, out, err) = qctl(&args);
    assert_eq!(code, 0, "show {targets:?}: {err}");
    out
}

fn compile_one(dir: &Path) -> Vec<u8> {
    let input = CompileInput {
        layers: vec![LayerInput {
            name: "shown".into(),
            dir: dir.to_path_buf(),
            only: None,
        }],
        policy: None,
    };
    match compile(&input) {
        Ok(c) => c.bytes,
        Err(e) => panic!("the shown frames do not compile: {e:?}"),
    }
}

#[test]
fn show_round_trips_through_the_compiler() {
    let tmp = TempDir::new("round-trip");
    let layer = tmp.0.join("layer");
    std::fs::create_dir_all(&layer).unwrap();
    let frames = golden_frames();
    assert_eq!(frames.len(), 7, "{frames:?}");
    let mut all = String::new();
    for f in &frames {
        all.push_str(&show(&[f.as_str()]));
        all.push('\n');
    }
    std::fs::write(layer.join("shown.toml"), &all).unwrap();
    std::fs::copy(
        format!("{GOLDEN}/vendor/enable.toml"),
        layer.join("enable.toml"),
    )
    .unwrap();
    let want = std::fs::read(format!("{GOLDEN}/expected.db")).unwrap();
    assert!(compile_one(&layer) == want, "bytes differ:\n{all}");
}

#[test]
fn show_marks_origins_and_keeps_substitutions_and_instance_names_as_written() {
    let getty = show(&["worker.getty"]);
    assert!(getty.starts_with("[worker.getty]\n"), "{getty}");
    assert!(getty.contains("instances = ["), "{getty}");
    assert!(getty.lines().any(|l| l.ends_with("# default")), "{getty}");
    assert!(
        getty
            .lines()
            .any(|l| l.starts_with("exec = ") && l.ends_with("# template tty-login")),
        "{getty}"
    );
    assert!(
        getty.contains("\"%i\""),
        "substitutions stay as written: {getty}"
    );
    let inst = show(&["worker.getty@tty1"]);
    assert!(
        inst.starts_with("# getty@tty1 is an instance of worker.getty\n"),
        "{inst}"
    );
    assert!(inst.ends_with(&getty), "{inst}");
    let sshd = show(&["worker.sshd"]);
    assert!(sshd.contains("restart.max = 9  # etc\n"), "{sshd}");
    assert!(sshd.contains("deps = [\n"), "{sshd}");
    assert!(
        !sshd.contains("errors ="),
        "a derived default is not printed: {sshd}"
    );
    let tpl = show(&["template.tty-login"]);
    assert!(tpl.starts_with("[template.tty-login]\n"), "{tpl}");
    assert!(tpl.contains("deps = [\n"), "{tpl}");
    let (code, _, err) = qctl(&[
        "show",
        &format!("--layer=vendor={GOLDEN}/vendor"),
        "--no-policy",
        "worker.nope",
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("worker.nope"), "{err}");
}

#[test]
fn show_policy_fills_the_rule_defaults() {
    let tmp = TempDir::new("policy");
    let policy = tmp.0.join("policy.toml");
    std::fs::write(
        &policy,
        "default = \"deny\"\nrlimits_max = { nofile = 8192 }\n\
         [[rule]]\nmatch = \"sshd\"\ncaps_max = [\"setuid\"]\n\
         [[rule]]\nmatch = \"*\"\nusers = [\"svc\"]\nallow_userns = \"range\"\nrlimits_max = { nice = 5 }\n",
    )
    .unwrap();
    let (code, out, err) = qctl(&[
        "show",
        &format!("--layer=vendor={GOLDEN}/vendor"),
        "--policy",
        &policy.display().to_string(),
        "policy",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("[[rule]]\n"), "{out}");
    assert!(out.contains("match = \"sshd\"  # policy\n"), "{out}");
    assert!(out.contains("allow_idmap = false  # default\n"), "{out}");
    assert!(out.contains("require_nnp = false  # default\n"), "{out}");
    // The shown policy is a policy the compiler accepts back.
    let again = tmp.0.join("again.toml");
    std::fs::write(&again, &out).unwrap();
    let model = |p: &Path| {
        let loaded =
            qinit_frames::policy::load_policy(p).unwrap_or_else(|e| panic!("{e:?}\n{out}"));
        qinit_frames::policy::to_model(&loaded)
    };
    assert_eq!(model(&again), model(&policy), "{out}");
}

#[test]
fn a_root_show_refuses_a_tree_that_is_not_roots() {
    let tmp = TempDir::new("root");
    let layer = tmp.0.join("layer");
    std::fs::create_dir_all(&layer).unwrap();
    std::fs::write(
        layer.join("a.toml"),
        "[worker.a]\ncredentials = { uid = \"svc\" }\nexec = [\"/a\"]\n",
    )
    .unwrap();
    let l = format!("l={}", layer.display());
    for target in ["worker.a", "policy"] {
        let (code, out, err) = qctl_as(&["show", "--layer", &l, "--no-policy", target], 0);
        assert_eq!(code, 1, "{target}: {err}");
        assert!(err.contains("owned by uid"), "{target}: {err}");
        assert!(out.is_empty(), "{target}: {out}");
    }
}

#[test]
fn deps_list_the_templates_groups_then_the_frames_own() {
    let tmp = TempDir::new("deps-order");
    let layer = tmp.0.join("vendor");
    std::fs::create_dir_all(&layer).unwrap();
    let worker = |name: &str| {
        format!("[worker.{name}]\nexec = [\"/bin/{name}\"]\ncredentials = {{ uid = \"root\" }}\n")
    };
    std::fs::write(
        layer.join("t.toml"),
        "[template.t]\ndeps = [{ group = \"require_all\", edges = [{ to = \"a\" }] }]\n",
    )
    .unwrap();
    std::fs::write(
        layer.join("b.toml"),
        format!(
            "{}template = \"t\"\ndeps = [{{ group = \"require_any\", edges = [{{ to = \"c\" }}] }}]\n",
            worker("b")
        ),
    )
    .unwrap();
    std::fs::write(layer.join("a.toml"), worker("a")).unwrap();
    std::fs::write(layer.join("c.toml"), worker("c")).unwrap();
    let l = format!("vendor={}", layer.display());
    let (code, out, err) = qctl(&["show", "--layer", &l, "--no-policy", "worker.b"]);
    assert_eq!(code, 0, "{err}");
    let start = out.find("deps = [\n").expect(&out);
    let lines: Vec<&str> = out[start..].lines().skip(1).take(2).collect();
    assert!(
        lines[0].contains("to = \"a\"") && lines[0].ends_with("# template t"),
        "{out}"
    );
    assert!(
        lines[1].contains("to = \"c\"") && lines[1].ends_with("# vendor"),
        "{out}"
    );
}

#[test]
fn show_prints_the_two_defaults_as_keys_not_comments() {
    let mount = show(&["forager.mount-var"]);
    assert!(
        mount.contains("\nstart_timeout = \"none\"  # default\n"),
        "{mount}"
    );
    let sshd = show(&["worker.sshd"]);
    assert!(
        sshd.contains("\nsandbox.user_map = \"own\"  # default\n"),
        "{sshd}"
    );
    for text in [&mount, &sshd] {
        assert!(
            !text
                .lines()
                .any(|l| l.starts_with("# ") && l.contains(" = ")),
            "{text}"
        );
    }
}

/// Two layers with an `enable.toml` each: vendor sets both lists, etc appends to `enable`.
fn enable_layers(tag: &str, vendor: Option<&str>, etc: Option<&str>) -> (TempDir, Vec<String>) {
    let tmp = TempDir::new(tag);
    let mut args = Vec::new();
    for (name, text) in [("vendor", vendor), ("etc", etc)] {
        let dir = tmp.0.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(text) = text {
            std::fs::write(dir.join("enable.toml"), text).unwrap();
        }
        args.push("--layer".to_owned());
        args.push(format!("{name}={}", dir.display()));
    }
    (tmp, args)
}

fn show_enable(layers: &[String]) -> (i32, String, String) {
    let mut args: Vec<&str> = vec!["show", "--no-policy"];
    args.extend(layers.iter().map(String::as_str));
    args.push("enable");
    qctl(&args)
}

#[test]
fn show_enable_prints_both_lists_with_origins() {
    let (_t, layers) = enable_layers(
        "enable-origins",
        Some("enable = [\"a\", \"b\"]\nsyslog = [\"s\"]\n"),
        Some("enable = { append = [\"c\"] }\n"),
    );
    let (code, out, err) = show_enable(&layers);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        out,
        "enable = [\"a\", \"b\", \"c\"]  # etc\nsyslog = [\"s\"]  # vendor\n"
    );
}

#[test]
fn show_enable_of_an_unset_list_is_empty_and_a_default() {
    let (_t, layers) = enable_layers("enable-unset", None, None);
    let (code, out, err) = show_enable(&layers);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "enable = []  # default\nsyslog = []  # default\n");
}

#[test]
fn show_enable_is_accepted_unchanged_by_the_compiler() {
    let (t, layers) = enable_layers(
        "enable-round",
        Some("enable = [\"a\", \"b\"]\nsyslog = [\"s\"]\n"),
        Some("enable = { remove = [\"a\"] }\n"),
    );
    let (_, out, _) = show_enable(&layers);
    let shown = t.0.join("shown");
    std::fs::create_dir_all(&shown).unwrap();
    std::fs::write(shown.join("enable.toml"), &out).unwrap();
    let layer = |name: &str, dir: PathBuf| LayerInput {
        name: name.into(),
        dir,
        only: None,
    };
    let want = qinit_frames::layers::load_enable(&[
        layer("vendor", t.0.join("vendor")),
        layer("etc", t.0.join("etc")),
    ])
    .expect("loads");
    let got = qinit_frames::layers::load_enable(&[layer("shown", shown)]).expect("loads");
    assert_eq!(got, want);
    assert_eq!(got.roots, ["b"]);
}

#[test]
fn a_malformed_enable_toml_is_reported_as_compile_reports_it() {
    let (t, layers) = enable_layers("enable-bad", Some("enable = [\n"), None);
    let (code, out, err) = show_enable(&layers);
    assert_eq!((code, out.as_str()), (1, ""), "{err}");
    // The same lines `compile` prints for the same file: no `qctl: ` before an error line, and
    // the parse error's own lines as the parser wrote them.
    let db = t.0.join("x.db");
    let mut args: Vec<&str> = vec!["compile", "--no-policy", "--output", db.to_str().unwrap()];
    args.extend(layers.iter().map(String::as_str));
    let (compile_code, _, compile_err) = qctl(&args);
    assert_eq!(compile_code, 1, "{compile_err}");
    assert_eq!(err, compile_err);
    let file = t.0.join("vendor/enable.toml");
    let first = format!("{}: TOML parse error", file.display());
    assert!(err.lines().any(|l| l.starts_with(&first)), "{err}");
    assert!(
        !err.lines()
            .any(|l| l.starts_with("qctl: ") && l.contains("enable.toml")),
        "{err}"
    );
}

#[test]
fn a_malformed_policy_is_reported_as_compile_reports_it() {
    let tmp = TempDir::new("policy-bad");
    let policy = tmp.0.join("policy.toml");
    std::fs::write(&policy, "rule = [\n").unwrap();
    let p = policy.display().to_string();
    let layer = format!("--layer=vendor={GOLDEN}/vendor");
    let (code, out, err) = qctl(&["show", &layer, "--policy", &p, "policy"]);
    assert_eq!((code, out.as_str()), (1, ""), "{err}");
    // The same lines `compile` prints for the same file.
    let db = tmp.0.join("x.db");
    let (compile_code, _, compile_err) = qctl(&[
        "compile",
        &layer,
        "--policy",
        &p,
        "--output",
        db.to_str().unwrap(),
    ]);
    assert_eq!(compile_code, 1, "{compile_err}");
    assert!(!err.is_empty(), "no error text");
    assert_eq!(err, compile_err);
}

#[test]
fn show_enable_skips_a_middle_layer_without_the_file() {
    let tmp = TempDir::new("enable-middle");
    let mut layers = Vec::new();
    for (name, text) in [
        ("vendor", Some("enable = [\"a\"]\n")),
        ("mid", None),
        ("etc", Some("enable = { append = [\"c\"] }\n")),
    ] {
        let dir = tmp.0.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(text) = text {
            std::fs::write(dir.join("enable.toml"), text).unwrap();
        }
        layers.push("--layer".to_owned());
        layers.push(format!("{name}={}", dir.display()));
    }
    let (code, out, err) = show_enable(&layers);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        out,
        "enable = [\"a\", \"c\"]  # etc\nsyslog = []  # default\n"
    );
}
