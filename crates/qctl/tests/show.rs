// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qctl show`: the effective frame or policy as TOML with origins (spec 2026-11-05 §4.3).
use qctl::compile::Defaults;
use qinit_frames::compile::{CompileInput, compile};
use qinit_frames::layers::LayerInput;
use std::path::{Path, PathBuf};

const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../qinit-frames/tests/golden");

/// Every frame of the golden tree that is a node or expands to nodes.
const FRAMES: [&str; 7] = [
    "brood.boot-complete",
    "worker.getty",
    "worker.logd",
    "forager.mount-var",
    "brood.multi-user",
    "worker.sshd",
    "worker.syslog-ng",
];

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
    let defaults = Defaults {
        vendor: "/nonexistent/vendor".into(),
        etc: "/nonexistent/etc".into(),
        policy: "/nonexistent/policy.toml".into(),
        euid: 1000,
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
    let mut all = String::new();
    for f in FRAMES {
        all.push_str(&show(&[f]));
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
fn show_marks_origins_and_quotes_instance_names() {
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
