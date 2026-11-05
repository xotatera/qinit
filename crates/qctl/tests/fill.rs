// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qctl fill`: the implicit defaults written into the last layer (spec 2026-11-05 §4.5).
use qctl::compile::Defaults;
use qinit_frames::compile::{CompileInput, compile};
use qinit_frames::layers::LayerInput;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../qinit-frames/tests/golden");
const FILLED: &str = "  # default, filled by qctl";

/// A scratch directory, removed on drop (also when the test panics).
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let d = std::env::temp_dir().join(format!("qctl-fill-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("vendor")).unwrap();
        std::fs::create_dir_all(d.join("etc")).unwrap();
        Self(d)
    }

    /// A copy of the golden tree's `vendor` and `etc` layers.
    fn golden(tag: &str) -> Self {
        let t = Self::new(tag);
        for layer in ["vendor", "etc"] {
            for e in std::fs::read_dir(format!("{GOLDEN}/{layer}")).unwrap() {
                let e = e.unwrap();
                std::fs::copy(e.path(), t.0.join(layer).join(e.file_name())).unwrap();
            }
        }
        t
    }

    fn write(&self, rel: &str, text: &str) {
        std::fs::write(self.0.join(rel), text).unwrap();
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.0.join(rel)).unwrap()
    }

    fn layer_args(&self) -> Vec<String> {
        vec![
            "--layer".into(),
            format!("vendor={}", self.0.join("vendor").display()),
            "--layer".into(),
            format!("etc={}", self.0.join("etc").display()),
        ]
    }

    /// Every file of the tree and its bytes.
    fn snapshot(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut out = BTreeMap::new();
        for layer in ["vendor", "etc"] {
            for e in std::fs::read_dir(self.0.join(layer)).unwrap() {
                let p = e.unwrap().path();
                out.insert(p.clone(), std::fs::read(&p).unwrap());
            }
        }
        out
    }

    /// The database of the tree (`policy` when given).
    fn db(&self, policy: Option<&Path>) -> Vec<u8> {
        let layer = |name: &str| LayerInput {
            name: name.into(),
            dir: self.0.join(name),
        };
        let input = CompileInput {
            layers: vec![layer("vendor"), layer("etc")],
            policy: policy.map(Path::to_path_buf),
        };
        match compile(&input) {
            Ok(c) => c.bytes,
            Err(e) => panic!("the tree does not compile: {e:?}"),
        }
    }

    /// `qctl fill` over the tree, without a policy, as a user other than root.
    fn fill(&self, extra: &[&str]) -> (i32, String, String) {
        let mut args = vec!["fill".to_owned()];
        args.extend(self.layer_args());
        if !extra.iter().any(|a| a.starts_with("--policy")) {
            args.push("--no-policy".into());
        }
        args.extend(extra.iter().map(|s| (*s).to_owned()));
        qctl(&args)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn qctl(args: &[String]) -> (i32, String, String) {
    let defaults = Defaults {
        vendor: "/nonexistent/vendor".into(),
        etc: "/nonexistent/etc".into(),
        policy: "/nonexistent/policy.toml".into(),
        euid: 1000,
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = qctl::run_with(args, &mut out, &mut err, &defaults);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn parses(text: &str) {
    if let Err(e) = text.parse::<toml::Table>() {
        panic!("not TOML: {e}\n{text}");
    }
}

#[test]
fn fill_writes_into_the_etc_layer_never_vendor() {
    let t = TempDir::golden("etc-only");
    let before = t.snapshot();
    let (code, _out, err) = t.fill(&["all"]);
    assert_eq!(code, 0, "{err}");
    let after = t.snapshot();
    for (p, bytes) in &before {
        if p.starts_with(t.0.join("vendor")) {
            assert!(after[p] == *bytes, "{} changed", p.display());
        }
    }
    assert_eq!(
        after
            .keys()
            .filter(|p| p.starts_with(t.0.join("vendor")))
            .count(),
        before
            .keys()
            .filter(|p| p.starts_with(t.0.join("vendor")))
            .count(),
    );
    // The amend table of etc/sshd.toml gains the defaults; its own line stays as it was.
    let sshd = t.read("etc/sshd.toml");
    parses(&sshd);
    assert!(sshd.contains("restart = { max = 9"), "{sshd}");
    assert!(sshd.contains("[worker.sshd]\n"), "{sshd}");
    assert!(sshd.contains(&format!("  cwd = \"/\"{FILLED}\n")), "{sshd}");
    assert!(
        sshd.contains(&format!("  stop.mode = \"main\"{FILLED}\n")),
        "{sshd}"
    );
    // A frame with no table in etc gets a new file named after its vendor file.
    let syslog = t.read("etc/syslog-ng.toml");
    parses(&syslog);
    assert!(syslog.starts_with("[worker.syslog-ng]\n"), "{syslog}");
    assert!(
        syslog.contains(&format!("  restart.delay = \"1000ms\"{FILLED}\n")),
        "{syslog}"
    );
    // getty sets none of the filled fields itself: they go to its template, not to getty.
    assert!(!t.0.join("etc/getty.toml").exists());
    let tty = t.read("etc/tty-login.toml");
    assert!(tty.starts_with("[template.tty-login]\n"), "{tty}");
    // The forager's start_timeout "none" has no word: it is not written.
    let mount = t.read("etc/mount-var.toml");
    assert!(
        mount.contains(&format!("  ready = \"exit\"{FILLED}\n")),
        "{mount}"
    );
    assert!(!mount.contains("start_timeout"), "{mount}");
    // Without a user namespace sandbox.user_map has no word either; errors is derived.
    for text in [&sshd, &syslog, &tty, &mount] {
        assert!(!text.contains("user_map"), "{text}");
        assert!(!text.contains("errors"), "{text}");
        assert!(!text.contains("instance"), "{text}");
    }
}

#[test]
fn fill_is_idempotent_and_keeps_the_database_bytes() {
    let t = TempDir::golden("idempotent");
    let want = std::fs::read(format!("{GOLDEN}/expected.db")).unwrap();
    assert!(
        t.db(None) == want,
        "the golden tree does not give expected.db"
    );
    let (code, out, err) = t.fill(&["all"]);
    assert_eq!(code, 0, "{err}");
    assert!(!out.contains("nothing to fill"), "{out}");
    assert!(t.db(None) == want, "the database changed");
    let once = t.snapshot();
    let (code, out, err) = t.fill(&["all"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("nothing to fill"), "{out}");
    assert!(t.snapshot() == once, "the second fill changed a file");
}

/// A one-worker tree: `vendor/x.toml` and the given `etc/x.toml`.
fn one_worker(tag: &str, etc: Option<&str>) -> TempDir {
    let t = TempDir::new(tag);
    t.write(
        "vendor/x.toml",
        "[worker.x]\nexec = [\"/bin/x\"]\ncredentials = { uid = \"root\" }\n",
    );
    if let Some(etc) = etc {
        t.write("etc/x.toml", etc);
    }
    t
}

#[test]
fn fill_inserts_inside_an_existing_inline_table() {
    let t = one_worker(
        "inline",
        Some("# my note\n[worker.x]\nrestart = { policy = \"always\" }  # keep\n"),
    );
    let db = t.db(None);
    let (code, _out, err) = t.fill(&["worker.x"]);
    assert_eq!(code, 0, "{err}");
    let x = t.read("etc/x.toml");
    parses(&x);
    assert!(x.starts_with("# my note\n[worker.x]\n"), "{x}");
    assert!(
        x.contains(
            "\nrestart = { policy = \"always\", max = 0, window = \"0ms\", delay = \"1000ms\" }  # keep\n"
        ),
        "{x}"
    );
    assert!(!x.contains("restart."), "{x}");
    assert!(t.db(None) == db, "the database changed:\n{x}");
}

#[test]
fn fill_uses_a_standard_subtable_when_one_exists() {
    let t = one_worker("subtable", Some("[worker.x.stop]\nmode = \"main\"\n"));
    let db = t.db(None);
    let (code, _out, err) = t.fill(&["worker.x"]);
    assert_eq!(code, 0, "{err}");
    let x = t.read("etc/x.toml");
    parses(&x);
    let stop = x.find("[worker.x.stop]\nmode = \"main\"\n").expect(&x);
    let grace = x
        .find(&format!("  grace = \"10000ms\"{FILLED}\n"))
        .expect(&x);
    assert!(grace > stop, "{x}");
    assert!(!x.contains("stop.grace"), "{x}");
    assert!(x.contains(&format!("cwd = \"/\"{FILLED}\n")), "{x}");
    assert!(t.db(None) == db, "the database changed:\n{x}");
}

#[test]
fn fill_extends_existing_dotted_keys() {
    let t = one_worker(
        "dotted",
        Some("[worker.x]\nrestart.policy = \"always\"\n# after\numask = 0o027\n"),
    );
    let db = t.db(None);
    let (code, _out, err) = t.fill(&["worker.x"]);
    assert_eq!(code, 0, "{err}");
    let x = t.read("etc/x.toml");
    parses(&x);
    assert!(x.contains("restart.policy = \"always\"\n"), "{x}");
    assert!(x.contains(&format!("restart.max = 0{FILLED}\n")), "{x}");
    assert!(x.contains("# after\numask = 0o027\n"), "{x}");
    assert_eq!(x.matches("umask").count(), 1, "{x}");
    assert!(t.db(None) == db, "the database changed:\n{x}");
}

#[test]
fn fill_writes_a_template_key_once_into_the_template() {
    let t = TempDir::new("template");
    t.write(
        "vendor/t.toml",
        "[template.t]\ncredentials = { uid = \"root\" }\n",
    );
    t.write(
        "vendor/a.toml",
        "[worker.a]\nexec = [\"/bin/a\"]\ntemplate = \"t\"\nrestart = { policy = \"always\" }\n",
    );
    t.write(
        "vendor/b.toml",
        "[worker.b]\nexec = [\"/bin/b\"]\ntemplate = \"t\"\n",
    );
    let db = t.db(None);
    let (code, _out, err) = t.fill(&["all"]);
    assert_eq!(code, 0, "{err}");
    let tt = t.read("etc/t.toml");
    parses(&tt);
    assert!(tt.starts_with("[template.t]\n"), "{tt}");
    assert_eq!(tt.matches("ready = \"pipe\"").count(), 1, "{tt}");
    // a sets restart itself, so its restart defaults go into its own table; b takes restart
    // from the template, so b's land there.
    assert_eq!(tt.matches("restart.max = 0").count(), 1, "{tt}");
    let a = t.read("etc/a.toml");
    assert!(a.starts_with("[worker.a]\n"), "{a}");
    assert!(a.contains(&format!("  restart.max = 0{FILLED}\n")), "{a}");
    assert!(!a.contains("ready"), "{a}");
    // b sets none of the filled fields: everything it lacks lands in the template.
    assert!(!t.0.join("etc/b.toml").exists());
    assert!(t.db(None) == db, "the database changed:\n{tt}\n{a}");
}

#[test]
fn fill_of_an_instance_fills_its_frame() {
    let t = TempDir::golden("instance");
    let (code, _out, err) = t.fill(&["worker.getty@tty1"]);
    assert_eq!(code, 0, "{err}");
    let tty = t.read("etc/tty-login.toml");
    assert!(
        tty.contains(&format!("  ready = \"pipe\"{FILLED}\n")),
        "{tty}"
    );
    assert!(!t.read("etc/sshd.toml").contains("filled by qctl"));
}

#[test]
fn dry_run_prints_a_diff_and_writes_nothing() {
    let t = TempDir::golden("dry-run");
    let before = t.snapshot();
    let (code, out, err) = t.fill(&["--dry-run", "worker.sshd", "worker.syslog-ng"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains(&format!("+  cwd = \"/\"{FILLED}\n")), "{out}");
    assert!(
        out.contains("-restart = { max = 9 }\n+restart = { max = 9, delay = \"1000ms\" }\n"),
        "{out}"
    );
    assert!(out.contains("--- /dev/null\n"), "{out}");
    assert!(out.contains("+[worker.syslog-ng]\n"), "{out}");
    assert!(t.snapshot() == before, "a dry run wrote");
    assert!(!t.0.join("etc/syslog-ng.toml").exists());
}

#[test]
fn fill_keeps_the_mode_of_a_file() {
    let t = TempDir::golden("mode");
    let sshd = t.0.join("etc/sshd.toml");
    std::fs::set_permissions(&sshd, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (code, _out, err) = t.fill(&["worker.sshd"]);
    assert_eq!(code, 0, "{err}");
    let meta = std::fs::metadata(&sshd).unwrap();
    assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
    assert!(t.read("etc/sshd.toml").contains("filled by qctl"));
    // No temporary file is left beside it.
    let names: Vec<_> = std::fs::read_dir(t.0.join("etc"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(names.iter().all(|n| !n.starts_with('.')), "{names:?}");
}

#[test]
fn fill_policy_writes_the_rule_defaults() {
    let t = TempDir::golden("policy");
    let policy = t.0.join("policy.toml");
    let text = "default = \"allow\"\n\n# the ssh daemon\n[[rule]]\nmatch = \"sshd\"\n\
                users = [\"root\"]\ncaps_max = [\"net_bind_service\", \"sys_chroot\", \"setuid\", \"setgid\"]\n\n\
                [[rule]]\nmatch = \"*\"\n";
    std::fs::write(&policy, text).unwrap();
    let db = t.db(Some(&policy));
    let arg = format!("--policy={}", policy.display());
    let (code, _out, err) = t.fill(&[&arg, "policy"]);
    assert_eq!(code, 0, "{err}");
    let p = std::fs::read_to_string(&policy).unwrap();
    parses(&p);
    assert!(
        p.starts_with("default = \"allow\"\n\n# the ssh daemon\n[[rule]]\nmatch = \"sshd\"\n"),
        "{p}"
    );
    assert_eq!(
        p.matches(&format!("  require_nnp = false{FILLED}\n"))
            .count(),
        2,
        "{p}"
    );
    assert_eq!(
        p.matches(&format!("  caps_max = []{FILLED}\n")).count(),
        1,
        "{p}"
    );
    assert_eq!(p.matches("users").count(), 1, "{p}");
    assert!(!p.contains("rlimits_max"), "{p}");
    assert!(t.db(Some(&policy)) == db, "the database changed:\n{p}");
    // Only the policy was the target: the layers are untouched.
    assert!(!t.read("etc/sshd.toml").contains("filled by qctl"));
}

#[test]
fn fill_refuses_a_single_layer() {
    let t = TempDir::golden("one-layer");
    let before = t.snapshot();
    let args: Vec<String> = [
        "fill",
        &format!("--layer=vendor={}", t.0.join("vendor").display()),
        "--no-policy",
        "all",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    let (code, _out, err) = qctl(&args);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("one layer"), "{err}");
    assert!(t.snapshot() == before, "a file changed");
}

#[test]
fn fill_refuses_a_file_toml_edit_would_reorder() {
    // The keys of one dotted table apart: toml_edit would write them together.
    let etc = "[worker.x]\nrestart.policy = \"always\"\ncwd = \"/\"\nrestart.max = 4\n";
    let t = one_worker("reorder", Some(etc));
    let (code, _out, err) = t.fill(&["worker.x"]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("byte for byte"), "{err}");
    assert_eq!(t.read("etc/x.toml"), etc);
}

#[test]
fn fill_writes_nothing_when_one_file_cannot_be_edited() {
    let t = TempDir::golden("all-or-nothing");
    // logd's amend table is fine; sshd's would be reordered.
    t.write(
        "etc/sshd.toml",
        "[worker.sshd]\nrestart.max = 9\nreload = \"SIGHUP\"\nrestart.delay = \"1s\"\n",
    );
    let before = t.snapshot();
    let (code, _out, err) = t.fill(&["all"]);
    assert_eq!(code, 1, "{err}");
    assert!(t.snapshot() == before, "a file was written");
}

#[test]
fn fill_refuses_a_symbolic_link_in_the_last_layer() {
    let t = TempDir::golden("symlink");
    let sshd = t.0.join("etc/sshd.toml");
    let elsewhere = t.0.join("sshd-elsewhere.toml");
    std::fs::rename(&sshd, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &sshd).unwrap();
    let target = std::fs::read(&elsewhere).unwrap();
    let before = t.snapshot();
    let (code, _out, err) = t.fill(&["worker.sshd"]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("symbolic link"), "{err}");
    assert!(t.snapshot() == before, "a file changed");
    assert!(
        std::fs::symlink_metadata(&sshd)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(
        std::fs::read(&elsewhere).unwrap() == target,
        "the link target changed"
    );
}

#[test]
fn a_default_the_template_users_disagree_on_stays_in_each_frame() {
    let t = TempDir::new("disagree");
    t.write(
        "vendor/t.toml",
        "[template.t]\ncredentials = { uid = \"root\" }\n",
    );
    t.write(
        "vendor/w.toml",
        "[worker.w]\nexec = [\"/bin/w\"]\ntemplate = \"t\"\n",
    );
    t.write(
        "vendor/f.toml",
        "[forager.f]\nexec = [\"/bin/f\"]\ntemplate = \"t\"\n",
    );
    let db = t.db(None);
    let (code, _out, err) = t.fill(&["all"]);
    assert_eq!(code, 0, "{err}");
    let (tt, w, f) = (
        t.read("etc/t.toml"),
        t.read("etc/w.toml"),
        t.read("etc/f.toml"),
    );
    // A worker is ready on "pipe", a forager on "exit": neither may go into the template.
    assert!(!tt.contains("ready"), "{tt}");
    assert!(w.contains(&format!("  ready = \"pipe\"{FILLED}\n")), "{w}");
    assert!(f.contains(&format!("  ready = \"exit\"{FILLED}\n")), "{f}");
    // The forager's start_timeout has no word, so the worker's goes into the worker.
    assert!(w.contains("start_timeout"), "{w}");
    assert!(!tt.contains("start_timeout") && !f.contains("start_timeout"));
    // What they agree on is written once, in the template.
    assert!(tt.contains(&format!("  cwd = \"/\"{FILLED}\n")), "{tt}");
    assert!(!w.contains("cwd") && !f.contains("cwd"));
    assert!(t.db(None) == db, "the database changed:\n{tt}\n{w}\n{f}");
    let (code, out, _) = t.fill(&["all"]);
    assert_eq!(code, 0);
    assert!(out.contains("nothing to fill"), "{out}");
}

#[test]
fn a_root_fill_refuses_a_tree_that_is_not_roots() {
    let t = TempDir::golden("root");
    let before = t.snapshot();
    let mut args = vec!["fill".to_owned()];
    args.extend(t.layer_args());
    args.extend(["--no-policy".to_owned(), "all".to_owned()]);
    let defaults = Defaults {
        vendor: "/nonexistent/vendor".into(),
        etc: "/nonexistent/etc".into(),
        policy: "/nonexistent/policy.toml".into(),
        euid: 0,
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = qctl::run_with(&args, &mut out, &mut err, &defaults);
    let err = String::from_utf8(err).unwrap();
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("owned by uid"), "{err}");
    assert!(out.is_empty());
    assert!(t.snapshot() == before, "a file changed");
}
