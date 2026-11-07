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
    // The forager's start_timeout "none" is written like any default.
    let mount = t.read("etc/mount-var.toml");
    assert!(
        mount.contains(&format!("  ready = \"exit\"{FILLED}\n")),
        "{mount}"
    );
    assert!(
        mount.contains(&format!("  start_timeout = \"none\"{FILLED}\n")),
        "{mount}"
    );
    // sandbox.user_map "own" is written too; errors is derived.
    for text in [&sshd, &syslog, &tty, &mount] {
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
    let db = t.db(None);
    let (code, _out, err) = t.fill(&["worker.getty@tty1"]);
    assert_eq!(code, 0, "{err}");
    let tty = t.read("etc/tty-login.toml");
    assert!(
        tty.contains(&format!("  ready = \"pipe\"{FILLED}\n")),
        "{tty}"
    );
    assert!(!t.read("etc/sshd.toml").contains("filled by qctl"));
    assert!(t.db(None) == db, "the database changed:\n{tty}");
    let once = t.snapshot();
    let (code, out, err) = t.fill(&["worker.getty@tty1"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("nothing to fill"), "{out}");
    assert!(t.snapshot() == once, "the second fill changed a file");
}

#[test]
fn fill_of_a_template_writes_only_what_goes_into_the_template() {
    let t = TempDir::new("template-target");
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
    let (code, out, err) = t.fill(&["template.t"]);
    assert_eq!(code, 0, "{err}");
    let tt = t.read("etc/t.toml");
    assert!(tt.starts_with("[template.t]\n"), "{tt}");
    assert!(
        tt.contains(&format!("  ready = \"pipe\"{FILLED}\n")),
        "{tt}"
    );
    // a's own restart defaults belong to a, not to the template: a template target leaves them.
    assert!(!t.0.join("etc/a.toml").exists());
    assert!(!t.0.join("etc/b.toml").exists());
    assert!(out.ends_with("in 1 files\n"), "{out}");
    assert!(t.db(None) == db, "the database changed:\n{tt}");
    let (code, _out, err) = t.fill(&["template.nope"]);
    assert_eq!(code, 1);
    assert!(err.contains("no frame template.nope"), "{err}");
}

#[test]
fn the_summary_counts_only_the_files_written() {
    let t = one_worker("summary", Some("[worker.x]\ncwd = \"/\"\n"));
    let x = t.0.join("etc/x.toml");
    let y = t.0.join("etc/y.toml");
    let before = t.read("etc/x.toml");
    let edit = |file: &Path, key: &str, value: &str| qctl::fill::Edit {
        file: file.to_path_buf(),
        table: vec!["worker".into(), "x".into()],
        key: key.into(),
        value: value.into(),
    };
    // x already has cwd: its edit inserts nothing; y gains one key.
    let edits = [edit(&x, "cwd", "\"/\""), edit(&y, "umask", "0o027")];
    let done = qctl::fill::apply(&edits, false, &mut Vec::new()).unwrap();
    assert_eq!(done, qctl::fill::Applied { keys: 1, files: 1 });
    assert_eq!(t.read("etc/x.toml"), before);
    assert!(t.read("etc/y.toml").contains("umask = 0o027"));
}

#[test]
fn a_file_that_cannot_be_staged_leaves_every_file_as_it_was() {
    let t = one_worker("staged", Some("[worker.x]\n"));
    let closed = t.0.join("closed");
    std::fs::create_dir_all(&closed).unwrap();
    std::fs::write(closed.join("z.toml"), "[worker.x]\n").unwrap();
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o555)).unwrap();
    // Root writes into a 0555 directory anyway: then there is nothing to test.
    let writable_anyway = std::fs::write(closed.join("probe"), "").is_ok();
    let edit = |file: PathBuf| qctl::fill::Edit {
        file,
        table: vec!["worker".into(), "x".into()],
        key: "umask".into(),
        value: "0o027".into(),
    };
    // A new file in a new directory, staged before z.toml fails: its directory goes too.
    let edits = [
        edit(t.0.join("etc/x.toml")),
        edit(t.0.join("etc/new/n.toml")),
        edit(closed.join("z.toml")),
    ];
    let r = qctl::fill::apply(&edits, false, &mut Vec::new());
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o755)).unwrap();
    if writable_anyway {
        return;
    }
    let e = r.unwrap_err();
    assert!(e.to_string().contains("z.toml"), "{e}");
    // x.toml was staged first and is untouched; its temporary file is gone.
    assert_eq!(t.read("etc/x.toml"), "[worker.x]\n");
    let names: Vec<_> = std::fs::read_dir(t.0.join("etc"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, ["x.toml"]);
}

#[test]
fn an_absent_default_etc_layer_is_created_and_filled() {
    let t = one_worker("no-etc", None);
    let etc = t.0.join("no-etc/frames");
    let defaults = Defaults {
        vendor: t.0.join("vendor"),
        etc: etc.clone(),
        policy: "/nonexistent/policy.toml".into(),
        euid: 1000,
    };
    let args: Vec<String> = ["fill", "--no-policy", "all"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = qctl::run_with(&args, &mut out, &mut err, &defaults);
    let err = String::from_utf8(err).unwrap();
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("etc layer") && err.contains("absent"), "{err}");
    let x = std::fs::read_to_string(etc.join("x.toml")).unwrap();
    assert!(x.starts_with("[worker.x]\n"), "{x}");
    assert!(x.contains(&format!("  cwd = \"/\"{FILLED}\n")), "{x}");
}

#[test]
fn where_an_absent_etc_layer_would_be_created_is_checked_as_root() {
    let t = TempDir::new("creatable");
    // Below the user's scratch directory: not root's, so nothing may be created there as root.
    let r = qctl::owner::creatable(&t.0.join("no-etc/frames"));
    assert!(
        matches!(r, Err(qctl::owner::Refusal::Owner { .. })),
        "{r:?}"
    );
    assert!(!t.0.join("no-etc").exists());
    // Below a root-owned directory nobody else may write: allowed.
    if qctl::owner::judge(&qctl::owner::ancestors(Path::new("/usr")).unwrap()).is_ok() {
        assert!(qctl::owner::creatable(Path::new("/usr/qctl-no-such/frames")).is_ok());
    }
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
fn a_file_without_a_final_newline_or_with_crlf_is_refused_with_the_reason() {
    for (tag, etc, why) in [
        (
            "no-newline",
            "[worker.x]\numask = 0o027",
            "does not end in a newline",
        ),
        ("crlf", "[worker.x]\r\numask = 0o027\r\n", "CRLF line ends"),
    ] {
        let t = one_worker(tag, Some(etc));
        let (code, _out, err) = t.fill(&["worker.x"]);
        assert_eq!(code, 1, "{err}");
        assert!(err.contains(why), "{tag}: {err}");
        assert_eq!(t.read("etc/x.toml"), etc);
    }
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
    // The forager's start_timeout is "none", the worker's 90000ms: they disagree, so each frame
    // gets its own.
    assert!(w.contains("start_timeout = \"90000ms\""), "{w}");
    assert!(f.contains("start_timeout = \"none\""), "{f}");
    assert!(!tt.contains("start_timeout"), "{tt}");
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

#[test]
fn fill_writes_both_defaults_and_the_database_is_unchanged() {
    let t = TempDir::new("d58");
    t.write(
        "vendor/x.toml",
        "[worker.x]\nexec = [\"/bin/x\"]\ncredentials = { uid = \"root\" }\n\
         [forager.m]\nexec = [\"/bin/m\"]\ncredentials = { uid = \"root\" }\nready = \"exit\"\n",
    );
    let before = t.db(None);
    let (code, _out, err) = t.fill(&["all"]);
    assert_eq!(code, 0, "{err}");
    let text = t.read("etc/x.toml");
    assert!(
        text.contains(&format!("  start_timeout = \"none\"{FILLED}\n")),
        "{text}"
    );
    assert!(
        text.contains(&format!("  sandbox.user_map = \"own\"{FILLED}\n")),
        "{text}"
    );
    assert!(t.db(None) == before, "the database changed:\n{text}");
}

/// What a file is: its bytes, mode, owner and inode.
#[derive(Debug, PartialEq, Eq)]
struct FileState {
    bytes: Vec<u8>,
    mode: u32,
    uid: u32,
    gid: u32,
    ino: u64,
}

fn file_state(p: &Path) -> FileState {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(p).unwrap();
    FileState {
        bytes: std::fs::read(p).unwrap(),
        mode: m.mode() & 0o7777,
        uid: m.uid(),
        gid: m.gid(),
        ino: m.ino(),
    }
}

/// The names in `dir`, sorted.
fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    v.sort();
    v
}

/// An edit inserting `umask` into `[worker.x]` of `file`.
fn umask_edit(file: PathBuf) -> qctl::fill::Edit {
    qctl::fill::Edit {
        file,
        table: vec!["worker".into(), "x".into()],
        key: "umask".into(),
        value: "0o027".into(),
    }
}

/// A group of this process other than the group a file it makes gets, if it has one: a file of
/// that group shows whether `fill` keeps a file's group without needing root.
fn other_group(made: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    let own = std::fs::metadata(made).unwrap().gid();
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let groups = status.lines().find_map(|l| l.strip_prefix("Groups:"))?;
    groups
        .split_whitespace()
        .filter_map(|g| g.parse().ok())
        .find(|&g| g != own)
}

/// Three existing files in two directories (modes 0600, 0640, 0604) and a new one in a new
/// directory, second in the order of the edits. `vendor/c.toml` is in another group of this
/// process when it has one.
fn four_files(tag: &str) -> (TempDir, Vec<qctl::fill::Edit>) {
    let t = TempDir::new(tag);
    for (rel, text, mode) in [
        ("etc/a.toml", "[worker.x]\n# a\n", 0o600),
        ("etc/b.toml", "# b\n[worker.x]\n", 0o640),
        ("vendor/c.toml", "[worker.x]\ncwd = \"/\"\n", 0o604),
    ] {
        t.write(rel, text);
        std::fs::set_permissions(t.0.join(rel), std::fs::Permissions::from_mode(mode)).unwrap();
    }
    let c = t.0.join("vendor/c.toml");
    if let Some(g) = other_group(&c) {
        std::os::unix::fs::chown(&c, None, Some(g)).unwrap();
    }
    let edits = vec![
        umask_edit(t.0.join("etc/a.toml")),
        umask_edit(t.0.join("etc/new/sub/n.toml")),
        umask_edit(t.0.join("etc/b.toml")),
        umask_edit(t.0.join("vendor/c.toml")),
    ];
    (t, edits)
}

const OLD_FILES: [&str; 3] = ["etc/a.toml", "etc/b.toml", "vendor/c.toml"];

/// The steps of committing [`four_files`]: the backups of a, b and c (0 to 2), then a's rename
/// (3), the new file's link and the removal of its temporary name (4, 5), b's and c's renames
/// (6, 7).
const STEPS: usize = 8;

/// `.<name>.qctl-old-<pid>` beside `rel` in `t`.
fn backup_of(t: &TempDir, rel: &str) -> PathBuf {
    let p = t.0.join(rel);
    let name = p.file_name().unwrap().to_str().unwrap().to_owned();
    p.with_file_name(format!(".{name}.qctl-old-{}", std::process::id()))
}

#[test]
fn a_failure_at_any_commit_step_leaves_every_file_as_it_was() {
    let mut failed = 0;
    for n in 0..64 {
        let (t, edits) = four_files(&format!("undo-{n}"));
        let before: Vec<FileState> = OLD_FILES.iter().map(|r| file_state(&t.0.join(r))).collect();
        let mut fault = |i: usize| {
            if i == n {
                Err(std::io::Error::other("injected fault"))
            } else {
                Ok(())
            }
        };
        match qctl::fill::apply_with(&edits, false, &mut Vec::new(), &mut fault) {
            Err(e) => {
                failed += 1;
                let msg = e.to_string();
                assert!(msg.contains("injected fault"), "step {n}: {msg}");
                assert!(!msg.contains("undoing failed"), "step {n}: {msg}");
                for (rel, was) in OLD_FILES.iter().zip(&before) {
                    assert_eq!(&file_state(&t.0.join(rel)), was, "step {n}: {rel}");
                }
                assert!(
                    !t.0.join("etc/new").exists(),
                    "step {n}: the new directory stays"
                );
                assert_eq!(names(&t.0.join("etc")), ["a.toml", "b.toml"], "step {n}");
                assert_eq!(names(&t.0.join("vendor")), ["c.toml"], "step {n}");
            }
            Ok(done) => {
                // The fault never fired: every step ran, and each of them failed in its turn.
                assert_eq!(failed, STEPS);
                assert_eq!(done, qctl::fill::Applied { keys: 4, files: 4 });
                // A replaced file is a new inode, so its owner is what `fill` gave it. Run as a
                // user other than root the uid cannot differ, and the gid only shows for
                // `vendor/c.toml` in another group (see `four_files`); the undo cases above
                // prove the owner by the inode, which is the old file's.
                for (rel, was) in OLD_FILES.iter().zip(&before) {
                    let now = file_state(&t.0.join(rel));
                    assert_ne!(now.ino, was.ino, "{rel} was not replaced");
                    assert_eq!(now.mode, was.mode, "{rel}");
                    assert_eq!((now.uid, now.gid), (was.uid, was.gid), "{rel}");
                    assert!(t.read(rel).contains("umask = 0o027"), "{rel}");
                }
                assert!(t.read("etc/new/sub/n.toml").contains("umask = 0o027"));
                assert_eq!(names(&t.0.join("etc")), ["a.toml", "b.toml", "new"]);
                assert_eq!(names(&t.0.join("etc/new/sub")), ["n.toml"]);
                assert_eq!(names(&t.0.join("vendor")), ["c.toml"]);
                return;
            }
        }
    }
    panic!("the commit never succeeded");
}

#[test]
fn a_stale_backup_stops_the_run_with_nothing_changed() {
    let (t, edits) = four_files("stale");
    let stale =
        t.0.join(format!("etc/.b.toml.qctl-old-{}", std::process::id()));
    std::fs::write(&stale, "stale\n").unwrap();
    let before: Vec<FileState> = OLD_FILES.iter().map(|r| file_state(&t.0.join(r))).collect();
    let stale_before = file_state(&stale);
    let e = qctl::fill::apply(&edits, false, &mut Vec::new()).unwrap_err();
    assert!(e.to_string().contains(&stale.display().to_string()), "{e}");
    for (rel, was) in OLD_FILES.iter().zip(&before) {
        assert_eq!(&file_state(&t.0.join(rel)), was, "{rel}");
    }
    assert_eq!(file_state(&stale), stale_before);
    assert!(!t.0.join("etc/new").exists(), "the new directory stays");
    let stale_name = stale.file_name().unwrap().to_str().unwrap().to_owned();
    assert_eq!(
        names(&t.0.join("etc")),
        [stale_name.as_str(), "a.toml", "b.toml"]
    );
    assert_eq!(names(&t.0.join("vendor")), ["c.toml"]);
}

#[test]
fn an_undo_that_fails_is_reported_and_the_old_text_stays_at_its_backup() {
    let (t, edits) = four_files("undo-fails");
    let a = t.0.join("etc/a.toml");
    let backup =
        t.0.join(format!("etc/.a.toml.qctl-old-{}", std::process::id()));
    let a_before = file_state(&a);
    let rest: Vec<FileState> = OLD_FILES[1..]
        .iter()
        .map(|r| file_state(&t.0.join(r)))
        .collect();
    // Step 4 comes after a.toml is replaced: a directory in its place makes renaming the backup
    // back fail.
    let mut fault = |i: usize| {
        if i == 4 {
            std::fs::remove_file(&a).unwrap();
            std::fs::create_dir(&a).unwrap();
            Err(std::io::Error::other("injected fault"))
        } else {
            Ok(())
        }
    };
    let e = qctl::fill::apply_with(&edits, false, &mut Vec::new(), &mut fault).unwrap_err();
    let msg = e.to_string();
    assert!(msg.contains("injected fault"), "{msg}");
    assert!(msg.contains("undoing failed"), "{msg}");
    assert!(msg.contains(&backup.display().to_string()), "{msg}");
    assert_eq!(file_state(&backup), a_before);
    for (rel, was) in OLD_FILES[1..].iter().zip(&rest) {
        assert_eq!(&file_state(&t.0.join(rel)), was, "{rel}");
    }
    assert!(!t.0.join("etc/new").exists(), "the new directory stays");
    let backup_name = backup.file_name().unwrap().to_str().unwrap().to_owned();
    assert_eq!(
        names(&t.0.join("etc")),
        [backup_name.as_str(), "a.toml", "b.toml"]
    );
}

#[test]
fn a_backup_that_cannot_be_linked_stops_the_run_with_nothing_changed() {
    let (t, edits) = four_files("nolink");
    let before: Vec<FileState> = OLD_FILES.iter().map(|r| file_state(&t.0.join(r))).collect();
    // Step 1 is the link of b's backup, after a's: refused as `fs.protected_hardlinks` refuses
    // the link of a file the caller does not own.
    let mut fault = |i: usize| {
        if i == 1 {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        } else {
            Ok(())
        }
    };
    let e = qctl::fill::apply_with(&edits, false, &mut Vec::new(), &mut fault).unwrap_err();
    let msg = e.to_string();
    let b = t.0.join("etc/b.toml");
    assert!(
        msg.contains(&format!("{}: cannot link its backup", b.display())),
        "{msg}"
    );
    assert!(msg.ends_with("; every file is as it was"), "{msg}");
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    for (rel, was) in OLD_FILES.iter().zip(&before) {
        assert_eq!(&file_state(&t.0.join(rel)), was, "{rel}");
    }
    assert!(!t.0.join("etc/new").exists(), "the new directory stays");
    // a's backup, linked before b's failed, is gone with the temporary files.
    assert_eq!(names(&t.0.join("etc")), ["a.toml", "b.toml"]);
    assert_eq!(names(&t.0.join("vendor")), ["c.toml"]);
}

#[test]
fn a_new_directory_something_else_was_put_in_stays_and_is_named() {
    let (t, edits) = four_files("foreign");
    let before: Vec<FileState> = OLD_FILES.iter().map(|r| file_state(&t.0.join(r))).collect();
    let sub = t.0.join("etc/new/sub");
    // Step 6 is b's rename, after the new file is in place: another writer puts a file of its own
    // in the new directory, and the step fails.
    let mut fault = |i: usize| {
        if i == 6 {
            std::fs::write(sub.join("other.toml"), "# other\n").unwrap();
            Err(std::io::Error::other("injected fault"))
        } else {
            Ok(())
        }
    };
    let e = qctl::fill::apply_with(&edits, false, &mut Vec::new(), &mut fault).unwrap_err();
    let msg = e.to_string();
    assert!(msg.contains("injected fault"), "{msg}");
    assert!(!msg.contains("undoing failed"), "{msg}");
    assert!(
        msg.ends_with(&format!(
            "; every file is as it was, but {}: made for a new file, it stays: something else \
             is in it",
            sub.display()
        )),
        "{msg}"
    );
    for (rel, was) in OLD_FILES.iter().zip(&before) {
        assert_eq!(&file_state(&t.0.join(rel)), was, "{rel}");
    }
    // Only the other writer's file is left there; the new file is gone.
    assert_eq!(names(&sub), ["other.toml"]);
    assert_eq!(names(&t.0.join("etc")), ["a.toml", "b.toml", "new"]);
}

#[test]
fn a_backup_already_gone_after_the_last_file_is_no_failure() {
    let (t, edits) = four_files("gone");
    let a_backup = backup_of(&t, "etc/a.toml");
    // Before the last step every backup is linked; a's is removed by someone else.
    let mut fault = |i: usize| {
        if i == STEPS - 1 {
            std::fs::remove_file(&a_backup).unwrap();
        }
        Ok(())
    };
    let done = qctl::fill::apply_with(&edits, false, &mut Vec::new(), &mut fault).unwrap();
    assert_eq!(done, qctl::fill::Applied { keys: 4, files: 4 });
    for rel in OLD_FILES {
        assert!(t.read(rel).contains("umask = 0o027"), "{rel}");
    }
    assert_eq!(names(&t.0.join("etc")), ["a.toml", "b.toml", "new"]);
    assert_eq!(names(&t.0.join("vendor")), ["c.toml"]);
}

#[test]
fn a_failure_after_the_last_file_is_replaced_is_reported_and_not_undone() {
    let (t, edits) = four_files("after");
    let a_backup = backup_of(&t, "etc/a.toml");
    // Before the last step a's backup is replaced by a directory, which no file removal takes.
    let mut fault = |i: usize| {
        if i == STEPS - 1 {
            std::fs::remove_file(&a_backup).unwrap();
            std::fs::create_dir(&a_backup).unwrap();
        }
        Ok(())
    };
    let e = qctl::fill::apply_with(&edits, false, &mut Vec::new(), &mut fault).unwrap_err();
    let msg = e.to_string();
    assert!(
        msg.starts_with(&format!(
            "every file is filled, but {}: cannot remove this backup: ",
            a_backup.display()
        )),
        "{msg}"
    );
    for rel in OLD_FILES {
        assert!(t.read(rel).contains("umask = 0o027"), "{rel}");
    }
    assert!(t.read("etc/new/sub/n.toml").contains("umask = 0o027"));
    // The other backups are removed all the same.
    assert!(!backup_of(&t, "etc/b.toml").exists());
    assert!(!backup_of(&t, "vendor/c.toml").exists());
}
