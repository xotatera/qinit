// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qctl compile` and the argument grammar.
use qctl::args::{self, Command, Outcome, PolicyChoice};
use qctl::compile::Defaults;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../qinit-frames/tests/golden");

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).to_owned()).collect()
}

fn qctl(args: &[&str]) -> (i32, String, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = qctl::run(&strings(args), &mut out, &mut err);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("qctl-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn compile_writes_the_same_bytes_as_the_library() {
    let dir = temp_dir("golden");
    let out = dir.join("colony.db").display().to_string();
    let dump = dir.join("colony.dump").display().to_string();
    let (code, _, err) = qctl(&[
        "compile",
        "--layer",
        &format!("vendor={GOLDEN}/vendor"),
        "--layer",
        &format!("etc={GOLDEN}/etc"),
        "--no-policy",
        "--output",
        &out,
        "--dump",
        &dump,
    ]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        std::fs::read(&out).unwrap(),
        std::fs::read(format!("{GOLDEN}/expected.db")).unwrap()
    );
    assert_eq!(
        std::fs::read(&dump).unwrap(),
        std::fs::read(format!("{GOLDEN}/expected.dump")).unwrap()
    );
    assert_eq!(std::fs::metadata(&out).unwrap().mode() & 0o777, 0o644);
    let left: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
    assert_eq!(left.len(), 2, "no temporary file is left behind");
}

#[test]
fn a_frame_error_names_file_line_and_key() {
    let dir = temp_dir("bad");
    let layer = dir.join("layer");
    std::fs::create_dir_all(&layer).unwrap();
    std::fs::write(layer.join("x.toml"), "[worker.x]\nexec = 1\n").unwrap();
    let out = dir.join("colony.db");
    let run = || {
        qctl(&[
            "compile",
            &format!("--layer=l={}", layer.display()),
            "--no-policy",
            "--output",
            &out.display().to_string(),
        ])
    };
    // An unknown key: the compiler names the key itself, so the line is the key's.
    std::fs::write(
        layer.join("x.toml"),
        "[worker.x]\nexec = [\"a\"]\nbogus = 1\n",
    )
    .unwrap();
    let (code, _, err) = run();
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("x.toml:3: worker.x.bogus: "), "{err}");
    // A wrong type: qinit-frames reports the key of the frame (it does not say which field).
    std::fs::write(layer.join("x.toml"), "[worker.x]\nexec = 1\n").unwrap();
    let (code, _, err) = run();
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("x.toml:1: worker.x: "), "{err}");
    assert!(!out.exists());
}

#[test]
fn a_missing_named_layer_is_an_error_and_a_missing_default_etc_is_a_notice() {
    let dir = temp_dir("missing");
    let out = dir.join("colony.db").display().to_string();
    let (code, _, err) = qctl(&[
        "compile",
        "--layer",
        &format!("l={}/nope", dir.display()),
        "--no-policy",
        "--output",
        &out,
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("nope"), "{err}");

    let defaults = Defaults {
        vendor: format!("{GOLDEN}/vendor").into(),
        etc: dir.join("no-etc"),
        policy: dir.join("no-policy.toml"),
    };
    let (mut o, mut e) = (Vec::new(), Vec::new());
    let code = qctl::run_with(
        &strings(&["compile", "--output", &out]),
        &mut o,
        &mut e,
        &defaults,
    );
    let e = String::from_utf8(e).unwrap();
    assert_eq!(code, 0, "{e}");
    assert!(e.contains("etc layer") && e.contains("absent"), "{e}");
    assert!(e.contains("no policy file"), "{e}");
}

#[test]
fn usage_errors_exit_2() {
    assert_eq!(qctl(&["compile", "--bogus"]).0, 2);
    assert_eq!(qctl(&[]).0, 2);
    assert_eq!(qctl(&["nonsense"]).0, 2);
    assert_eq!(qctl(&["compile", "--layer", "nodir"]).0, 2);
    assert_eq!(qctl(&["compile", "--policy", "p", "--no-policy"]).0, 2);
}

#[test]
fn help_prints_the_grammar_and_exits_0() {
    let (code, out, _) = qctl(&["--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("qctl compile") && out.contains("qctl watch"));
}

#[test]
fn a_command_that_is_not_built_yet_is_a_usage_error() {
    let (code, _, err) = qctl(&["status", "worker.sshd"]);
    assert_eq!(code, 2);
    assert!(err.contains("not implemented yet"), "{err}");
}

fn parsed(a: &[&str]) -> args::Parsed {
    match args::parse(&strings(a)).unwrap() {
        Outcome::Run(p) => p,
        Outcome::Help => panic!("help"),
    }
}

#[test]
fn the_grammar_parses_every_command() {
    let p = parsed(&[
        "--socket=/s",
        "compile",
        "--output",
        "o",
        "--policy",
        "p",
        "--layer",
        "a=b",
    ]);
    assert_eq!(p.socket, PathBuf::from("/s"));
    let Command::Compile(c) = p.command else {
        panic!()
    };
    assert_eq!(c.policy, PolicyChoice::File("p".into()));
    assert_eq!(c.layers, vec![("a".to_owned(), PathBuf::from("b"))]);
    assert_eq!(
        parsed(&["compile"]).socket,
        PathBuf::from("/run/qinit/colony")
    );

    assert!(matches!(
        parsed(&["list", "foragers"]).command,
        Command::List { kind: 2 }
    ));
    assert!(matches!(
        parsed(&["restart", "worker.a", "--wait", "5"]).command,
        Command::Change { wait: Some(5), .. }
    ));
    assert!(matches!(
        parsed(&["reboot"]).command,
        Command::Shutdown { wait: None, .. }
    ));
    assert!(matches!(
        parsed(&["watch", "--all"]).command,
        Command::Watch { all: true, .. }
    ));
    let Command::Launch(l) = parsed(&[
        "launch",
        "worker.a",
        "--env",
        "K=V",
        "--fds",
        "stdin,stdout",
        "--pidfd",
        "--",
        "-x",
        "y",
    ])
    .command
    else {
        panic!()
    };
    assert_eq!(
        (l.env.len(), l.fds.stdin, l.fds.stderr, l.pidfd, l.wait),
        (1, true, false, true, 600_000)
    );
    assert_eq!(l.args, ["-x", "y"]);
    let Command::Run(r) = parsed(&[
        "run",
        "r.toml",
        "--name",
        "n",
        "--stop-mode",
        "cell",
        "--wait-ready",
    ])
    .command
    else {
        panic!()
    };
    assert!(r.stop_cell && r.wait_ready);
    assert!(matches!(
        parsed(&["fill", "--dry-run", "all"]).command,
        Command::Fill(_)
    ));
    assert!(matches!(
        parsed(&["show", "policy"]).command,
        Command::Show(_)
    ));
    assert!(matches!(
        parsed(&["refresh", "db"]).command,
        Command::Refresh { .. }
    ));
    assert!(matches!(
        parsed(&["status", "worker.a"]).command,
        Command::Status { .. }
    ));
    assert!(
        args::parse(&strings(&["run", "r.toml"])).is_err(),
        "--name is required"
    );
}
