// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qctl compile` and the argument grammar.
use qctl::args::{self, Command, Outcome, PolicyChoice};
use qctl::compile::Defaults;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
mod common;

use common::TempDir;
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

#[test]
fn compile_writes_the_same_bytes_as_the_library() {
    let tmp = TempDir::new("golden");
    let dir = tmp.path();
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
    let left: Vec<_> = std::fs::read_dir(dir).unwrap().collect();
    assert_eq!(left.len(), 2, "no temporary file is left behind");
}

#[test]
fn a_frame_error_names_file_line_and_key() {
    let tmp = TempDir::new("bad");
    let dir = tmp.path();
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
    let tmp = TempDir::new("missing");
    let dir = tmp.path();
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
        euid: 1000,
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
fn watch_without_a_server_fails_with_exit_1() {
    let (code, out, err) = qctl(&["--socket", "/nonexistent/qctl-sock", "watch", "--all"]);
    assert_eq!((code, out.as_str()), (1, ""));
    assert!(err.starts_with("qctl: "), "{err}");
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
    // The run defaults are the client's `RunArgs` and the frames' (10 s grace, no ceilings).
    let Command::Run(r) = parsed(&["run", "r.toml", "--name", "n"]).command else {
        panic!()
    };
    assert_eq!(
        (r.stop_grace, r.memory_max, r.pids_max, r.stop_cell, r.wait),
        (10_000, 0, 0, false, 600_000)
    );
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

fn compile_golden(out: &str, dump: Option<&str>) -> (i32, String) {
    let vendor = format!("vendor={GOLDEN}/vendor");
    let mut a = vec![
        "compile",
        "--layer",
        &vendor,
        "--no-policy",
        "--output",
        out,
    ];
    if let Some(d) = dump {
        a.extend(["--dump", d]);
    }
    let (code, _, err) = qctl(&a);
    (code, err)
}

#[test]
fn a_symlink_at_the_temporary_name_is_refused_and_its_target_left_alone() {
    let tmp = TempDir::new("tmplink");
    let target = tmp.join("target");
    std::fs::write(&target, "keep").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = tmp.join("colony.db");
    let planted = tmp.join(format!("colony.db.tmp-{}", std::process::id()));
    std::os::unix::fs::symlink(&target, &planted).unwrap();
    let (code, err) = compile_golden(out.to_str().unwrap(), None);
    assert_eq!(code, 1, "{err}");
    assert!(
        err.starts_with("qctl: ") && err.contains("colony.db"),
        "{err}"
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    assert_eq!(std::fs::metadata(&target).unwrap().mode() & 0o777, 0o600);
    assert!(!out.exists());
    assert!(std::fs::symlink_metadata(&planted).unwrap().is_symlink());
}

#[test]
fn a_dump_that_cannot_be_written_leaves_no_database() {
    let tmp = TempDir::new("dumpfail");
    let out = tmp.join("colony.db");
    let dump = tmp.join("no-such-dir/colony.dump");
    let (code, err) = compile_golden(out.to_str().unwrap(), Some(dump.to_str().unwrap()));
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("colony.dump"), "{err}");
    assert!(!out.exists(), "the database is not left without its dump");
    let left: Vec<_> = std::fs::read_dir(tmp.path()).unwrap().collect();
    assert!(left.is_empty(), "{left:?}");
}

#[test]
fn a_root_compile_refuses_an_output_directory_that_is_not_roots() {
    let tmp = TempDir::new("outowner");
    let out = tmp.join("colony.db");
    // A root run reaches the output only past the layer check, and the checked-in golden tree
    // is the user's: the output is written through `write_output` itself, as root.
    let mut err = Vec::new();
    let r = qctl::compile::write_output(&out, b"db", None, 0, &mut err);
    assert!(r.is_err());
    let e = String::from_utf8(err).unwrap();
    assert!(
        e.starts_with("qctl: ") && e.contains("the output directory must be root's"),
        "{e}"
    );
    assert!(!out.exists());
}
