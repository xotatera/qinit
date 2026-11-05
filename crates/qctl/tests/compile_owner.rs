// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! D26 wired into `qctl compile`: a compile run "as root" (the euid injected through
//! `Defaults`) refuses a layer or a policy file that is not root's.
use qctl::compile::Defaults;
use qctl::owner::{collect, judge};
use std::path::{Path, PathBuf};

const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../qinit-frames/tests/golden");

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).to_owned()).collect()
}

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("qctl-cown-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run(args: &[&str], euid: u32, dir: &Path) -> (i32, String) {
    let defaults = Defaults {
        vendor: format!("{GOLDEN}/vendor").into(),
        etc: dir.join("no-etc"),
        policy: dir.join("no-policy.toml"),
        euid,
    };
    let (mut o, mut e) = (Vec::new(), Vec::new());
    let code = qctl::run_with(&strings(args), &mut o, &mut e, &defaults);
    (code, String::from_utf8(e).unwrap())
}

/// The refusal text the check gives for `path` alone.
fn expected(path: &Path) -> String {
    format!("{}\n", judge(&collect(&[path]).unwrap()).unwrap_err())
}

/// A small root-owned directory that passes the check, or None on a host without one.
fn clean_layer() -> Option<PathBuf> {
    [
        "/usr/lib/binfmt.d",
        "/usr/lib/sysusers.d",
        "/usr/share/factory",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.is_dir() && judge(&collect(&[p]).unwrap()).is_ok())
}

#[test]
fn a_root_compile_refuses_a_layer_that_is_not_roots() {
    let dir = temp_dir("layer");
    let layer = dir.join("layer");
    std::fs::create_dir_all(&layer).unwrap();
    let out = dir.join("colony.db").display().to_string();
    let l = format!("l={}", layer.display());
    let (code, err) = run(
        &["compile", "--layer", &l, "--no-policy", "--output", &out],
        0,
        &dir,
    );
    assert_eq!(code, 1, "{err}");
    assert_eq!(err, expected(&layer));
    assert!(err.starts_with("qctl: ") && err.contains("the policy and the layers must be root's"));
    assert!(!Path::new(&out).exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_root_compile_refuses_a_policy_file_that_is_not_roots_with_a_clean_layer() {
    let Some(layer) = clean_layer() else {
        eprintln!("no clean root-owned layer on this host; skipped");
        return;
    };
    let dir = temp_dir("policy");
    let policy = dir.join("policy.toml");
    std::fs::write(&policy, "").unwrap();
    let out = dir.join("colony.db").display().to_string();
    let args = [
        "compile",
        "--layer",
        &format!("l={}", layer.display()),
        "--policy",
        &policy.display().to_string(),
        "--output",
        &out,
    ];
    let (code, err) = run(&args, 0, &dir);
    assert_eq!(code, 1, "{err}");
    assert_eq!(err, expected(&policy));
    assert!(!Path::new(&out).exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unprivileged_compile_prints_the_notice_and_goes_on() {
    let dir = temp_dir("user");
    let out = dir.join("colony.db").display().to_string();
    let (code, err) = run(&["compile", "--no-policy", "--output", &out], 1000, &dir);
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("qctl: not root: the ownership of the policy and layers is not checked\n")
    );
    let _ = std::fs::remove_dir_all(&dir);
}
