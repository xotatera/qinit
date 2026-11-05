// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! D26 wired into `qctl compile`: a compile run "as root" (the euid injected through
//! `Defaults`) refuses a layer or a policy file that is not root's.
use qctl::compile::Defaults;
use qctl::owner::{collect, judge};
mod common;

use common::TempDir;
use std::path::{Path, PathBuf};

const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../qinit-frames/tests/golden");

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).to_owned()).collect()
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

/// A small root-owned directory that passes the check. A host without any fails the test rather
/// than skipping it: the list then needs a directory that host has.
fn clean_layer() -> PathBuf {
    const CANDIDATES: [&str; 8] = [
        "/usr/lib/binfmt.d",
        "/usr/lib/sysusers.d",
        "/usr/lib/modules-load.d",
        "/usr/share/factory",
        "/usr/local/src",
        "/usr/local/sbin",
        "/var/empty",
        "/usr/local",
    ];
    CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_dir() && collect(&[p]).is_ok_and(|e| judge(&e).is_ok()))
        .unwrap_or_else(|| panic!("no clean root-owned directory among {CANDIDATES:?}"))
}

#[test]
fn a_root_compile_refuses_a_layer_that_is_not_roots() {
    let tmp = TempDir::new("cown-layer");
    let dir = tmp.path();
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
}

#[test]
fn a_root_compile_refuses_a_policy_file_that_is_not_roots_with_a_clean_layer() {
    let layer = clean_layer();
    let tmp = TempDir::new("cown-policy");
    let dir = tmp.path();
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
}

#[test]
fn an_unprivileged_compile_prints_the_notice_and_goes_on() {
    let tmp = TempDir::new("cown-user");
    let dir = tmp.path();
    let out = dir.join("colony.db").display().to_string();
    let (code, err) = run(&["compile", "--no-policy", "--output", &out], 1000, &dir);
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("qctl: not root: the ownership of the policy and layers is not checked\n")
    );
}
