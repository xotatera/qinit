// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use xtask::duplication::cli::{DupArgs, run};
use xtask::duplication::files::rust_files;
use xtask::duplication::{BASELINE, gate};

/// A body far above any floor `dup sweep` offers (largest: 120 tokens).
fn long_fn(name: &str, var: &str) -> String {
    let mut body = String::new();
    for i in 0..40 {
        let _ = writeln!(body, "    {var} += x * {i};");
    }
    format!("pub fn {name}(x: u64) -> u64 {{\n    let mut {var} = 0;\n{body}    {var}\n}}\n")
}

/// A scratch directory removed when the test ends, pass or fail.
struct Scratch(PathBuf);

impl Scratch {
    fn join(&self, p: &str) -> PathBuf {
        self.0.join(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!("xtask-dup-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::create_dir_all(dir.join("gates")).unwrap();
    Scratch(dir)
}

#[test]
fn a_new_duplicate_fails_and_says_how_to_proceed() {
    let dir = scratch("new");
    fs::write(
        dir.join("src/lib.rs"),
        long_fn("a", "acc") + &long_fn("b", "sum"),
    )
    .unwrap();
    let err = gate(&dir.0).unwrap_err();
    assert!(
        err.contains("src/lib.rs::a") && err.contains("src/lib.rs::b"),
        "{err}"
    );
    assert!(err.contains("renamed or moved"), "{err}");
}

#[test]
fn a_baselined_duplicate_passes() {
    let dir = scratch("baselined");
    fs::write(
        dir.join("src/lib.rs"),
        long_fn("a", "acc") + &long_fn("b", "sum"),
    )
    .unwrap();
    fs::write(
        dir.join(BASELINE),
        "src/lib.rs::a | src/lib.rs::b  # test\n",
    )
    .unwrap();
    assert_eq!(gate(&dir.0), Ok(()));
}

#[test]
fn renaming_a_baselined_function_fails() {
    let dir = scratch("renamed");
    fs::write(
        dir.join("src/lib.rs"),
        long_fn("a", "acc") + &long_fn("c", "sum"),
    )
    .unwrap();
    fs::write(
        dir.join(BASELINE),
        "src/lib.rs::a | src/lib.rs::b  # test\n",
    )
    .unwrap();
    assert!(gate(&dir.0).is_err());
}

#[test]
fn removing_a_copy_passes() {
    let dir = scratch("removed");
    fs::write(dir.join("src/lib.rs"), long_fn("a", "acc")).unwrap();
    fs::write(
        dir.join(BASELINE),
        "src/lib.rs::a | src/lib.rs::b  # test\n",
    )
    .unwrap();
    assert_eq!(gate(&dir.0), Ok(()));
}

#[test]
fn duplicates_in_tests_do_not_count() {
    let dir = scratch("tests");
    fs::create_dir_all(dir.join("tests")).unwrap();
    fs::write(dir.join("src/lib.rs"), long_fn("a", "acc")).unwrap();
    fs::write(
        dir.join("tests/it.rs"),
        long_fn("t1", "acc") + &long_fn("t2", "sum"),
    )
    .unwrap();
    assert_eq!(gate(&dir.0), Ok(()));
}

#[test]
fn no_input_is_a_failure_not_a_pass() {
    let dir = scratch("empty");
    assert!(gate(&dir.0).unwrap_err().contains("no Rust functions"));
}

#[test]
fn bless_on_an_empty_scan_refuses_and_keeps_the_baseline() {
    let dir = scratch("bless-empty");
    let entry = "src/lib.rs::a | src/lib.rs::b  # keep\n";
    fs::write(dir.join(BASELINE), entry).unwrap();
    let err = run(&DupArgs::Bless, &dir.0).unwrap_err();
    assert!(err.contains("no Rust functions"), "{err}");
    assert_eq!(fs::read_to_string(dir.join(BASELINE)).unwrap(), entry);
}

#[test]
fn rust_files_uses_git_and_honours_ignores_and_deletions() {
    let dir = scratch("git-list");
    let git = |args: &[&str]| {
        let st = xtask::git::command()
            .args(["-c", "user.name=t", "-c", "user.email=t@t"])
            .args(args)
            .current_dir(&dir.0)
            .status()
            .unwrap();
        assert!(st.success(), "git {args:?}");
    };
    git(&["init", "-q"]);
    fs::write(dir.join(".gitignore"), "ignored/\n").unwrap();
    fs::write(dir.join("src/gone.rs"), "fn g() {}\n").unwrap();
    git(&["add", ".gitignore", "src/gone.rs"]);
    git(&["commit", "-q", "-m", "init"]);
    fs::remove_file(dir.join("src/gone.rs")).unwrap();
    fs::write(dir.join("src/lib.rs"), "fn a() {}\n").unwrap();
    fs::create_dir_all(dir.join("ignored")).unwrap();
    fs::write(dir.join("ignored/x.rs"), "fn x() {}\n").unwrap();
    // A plain directory walk would list ignored/x.rs; only git knows to skip it.
    assert_eq!(rust_files(&dir.0).unwrap(), vec!["src/lib.rs".to_string()]);
}

#[test]
fn cli_parses_and_rejects() {
    use xtask::duplication::cli::{DupArgs, parse};
    assert_eq!(parse(&["sweep"]), Ok(DupArgs::Sweep { path: None }));
    assert_eq!(
        parse(&["report", "--loose", "--min-tokens", "30", "--path", "/r"]),
        Ok(DupArgs::Report {
            path: Some("/r".into()),
            min_tokens: Some(30),
            include_tests: false,
            loose: true
        })
    );
    assert_eq!(parse(&["bless"]), Ok(DupArgs::Bless));
    assert!(parse(&["bless", "--loose"]).is_err());
    assert!(parse(&["report", "--min-tokens", "x"]).is_err());
    assert!(parse(&[]).is_err());
}

#[test]
fn report_and_sweep_refuse_an_empty_scan() {
    let dir = scratch("empty-cli");
    for args in [
        DupArgs::Report {
            path: None,
            min_tokens: None,
            include_tests: false,
            loose: false,
        },
        DupArgs::Sweep { path: None },
    ] {
        let err = run(&args, &dir.0).unwrap_err();
        assert!(err.contains("no Rust functions"), "{args:?}: {err}");
    }
}

#[test]
fn excluded_directories_match_at_any_depth() {
    let dir = scratch("exclude");
    for p in [
        "vendor/top.rs",
        "crates/a/vendor/x.rs",
        "crates/a/src/lib.rs",
        "src/vendored.rs",
        "src/third_party/y.rs",
    ] {
        let path = dir.join(p);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "fn f() {}\n").unwrap();
    }
    // No git repository here, so this is the walk fallback.
    assert_eq!(
        rust_files(&dir.0).unwrap(),
        vec![
            "crates/a/src/lib.rs".to_string(),
            "src/vendored.rs".to_string()
        ]
    );
}

#[test]
fn a_non_utf8_file_name_is_an_error_not_skipped() {
    use std::os::unix::ffi::OsStrExt as _;
    let dir = scratch("non-utf8");
    let ok = xtask::git::command()
        .args(["init", "-q"])
        .current_dir(&dir.0)
        .status()
        .unwrap()
        .success();
    assert!(ok);
    let name = std::ffi::OsStr::from_bytes(b"src/bad\xff.rs");
    fs::write(dir.0.join(name), "fn f() {}\n").unwrap();
    let err = rust_files(&dir.0).unwrap_err();
    assert!(err.contains("non-UTF-8 file name"), "{err}");
}

#[test]
fn a_git_failure_other_than_no_repository_is_an_error() {
    let dir = scratch("bad-index");
    let ok = xtask::git::command()
        .args(["init", "-q"])
        .current_dir(&dir.0)
        .status()
        .unwrap()
        .success();
    assert!(ok);
    fs::write(dir.0.join("src/lib.rs"), "fn a() {}\n").unwrap();
    fs::write(dir.0.join(".git/index"), b"garbage").unwrap();
    let err = rust_files(&dir.0).unwrap_err();
    assert!(err.starts_with("git ls-files: "), "{err}");
}
