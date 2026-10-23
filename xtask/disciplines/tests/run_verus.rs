// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! A `kind = "verus"` proof end to end, in-process: `execute_with` on a
//! scratch workspace whose one proof entry is Verus. `cargo-verus` is a
//! stand-in that logs where it ran, the `RUSTUP_TOOLCHAIN` and
//! `CARGO_TARGET_DIR` it got, then prints the output and exits with the
//! code the test chose. Cargo's build directory is pinned inside the
//! scratch workspace, so a configured `build.build-dir` is not touched. The runner
//! drops the caller's `RUSTUP_TOOLCHAIN`; rustup's `cargo` proxy then sets
//! its own default for the subcommand, which the real `cargo-verus` replaces
//! with Verus's toolchain (spike S1). atc is hidden: a stand-in `atc` that
//! is not available.
//!
//! The tests re-run themselves as a child with that environment (`set_var`
//! is `unsafe`, which the workspace forbids); llvm-cov counts the child too.
use std::fs;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command as Proc;

use xtask::{Command, Runner, Scope, execute_with};

const MANIFEST: &str = r#"[workspace]
members = ["tooth"]
resolver = "3"

[workspace.metadata.disciplines]
proof_memory_budget = "4G"

[[workspace.metadata.disciplines.proof]]
name = "tooth"
kind = "verus"
package = "tooth"
memory = "1G"
"#;

const PASS: &str = "verification results:: 2 verified, 0 errors\n";
const FAIL: &str = "error: postcondition not satisfied\n  --> tooth/src/lib.rs:9:13\n\nverification results:: 1 verified, 1 errors\n";
const VACUOUS: &str = "verification results:: 0 verified, 0 errors\n";
/// `--no-cheating` rejecting line 3 (Verus 0.2026.10.04's wording).
const CHEAT: &str = "error: assume/admit not allowed with --no-cheating\n  --> tooth/src/lib.rs:3:13\n   |\nerror: could not compile `tooth` (lib) due to 1 previous error\n";

/// Answers from `ctl/out` and `ctl/rc`; the `--no-cheating` pass from
/// `ctl/out.nc` and `ctl/rc.nc` when the test wrote them. Writes Verus's
/// logs into `--log-dir`: `ctl/vir` and `ctl/names` when the test wrote
/// them, else a log declaring one verified function of `tooth`.
const FAKE: &str = "#!/bin/sh
[ -z \"${VERUS_DRIVER_LOG-}\" ] || echo \"$*\" >> \"$VERUS_DRIVER_LOG\"
echo \"$(pwd) ${RUSTUP_TOOLCHAIN-unset} ${CARGO_TARGET_DIR-unset} $*\" >> \"$VERUS_LOG\"
o=\"$VERUS_OUT\"; r=\"$VERUS_RC\"
case \"$*\" in *--no-cheating*) [ -f \"$o.nc\" ] && o=\"$o.nc\" && r=\"$r.nc\" ;; esac
d=; p=; for a in \"$@\"; do [ \"$p\" = --log-dir ] && d=\"$a\"; p=\"$a\"; done
c=$(dirname \"$VERUS_OUT\")
if [ -n \"$d\" ]; then
  mkdir -p \"$d\"
  if [ -f \"$c/vir\" ]; then cp \"$c/vir\" \"$d/crate.vir\"; cp \"$c/names\" \"$d/crate.impl_names\"
  else echo '(Function :name (Fun :path tooth::f) :body (@@ v))' > \"$d/crate.vir\"; : > \"$d/crate.impl_names\"; fi
fi
cat \"$o\"
exit \"$(cat \"$r\")\"
";

fn driver_verus(version: &str) -> String {
    format!("#!/bin/sh\nprintf '%s\\n' 'Verus' '  Version: {version}'\n")
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn exe(path: &Path, text: &str) {
    write(path, text);
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn git(root: &Path, args: &[&str]) {
    let ok = Proc::new("git")
        .args(args)
        .current_dir(root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap()
        .status
        .success();
    assert!(ok, "git {args:?}");
}

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch(tag: &str) -> Scratch {
    let root = std::env::temp_dir().join(format!("xtask-run-verus-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    write(&root.join("Cargo.toml"), MANIFEST);
    write(
        &root.join("tooth/Cargo.toml"),
        "[package]\nname = \"tooth\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    );
    write(&root.join("tooth/src/lib.rs"), "#![no_std]\n");
    let bin = root.join("bin");
    exe(&bin.join("cargo-verus"), FAKE);
    exe(
        &bin.join("verus"),
        "#!/bin/sh\nprintf '%s\\n' 'Verus' '  Version: 0.2026.10.04.426d8b0'\n",
    );
    exe(&bin.join("verusfmt"), "#!/bin/sh\necho 'verusfmt 0.7.4'\n");
    exe(&bin.join("atc"), "#!/bin/sh\nexit 1\n");
    write(&root.join("ctl/out"), PASS);
    write(&root.join("ctl/rc"), "0");
    write(
        &root.join(".gitignore"),
        "/build/\n/ctl/\n/target/\n/verus.log\n",
    );
    let lock = Proc::new("cargo")
        .args(["generate-lockfile", "--offline"])
        .current_dir(&root)
        .status()
        .unwrap();
    assert!(lock.success());
    git(&root, &["init", "-q", "-b", "feat/x"]);
    git(&root, &["add", "-A"]);
    git(
        &root,
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-qm",
            "init",
        ],
    );
    Scratch(root)
}

fn gate(root: &Path) -> bool {
    let runner = Runner {
        registry: Vec::new,
        dirs: vec![PathBuf::from(env!("CARGO_MANIFEST_DIR"))],
    };
    let cmd = Command::Gate {
        only: None,
        no_cache: false,
        scope: Scope::All,
    };
    execute_with(&runner, &cmd, root)
}

fn log(root: &Path) -> Vec<String> {
    fs::read_to_string(root.join("verus.log"))
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

/// The prover's answer for the next run.
fn answer(root: &Path, out: &str, rc: u8) {
    write(&root.join("ctl/out"), out);
    write(&root.join("ctl/rc"), &rc.to_string());
}

const CHILD: &str = "XTASK_RUN_VERUS_ROOT";

#[test]
fn a_verus_proof_runs_focus_in_its_package_caches_and_fails_on_errors() {
    let Some(root) = std::env::var_os(CHILD).map(PathBuf::from) else {
        let s = scratch("run");
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut dirs = vec![s.0.join("bin")];
        dirs.extend(std::env::split_paths(&path));
        let out = Proc::new(std::env::current_exe().unwrap())
            .args([
                "a_verus_proof_runs_focus_in_its_package_caches_and_fails_on_errors",
                "--exact",
                "--nocapture",
            ])
            .env(CHILD, &s.0)
            .env("PATH", std::env::join_paths(dirs).unwrap())
            .env("VERUS_LOG", s.0.join("verus.log"))
            .env("VERUS_OUT", s.0.join("ctl/out"))
            .env("VERUS_RC", s.0.join("ctl/rc"))
            .env("RUSTUP_TOOLCHAIN", "1.99.0")
            .env("CARGO_BUILD_BUILD_DIR", s.0.join("build"))
            .env_remove("DISCIPLINES_GATE_CONTEXT")
            .env_remove("DISCIPLINES_GATE_NO_CACHE")
            .env_remove("ATC_HELD")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    };
    let root = &root;
    let tooth = root.join("tooth").canonicalize().unwrap();

    assert!(gate(root), "a verified run passes");
    let first = log(root);
    let words: Vec<&str> = first[0].split(' ').collect();
    assert_eq!(words[0], tooth.display().to_string(), "runs in the package");
    assert_ne!(
        words[1], "1.99.0",
        "the caller's RUSTUP_TOOLCHAIN is dropped"
    );
    let build = words[2];
    assert_build_dir(root, build);
    assert_eq!(
        words[3..],
        [
            "verus",
            "focus",
            "--lib",
            "--",
            "--no-cheating",
            "--no-external-by-default",
            "--num-threads",
            "1",
            "--log",
            "vir",
            "--log",
            "impl-names",
            "--log-dir",
            &format!("{build}/log")
        ],
        "one pass when nothing is taken on trust"
    );

    assert!(gate(root), "the pass is cached");
    assert_eq!(log(root).len(), 1, "cached: the prover did not run");

    write(&root.join("tooth/src/lib.rs"), "#![no_std]\n// edit\n");
    answer(root, FAIL, 101);
    assert!(!gate(root), "a verification error fails the gate");
    assert_eq!(log(root).len(), 3, "the first pass failed, so a second ran");

    answer(root, VACUOUS, 0);
    assert!(!gate(root), "a run that verified nothing fails the gate");
    assert_eq!(log(root).len(), 4);

    answer(root, PASS, 0);
    assert!(gate(root), "fixed: passes again");
    assert_eq!(log(root).len(), 5);

    // The first pass names what is taken on trust; each line needs a marker.
    let trusted = "#![no_std]\npub fn f() {\n    proof { assume(true); }\n}\n"; // disciplines:allow-trusted (test input)
    write(&root.join("tooth/src/lib.rs"), trusted);
    write(&root.join("ctl/out.nc"), CHEAT);
    write(&root.join("ctl/rc.nc"), "101");
    assert!(!gate(root), "an unmarked assume fails the gate");
    assert_eq!(log(root).len(), 7, "two passes");
    write(
        &root.join("tooth/src/lib.rs"),
        &trusted.replace("}\n}", "} // disciplines:allow-trusted (spike)\n}"), // disciplines:allow-trusted (test input)
    );
    assert!(
        gate(root),
        "a marked assume passes, judged by the second pass"
    );
    assert_eq!(log(root).len(), 9);

    the_logs_are_judged(root);

    // `#[verifier::external]` is found by text, before the prover runs. // disciplines:allow-trusted (test comment)
    let external = "#![no_std]\n#[verifier::external]\nfn hidden() {}\n"; // disciplines:allow-trusted (test input)
    write(&root.join("tooth/src/lib.rs"), external);
    assert!(!gate(root), "an unmarked external fails the gate");
    assert_eq!(log(root).len(), 11, "the prover did not run");
}

/// The logs name an external trait impl: it needs a marker where it is
/// written; an external free function is only listed.
fn the_logs_are_judged(root: &Path) {
    write(&root.join("ctl/out.nc"), PASS);
    write(&root.join("ctl/rc.nc"), "0");
    write(
        &root.join("ctl/vir"),
        "(Function :name (Fun :path tooth::f) :body (@@ v))\n(external_fn (Fun :path tooth::impl&%0::one))\n(external_fn (Fun :path tooth::lie))\n",
    );
    write(
        &root.join("ctl/names"),
        "tooth::impl&%0   ###   tooth::One   ###   tooth::S   ###   tooth/src/lib.rs:3:1: 3:16 (#0)\n",
    );
    let lying = "#![no_std]\n// the impl\nimpl One for S {}\n";
    write(&root.join("tooth/src/lib.rs"), lying);
    assert!(
        !gate(root),
        "an unmarked external impl in the logs fails the gate"
    );
    write(
        &root.join("tooth/src/lib.rs"),
        &lying.replace("// the impl", "// disciplines:allow-trusted (test input)"), // disciplines:allow-trusted (test input)
    );
    assert!(gate(root), "marked, it passes; the free function is listed");
    fs::remove_file(root.join("ctl/vir")).unwrap();
}

/// The build directory differs from the target directory, so the runner is
/// seen to take cargo's `build_directory`; then a 16-digit workspace key,
/// then the entry.
fn assert_build_dir(root: &Path, build: &str) {
    let under = root.canonicalize().unwrap().join("build/verus/");
    let rest = build
        .strip_prefix(&under.display().to_string())
        .unwrap_or_else(|| panic!("not under {}: {build}", under.display()));
    let (key, entry) = rest.split_once('/').unwrap_or_default();
    assert!(
        key.len() == 16 && key.bytes().all(|b| b.is_ascii_hexdigit()) && entry == "tooth",
        "builds in verus/<workspace>/<name> under the build directory: {build}"
    );
}

const NO_PROVER: &str = "XTASK_NO_PROVER_ROOT";

/// The registry's `preflight` alone, before the proof gate.
fn preflight_only() -> Vec<xtask::Gate> {
    xtask::registry()
        .into_iter()
        .filter(|g| g.name == "preflight")
        .collect()
}

fn gate_scoped(root: &Path, scope: Scope) -> bool {
    let runner = Runner {
        registry: preflight_only,
        dirs: vec![PathBuf::from(env!("CARGO_MANIFEST_DIR"))],
    };
    let cmd = Command::Gate {
        only: None,
        no_cache: false,
        scope,
    };
    execute_with(&runner, &cmd, root)
}

/// The `cargo xtask proofs` command: proof gates without preflight.
fn proofs_only(root: &Path) -> bool {
    let runner = Runner {
        registry: Vec::new,
        dirs: vec![PathBuf::from(env!("CARGO_MANIFEST_DIR"))],
    };
    let cmd = Command::Gate {
        only: None,
        no_cache: false,
        scope: Scope::ProofsOnly,
    };
    execute_with(&runner, &cmd, root)
}

/// `PATH` holds every tool but Verus's: the declared proof makes preflight
/// reject the missing selected release before either gate scope reaches a
/// proof gate.
#[test]
fn a_declared_verus_proof_requires_the_selected_verus_release() {
    let Some(root) = std::env::var_os(NO_PROVER).map(PathBuf::from) else {
        let s = scratch("no-prover");
        let path = std::env::var_os("PATH").unwrap_or_default();
        let dir = s.0.join("tools");
        fs::create_dir_all(&dir).unwrap();
        for tool in [
            "cargo",
            "rustc",
            "rustfmt",
            "cargo-clippy",
            "git",
            "prlimit",
            "timeout",
        ] {
            let real = xtask::tools::resolve_in(&path, tool).unwrap();
            std::os::unix::fs::symlink(real, dir.join(tool)).unwrap();
        }
        exe(&dir.join("verusfmt"), "#!/bin/sh\necho 'verusfmt 0.7.4'\n");
        exe(&dir.join("atc"), "#!/bin/sh\nexit 1\n");
        let out = Proc::new(std::env::current_exe().unwrap())
            .args([
                "a_declared_verus_proof_requires_the_selected_verus_release",
                "--exact",
                "--nocapture",
            ])
            .env(NO_PROVER, &s.0)
            .env("PATH", &dir)
            .env("CARGO_BUILD_BUILD_DIR", s.0.join("build"))
            .env_remove("DISCIPLINES_GATE_CONTEXT")
            .env_remove("DISCIPLINES_GATE_NO_CACHE")
            .env_remove("ATC_HELD")
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "{}{err}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(err.contains("FAIL preflight ("), "{err}");
        assert!(
            err.contains(
                "\nmissing: verus  (install: the selected Verus 0.2026.10.04.426d8b0 release)"
            ),
            "{err}"
        );
        return;
    };
    assert!(
        !gate_scoped(&root, Scope::NoProofs),
        "a declared Verus proof validates its selected release before it is skipped"
    );
    assert!(
        !gate_scoped(&root, Scope::All),
        "a declared Verus proof validates its selected release"
    );
    fs::write(root.join("Cargo.toml"), "[workspace]\nresolver = \"3\"\n").unwrap();
    assert!(
        gate_scoped(&root, Scope::All),
        "an empty workspace does not require Verus"
    );
}

const WRONG_VERUSFMT: &str = "XTASK_WRONG_VERUSFMT_ROOT";

/// The scratch workspace's tools, with a `verusfmt` that reports another
/// release: the declared Verus proof makes preflight reject it, and an empty
/// workspace does not check it.
#[test]
fn a_declared_verus_proof_requires_the_pinned_verusfmt() {
    let Some(root) = std::env::var_os(WRONG_VERUSFMT).map(PathBuf::from) else {
        let s = scratch("wrong-verusfmt");
        exe(
            &s.0.join("bin/verusfmt"),
            "#!/bin/sh\necho 'verusfmt 0.7.3'\n",
        );
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut dirs = vec![s.0.join("bin")];
        dirs.extend(std::env::split_paths(&path));
        let out = Proc::new(std::env::current_exe().unwrap())
            .args([
                "a_declared_verus_proof_requires_the_pinned_verusfmt",
                "--exact",
                "--nocapture",
            ])
            .env(WRONG_VERUSFMT, &s.0)
            .env("PATH", std::env::join_paths(dirs).unwrap())
            .env("CARGO_BUILD_BUILD_DIR", s.0.join("build"))
            .env_remove("DISCIPLINES_GATE_CONTEXT")
            .env_remove("DISCIPLINES_GATE_NO_CACHE")
            .env_remove("ATC_HELD")
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "{}{err}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(err.contains("FAIL preflight ("), "{err}");
        assert!(
            err.contains("reported verusfmt 0.7.3; expected 0.7.4"),
            "{err}"
        );
        return;
    };
    assert!(
        !gate_scoped(&root, Scope::All),
        "a declared Verus proof checks the pinned verusfmt"
    );
    fs::write(root.join("Cargo.toml"), "[workspace]\nresolver = \"3\"\n").unwrap();
    assert!(
        gate_scoped(&root, Scope::All),
        "an empty workspace does not check verusfmt"
    );
}

const DRIVER: &str = "XTASK_VERUS_DRIVER_ROOT";
const DRIVER_CASE: &str = "XTASK_VERUS_DRIVER_CASE";
const DRIVER_DIR: &str = "XTASK_VERUS_DRIVER_DIR";

fn cargo_verus_driver_parent(non_utf8: bool) {
    let s = scratch(if non_utf8 {
        "cargo-verus-driver-nonutf"
    } else {
        "cargo-verus-driver"
    });
    fs::remove_file(s.0.join("bin/cargo-verus")).unwrap();
    let driver = if non_utf8 {
        s.0.join("ctl")
            .join(std::ffi::OsStr::from_bytes(b"driver-\xff"))
    } else {
        s.0.join("driver-bin")
    };
    exe(&driver.join("cargo-verus"), FAKE);
    exe(&driver.join("verus"), &driver_verus("0.2026.10.04.426d8b0"));
    for install in ["rust_verify", "z3", "vstd.vir"] {
        write(&driver.join(install), "selected installation input\n");
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut dirs = vec![s.0.join("bin"), driver.clone()];
    dirs.extend(std::env::split_paths(&path));
    let path = std::env::join_paths(dirs).unwrap();
    let run = |case: &str, child_path: &std::ffi::OsStr| {
        let test = if non_utf8 && case == "cache" {
            "a_non_utf8_cargo_verus_sibling_invalidates_cached_scopes"
        } else {
            "a_verus_proof_requires_the_selected_cargo_verus_driver"
        };
        Proc::new(std::env::current_exe().unwrap())
            .args([test, "--exact", "--nocapture"])
            .env(DRIVER, &s.0)
            .env(DRIVER_CASE, case)
            .env(DRIVER_DIR, &driver)
            .env("PATH", child_path)
            .env("VERUS_LOG", s.0.join("verus.log"))
            .env("VERUS_DRIVER_LOG", s.0.join("driver.log"))
            .env("VERUS_OUT", s.0.join("ctl/out"))
            .env("VERUS_RC", s.0.join("ctl/rc"))
            .env("RUSTUP_TOOLCHAIN", "1.99.0")
            .env("CARGO_BUILD_BUILD_DIR", s.0.join("build"))
            .env_remove("DISCIPLINES_GATE_CONTEXT")
            .env_remove("DISCIPLINES_GATE_NO_CACHE")
            .env_remove("ATC_HELD")
            .output()
            .unwrap()
    };

    exe(&driver.join("verus"), &driver_verus("0.2026.10.05.next"));
    let mismatch = run("mismatch", &path);
    let mismatch_log = String::from_utf8_lossy(&mismatch.stderr);
    assert!(mismatch.status.success(), "{mismatch_log}");
    assert!(
        mismatch_log.contains("cargo-verus driver")
            && mismatch_log.contains("0.2026.10.05.next")
            && mismatch_log.contains("expected 0.2026.10.04.426d8b0"),
        "{mismatch_log}"
    );

    exe(&driver.join("verus"), &driver_verus("0.2026.10.04.426d8b0"));
    let exact = run("exact", &path);
    let driver_log = fs::read_to_string(s.0.join("driver.log")).unwrap_or_default();
    assert!(
        exact.status.success(),
        "{}{}driver log:\n{driver_log}",
        String::from_utf8_lossy(&exact.stdout),
        String::from_utf8_lossy(&exact.stderr)
    );

    let cache = run("cache", &path);
    assert!(
        cache.status.success(),
        "{}{}",
        String::from_utf8_lossy(&cache.stdout),
        String::from_utf8_lossy(&cache.stderr)
    );
    if non_utf8 {
        return;
    }

    let tools = s.0.join("missing-tools");
    fs::create_dir_all(&tools).unwrap();
    for tool in [
        "cargo",
        "rustc",
        "rustfmt",
        "cargo-clippy",
        "git",
        "prlimit",
        "timeout",
        "sh",
    ] {
        let real = xtask::tools::resolve_in(&path, tool).unwrap();
        std::os::unix::fs::symlink(real, tools.join(tool)).unwrap();
    }
    std::os::unix::fs::symlink(s.0.join("bin/verus"), tools.join("verus")).unwrap();
    exe(&tools.join("atc"), "#!/bin/sh\nexit 1\n");
    let missing = run("missing", tools.as_os_str());
    let missing_log = String::from_utf8_lossy(&missing.stderr);
    assert!(missing.status.success(), "{missing_log}");
    assert!(
        missing_log.contains("missing: cargo-verus"),
        "{missing_log}"
    );
}

/// A selected `verus` alone cannot prove the `cargo-verus` driver Cargo
/// dispatches is the selected release. Both full preflight and `proofs` must
/// reject a missing or different driver; the latter reaches the proof run.
#[test]
fn a_verus_proof_requires_the_selected_cargo_verus_driver() {
    let Some(root) = std::env::var_os(DRIVER).map(PathBuf::from) else {
        cargo_verus_driver_parent(false);
        return;
    };

    match std::env::var(DRIVER_CASE).as_deref() {
        Ok("mismatch") => {
            assert!(
                !gate_scoped(&root, Scope::All),
                "preflight rejects a mismatched cargo-verus driver"
            );
            assert!(
                !proofs_only(&root),
                "cargo xtask proofs rejects a mismatched driver before invoking it"
            );
            assert!(log(&root).is_empty(), "the mismatched driver did not prove");
        }
        Ok("missing") => assert!(
            !proofs_only(&root),
            "cargo xtask proofs rejects a missing cargo-verus driver"
        ),
        Ok("exact") => {
            assert_eq!(
                xtask::tools::resolve_in(&std::env::var_os("PATH").unwrap(), "cargo-verus"),
                Some(PathBuf::from(std::env::var_os(DRIVER_DIR).unwrap()).join("cargo-verus"))
            );
            assert!(
                gate(&root),
                "the selected cargo-verus driver runs the proof"
            );
            assert_eq!(log(&root).len(), 1, "the exact driver ran the proof");
            assert!(
                fs::read_to_string(root.join("driver.log"))
                    .unwrap()
                    .contains("verus focus"),
                "Cargo invoked the selected cargo-verus driver"
            );
        }
        Ok("cache") => cached_driver_sibling_must_invalidate(
            &root,
            &PathBuf::from(std::env::var_os(DRIVER_DIR).unwrap()),
        ),
        Ok(other) => panic!("unknown cargo-verus driver test case: {other}"),
        Err(error) => panic!("missing cargo-verus driver test case: {error}"),
    }
}

fn cached_driver_sibling_must_invalidate(root: &Path, driver: &Path) {
    xtask::cache::store::Store::open(root)
        .unwrap()
        .clear()
        .unwrap();
    assert!(
        gate_scoped(root, Scope::NoProofs),
        "a selected preflight passes before caching"
    );
    assert!(
        gate_scoped(root, Scope::NoProofs),
        "the selected no-proofs run is cached"
    );
    let proofs_before = log(root).len();
    assert!(
        gate_scoped(root, Scope::All),
        "a full registry run passes before caching"
    );
    assert_eq!(log(root).len(), proofs_before + 1);
    assert!(
        gate_scoped(root, Scope::All),
        "the selected full registry run is cached"
    );
    assert_eq!(
        log(root).len(),
        proofs_before + 1,
        "the cached proof did not run"
    );

    let sibling = driver.join("verus").canonicalize().unwrap();
    assert_eq!(
        preflight_only()[0].cache_paths,
        std::slice::from_ref(&sibling)
    );
    let proof = xtask::proof_gates(root, None).unwrap().remove(0);
    assert!(
        proof.cache_paths.contains(&sibling),
        "proof cache input includes cargo-verus's resolved sibling"
    );
    let path_verus = fs::read(root.join("bin/verus")).unwrap();
    let cargo_verus = fs::read(driver.join("cargo-verus")).unwrap();
    let install: Vec<Vec<u8>> = ["rust_verify", "z3", "vstd.vir"]
        .iter()
        .map(|name| fs::read(driver.join(name)).unwrap())
        .collect();
    exe(&driver.join("verus"), &driver_verus("0.2026.10.05.next"));
    assert_eq!(fs::read(root.join("bin/verus")).unwrap(), path_verus);
    assert_eq!(fs::read(driver.join("cargo-verus")).unwrap(), cargo_verus);
    assert_eq!(
        ["rust_verify", "z3", "vstd.vir"]
            .iter()
            .map(|name| fs::read(driver.join(name)).unwrap())
            .collect::<Vec<_>>(),
        install,
        "only the sibling Verus executable changed"
    );

    assert!(
        !gate_scoped(root, Scope::NoProofs),
        "preflight must not serve its old cache entry"
    );
    assert!(
        !gate_scoped(root, Scope::All),
        "a full registry run must not serve cached preflight or proof success"
    );
    assert!(
        !proofs_only(root),
        "proofs must not serve their old cache entry"
    );
    assert_eq!(
        log(root).len(),
        proofs_before + 1,
        "the mismatched driver did not prove"
    );
}

/// A non-UTF-8 cargo-verus install path still fingerprints its real sibling,
/// rather than a lossy replacement path.
#[cfg(not(windows))]
#[test]
fn a_non_utf8_cargo_verus_sibling_invalidates_cached_scopes() {
    let Some(root) = std::env::var_os(DRIVER).map(PathBuf::from) else {
        cargo_verus_driver_parent(true);
        return;
    };
    let driver = PathBuf::from(std::env::var_os(DRIVER_DIR).unwrap());
    assert!(
        driver.as_os_str().as_bytes().contains(&0xff),
        "the regression uses a non-UTF-8 cargo-verus install path"
    );
    cached_driver_sibling_must_invalidate(&root, &driver);
}
