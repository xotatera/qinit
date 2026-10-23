// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The proof tier's pure logic: declarations, job counts, argv, Kani output.
use xtask::proofs::cgroup::Usage;
use xtask::proofs::{self, Kind, Proof};

/// `cargo metadata` JSON for a workspace at /ws with members a (crates/a),
/// b (crates/b), c (crates/c) and root (the root package), plus `extra`
/// spliced into `metadata.disciplines`. a depends on b (path); b
/// dev-depends on a (path), which forms a cycle; c depends on serde (registry).
/// Its target directory is /ws/target; no build directory is configured.
fn metadata(extra: &str) -> String {
    format!(
        r#"{{
  "workspace_root": "/ws",
  "target_directory": "/ws/target",
  "packages": [
    {{"name": "a", "manifest_path": "/ws/crates/a/Cargo.toml",
      "dependencies": [{{"name": "b", "kind": null, "path": "/ws/crates/b"}}]}},
    {{"name": "b", "manifest_path": "/ws/crates/b/Cargo.toml",
      "dependencies": [{{"name": "a", "kind": "dev", "path": "/ws/crates/a"}}]}},
    {{"name": "c", "manifest_path": "/ws/crates/c/Cargo.toml",
      "dependencies": [{{"name": "serde", "kind": null}}]}},
    {{"name": "root", "manifest_path": "/ws/Cargo.toml", "dependencies": []}}
  ],
  "metadata": {{"disciplines": {{ {extra} }} }}
}}"#
    )
}

/// FNV-1a of `/ws`, the fixture's workspace root: Verus build directories
/// are per workspace.
const WS: &str = "eddf6817e64561a8";

fn one(extra: &str) -> Proof {
    let declared = proofs::parse(&metadata(extra)).unwrap();
    assert_eq!(declared.proofs.len(), 1);
    declared.proofs.into_iter().next().unwrap()
}

fn err(extra: &str) -> String {
    proofs::parse(&metadata(extra)).unwrap_err()
}

const KANI_A: &str =
    r#""proof": [{"name": "core", "kind": "kani", "package": "a", "memory": "4G"}]"#;

#[test]
fn no_entries_means_no_proofs() {
    let d = proofs::parse(&metadata(r#""no_std_target": "x""#)).unwrap();
    assert_eq!(d.proofs, Vec::new());
    assert_eq!(d.budget, None);
}

#[test]
fn a_kani_entry_with_defaults() {
    let p = one(KANI_A);
    assert_eq!(p.name, "core");
    assert_eq!(p.kind, Kind::Kani);
    assert_eq!(p.package, "a");
    assert_eq!(p.dir, "crates/a");
    assert_eq!(p.memory, 4 << 30);
    assert_eq!(p.timeout_s, 300);
    assert_eq!(p.gate_name(), "proof:core");
    assert_eq!(p.workdir(), "");
}

#[test]
fn a_command_entry() {
    let p = one(
        r#""proof": [{"name": "kernel", "kind": "command", "package": "c",
            "command": ["cargo", "verus", "verify"], "memory": "16G", "timeout": "20m"}]"#,
    );
    assert_eq!(
        p.kind,
        Kind::Command(vec!["cargo".into(), "verus".into(), "verify".into()])
    );
    assert_eq!(p.timeout_s, 1200);
    assert_eq!(p.workdir(), "crates/c");
}

#[test]
fn command_timeout_defaults_to_thirty_minutes() {
    let p = one(
        r#""proof": [{"name": "k", "kind": "command", "package": "c",
            "command": ["true"], "memory": "1G"}]"#,
    );
    assert_eq!(p.timeout_s, 1800);
}

#[test]
fn the_budget_is_parsed() {
    let d = proofs::parse(&metadata(&format!(
        r#""proof_memory_budget": "24G", {KANI_A}"#
    )))
    .unwrap();
    assert_eq!(d.budget, Some(24 << 30));
}

#[test]
fn inputs_follow_path_dependencies_transitively_and_cycles_end() {
    let p = one(KANI_A);
    assert_eq!(p.dirs, vec!["crates/a".to_string(), "crates/b".to_string()]);
    assert_eq!(
        p.globs(),
        [
            "crates/a/**",
            "crates/b/**",
            "Cargo.lock",
            "rust-toolchain.toml",
            "rust-toolchain"
        ]
        .map(String::from)
        .to_vec()
    );
}

#[test]
fn registry_dependencies_are_not_inputs() {
    let p = one(r#""proof": [{"name": "c", "kind": "kani", "package": "c", "memory": "1G"}]"#);
    assert_eq!(p.dirs, vec!["crates/c".to_string()]);
}

#[test]
fn the_root_package_keys_the_whole_tree() {
    let p = one(r#""proof": [{"name": "r", "kind": "kani", "package": "root", "memory": "1G"}]"#);
    assert_eq!(p.dir, "");
    assert_eq!(p.globs()[0], "**");
}

#[test]
fn the_declaration_is_part_of_the_key() {
    let a = one(KANI_A);
    let b = one(r#""proof": [{"name": "core", "kind": "kani", "package": "a", "memory": "8G"}]"#);
    assert_ne!(a.decl, b.decl);
}

#[test]
fn entry_errors_name_the_entry() {
    for (extra, needle) in [
        (
            r#""proof": [{"name": "x", "kind": "coq", "package": "a", "memory": "1G"}]"#,
            "unknown kind `coq`",
        ),
        (
            r#""proof": [{"name": "x", "kind": "kani", "memory": "1G"}]"#,
            "missing `package`",
        ),
        (
            r#""proof": [{"name": "x", "kind": "kani", "package": "zzz", "memory": "1G"}]"#,
            "package `zzz` is not a workspace member",
        ),
        (
            r#""proof": [{"name": "x", "kind": "kani", "package": "a"}]"#,
            "missing `memory`",
        ),
        (
            r#""proof": [{"name": "x", "kind": "kani", "package": "a", "memory": "512M"}]"#,
            "below the 1G minimum",
        ),
        (
            r#""proof": [{"name": "x", "kind": "kani", "package": "a", "memory": "4X"}]"#,
            "bad size `4X`",
        ),
        (
            r#""proof": [{"name": "x", "kind": "kani", "package": "a", "memory": "1G", "timeout": "5d"}]"#,
            "bad duration `5d`",
        ),
        (
            r#""proof": [{"name": "x", "kind": "kani", "package": "a", "memory": "1G", "command": ["a"]}]"#,
            "`command` is only for kind = \"command\"",
        ),
        (
            r#""proof": [{"name": "x", "kind": "command", "package": "a", "memory": "1G"}]"#,
            "kind = \"command\" needs `command`",
        ),
        (
            r#""proof": [{"name": "x", "kind": "command", "package": "a", "memory": "1G", "command": []}]"#,
            "`command` is empty",
        ),
        (
            r#""proof": [{"name": "x", "kind": "kani", "package": "a", "memory": "1G", "jobs": 3}]"#,
            "unknown field `jobs`",
        ),
        (
            r#""proof": [{"name": "Bad/Name", "kind": "kani", "package": "a", "memory": "1G"}]"#,
            "use lowercase letters, digits, `-` and `_`",
        ),
        (
            r#""proof": [{"name": "has space", "kind": "kani", "package": "a", "memory": "1G"}]"#,
            "use lowercase letters, digits, `-` and `_`",
        ),
    ] {
        let e = err(extra);
        assert!(e.contains(needle), "{extra}\n  gave: {e}");
        assert!(e.starts_with("proof entry "), "{e}");
    }
}

#[test]
fn an_entry_without_a_name_is_numbered() {
    let e = err(r#""proof": [{"kind": "kani", "package": "a", "memory": "1G"}]"#);
    assert!(e.starts_with("proof entry #1: missing `name`"), "{e}");
}

#[test]
fn duplicate_names_are_refused() {
    let e = err(&format!(
        r#""proof": [{0}, {0}]"#,
        r#"{"name": "core", "kind": "kani", "package": "a", "memory": "1G"}"#
    ));
    assert!(e.contains("`core`: duplicate name"), "{e}");
}

#[test]
fn a_bad_budget_is_refused() {
    let e = err(r#""proof_memory_budget": "lots""#);
    assert!(e.starts_with("proof_memory_budget: bad size `lots`"), "{e}");
}

#[test]
fn sizes_and_durations() {
    assert_eq!(proofs::parse_size("1024"), Ok(1024));
    assert_eq!(proofs::parse_size("2K"), Ok(2048));
    assert_eq!(proofs::parse_size("3M"), Ok(3 << 20));
    assert_eq!(proofs::parse_size("4G"), Ok(4 << 30));
    assert!(proofs::parse_size("").is_err());
    assert!(proofs::parse_size("G").is_err());
    assert!(proofs::parse_size("99999999999999G").is_err());
    assert_eq!(proofs::parse_duration("90"), Ok(90));
    assert_eq!(proofs::parse_duration("90s"), Ok(90));
    assert_eq!(proofs::parse_duration("2m"), Ok(120));
    assert_eq!(proofs::parse_duration("1h"), Ok(3600));
    assert!(proofs::parse_duration("0s").is_err());
    assert!(proofs::parse_duration("1.5m").is_err());
}

#[test]
fn memory_and_job_counts() {
    assert_eq!(
        proofs::mem_total("MemTotal:       48000000 kB\nMemFree: 1 kB\n"),
        Some(48_000_000 * 1024)
    );
    assert_eq!(proofs::mem_total("nothing"), None);
    assert_eq!(proofs::budget(Some(10), Some(100), 4), 10);
    assert_eq!(proofs::budget(None, Some(100), 4), 50);
    assert_eq!(proofs::budget(None, None, 4), 4);
    assert_eq!(proofs::jobs(32, 24 << 30, 4 << 30), 6);
    assert_eq!(proofs::jobs(4, 24 << 30, 4 << 30), 4);
    assert_eq!(proofs::jobs(32, 2 << 30, 4 << 30), 1);
    assert_eq!(proofs::jobs(0, 0, 0), 1);
}

#[test]
fn kani_argv() {
    let p = one(KANI_A);
    assert_eq!(
        proofs::argv(&p, 6, &proofs::Cap::Prlimit),
        [
            "prlimit",
            "--as=4294967296",
            "--",
            "sh",
            "-c",
            proofs::TIMEOUT_SH,
            "xtask-proof",
            "-k",
            "30s",
            "7200",
            "cargo",
            "kani",
            "-p",
            "a",
            "-j",
            "6",
            "--output-format",
            "terse",
            "-Z",
            "unstable-options",
            "--harness-timeout",
            "300s"
        ]
        .map(String::from)
        .to_vec()
    );
    assert_eq!(proofs::DROPPED_ENV, &["RUSTUP_TOOLCHAIN"]);
}

#[test]
fn command_argv() {
    let p = one(
        r#""proof": [{"name": "k", "kind": "command", "package": "c",
            "command": ["cargo", "verus", "verify"], "memory": "1G", "timeout": "20m"}]"#,
    );
    assert_eq!(
        proofs::argv(&p, 3, &proofs::Cap::Prlimit),
        [
            "prlimit",
            "--as=1073741824",
            "--",
            "sh",
            "-c",
            proofs::CPU_SH,
            "xtask-proof",
            "1200",
            "1230",
            "cargo",
            "verus",
            "verify"
        ]
        .map(String::from)
        .to_vec()
    );
}

const KANI_PARALLEL: &str = "\
Thread 1: Checking harness proofs::bad_overflows...
Thread 0: Checking harness proofs::slow...
Thread 1:
VERIFICATION RESULT:
 ** 1 of 1 failed
VERIFICATION:- FAILED
Thread 1: Checking harness proofs::add_ok...
Thread 1:
VERIFICATION:- SUCCESSFUL
Thread 2: Checking harness proofs::hog...
Thread 0:
CBMC failed
VERIFICATION:- FAILED
CBMC timed out. You may want to rerun your proof with a larger timeout.
Thread 2:
CBMC failed with status 6
VERIFICATION:- FAILED
Manual Harness Summary:
Verification failed for - proofs::slow
Verification failed for - proofs::bad_overflows
Verification failed for - proofs::hog
Complete - 1 successfully verified harnesses, 3 failures, 4 total.
";

#[test]
fn kani_failures_are_attributed_per_thread() {
    assert_eq!(
        proofs::kani_failures(KANI_PARALLEL),
        vec![
            "proofs::slow (timed out)".to_string(),
            "proofs::bad_overflows".to_string(),
            "proofs::hog (CBMC exited with status 6; it may have hit the memory cap)".to_string(),
        ]
    );
}

#[test]
fn kani_failures_without_threads() {
    let out = "Checking harness hog::big...\nCBMC failed with status 6\nVERIFICATION:- FAILED\n\
               Manual Harness Summary:\nVerification failed for - hog::big\n";
    assert_eq!(
        proofs::kani_failures(out),
        vec!["hog::big (CBMC exited with status 6; it may have hit the memory cap)".to_string()]
    );
}

#[test]
fn kani_reports() {
    let p = one(KANI_A);
    assert_eq!(proofs::kani_report(&p, "anything", Some(0), None), Ok(()));
    let e = proofs::kani_report(&p, KANI_PARALLEL, Some(1), None).unwrap_err();
    assert!(
        e.starts_with("3 harnesses of package `a` failed:\n  - proofs::slow (timed out)\n"),
        "{e}"
    );
    let early = (1..=30)
        .map(|i| format!("line {i}"))
        .collect::<Vec<_>>()
        .join("\n");
    let e = proofs::kani_report(&p, &early, Some(1), None).unwrap_err();
    assert!(
        e.starts_with("`cargo kani -p a` failed before any harness result:\nline 11\n"),
        "{e}"
    );
    assert!(e.ends_with("line 30"), "{e}");
}

#[test]
fn command_reports() {
    let p = one(
        r#""proof": [{"name": "k", "kind": "command", "package": "c",
            "command": ["sleep", "5"], "memory": "1G", "timeout": "1s"}]"#,
    );
    assert_eq!(proofs::command_report(&p, Some(0), None), Ok(()));
    assert_eq!(
        proofs::command_report(&p, Some(152), None),
        Err("`sleep 5` used its CPU limit: a process ran 1s of CPU (`timeout`)".to_string())
    );
    assert_eq!(
        proofs::command_report(&p, Some(2), None),
        Err("`sleep 5` failed (exit 2); a process may have hit the 1G memory cap".to_string())
    );
    assert_eq!(
        proofs::command_report(&p, None, None),
        Err(
            "`sleep 5` was killed by a signal; a process may have hit the 1G memory cap"
                .to_string()
        )
    );
}

#[test]
fn required_tools_follow_the_entries() {
    assert_eq!(proofs::required_tools(&[]), Vec::new());
    // The prover is the gate's own: `--no-proofs` needs none.
    assert_eq!(proofs::required_tools(&[one(KANI_A)]), Vec::new());
    let names: Vec<&str> = proofs::gate_tools(&one(KANI_A))
        .iter()
        .map(|t| t.0)
        .collect();
    assert_eq!(names, ["prlimit", "timeout", "cargo-kani"]);
}

/// Like `metadata`, but `a` also path-depends on `vend`, an in-tree crate
/// outside the members (`exclude`), so `cargo metadata --no-deps` never
/// lists it.
fn metadata_with_non_member(extra: &str) -> String {
    metadata(extra).replace(
        r#"[{"name": "b", "kind": null, "path": "/ws/crates/b"}]"#,
        r#"[{"name": "b", "kind": null, "path": "/ws/crates/b"},
            {"name": "vend", "kind": null, "path": "/ws/vend"}]"#,
    )
}

#[test]
fn a_non_member_path_dependency_keys_the_whole_tree() {
    let d = proofs::parse(&metadata_with_non_member(KANI_A)).unwrap();
    assert_eq!(d.proofs[0].globs()[0], "**");
    // Unreached by `c`: its key stays narrow.
    let d = proofs::parse(&metadata_with_non_member(
        r#""proof": [{"name": "c", "kind": "kani", "package": "c", "memory": "1G"}]"#,
    ))
    .unwrap();
    assert_eq!(d.proofs[0].dirs, vec!["crates/c".to_string()]);
}

#[test]
fn path_patches_in_the_root_manifest_key_the_whole_tree() {
    let mut d = proofs::parse(&metadata(KANI_A)).unwrap();
    proofs::widen_for_patches(&mut d, "[workspace]\nmembers = []\n");
    assert_eq!(
        d.proofs[0].dirs,
        vec!["crates/a".to_string(), "crates/b".to_string()]
    );
    for header in ["[patch.crates-io]", "[replace]", "  [patch.'https://x']"] {
        let mut d = proofs::parse(&metadata(KANI_A)).unwrap();
        proofs::widen_for_patches(
            &mut d,
            &format!("[workspace]\n{header}\nx = {{ path = \"p/x\" }}\n"),
        );
        assert_eq!(d.proofs[0].globs()[0], "**", "{header}");
    }
}

#[test]
fn entries_may_declare_extra_inputs_paths_and_tools() {
    let p = one(
        r#""proof": [{"name": "k", "kind": "command", "package": "c",
            "command": ["cargo", "verus", "verify"], "memory": "1G",
            "inputs": ["data/**"], "extra_paths": ["~/verus"], "tools": ["verus"]}]"#,
    );
    assert!(p.globs().contains(&"data/**".to_string()));
    assert_eq!(p.extra_paths, vec!["~/verus".to_string()]);
    assert_eq!(
        p.tools,
        vec![
            "cargo".to_string(),
            "cargo-verus".to_string(),
            "verus".to_string()
        ]
    );
    let other = one(
        r#""proof": [{"name": "k", "kind": "command", "package": "c",
            "command": ["cargo", "verus", "verify"], "memory": "1G"}]"#,
    );
    assert_ne!(p.decl, other.decl);
    assert_eq!(
        other.tools,
        vec!["cargo".to_string(), "cargo-verus".to_string()]
    );
    assert_eq!(one(KANI_A).tools, vec!["cargo-kani".to_string()]);
    let e = err(
        r#""proof": [{"name": "x", "kind": "kani", "package": "a", "memory": "1G", "inputs": "data"}]"#,
    );
    assert!(e.contains("`inputs` must be an array of strings"), "{e}");
}

#[test]
fn kani_runs_under_a_whole_run_timeout() {
    let p = one(KANI_A);
    assert_eq!(p.run_timeout_s, 7200);
    let p = one(
        r#""proof": [{"name": "core", "kind": "kani", "package": "a", "memory": "4G", "run_timeout": "30m"}]"#,
    );
    assert_eq!(p.run_timeout_s, 1800);
    assert_eq!(
        proofs::kani_report(&p, "Checking harness x...\n", Some(124), None),
        Err("`cargo kani -p a` timed out after 1800s (run_timeout)".to_string())
    );
    let e = err(
        r#""proof": [{"name": "k", "kind": "command", "package": "c", "command": ["true"], "memory": "1G", "run_timeout": "1m"}]"#,
    );
    assert!(
        e.contains("`run_timeout` is only for kind = \"kani\""),
        "{e}"
    );
}

#[test]
fn harness_times_are_read_and_sorted_slowest_first() {
    let out = "\
Thread 1: Checking harness proofs::fast...
Thread 0: Checking harness proofs::slow...
Thread 1:
VERIFICATION:- SUCCESSFUL
Verification Time: 0.25s
Thread 2: Checking harness proofs::mid...
Thread 0:
VERIFICATION:- SUCCESSFUL
Verification Time: 372.5s
Thread 2:
VERIFICATION:- SUCCESSFUL
Verification Time: 12.0s
";
    let times = proofs::kani_times(out);
    assert_eq!(
        times,
        vec![
            ("proofs::slow".to_string(), 372.5),
            ("proofs::mid".to_string(), 12.0),
            ("proofs::fast".to_string(), 0.25),
        ]
    );
    assert_eq!(
        proofs::slowest(&times, 2),
        "slowest harnesses: proofs::slow 372.5 s, proofs::mid 12.0 s"
    );
    assert_eq!(proofs::slowest(&[], 3), "");
}

#[test]
fn dotted_patch_keys_widen_too() {
    let mut d = proofs::parse(&metadata(KANI_A)).unwrap();
    proofs::widen_for_patches(
        &mut d,
        "[workspace]\npatch.crates-io.x = { path = \"p/x\" }\n",
    );
    assert_eq!(d.proofs[0].globs()[0], "**");
}

#[test]
fn cargo_config_files_that_may_patch() {
    use std::path::{Path, PathBuf};
    assert_eq!(
        proofs::cargo_config_paths(Path::new("/w/repo"), Some(Path::new("/h/.cargo"))),
        [
            "/w/repo/.cargo/config.toml",
            "/w/repo/.cargo/config",
            "/w/.cargo/config.toml",
            "/w/.cargo/config",
            "/.cargo/config.toml",
            "/.cargo/config",
            "/h/.cargo/config.toml",
            "/h/.cargo/config",
        ]
        .map(PathBuf::from)
        .to_vec()
    );
}

#[test]
fn a_toolchain_argument_is_not_the_subcommand() {
    let p = one(
        r#""proof": [{"name": "m", "kind": "command", "package": "c",
            "command": ["cargo", "+nightly", "miri", "test"], "memory": "2G"}]"#,
    );
    assert_eq!(p.tools, vec!["cargo".to_string(), "cargo-miri".to_string()]);
}

#[test]
fn patch_detection_reads_tables_and_dotted_keys() {
    assert!(proofs::patches("[patch.crates-io]\nx = { path = \"p\" }\n"));
    assert!(proofs::patches("  [replace]\n"));
    assert!(proofs::patches("patch.crates-io.x = { path = \"p\" }\n"));
    assert!(!proofs::patches("[workspace]\nmembers = [\"a\"]\n"));
    assert!(!proofs::patches("# [patch.crates-io] is commented out\n"));
}

#[test]
fn a_cgroup_cap_wraps_the_driver_in_a_move() {
    let p = one(KANI_A);
    let cap = proofs::Cap::Cgroup("/sys/fs/cgroup/1/delegated/xtask-proof-core-7".into());
    let v = proofs::argv(&p, 2, &cap);
    assert_eq!(
        v[..4],
        [
            "sh",
            "-c",
            proofs::MOVE_SH,
            "/sys/fs/cgroup/1/delegated/xtask-proof-core-7"
        ]
        .map(String::from)
    );
    assert_eq!(
        v[4..11],
        [
            "sh",
            "-c",
            proofs::TIMEOUT_SH,
            "xtask-proof",
            "-k",
            "30s",
            "7200"
        ]
        .map(String::from)
    );
    assert!(!v.iter().any(|a| a == "prlimit"));
}

#[test]
fn the_move_script_moves_then_execs() {
    let dir = std::env::temp_dir().join(format!("xtask-move-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = std::process::Command::new("sh")
        .args(["-c", proofs::MOVE_SH])
        .arg(&dir)
        .args(["echo", "ran"])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "ran\n");
    assert_ne!(
        std::fs::read_to_string(dir.join("cgroup.procs"))
            .unwrap()
            .trim(),
        ""
    );
    let missing = dir.join("missing");
    let out = std::process::Command::new("sh")
        .args(["-c", proofs::MOVE_SH])
        .arg(&missing)
        .args(["echo", "ran"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(out.stdout, b"");
    assert!(String::from_utf8_lossy(&out.stderr).contains("xtask: cannot move into"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_cgroup_cap_is_shared_by_kani_jobs() {
    let kani = one(KANI_A);
    assert_eq!(proofs::cgroup_cap(&kani, 3), 3 * (4 << 30));
    let cmd = one(
        r#""proof": [{"name": "k", "kind": "command", "package": "c",
            "command": ["true"], "memory": "1G"}]"#,
    );
    assert_eq!(proofs::cgroup_cap(&cmd, 3), 1 << 30);
}

fn used(peak: Option<u64>, cap: u64, oom_kills: u64) -> Usage {
    Usage {
        peak,
        cap,
        oom_kills,
    }
}

#[test]
fn kani_failures_name_an_oom_kill() {
    let p = one(KANI_A);
    let u = used(Some(12 << 30), 12 << 30, 2);
    let e = proofs::kani_report(&p, KANI_PARALLEL, Some(1), Some(&u)).unwrap_err();
    assert!(
        e.ends_with("\nOOM-killed 2 process(es) at the 12G cgroup cap; raise memory or lower jobs"),
        "{e}"
    );
    // No OOM kill under a cgroup: the cbmc status is not blamed on the cap,
    // which prlimit (failed allocations) can only suggest.
    let quiet = used(Some(1 << 30), 12 << 30, 0);
    assert_eq!(
        proofs::kani_report(&p, KANI_PARALLEL, Some(1), Some(&quiet)),
        proofs::kani_report(&p, KANI_PARALLEL, Some(1), None)
            .map_err(|e| e.replace("; it may have hit the memory cap", ""))
    );
    assert_eq!(proofs::kani_report(&p, "", Some(0), Some(&u)), Ok(()));
}

#[test]
fn command_failures_under_a_cgroup() {
    let p = one(
        r#""proof": [{"name": "k", "kind": "command", "package": "c",
            "command": ["cargo", "verus", "verify"], "memory": "1G"}]"#,
    );
    let oom = used(None, 1 << 30, 1);
    assert_eq!(
        proofs::command_report(&p, Some(137), Some(&oom)),
        Err("`cargo verus verify` was OOM-killed at the 1G cgroup cap".to_string())
    );
    let quiet = used(None, 1 << 30, 0);
    assert_eq!(
        proofs::command_report(&p, Some(2), Some(&quiet)),
        Err("`cargo verus verify` failed (exit 2)".to_string())
    );
    assert_eq!(
        proofs::command_report(&p, None, Some(&quiet)),
        Err("`cargo verus verify` was killed by a signal".to_string())
    );
    assert!(
        proofs::command_report(&p, Some(152), Some(&oom))
            .unwrap_err()
            .contains("used its CPU limit")
    );
}

#[test]
fn peak_line_formats() {
    assert_eq!(
        proofs::peak_line(&used(Some((9 << 30) + (400 << 20)), 14 << 30, 0)),
        "peak memory: 9.4G of 14G cap"
    );
    assert_eq!(
        proofs::peak_line(&used(Some(300 << 20), 1 << 30, 0)),
        "peak memory: 300M of 1G cap"
    );
    assert_eq!(proofs::peak_line(&used(None, 1 << 30, 0)), "");
}

#[test]
fn unstable_flags_reach_the_kani_argv() {
    let p = one(
        r#""proof": [{"name": "core", "kind": "kani", "package": "a", "memory": "4G",
            "unstable": ["function-contracts", "stubbing"]}]"#,
    );
    assert_eq!(p.unstable, ["function-contracts", "stubbing"]);
    let v = proofs::argv(&p, 1, &proofs::Cap::Prlimit);
    let at = v.iter().position(|a| a == "unstable-options").unwrap();
    assert_eq!(
        v[at + 1..at + 5],
        ["-Z", "function-contracts", "-Z", "stubbing"].map(String::from)
    );
    assert!(
        p.decl
            .ends_with(r#" unstable=["function-contracts", "stubbing"]"#),
        "{}",
        p.decl
    );
}

#[test]
fn no_unstable_keeps_the_decl() {
    let p = one(KANI_A);
    assert_eq!(p.unstable, Vec::<String>::new());
    assert!(!p.decl.contains("unstable"), "{}", p.decl);
}

#[test]
fn bad_unstable_values_are_refused() {
    assert!(
        err(
            r#""proof": [{"name": "core", "kind": "kani", "package": "a", "memory": "4G",
            "unstable": ["async-lib"]}]"#
        )
        .contains(
            "unstable: unknown `async-lib` (one of: function-contracts, loop-contracts, stubbing)"
        )
    );
    assert!(
        err(
            r#""proof": [{"name": "k", "kind": "command", "package": "c",
            "command": ["true"], "memory": "1G", "unstable": ["stubbing"]}]"#
        )
        .contains("`unstable` is only for kind = \"kani\"")
    );
}

/// /ws with spine `s` (core, no tooth), bridge `proto` (core), tooth crate
/// `t` (core, tooth alpha) depending on s and proto, and `x` (core, tooth
/// beta) depending on an outside path crate.
fn comb_metadata(extra: &str) -> String {
    format!(
        r#"{{
  "workspace_root": "/ws",
  "packages": [
    {{"name": "s", "manifest_path": "/ws/crates/s/Cargo.toml", "dependencies": [],
      "metadata": {{"disciplines": {{"layer": "core"}}}}}},
    {{"name": "proto", "manifest_path": "/ws/crates/proto/Cargo.toml", "dependencies": [],
      "metadata": {{"disciplines": {{"layer": "core"}}}}}},
    {{"name": "t", "manifest_path": "/ws/crates/t/Cargo.toml",
      "dependencies": [{{"name": "s", "kind": null, "path": "/ws/crates/s"}},
                       {{"name": "proto", "kind": null, "path": "/ws/crates/proto"}}],
      "metadata": {{"disciplines": {{"layer": "core", "tooth": "alpha"}}}}}},
    {{"name": "x", "manifest_path": "/ws/crates/x/Cargo.toml",
      "dependencies": [{{"name": "outside", "kind": null, "path": "/elsewhere/outside"}}],
      "metadata": {{"disciplines": {{"layer": "core", "tooth": "beta"}}}}}}
  ],
  "metadata": {{"disciplines": {{ {extra} }} }}
}}"#
    )
}

const SPINE_PROOF: &str = r#"{"name": "spine", "kind": "kani", "package": "s", "memory": "2G"}"#;

#[test]
fn spine_contracts_builds_a_contract() {
    let json = comb_metadata(&format!(
        r#""proof": [{SPINE_PROOF},
            {{"name": "alpha", "kind": "kani", "package": "t", "memory": "2G",
              "spine": "contracts", "inputs": ["data/**"]}}]"#
    ));
    let d = proofs::parse(&json).unwrap();
    let c = d.proofs[1].contract.clone().unwrap();
    // `proto` has no Kani entry of its own, so it is keyed by its files.
    assert_eq!(c.spine_dirs, ["crates/s"]);
    assert_eq!(c.prerequisites, ["proof:spine"]);
    assert_eq!(
        c.globs,
        [
            "crates/proto/**",
            "crates/t/**",
            "data/**",
            "Cargo.lock",
            "rust-toolchain.toml",
            "rust-toolchain",
            "crates/s/Cargo.toml"
        ]
    );
    assert_eq!(d.proofs[0].contract, None);
    assert!(
        d.proofs[1].decl.ends_with(r#" spine="contracts""#),
        "{}",
        d.proofs[1].decl
    );
    assert!(!d.proofs[0].decl.contains("spine"), "{}", d.proofs[0].decl);
}

#[test]
fn spine_contracts_is_refused_where_it_cannot_hold() {
    let err = |entries: &str| {
        proofs::parse(&comb_metadata(&format!(r#""proof": [{entries}]"#))).unwrap_err()
    };
    assert!(
        err(r#"{"name": "a", "kind": "kani", "package": "t", "memory": "2G", "spine": "bodies"}"#)
            .contains("spine: use \"contracts\"")
    );
    assert!(err(r#"{"name": "a", "kind": "command", "package": "t", "memory": "2G", "command": ["true"], "spine": "contracts"}"#)
        .contains("`spine` is only for kind = \"kani\""));
    assert!(err(&format!(r#"{SPINE_PROOF}, {{"name": "a", "kind": "kani", "package": "s", "memory": "2G", "spine": "contracts"}}"#))
        .contains("`spine = \"contracts\"` needs a package in a tooth"));
    assert!(
        err(
            r#"{"name": "a", "kind": "kani", "package": "t", "memory": "2G", "spine": "contracts"}"#
        )
        .contains("no kani proof entry covers a spine crate `t` reaches")
    );
    assert!(err(&format!(r#"{SPINE_PROOF}, {{"name": "a", "kind": "kani", "package": "x", "memory": "2G", "spine": "contracts"}}"#))
        .contains("reaches a path dependency outside the workspace"));
}

#[test]
fn a_patch_drops_the_contract() {
    let json = comb_metadata(&format!(
        r#""proof": [{SPINE_PROOF},
            {{"name": "alpha", "kind": "kani", "package": "t", "memory": "2G", "spine": "contracts"}}]"#
    ));
    let mut d = proofs::parse(&json).unwrap();
    proofs::widen_for_patches(&mut d, "[patch.crates-io]\nfoo = { path = \"x\" }\n");
    assert_eq!(d.proofs[1].contract, None);
}

/// `t` (tooth alpha) also reaches `gen` (tooling, build-dep), `p` (a
/// primitive with only a Miri command entry) and `u` (tooth beta, dev-dep).
fn wide_metadata(extra: &str) -> String {
    format!(
        r#"{{
  "workspace_root": "/ws",
  "packages": [
    {{"name": "s", "manifest_path": "/ws/crates/s/Cargo.toml", "dependencies": [],
      "metadata": {{"disciplines": {{"layer": "core"}}}}}},
    {{"name": "p", "manifest_path": "/ws/crates/p/Cargo.toml", "dependencies": [],
      "metadata": {{"disciplines": {{"layer": "primitive"}}}}}},
    {{"name": "gen", "manifest_path": "/ws/crates/gen/Cargo.toml", "dependencies": [],
      "metadata": {{"disciplines": {{"layer": "tooling"}}}}}},
    {{"name": "u", "manifest_path": "/ws/crates/u/Cargo.toml", "dependencies": [],
      "metadata": {{"disciplines": {{"layer": "core", "tooth": "beta"}}}}}},
    {{"name": "t", "manifest_path": "/ws/crates/t/Cargo.toml",
      "dependencies": [{{"name": "s", "kind": null, "path": "/ws/crates/s"}},
                       {{"name": "p", "kind": null, "path": "/ws/crates/p"}},
                       {{"name": "gen", "kind": "build", "path": "/ws/crates/gen"}},
                       {{"name": "u", "kind": "dev", "path": "/ws/crates/u"}}],
      "metadata": {{"disciplines": {{"layer": "core", "tooth": "alpha"}}}}}}
  ],
  "metadata": {{"disciplines": {{ {extra} }} }}
}}"#
    )
}

#[test]
fn only_kani_proved_spine_crates_are_read_through_contracts() {
    let json = wide_metadata(&format!(
        r#""proof": [{SPINE_PROOF},
            {{"name": "miri", "kind": "command", "package": "p", "memory": "2G", "command": ["cargo", "miri", "test"]}},
            {{"name": "alpha", "kind": "kani", "package": "t", "memory": "2G", "spine": "contracts"}}]"#
    ));
    let c = proofs::parse(&json).unwrap().proofs[2]
        .contract
        .clone()
        .unwrap();
    assert_eq!(c.spine_dirs, ["crates/s"]);
    for dir in ["crates/gen/**", "crates/p/**", "crates/t/**", "crates/u/**"] {
        assert!(
            c.globs.iter().any(|g| g == dir),
            "{dir} missing: {:?}",
            c.globs
        );
    }
    assert!(!c.globs.iter().any(|g| g == "crates/s/**"), "{:?}", c.globs);
}

#[test]
fn under_atc_the_driver_runs_in_atc_with_the_cap() {
    let p = one(KANI_A);
    let cap = proofs::Cap::Atc {
        repo: "my-repo".to_string(),
        never_pause: false,
    };
    let v = proofs::argv(&p, 3, &cap);
    assert_eq!(
        v[..16],
        [
            "atc",
            "run",
            "--name",
            "my-repo/proof:core",
            "--cpu-min",
            "3",
            "--ram-min",
            "4G",
            "--ram-max",
            "12G",
            "--gpu-min",
            "0",
            "--vram-min",
            "0",
            "--never-pause",
            "--"
        ]
        .map(String::from)
    );
    assert_eq!(
        v[16..23],
        [
            "sh",
            "-c",
            proofs::TIMEOUT_SH,
            "xtask-proof",
            "-k",
            "30s",
            "7200"
        ]
        .map(String::from)
    );
    assert!(!v.iter().any(|a| a == "prlimit" || a == proofs::MOVE_SH));
}

#[test]
fn a_command_under_atc_takes_one_cpu_and_its_memory() {
    let p = one(
        r#""proof": [{"name": "k", "kind": "command", "package": "c",
            "command": ["cargo", "verus", "verify"], "memory": "1G", "timeout": "20m"}]"#,
    );
    let cap = proofs::Cap::Atc {
        repo: "r".to_string(),
        never_pause: false,
    };
    assert_eq!(
        proofs::argv(&p, 3, &cap),
        [
            "atc",
            "run",
            "--name",
            "r/proof:k",
            "--cpu-min",
            "1",
            "--ram-min",
            "1G",
            "--ram-max",
            "1G",
            "--gpu-min",
            "0",
            "--vram-min",
            "0",
            "--",
            "sh",
            "-c",
            proofs::CPU_SH,
            "xtask-proof",
            "1200",
            "1230",
            "cargo",
            "verus",
            "verify"
        ]
        .map(String::from)
        .to_vec()
    );
}

#[test]
fn sizes_are_written_in_atcs_grammar() {
    assert_eq!(proofs::size_arg(4 << 30), "4G");
    assert_eq!(proofs::size_arg(512 << 20), "512M");
    assert_eq!(proofs::size_arg(64 << 10), "64K");
    assert_eq!(proofs::size_arg(1000), "1000");
}

#[test]
fn atc_76_keeps_the_kani_failures() {
    let p = one(KANI_A);
    let e = proofs::atc_report(&p, KANI_PARALLEL, Some(76), 8 << 30, false).unwrap_err();
    let (failures, cap) = e.rsplit_once('\n').unwrap();
    assert!(failures.contains("of package `a` failed"), "{e}");
    assert_eq!(cap, "exceeded its memory cap of 8G (atc --ram-max)");
}

#[test]
fn atcs_other_codes_name_the_driver() {
    let p = one(KANI_A);
    assert_eq!(
        proofs::atc_report(&p, "", Some(69), 4 << 30, false),
        Err("`cargo kani -p a`: atc daemon unavailable, or its protocol changed (atc was upgraded: rerun)".to_string())
    );
    let c = one(
        r#""proof": [{"name": "k", "kind": "command", "package": "c",
            "command": ["hog"], "memory": "1G"}]"#,
    );
    assert_eq!(
        proofs::atc_report(&c, "", Some(76), 1 << 30, false),
        Err("`hog`: exceeded its memory cap of 1G (atc --ram-max)".to_string())
    );
    assert_eq!(
        proofs::atc_report(&c, "", Some(78), 1 << 30, true),
        Err("`hog`: atc refused the reservation (see atc's line above); xtask runs inside an `atc run`: xtask wraps its steps, nothing wraps xtask".to_string())
    );
}

#[test]
fn a_plain_failure_under_atc_does_not_blame_the_cap() {
    let c = one(
        r#""proof": [{"name": "k", "kind": "command", "package": "c",
            "command": ["hog"], "memory": "1G", "timeout": "20m"}]"#,
    );
    assert_eq!(proofs::atc_report(&c, "", Some(0), 1 << 30, false), Ok(()));
    assert_eq!(
        proofs::atc_report(&c, "", Some(152), 1 << 30, false),
        Err("`hog` used its CPU limit: a process ran 1200s of CPU (`timeout`)".to_string())
    );
    assert_eq!(
        proofs::atc_report(&c, "", Some(2), 1 << 30, false),
        Err("`hog` failed (exit 2)".to_string())
    );
    assert_eq!(
        proofs::atc_report(&c, "", None, 1 << 30, false),
        Err("`hog` was killed by a signal".to_string())
    );
    let p = one(KANI_A);
    assert_eq!(proofs::atc_report(&p, "", Some(0), 4 << 30, false), Ok(()));
    let e = proofs::atc_report(&p, KANI_PARALLEL, Some(1), 4 << 30, false).unwrap_err();
    assert!(!e.contains("memory cap"), "{e}");
}

const GPU_CMD: &str = r#""proof": [{"name": "s", "kind": "command", "package": "c",
    "command": ["naga", "validate"], "memory": "1G", "gpu": true}]"#;

#[test]
fn gpu_is_off_unless_declared_per_repo_or_per_command_entry() {
    let d = proofs::parse(&metadata(KANI_A)).unwrap();
    assert!(!d.gpu);
    assert!(!d.proofs[0].gpu);
    let d = proofs::parse(&metadata(&format!(r#""gpu": true, {KANI_A}"#))).unwrap();
    assert!(d.gpu);
    assert!(!d.proofs[0].gpu, "the repo flag is for the cargo gates");
    assert!(one(GPU_CMD).gpu);
}

#[test]
fn gpu_declarations_are_checked() {
    assert_eq!(
        proofs::parse(&metadata(r#""gpu": "yes""#)).unwrap_err(),
        "gpu: expected true or false"
    );
    assert_eq!(
        err(
            r#""proof": [{"name": "core", "kind": "kani", "package": "a", "memory": "4G", "gpu": true}]"#
        ),
        "proof entry `core`: `gpu` is only for kind = \"command\": Kani and Verus never use the GPU"
    );
    assert_eq!(
        err(
            r#""proof": [{"name": "s", "kind": "command", "package": "c",
            "command": ["x"], "memory": "1G", "gpu": 1}]"#
        ),
        "proof entry `s`: `gpu` must be true or false"
    );
}

#[test]
fn a_gpu_entry_leaves_its_gpu_use_to_atc() {
    let p = one(GPU_CMD);
    let v = proofs::argv(
        &p,
        1,
        &proofs::Cap::Atc {
            repo: "r".to_string(),
            never_pause: false,
        },
    );
    assert!(
        !v.iter().any(|a| a == "--gpu-min" || a == "--vram-min"),
        "{v:?}"
    );
    let plain = one(GPU_CMD.replace(r#", "gpu": true"#, "").as_str());
    assert_eq!(p.decl, plain.decl, "gpu is scheduling, not a key input");
}

#[test]
fn a_signal_kill_under_atc_reads_as_one() {
    let c = one(
        r#""proof": [{"name": "k", "kind": "command", "package": "c",
            "command": ["hog"], "memory": "1G"}]"#,
    );
    // atc returns 128 + N when signal N killed the command.
    assert_eq!(
        proofs::atc_report(&c, "", Some(143), 1 << 30, false),
        Err("`hog` was killed by signal 15".to_string())
    );
    // SIGKILL: possibly the CPU limit's hard kill.
    assert_eq!(
        proofs::atc_report(&c, "", Some(137), 1 << 30, false),
        Err(
            "`hog` was killed by signal 9: a process may have reached its hard CPU limit (30s past `timeout`)"
                .to_string()
        )
    );
    assert_eq!(
        proofs::command_report(&c, Some(137), None),
        proofs::atc_report(&c, "", Some(137), 1 << 30, false)
    );
    assert_eq!(
        proofs::atc_report(&c, "", Some(128), 1 << 30, false),
        Err("`hog` failed (exit 128)".to_string())
    );
}

#[test]
fn the_repo_gpu_flag_reads_even_when_a_proof_entry_is_bad() {
    // Gates other than preflight must not fail on a bad declaration (whether
    // atc is present never changes a result): `gpu` is read on its own.
    let bad = metadata(r#""gpu": true, "proof": [{"name": "bad", "kind": "coq"}]"#);
    assert!(proofs::parse(&bad).is_err());
    assert!(proofs::repo_gpu(&bad));
    assert!(!proofs::repo_gpu(&metadata(r#""gpu": "yes""#)));
    assert!(!proofs::repo_gpu(&metadata("")));
    assert!(!proofs::repo_gpu("not json"));
}

/// A FIFO the process under test opens on fd 3 and writes its pid to, then
/// keeps open through `exec`, as every child it starts does: the pid line
/// says it started, and EOF says every holder of fd 3 has exited (the
/// handshake of `suites/handle/tests/driver.rs`). A reader thread reports
/// both; a test that fails before the writer opens leaves that thread
/// blocked until the test process ends.
struct Fifo {
    path: std::path::PathBuf,
    events: std::sync::mpsc::Receiver<bool>,
}

/// How long the process under test may take to start, or to end once it is
/// stopped, spent in slices (a pause costs one). Only a failure waits this
/// long.
const FIFO_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);

impl Fifo {
    fn new(tag: &str) -> Fifo {
        use std::io::BufRead as _;
        let path = std::env::temp_dir().join(format!("xtask-fifo-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        let (tx, events) = std::sync::mpsc::channel();
        let read = path.clone();
        std::thread::spawn(move || {
            let Ok(file) = std::fs::File::open(&read) else {
                return;
            };
            let mut lines = std::io::BufReader::new(file);
            let mut pid = String::new();
            if lines.read_line(&mut pid).is_ok_and(|n| n > 0) {
                let _ = tx.send(true);
            }
            let _ = std::io::copy(&mut lines, &mut std::io::sink());
            let _ = tx.send(false);
        });
        Fifo { path, events }
    }

    /// `sh -c` text that opens the FIFO (`$0`) on fd 3, writes its pid, then
    /// runs `then`.
    fn script(then: &str) -> String {
        format!(r#"exec 3>"$0"; echo $$ >&3; {then}"#)
    }

    fn started(&self) -> bool {
        xtask::watch::Budget::new(FIFO_DEADLINE).recv(&self.events) == Ok(true)
    }

    fn stopped(&self) -> bool {
        xtask::watch::Budget::new(FIFO_DEADLINE).recv(&self.events) == Ok(false)
    }
}

impl Drop for Fifo {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Whether this process started with SIGINT ignored, as a shell's
/// background job does: no Ctrl-C reaches it, and a shell it starts cannot
/// trap the signal.
fn sigint_ignored() -> bool {
    std::fs::read_to_string("/proc/self/status").is_ok_and(|s| {
        s.lines()
            .find_map(|l| l.strip_prefix("SigIgn:"))
            .and_then(|m| u64::from_str_radix(m.trim(), 16).ok())
            .is_some_and(|m| m & (1 << 1) != 0)
    })
}

#[test]
fn a_sigint_to_the_callers_group_stops_the_driver() {
    use std::os::unix::process::CommandExt as _;
    if sigint_ignored() {
        eprintln!("skipped: SIGINT is ignored in this process (a background job)");
        return;
    }
    let marker = format!("300.{}1", std::process::id());
    let fifo = Fifo::new("sigint");
    let p = one(&format!(
        r#""proof": [{{"name": "s", "kind": "command", "package": "c",
            "command": ["sh", "-c", {}, {}], "memory": "1G", "timeout": "60s"}}]"#,
        serde_json::to_string(&Fifo::script(&format!("exec sleep {marker}"))).unwrap(),
        serde_json::to_string(&fifo.path.to_str().unwrap()).unwrap(),
    ));
    let v = proofs::argv(&p, 1, &proofs::Cap::Prlimit);
    // A foreground job's group, led by a parent the way xtask leads it (the
    // driver must not lead the group itself: `timeout` would then stay in it).
    let mut child = std::process::Command::new("sh")
        .args(["-c", "\"$@\"; exit $?", "xtask"])
        .args(&v)
        .process_group(0)
        .spawn()
        .unwrap();
    assert!(fifo.started(), "the driver never started");
    let ok = std::process::Command::new("kill")
        .args(["-INT", "--", &format!("-{}", child.id())])
        .status()
        .unwrap()
        .success();
    assert!(ok);
    // Checked before waiting: a shell holds its own SIGINT until its child
    // ends, which a surviving driver would delay to its timeout.
    let stopped = fifo.stopped();
    if !stopped {
        let _ = std::process::Command::new("pkill")
            .args(["-f", &format!("^sleep {marker}$")])
            .status();
    }
    let _ = child.wait();
    assert!(stopped, "the driver outlived the group's SIGINT");
}

/// A Verus or command run has a CPU limit, not a deadline: the driver
/// spins until its process has used 1 s of CPU, is stopped by SIGXCPU
/// (152), and the rest of its group (a sleeping child holding the FIFO)
/// goes with it.
#[test]
fn a_cpu_limit_still_stops_the_drivers_children() {
    let marker = format!("300.{}2", std::process::id());
    let fifo = Fifo::new("timeout");
    let p = one(&format!(
        r#""proof": [{{"name": "s", "kind": "command", "package": "c",
            "command": ["sh", "-c", {}, {}], "memory": "1G", "timeout": "1s"}}]"#,
        serde_json::to_string(&Fifo::script(&format!(
            "sleep {marker} & while :; do :; done"
        )))
        .unwrap(),
        serde_json::to_string(&fifo.path.to_str().unwrap()).unwrap(),
    ));
    let v = proofs::argv(&p, 1, &proofs::Cap::Prlimit);
    let err = std::env::temp_dir().join(format!("xtask-cpu-limit-{}", std::process::id()));
    let status = std::process::Command::new(&v[0])
        .args(&v[1..])
        .stderr(std::fs::File::create(&err).unwrap())
        .status()
        .unwrap();
    let stderr = std::fs::read_to_string(&err).unwrap();
    std::fs::remove_file(&err).unwrap();
    assert_eq!(status.code(), Some(proofs::CPU_LIMIT_EXIT));
    assert!(fifo.started(), "the proof never started");
    assert!(fifo.stopped(), "a child outlived the CPU limit");
    // A core limit of one byte: no core file, and no piped core dump either.
    assert!(!stderr.contains("dumped core"), "{stderr}");
    assert!(
        proofs::CPU_SH.contains(&format!("timeout -k {} 0", proofs::KILL_AFTER)),
        "the CPU wrapper's grace is KILL_AFTER"
    );
}

#[test]
fn a_missing_or_unrunnable_program_is_named_not_blamed_on_the_cap() {
    let p = one(
        r#""proof": [{"name": "k", "kind": "command", "package": "c",
            "command": ["verus-typo", "verify"], "memory": "1G", "timeout": "20m"}]"#,
    );
    assert_eq!(
        proofs::command_report(&p, Some(127), None),
        Err("`verus-typo verify` could not start (exit 127: not found); is `verus-typo` installed and on PATH?".to_string())
    );
    assert_eq!(
        proofs::command_report(&p, Some(126), None),
        Err("`verus-typo verify` could not start (exit 126: not executable); is `verus-typo` installed and on PATH?".to_string())
    );
    assert_eq!(
        proofs::atc_report(&p, "", Some(127), 1 << 30, false),
        Err("`verus-typo verify` could not start (exit 127: not found); is `verus-typo` installed and on PATH?".to_string())
    );
}

#[test]
fn a_signal_kill_reported_by_the_wrapper_is_named() {
    let p = one(
        r#""proof": [{"name": "k", "kind": "command", "package": "c",
            "command": ["cargo", "verus", "verify"], "memory": "1G", "timeout": "20m"}]"#,
    );
    // The shell reports a signal death as 128 + N.
    assert_eq!(
        proofs::command_report(&p, Some(134), None),
        Err(
            "`cargo verus verify` was killed by signal 6; a process may have hit the 1G memory cap"
                .to_string()
        )
    );
    let u = proofs::cgroup::Usage {
        cap: 1 << 30,
        peak: None,
        oom_kills: 0,
    };
    assert_eq!(
        proofs::command_report(&p, Some(143), Some(&u)),
        Err("`cargo verus verify` was killed by signal 15".to_string())
    );
}

#[test]
fn only_atc_waiting_lines_are_shown_live() {
    assert!(proofs::live_line("atc: waiting for full/proof:billing"));
    assert!(!proofs::live_line(
        "atc: r/proof:k peak memory 1.2G of 4G limit"
    ));
    assert!(!proofs::live_line("waiting for atc"));
}

#[test]
fn a_kani_report_under_a_cgroup_without_oom_kills_does_not_blame_the_cap() {
    let p = one(KANI_A);
    let out = "Checking harness proofs::a...\nCBMC failed with status 137\nVerification failed for - proofs::a\n";
    let u = proofs::cgroup::Usage {
        cap: 8 << 30,
        peak: None,
        oom_kills: 0,
    };
    let err = proofs::kani_report(&p, out, Some(1), Some(&u)).unwrap_err();
    assert!(
        err.contains("proofs::a (CBMC exited with status 137)"),
        "{err}"
    );
    assert!(!err.contains("memory cap"), "{err}");
    // Under prlimit the cap stays a likely cause.
    let err = proofs::kani_report(&p, out, Some(1), None).unwrap_err();
    assert!(err.contains("it may have hit the memory cap"), "{err}");
}

#[test]
fn spine_entries_carry_the_flag() {
    let json = comb_metadata(&format!(
        r#""proof": [{SPINE_PROOF},
            {{"name": "alpha", "kind": "kani", "package": "t", "memory": "2G",
              "spine": "contracts"}}]"#
    ));
    let d = proofs::parse(&json).unwrap();
    assert!(!d.proofs[0].spine);
    assert!(d.proofs[1].spine && d.proofs[1].contract.is_some());
}

#[test]
fn a_captured_prover_writing_more_than_a_pipe_keeps_its_whole_output() {
    // Review Focus 2 and 3: line reading neither deadlocks nor chokes on
    // non-UTF-8 bytes.
    // Built by hand, like tests/proof_atc.rs's `command()`: an empty `dir`
    // runs it in `root`.
    let p = proofs::Proof {
        name: "big".to_string(),
        kind: proofs::Kind::Command(
            [
                "sh",
                "-c",
                "head -c 300000 /dev/zero | tr '\\0' a; printf '\\n\\377\\nend\\n'",
            ]
            .map(String::from)
            .to_vec(),
        ),
        package: "c".to_string(),
        dir: String::new(),
        dirs: vec![String::new()],
        extra_globs: Vec::new(),
        extra_paths: Vec::new(),
        tools: Vec::new(),
        memory: 1 << 30,
        timeout_s: 60,
        run_timeout_s: 0,
        unstable: Vec::new(),
        contract: None,
        spine: false,
        gpu: false,
        harness_budget_s: xtask::proofs::KANI_HARNESS_BUDGET_S,
        decl: String::new(),
        verus_root: String::new(),
    };
    let (result, log) = xtask::gates::proof_run_as(
        &std::env::temp_dir(),
        &p,
        1,
        true,
        &xtask::atc::Reserve::None,
    );
    assert_eq!(result, Ok(()));
    assert!(log.contains(&"a".repeat(300_000)), "output truncated");
    assert!(
        log.contains("\u{fffd}\nend\n"),
        "{}",
        &log[log.len().saturating_sub(80)..]
    );
}

#[test]
fn a_kill_after_the_deadline_is_a_timeout() {
    // `timeout -k` SIGKILLs a prover that ignored its SIGTERM: exit 137 once
    // the deadline has passed is the timeout, not a signal from elsewhere.
    let d = std::time::Duration::from_secs;
    assert_eq!(proofs::exit_after(Some(137), d(31), 1), Some(124));
    assert_eq!(proofs::exit_after(Some(137), d(0), 60), Some(137));
    assert_eq!(proofs::exit_after(Some(1), d(90), 60), Some(1));
    assert_eq!(proofs::exit_after(None, d(90), 60), None);
}

#[test]
fn the_wrapper_exits_with_the_signal_it_got() {
    let marker = format!("300.{}3", std::process::id());
    let fifo = Fifo::new("wrapper");
    let mut child = std::process::Command::new("sh")
        .args([
            "-c",
            proofs::TIMEOUT_SH,
            "xtask-proof",
            "-k",
            "30s",
            // A hang guard only: the test sends TERM itself, so a pause of
            // the gate step must not reach this deadline first.
            "86400",
            "sh",
            "-c",
            &Fifo::script(&format!("exec sleep {marker}")),
        ])
        .arg(&fifo.path)
        .spawn()
        .unwrap();
    assert!(fifo.started(), "the driver never started");
    let ok = std::process::Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap()
        .success();
    assert!(ok);
    let stopped = fifo.stopped();
    if !stopped {
        let _ = std::process::Command::new("pkill")
            .args(["-f", &format!("^sleep {marker}$")])
            .status();
    }
    let status = child.wait().unwrap();
    assert!(stopped, "the driver outlived SIGTERM");
    assert_eq!(status.code(), Some(143), "128 + SIGTERM");
}

#[test]
fn an_unsatisfied_cover_fails_a_passing_run() {
    // `kani::cover!` guards against vacuous harnesses; Kani reports an
    // unreachable one but still exits 0.
    let p = one(KANI_A);
    let ok = "Checking harness a::h...\n ** 1 of 1 cover properties satisfied\nVERIFICATION:- SUCCESSFUL\n";
    assert_eq!(proofs::kani_report(&p, ok, Some(0), None), Ok(()));
    let vacuous = "Checking harness a::h...\n ** 0 of 1 cover properties satisfied\nVERIFICATION:- SUCCESSFUL\n";
    assert_eq!(
        proofs::kani_report(&p, vacuous, Some(0), None),
        Err("a harness of package `a` is vacuous: 0 of 1 cover properties satisfied".to_string())
    );
}

#[test]
fn a_driver_killed_by_its_own_address_space_cap_is_named() {
    // prlimit caps the Kani driver too, which outgrows `memory` with many
    // harnesses: the run then dies before any harness result.
    let p = one(KANI_A);
    let out = "Thread 0: Checking harness a::h...\nmemory allocation of 15 bytes failed\n\
               thread 'main' panicked at kani-verifier-0.68.0/src/lib.rs:159:38:\nNo exit code?\n";
    let e = proofs::kani_report(&p, out, Some(101), None).unwrap_err();
    assert!(
        e.starts_with("the Kani driver of package `a` ran out of its "),
        "{e}"
    );
    assert!(e.contains("prlimit caps every process"), "{e}");
    // Under a cgroup the driver is not capped alone: the generic report stands.
    let u = used(Some(1 << 30), 4 << 30, 0);
    let e = proofs::kani_report(&p, out, Some(101), Some(&u)).unwrap_err();
    assert!(
        e.starts_with("`cargo kani -p a` failed before any harness result:"),
        "{e}"
    );
}

const VERUS_A: &str =
    r#""proof": [{"name": "spine", "kind": "verus", "package": "a", "memory": "2G"}]"#;

/// `cargo verus focus` on a tooth that verifies (Verus 0.2026.10.04, captured
/// 2026-10-13).
const VERUS_PASS: &str = "    Checking vtooth v0.1.0 (/tmp/s1/vtooth)
verification results:: 2 verified, 0 errors
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 13.10s
";

/// The same tooth with a false postcondition (exit 101).
const VERUS_FAIL: &str = "    Checking vtooth v0.1.0 (/tmp/s1/vtooth)
error: postcondition not satisfied
  --> vtooth/src/lib.rs:9:13
   |
 9 |     ensures r.0.is_some() ==> r.0.unwrap() == 7,
   |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ failed this postcondition
...
14 |     r_helper(a, b)
   |     -------------- at the end of the function body

verification results:: 1 verified, 1 errors
error: could not compile `vtooth` (lib) due to 1 previous error
";

#[test]
fn a_verus_entry_with_defaults() {
    let p = one(VERUS_A);
    assert_eq!(p.kind, Kind::Verus);
    assert!(p.kind.is_core_prover());
    assert!(Kind::Kani.is_core_prover());
    assert!(!Kind::Command(vec!["x".into()]).is_core_prover());
    assert_eq!(p.timeout_s, proofs::VERUS_TIMEOUT_S);
    assert_eq!(p.workdir(), "crates/a");
    assert_eq!(p.tools, ["cargo", "cargo-verus", "verus"]);
    assert_eq!(proofs::cgroup_cap(&p, 8), 2 << 30);
    assert_eq!(proofs::deadline_s(&p), proofs::VERUS_TIMEOUT_S);
}

#[test]
fn verus_entries_refuse_kani_and_command_fields() {
    let with = |field: &str| {
        err(&format!(
            r#""proof": [{{"name": "s", "kind": "verus", "package": "a", "memory": "2G", {field}}}]"#
        ))
    };
    for (field, want) in [
        (
            r#""command": ["x"]"#,
            "`command` is only for kind = \"command\"",
        ),
        (r#""gpu": true"#, "`gpu` is only for kind = \"command\""),
        (
            r#""unstable": ["stubbing"]"#,
            "`unstable` is only for kind = \"kani\"",
        ),
        (
            r#""run_timeout": "1h""#,
            "`run_timeout` is only for kind = \"kani\"",
        ),
    ] {
        let e = with(field);
        assert!(e.contains(want), "{field}: {e}");
    }
    let e = err(r#""proof": [{"name": "s", "kind": "lean", "package": "a", "memory": "2G"}]"#);
    assert!(e.contains(r#"use "kani", "verus" or "command""#), "{e}");
}

#[test]
fn verus_argv_runs_focus_in_the_package_with_one_cpu() {
    let p = one(VERUS_A);
    let v = proofs::argv(&p, 4, &proofs::Cap::Prlimit);
    assert_eq!(
        v[v.len() - 6..],
        [
            "sh",
            "-c",
            proofs::VERUS_SH,
            "xtask-verus",
            "a",
            &format!("/ws/target/verus/{WS}/spine")
        ]
    );
    assert!(
        proofs::VERUS_SH
            .contains(r#"d="$2"; export CARGO_TARGET_DIR="$d" CARGO_BUILD_BUILD_DIR="$d""#)
    );
    assert!(
        proofs::VERUS_SH
            .contains("cargo verus focus --lib -- --no-cheating --no-external-by-default --num-threads 1 --log vir --log impl-names --log-dir \"$d/log\" && exit 0")
    );
    assert!(proofs::VERUS_SH.contains(proofs::VERUS_SECOND_PASS));
    assert!(proofs::VERUS_SH.contains("CARGO_TERM_COLOR=never"));
    assert!(
        proofs::VERUS_SH.ends_with(
            r#"cargo clean -q -p "$1" && exec cargo verus focus --lib -- --no-external-by-default --num-threads 1 --log vir --log impl-names --log-dir "$d/log""#
        )
    );
    let cap = proofs::Cap::Atc {
        repo: "r".to_string(),
        never_pause: false,
    };
    let v = proofs::argv(&p, 4, &cap);
    assert_eq!(
        v[3..8],
        ["r/proof:spine", "--cpu-min", "1", "--ram-min", "2G"]
    );
    assert_eq!(v[8..10], ["--ram-max", "2G"]);
}

#[test]
fn verus_results_sum_every_target() {
    assert_eq!(proofs::verus_results(VERUS_PASS), Some((2, 0)));
    assert_eq!(proofs::verus_results(VERUS_FAIL), Some((1, 1)));
    // A lib and a bin (Verus 0.2026.10.04): the lib's count stands.
    let lib_and_bin = "verification results:: 1 verified, 0 errors\nverification results:: 0 verified, 0 errors\n";
    assert_eq!(proofs::verus_results(lib_and_bin), Some((1, 0)));
    let failing_bin = "verification results:: 3 verified, 0 errors\nverification results:: 1 verified, 2 errors\n";
    assert_eq!(proofs::verus_results(failing_bin), Some((4, 2)));
    assert_eq!(proofs::verus_results("Finished\n"), None);
    assert_eq!(
        proofs::verus_results("verification results:: garbled\n"),
        None
    );
}

#[test]
fn verus_reports() {
    let p = one(VERUS_A);
    assert_eq!(proofs::verus_report(&p, VERUS_PASS, Some(0), None), Ok(()));
    let e = proofs::verus_report(&p, VERUS_FAIL, Some(101), None).unwrap_err();
    assert!(
        e.starts_with(
            "`cargo verus focus (a)`: 1 verification error(s)\nerror: postcondition not satisfied"
        ),
        "{e}"
    );
    assert!(e.contains("failed this postcondition"), "{e}");
    let vacuous = "verification results:: 0 verified, 0 errors\n";
    let e = proofs::verus_report(&p, vacuous, Some(0), None).unwrap_err();
    assert!(e.contains("verified nothing"), "{e}");
    let e = proofs::verus_report(&p, "Finished\n", Some(0), None).unwrap_err();
    assert!(e.contains("printed no `verification results` line"), "{e}");
    assert_eq!(
        proofs::verus_report(&p, "", Some(152), None),
        Err(
            "`cargo verus focus (a)` used its CPU limit: a process ran 600s of CPU (`timeout`)"
                .to_string()
        )
    );
    let e = proofs::verus_report(&p, "", Some(127), None).unwrap_err();
    assert!(e.contains("is `cargo` installed"), "{e}");
    // A missing cargo-verus: cargo's own refusal, exit 101.
    let e =
        proofs::verus_report(&p, "error: no such command: `verus`\n", Some(101), None).unwrap_err();
    assert!(
        e.contains("`cargo-verus` is not installed or not on PATH"),
        "{e}"
    );
    // A compile error prints no results; the output is shown.
    let compile = "error[E0061]: this function takes 1 argument but 0 arguments were supplied\n --> src/lib.rs:3:5\n";
    let e = proofs::verus_report(&p, compile, Some(101), None).unwrap_err();
    assert!(
        e.contains("failed (exit 101)") && e.contains("error[E0061]"),
        "{e}"
    );
    // One target verified, another failed to build: the summed results
    // show no error, the exit does, and the output is kept.
    let partial =
        "verification results:: 11 verified, 0 errors\nerror[E0425]: cannot find value `x`\n";
    let e = proofs::verus_report(&p, partial, Some(101), None).unwrap_err();
    assert!(
        e.contains("failed (exit 101)") && e.contains("error[E0425]"),
        "{e}"
    );
    // No crate opted in: cargo-verus warns and exits 0.
    let warn = "WARNING: cargo-verus did not find any crates that opted into verification\n";
    let e = proofs::verus_report(&p, warn, Some(0), None).unwrap_err();
    assert!(
        e.contains("printed no `verification results` line\nWARNING"),
        "{e}"
    );
}

#[test]
fn each_verus_entry_builds_in_its_own_directory() {
    let p = one(VERUS_A);
    assert_eq!(
        proofs::verus_build_dir(&p),
        format!("/ws/target/verus/{WS}/spine")
    );
    let root =
        one(r#""proof": [{"name": "r", "kind": "verus", "package": "root", "memory": "2G"}]"#);
    assert_eq!(
        proofs::verus_build_dir(&root),
        format!("/ws/target/verus/{WS}/r")
    );
    // A configured build directory (cargo's `build.build-dir`) wins: a
    // checkout regenerated at the same path keeps its Verus library.
    let configured = metadata(VERUS_A).replacen(
        r#""target_directory": "/ws/target","#,
        r#""target_directory": "/ws/target", "build_directory": "/cache/ab/cd","#,
        1,
    );
    let p = proofs::parse(&configured).unwrap().proofs.remove(0);
    assert_eq!(
        proofs::verus_build_dir(&p),
        format!("/cache/ab/cd/verus/{WS}/spine")
    );
    let neither = metadata(VERUS_A).replacen(r#""target_directory": "/ws/target","#, "", 1);
    assert_eq!(
        proofs::parse(&neither).unwrap_err(),
        "proof entry `spine`: cargo metadata names no build or target directory"
    );
    let kani =
        metadata(r#""proof": [{"name": "k", "kind": "kani", "package": "a", "memory": "2G"}]"#)
            .replacen(r#""target_directory": "/ws/target","#, "", 1);
    assert!(proofs::parse(&kani).is_ok(), "only Verus entries need it");
    // Two workspaces sharing one build directory build apart.
    let other = configured.replace("/ws", "/other");
    let q = proofs::parse(&other).unwrap().proofs.remove(0);
    assert_ne!(proofs::verus_build_dir(&q), proofs::verus_build_dir(&p));
    assert!(proofs::verus_build_dir(&q).starts_with("/cache/ab/cd/verus/"));
}

#[test]
fn verus_install_files_are_found_beside_cargo_verus() {
    let dir = std::env::temp_dir().join(format!("xtask-verus-install-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("opt/verus-1")).unwrap();
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    std::fs::write(dir.join("opt/verus-1/cargo-verus"), "").unwrap();
    std::os::unix::fs::symlink(
        dir.join("opt/verus-1/cargo-verus"),
        dir.join("bin/cargo-verus"),
    )
    .unwrap();
    let found = proofs::verus_install_files(&dir.join("bin/cargo-verus"));
    let missing = proofs::verus_install_files(&dir.join("bin/none"));
    let opt = dir.join("opt/verus-1").canonicalize().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let want: Vec<std::path::PathBuf> = ["rust_verify", "z3", "vstd.vir"]
        .iter()
        .map(|f| opt.join(f))
        .collect();
    assert_eq!(found, want);
    assert_eq!(missing, Vec::<std::path::PathBuf>::new());
}

#[test]
fn verus_under_atc() {
    let p = one(VERUS_A);
    assert_eq!(
        proofs::atc_report(&p, VERUS_PASS, Some(0), 2 << 30, false),
        Ok(())
    );
    let e = proofs::atc_report(&p, VERUS_FAIL, Some(101), 2 << 30, false).unwrap_err();
    assert!(e.contains("1 verification error(s)"), "{e}");
    assert_eq!(
        proofs::atc_report(&p, "", Some(152), 2 << 30, false),
        Err(
            "`cargo verus focus (a)` used its CPU limit: a process ran 600s of CPU (`timeout`)"
                .to_string()
        )
    );
    let e = proofs::atc_report(&p, "", Some(76), 2 << 30, false).unwrap_err();
    assert!(e.starts_with("`cargo verus focus (a)`: "), "{e}");
}

#[test]
fn verus_entries_require_cargo_verus() {
    let names = |tools: Vec<(&'static str, &str)>| -> Vec<&'static str> {
        tools.iter().map(|t| t.0).collect()
    };
    assert_eq!(
        names(proofs::gate_tools(&one(VERUS_A))),
        ["prlimit", "timeout", "cargo-verus", "verus"]
    );
    // Preflight validates the selected Verus release and keeps verusfmt for
    // `verus!` bodies once a Verus proof is declared.
    assert_eq!(
        names(proofs::required_tools(&[one(VERUS_A)])),
        ["verus", "cargo-verus", "verusfmt"]
    );
}

/// Two passes: `--no-cheating` rejected lines 3 and 7 of a tooth (Verus
/// 0.2026.10.04's wording), then the plain pass verified.
const VERUS_TRUSTED: &str =
    "error: external_body/assume_specification not allowed with --no-cheating
 --> tooth/src/lib.rs:3:1
  |
3 | pub axiom fn bad()
error: assume/admit not allowed with --no-cheating
  --> tooth/src/lib.rs:7:16
   |
error: could not compile `tooth` (lib) due to 2 previous errors
xtask-verus: second pass
verification results:: 4 verified, 0 errors
";

#[test]
fn verus_trust_needs_a_marker_on_each_line_the_first_pass_named() {
    let src = |marked: bool| {
        move |path: &str, n: usize| {
            assert_eq!(path, "tooth/src/lib.rs");
            Some(if marked || n == 3 {
                "x // disciplines:allow-trusted (an `axiom` we accept)".to_string() // disciplines:allow-trusted (test input)
            } else {
                "proof { assume(x); }".to_string() // disciplines:allow-trusted (test input)
            })
        }
    };
    let e = proofs::verus_trust(VERUS_TRUSTED, src(false)).unwrap_err();
    assert!(
        e.starts_with("tooth/src/lib.rs:7: error: assume/admit not allowed with --no-cheating\n"),
        "{e}"
    );
    assert_eq!(
        proofs::verus_trust(VERUS_TRUSTED, src(true)),
        Ok("\nverification results:: 4 verified, 0 errors\n")
    );
    assert_eq!(
        proofs::verus_trust(VERUS_PASS, src(false)),
        Ok(VERUS_PASS),
        "one pass"
    );
    let gone = |_: &str, _: usize| None;
    let e = proofs::verus_trust(VERUS_TRUSTED, gone).unwrap_err();
    assert_eq!(
        e.matches("not allowed").count(),
        2,
        "an unreadable line is not marked: {e}"
    );
}

#[test]
fn verus_trust_fails_closed_when_the_first_pass_may_be_incomplete() {
    let marked = |_: &str, _: usize| Some("x // disciplines:allow-trusted (ok)".to_string()); // disciplines:allow-trusted (test input)
    let second = "xtask-verus: second pass\nverification results:: 1 verified, 0 errors\n";
    // Another error beside a marked rejection: the listing stopped early.
    let stopped = format!(
        "error: assume/admit not allowed with --no-cheating\n --> a/src/lib.rs:3:1\nerror: some other rejection\n --> a/src/lib.rs:9:1\n{second}"
    );
    let e = proofs::verus_trust(&stopped, marked).unwrap_err();
    assert!(
        e.contains("failed for another reason") && e.contains("some other rejection"),
        "{e}"
    );
    // A failing first pass that names nothing (killed, or a build error).
    let silent = format!("Compiling a\n{second}");
    let e = proofs::verus_trust(&silent, marked).unwrap_err();
    assert!(e.contains("failed for another reason"), "{e}");
    // A rejection without its location counts as unmarked.
    let nowhere = format!("error: assume/admit not allowed with --no-cheating\n{second}");
    let e = proofs::verus_trust(&nowhere, marked).unwrap_err();
    assert!(e.starts_with("(no location): error: assume/admit"), "{e}");
    // A location is not borrowed from the next rejection.
    let borrowed = format!(
        "error: assume/admit not allowed with --no-cheating\nerror: #[verifier::assume_termination] not allowed with --no-cheating\n --> a/src/lib.rs:6:1\n{second}"
    );
    let e = proofs::verus_trust(&borrowed, marked).unwrap_err();
    assert_eq!(e.matches("(no location)").count(), 1, "{e}");
    // A marked line quoting the separator cannot split the output early.
    let spoof = format!(
        "error: assume/admit not allowed with --no-cheating\n --> a/src/lib.rs:3:1\n3 | x // xtask-verus: second pass\nerror: assume/admit not allowed with --no-cheating\n --> a/src/lib.rs:4:1\n{second}"
    );
    let only_3 = |_: &str, n: usize| {
        Some(if n == 3 {
            "x // disciplines:allow-trusted (ok)".to_string() // disciplines:allow-trusted (test input)
        } else {
            "assume(x);".to_string() // disciplines:allow-trusted (test input)
        })
    };
    let e = proofs::verus_trust(&spoof, only_3).unwrap_err();
    assert!(e.starts_with("a/src/lib.rs:4: "), "{e}");
    // A package without a library says so.
    let no_lib = format!("error: no library targets found in package `a`\n{second}");
    let e = proofs::verus_trust(&no_lib, marked).unwrap_err();
    assert!(e.contains("no library target"), "{e}");
    // `assume_termination`, marked, is accepted.
    let termination = format!(
        "error: #[verifier::assume_termination] not allowed with --no-cheating\n --> a/src/lib.rs:6:1\nerror: could not compile `a` (lib) due to 1 previous error\n{second}"
    );
    assert!(proofs::verus_trust(&termination, marked).is_ok());
}

/// Three harnesses: 372.5 s, 12.0 s and 0.25 s.
const KANI_TIMED: &str = "\
Thread 1: Checking harness proofs::fast...
Thread 0: Checking harness proofs::slow...
Thread 1:
VERIFICATION:- SUCCESSFUL
Verification Time: 0.25s
Thread 2: Checking harness proofs::mid...
Thread 0:
VERIFICATION:- SUCCESSFUL
Verification Time: 372.5s
Thread 2:
VERIFICATION:- SUCCESSFUL
Verification Time: 12.0s
";

#[test]
fn the_harness_budget_defaults_to_sixty_seconds_and_is_kani_only() {
    let p = one(KANI_A);
    assert_eq!(p.harness_budget_s, 60);
    assert!(
        !p.decl.contains("harness_budget"),
        "undeclared: keys unchanged"
    );
    let p = one(
        r#""proof": [{"name": "core", "kind": "kani", "package": "a", "memory": "4G", "harness_budget": "10m"}]"#,
    );
    assert_eq!(p.harness_budget_s, 600);
    assert!(p.decl.ends_with(" harness_budget=600"), "{}", p.decl);
    for kind in [
        r#""kind": "verus""#,
        r#""kind": "command", "command": ["x"]"#,
    ] {
        let e = err(&format!(
            r#""proof": [{{"name": "c", {kind}, "package": "a", "memory": "2G", "harness_budget": "1m"}}]"#
        ));
        assert!(
            e.contains("`harness_budget` is only for kind = \"kani\""),
            "{e}"
        );
    }
    let e = err(
        r#""proof": [{"name": "c", "kind": "kani", "package": "a", "memory": "2G", "harness_budget": "soon"}]"#,
    );
    assert!(e.contains("harness_budget:"), "{e}");
}

#[test]
fn a_harness_over_budget_is_a_warning() {
    let p = one(KANI_A);
    let w = proofs::harness_budget_report(&p, KANI_TIMED).unwrap();
    assert!(
        w.starts_with("warning: harness over its 60 s budget: proofs::slow 372.5 s; split it"),
        "{w}"
    );
    assert!(!w.contains("proofs::mid"), "{w}");
    let roomy = one(
        r#""proof": [{"name": "core", "kind": "kani", "package": "a", "memory": "4G", "harness_budget": "400s"}]"#,
    );
    assert_eq!(proofs::harness_budget_report(&roomy, KANI_TIMED), None);
}

#[test]
fn unreadable_harness_times_are_reported() {
    let p = one(KANI_A);
    let summary =
        format!("{KANI_TIMED}Complete - 4 successfully verified harnesses, 0 failures, 4 total.\n");
    let w = proofs::harness_budget_report(&p, &summary).unwrap();
    assert!(
        w.contains("read 3 harness times, but Kani verified 4"),
        "{w}"
    );
    assert!(
        w.contains("\nwarning: harness over its 60 s budget: proofs::slow"),
        "both warnings: {w}"
    );
    let fits = "Checking harness a...\nVERIFICATION:- SUCCESSFUL\nVerification Time: 1.0s\nComplete - 1 successfully verified harnesses, 0 failures, 1 total.\n";
    assert_eq!(proofs::harness_budget_report(&p, fits), None);
}

#[test]
fn a_caller_can_ask_for_never_pause_on_every_kind() {
    let p = one(
        r#""proof": [{"name": "k", "kind": "command", "package": "c",
            "command": ["sleep", "1"], "memory": "1G"}]"#,
    );
    let atc = |never_pause| proofs::Cap::Atc {
        repo: "r".to_string(),
        never_pause,
    };
    let has = |v: Vec<String>| v.iter().any(|a| a == "--never-pause");
    assert!(!has(proofs::argv(&p, 1, &atc(false))), "a command pauses");
    assert!(has(proofs::argv(&p, 1, &atc(true))));
    assert!(
        has(proofs::argv(&one(KANI_A), 1, &atc(false))),
        "Kani never"
    );
}
