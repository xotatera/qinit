// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The proof tier's cgroup cap: detection and cleanup against a fake
//! cgroup tree in a temp dir, and real runs where a cgroup is writable.
use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use xtask::gates;
use xtask::proofs::cgroup::{self, Usage};
use xtask::proofs::{Kind, Proof};

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!("xtask-cg-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

/// A fake cgroup at `cg` under `root` with these controller files.
fn fake(root: &Path, cg: &str, controllers: &str, subtree: &str) -> PathBuf {
    let d = cgroup::dir(root, cg);
    fs::create_dir_all(&d).unwrap();
    fs::write(d.join("cgroup.controllers"), controllers).unwrap();
    fs::write(d.join("cgroup.subtree_control"), subtree).unwrap();
    d
}

const SESSION: &str = "0::/1/session\n";
/// The pid namespace fake runs are named with.
const NS: u64 = 7;

/// This process's pid namespace, as the gate reads it.
fn ns() -> u64 {
    let link = fs::read_link("/proc/self/ns/pid").unwrap();
    cgroup::pid_ns(&link.to_string_lossy()).unwrap()
}

#[test]
fn own_reads_the_v2_line() {
    assert_eq!(cgroup::own(SESSION), Ok("/1/session".to_string()));
    assert_eq!(
        cgroup::own("12:memory:/x\n0::/x/y\n"),
        Ok("/x/y".to_string())
    );
    assert_eq!(cgroup::own("12:memory:/x\n"), Err("cgroup v1".to_string()));
    assert_eq!(cgroup::own("0::/\n"), Err("root cgroup".to_string()));
}

#[test]
fn candidates_are_the_delegated_sibling_then_the_parent() {
    assert_eq!(cgroup::candidates("/1/session"), ["/1/delegated", "/1"]);
    assert_eq!(cgroup::candidates("/a/b/c"), ["/a/b/delegated", "/a/b"]);
    assert_eq!(cgroup::candidates("/session"), Vec::<String>::new());
}

#[test]
fn create_prefers_delegated_and_enables_memory_there() {
    let s = scratch("prefer");
    let delegated = fake(&s.0, "/1/delegated", "cpu memory\n", "");
    fake(&s.0, "/1", "cpu memory\n", "memory\n");
    let path = cgroup::create(&s.0, SESSION, "xtask-proof-k-1", 4096, NS, &|_| true).unwrap();
    assert_eq!(path, delegated.join("xtask-proof-k-1"));
    assert_eq!(
        fs::read_to_string(delegated.join("cgroup.subtree_control")).unwrap(),
        "+memory"
    );
    assert_eq!(fs::read_to_string(path.join("memory.max")).unwrap(), "4096");
    assert_eq!(
        fs::read_to_string(path.join("memory.swap.max")).unwrap(),
        "0"
    );
    // The probe shell wrote its pid.
    assert_ne!(
        fs::read_to_string(path.join("cgroup.procs"))
            .unwrap()
            .trim(),
        ""
    );
}

#[test]
fn a_candidate_without_the_memory_controller_is_skipped() {
    let s = scratch("no-memory");
    fake(&s.0, "/1/delegated", "cpu\n", "");
    let parent = fake(&s.0, "/1", "cpu memory\n", "memory\n");
    let path = cgroup::create(&s.0, SESSION, "xtask-proof-k-1", 4096, NS, &|_| true).unwrap();
    assert_eq!(path, parent.join("xtask-proof-k-1"));
}

#[test]
fn inside_an_atc_job_no_cgroup_is_made() {
    // atc places each job in `<sid>/delegated/atc/d-*/job-<id>`; a run's own
    // cgroup beside it would escape the job's pausing, accounting and kill.
    let s = scratch("atc-job");
    fake(
        &s.0,
        "/1/delegated/atc/d-37-1/delegated",
        "cpu memory\n",
        "memory\n",
    );
    fake(&s.0, "/1/delegated/atc/d-37-1", "cpu memory\n", "memory\n");
    let own = "0::/1/delegated/atc/d-37-1/job-2\n";
    assert_eq!(
        cgroup::create(&s.0, own, "xtask-proof-k-1", 4096, NS, &|_| true),
        Err("inside an atc job, whose cgroup caps the run".to_string())
    );
    assert!(cgroup::in_atc_tree("/1/delegated/atc/daemon"));
    assert!(cgroup::in_atc_tree("/1/delegated/atc"));
    assert!(!cgroup::in_atc_tree("/1/delegated/atcx/job"));
    assert!(!cgroup::in_atc_tree("/1/session"));
}

#[test]
fn a_candidate_whose_subtree_control_cannot_be_written_is_skipped() {
    let s = scratch("busy");
    let delegated = cgroup::dir(&s.0, "/1/delegated");
    fs::create_dir_all(delegated.join("cgroup.subtree_control")).unwrap();
    fs::write(delegated.join("cgroup.controllers"), "memory\n").unwrap();
    let parent = fake(&s.0, "/1", "memory\n", "memory\n");
    let path = cgroup::create(&s.0, SESSION, "xtask-proof-k-1", 4096, NS, &|_| true).unwrap();
    assert_eq!(path, parent.join("xtask-proof-k-1"));
}

#[test]
fn no_candidate_means_no_writable_cgroup() {
    let s = scratch("none");
    assert_eq!(
        cgroup::create(&s.0, SESSION, "xtask-proof-k-1", 4096, NS, &|_| true),
        Err(
            "no writable cgroup: /1/delegated: no memory controller; /1: no memory controller"
                .to_string()
        )
    );
    assert_eq!(
        cgroup::create(&s.0, "12:memory:/x\n", "xtask-proof-k-1", 4096, NS, &|_| {
            true
        }),
        Err("cgroup v1".to_string())
    );
}

#[test]
fn the_sweep_removes_only_dead_runs() {
    let s = scratch("sweep");
    for d in [
        "xtask-proof-a-7-100",
        "xtask-proof-b-7-200",
        "xtask-proof-c-7-300",
        "xtask-proof-d-8-400",
        "xtask-proof-e-500",
        "other-600",
    ] {
        fs::create_dir(s.0.join(d)).unwrap();
    }
    // A process of this test's own, never someone else's (pid 1 as root
    // would be init): the sweep must kill it.
    let sleeper = Command::new("sleep").arg("30").spawn().unwrap();
    fs::write(
        s.0.join("xtask-proof-c-7-300/cgroup.procs"),
        sleeper.id().to_string(),
    )
    .unwrap();
    cgroup::sweep(&s.0, 7, &|pid| pid == 200);
    assert!(
        killed(sleeper),
        "the sweep kills a dead run's leftover process"
    );
    assert!(!s.0.join("xtask-proof-a-7-100").exists(), "dead and empty");
    assert!(s.0.join("xtask-proof-b-7-200").exists(), "its run is alive");
    assert!(s.0.join("xtask-proof-c-7-300").exists(), "not empty");
    assert!(
        s.0.join("xtask-proof-d-8-400").exists(),
        "another pid namespace"
    );
    assert!(
        s.0.join("xtask-proof-e-500").exists(),
        "no namespace in the name"
    );
    assert!(s.0.join("other-600").exists(), "not ours");
}

#[test]
fn usage_reads_peak_and_oom_kills() {
    let s = scratch("usage");
    fs::write(s.0.join("memory.peak"), "1234\n").unwrap();
    fs::write(
        s.0.join("memory.events"),
        "low 0\nhigh 0\nmax 3\noom 2\noom_kill 1\noom_group_kill 0\n",
    )
    .unwrap();
    assert_eq!(
        cgroup::usage(&s.0, 9),
        Usage {
            peak: Some(1234),
            cap: 9,
            oom_kills: 1
        }
    );
    fs::remove_file(s.0.join("memory.peak")).unwrap();
    assert_eq!(cgroup::usage(&s.0, 9).peak, None);
}

#[test]
fn events_parsing() {
    assert_eq!(cgroup::oom_kills("oom_group_kill 4\noom_kill 2\n"), 2);
    assert_eq!(cgroup::oom_kills(""), 0);
    assert!(cgroup::populated("populated 1\nfrozen 0\n"));
    assert!(!cgroup::populated("populated 0\nfrozen 0\n"));
}

#[test]
fn run_names() {
    assert_eq!(cgroup::run_name("core", 7, 42), "xtask-proof-core-7-42");
    assert!(cgroup::run_name("core", 7, 42).starts_with(cgroup::PREFIX));
    assert_eq!(cgroup::pid_ns("pid:[4026531836]"), Some(4_026_531_836));
    assert_eq!(cgroup::pid_ns("net:[1]"), None);
}

/// Whether this process may create a cgroup here; the reason if not.
fn real_cgroup(label: &str) -> Result<(), String> {
    let text = fs::read_to_string("/proc/self/cgroup").map_err(|e| e.to_string())?;
    // Tests run in parallel: one probe name each.
    let name = cgroup::run_name(&format!("probe-{label}"), ns(), std::process::id());
    let path = cgroup::create(
        Path::new("/sys/fs/cgroup"),
        &text,
        &name,
        64 << 20,
        ns(),
        &|_| true,
    )?;
    let _ = cgroup::finish(&path, 64 << 20);
    Ok(())
}

fn command(name: &str, argv: &[&str]) -> Proof {
    Proof {
        name: name.to_string(),
        kind: Kind::Command(argv.iter().map(|a| (*a).to_string()).collect()),
        package: "x".to_string(),
        dir: String::new(),
        dirs: vec![String::new()],
        extra_globs: Vec::new(),
        extra_paths: Vec::new(),
        tools: Vec::new(),
        memory: 64 << 20,
        timeout_s: 60,
        run_timeout_s: 0,
        unstable: Vec::new(),
        contract: None,
        spine: false,
        gpu: false,
        harness_budget_s: xtask::proofs::KANI_HARNESS_BUDGET_S,
        decl: String::new(),
        verus_root: String::new(),
    }
}

fn assert_no_leftover(proof: &str) {
    let text = fs::read_to_string("/proc/self/cgroup").unwrap();
    let name = cgroup::run_name(proof, ns(), std::process::id());
    for c in cgroup::candidates(&cgroup::own(&text).unwrap()) {
        let path = cgroup::dir(Path::new("/sys/fs/cgroup"), &c).join(&name);
        assert!(!path.exists(), "{} left behind", path.display());
    }
}

#[test]
fn an_allocation_past_the_cap_is_reported_as_an_oom_kill() {
    if let Err(reason) = real_cgroup("oom") {
        eprintln!("skipped: {reason}");
        return;
    }
    if !xtask::tools::on_path("python3") {
        eprintln!("skipped: no python3");
        return;
    }
    let s = scratch("oom");
    let p = command("oom", &["python3", "-c", "b = bytearray(256 << 20)"]);
    let e = gates::proof_run_as(&s.0, &p, 1, false, &xtask::atc::Reserve::None)
        .0
        .unwrap_err();
    assert_eq!(
        e,
        "`python3 -c b = bytearray(256 << 20)` was OOM-killed at the 64M cgroup cap"
    );
    assert_no_leftover("oom");
}

#[test]
fn processes_left_behind_are_killed_and_the_cgroup_removed() {
    if let Err(reason) = real_cgroup("orphan") {
        eprintln!("skipped: {reason}");
        return;
    }
    let s = scratch("orphan");
    // Not judged by time (a gate step can be paused): `assert_no_leftover`
    // catches an orphan left alive, and the marker, which the orphan writes
    // only if it outlives its sleep, catches a run that waited for it (that
    // run fails after its 300 s).
    let marker = s.0.join("orphan-finished");
    let script = format!("(sleep 300; touch '{}') & exit 0", marker.display());
    let p = command("orphan", &["sh", "-c", &script]);
    assert_eq!(
        gates::proof_run_as(&s.0, &p, 1, false, &xtask::atc::Reserve::None).0,
        Ok(())
    );
    assert_no_leftover("orphan");
    assert!(!marker.exists(), "the orphan was not killed");
}

#[test]
fn finish_kills_what_is_left_and_removes_the_cgroup() {
    // atc, when it runs the proof, reaps leftovers itself; this drives
    // `finish` on its own.
    if let Err(reason) = real_cgroup("finish") {
        eprintln!("skipped: {reason}");
        return;
    }
    let text = fs::read_to_string("/proc/self/cgroup").unwrap();
    let name = cgroup::run_name("finish", ns(), std::process::id());
    let path = cgroup::create(
        Path::new("/sys/fs/cgroup"),
        &text,
        &name,
        64 << 20,
        ns(),
        &|_| true,
    )
    .unwrap();
    let mut child = moved_in(&path);
    let (_, warnings) = cgroup::finish(&path, 64 << 20);
    assert_eq!(warnings, Vec::<String>::new());
    assert!(!path.exists());
    assert!(child.wait().unwrap().code().is_none(), "killed by a signal");
}

/// Starts `sleep 300` in the cgroup at `path` through `MOVE_SH`, and returns
/// once it is inside: the shell prints a line after the move, before it
/// execs. A failed move ends the shell, so the read sees EOF and the test
/// fails instead of waiting.
fn moved_in(path: &Path) -> Child {
    let mut child = Command::new("sh")
        .args(["-c", xtask::proofs::MOVE_SH])
        .arg(path)
        .args(["sh", "-c", "echo in; exec sleep 300"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line, "in\n", "never moved in");
    child
}

/// Whether `child` died by a signal. A blocking wait, not a deadline: if
/// nothing kills it, its own sleep ends it with a code, and the caller's
/// assertion fails then. A pause cannot fail it.
fn killed(mut child: Child) -> bool {
    child.wait().unwrap().code().is_none()
}

/// A process that is killed and reaped when the test ends, even by a panic.
struct Owner(std::process::Child);
impl Drop for Owner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn the_sweep_kills_a_dead_runs_leftovers() {
    // An interrupted xtask leaves its proof running in its cgroup.
    // The run is named for a live process of its own, which this test's
    // sweep alone treats as dead: real sweeps (concurrent proof runs, this
    // test in another process) see it alive, and the name is unique.
    if let Err(reason) = real_cgroup("sweep-kill") {
        eprintln!("skipped: {reason}");
        return;
    }
    let owner = Owner(
        std::process::Command::new("sleep")
            .arg("300")
            .spawn()
            .unwrap(),
    );
    let dead = owner.0.id();
    let text = fs::read_to_string("/proc/self/cgroup").unwrap();
    let name = cgroup::run_name("sweep-kill", ns(), dead);
    let path = cgroup::create(
        Path::new("/sys/fs/cgroup"),
        &text,
        &name,
        64 << 20,
        ns(),
        &|_| true,
    )
    .unwrap();
    let mut child = moved_in(&path);
    // A concurrent proof run sweeps with the real liveness test: it must
    // leave this run alone.
    let real = |pid: u32| Path::new("/proc").join(pid.to_string()).exists();
    cgroup::sweep(path.parent().unwrap(), ns(), &real);
    assert!(
        fs::read_to_string(path.join("cgroup.events")).is_ok_and(|t| cgroup::populated(&t)),
        "a real sweep killed the test's run"
    );
    cgroup::sweep(path.parent().unwrap(), ns(), &|pid| pid != dead);
    let gone = !path.exists();
    if !gone {
        let _ = cgroup::finish(&path, 64 << 20);
    }
    drop(owner);
    assert!(gone, "a dead run's populated cgroup survived the sweep");
    assert!(child.wait().unwrap().code().is_none(), "killed by a signal");
}

#[test]
fn each_rejected_candidate_names_its_reason() {
    use std::os::unix::fs::PermissionsExt;
    let s = scratch("reasons");
    let delegated = fake(&s.0, "/1/delegated", "memory\n", "memory\n");
    fs::set_permissions(&delegated, fs::Permissions::from_mode(0o555)).unwrap();
    let e = cgroup::create(&s.0, SESSION, "xtask-proof-k-1", 4096, NS, &|_| true).unwrap_err();
    fs::set_permissions(&delegated, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        e.starts_with("no writable cgroup: /1/delegated: cannot create xtask-proof-k-1: "),
        "{e}"
    );
    assert!(e.ends_with("; /1: no memory controller"), "{e}");
}

#[test]
fn a_path_that_is_not_utf8_is_refused() {
    use std::os::unix::ffi::OsStrExt;
    let s = scratch("utf8");
    let root = s.0.join(std::ffi::OsStr::from_bytes(b"\xff"));
    fake(&root, "/1/delegated", "memory\n", "memory\n");
    let e = cgroup::create(&root, SESSION, "xtask-proof-k-1", 4096, NS, &|_| true).unwrap_err();
    assert!(e.contains("/1/delegated: path is not UTF-8"), "{e}");
}

#[test]
fn finish_never_creates_cgroup_kill() {
    // Kernels before 5.14 have no cgroup.kill: an empty run is not a warning.
    let s = scratch("no-kill");
    fs::write(s.0.join("cgroup.events"), "populated 0\n").unwrap();
    let (_, warnings) = cgroup::finish(&s.0, 1);
    assert!(!s.0.join("cgroup.kill").exists());
    assert!(
        !warnings.iter().any(|w| w.contains("cannot kill")),
        "{warnings:?}"
    );
}

#[test]
fn without_cgroup_kill_finish_kills_the_listed_processes() {
    let s = scratch("procs-kill");
    let child = Command::new("sleep").arg("300").spawn().unwrap();
    fs::write(s.0.join("cgroup.procs"), format!("{}\n", child.id())).unwrap();
    let (_, warnings) = cgroup::finish(&s.0, 1);
    assert!(killed(child), "{warnings:?}");
    assert!(
        !warnings.iter().any(|w| w.contains("cannot kill")),
        "{warnings:?}"
    );
}

#[test]
fn a_dropped_guard_kills_and_removes_its_cgroup() {
    // A run that unwinds before `finish` must not leave its cgroup behind.
    if let Err(reason) = real_cgroup("guard") {
        eprintln!("skipped: {reason}");
        return;
    }
    let text = fs::read_to_string("/proc/self/cgroup").unwrap();
    let name = cgroup::run_name("guard", ns(), std::process::id());
    let path = cgroup::create(
        Path::new("/sys/fs/cgroup"),
        &text,
        &name,
        64 << 20,
        ns(),
        &|_| true,
    )
    .unwrap();
    let mut child = moved_in(&path);
    drop(cgroup::Guard::new(path.clone(), 64 << 20));
    let gone = !path.exists();
    if !gone {
        let _ = cgroup::finish(&path, 64 << 20);
    }
    assert!(gone, "the guard left its cgroup");
    assert!(child.wait().unwrap().code().is_none(), "killed by a signal");
}

#[test]
fn a_guard_finishes_once_whether_finished_or_dropped() {
    // Against a fake, empty cgroup: inside an atc job no real one is made,
    // and the guard's own logic must still run (DEFERRED D1).
    let s = scratch("guard-fake");
    fs::write(s.0.join("cgroup.events"), "populated 0\n").unwrap();
    fs::write(s.0.join("memory.peak"), "4096\n").unwrap();
    let (usage, _) = cgroup::Guard::new(s.0.clone(), 1 << 20).finish();
    assert_eq!(usage.peak, Some(4096));
    let dropped = scratch("guard-dropped");
    fs::write(dropped.0.join("cgroup.events"), "populated 0\n").unwrap();
    drop(cgroup::Guard::new(dropped.0.clone(), 1 << 20));
}

#[test]
fn the_kernel_signals_an_emptied_cgroup_on_cgroup_events() {
    // `wait_empty` relies on this: the first check kills the cgroup's only
    // process and reports nothing, so a later "empty" can only come from a
    // modify event on `cgroup.events`.
    if let Err(reason) = real_cgroup("events") {
        eprintln!("skipped: {reason}");
        return;
    }
    let text = fs::read_to_string("/proc/self/cgroup").unwrap();
    let name = cgroup::run_name("events", ns(), std::process::id());
    let path = cgroup::create(
        Path::new("/sys/fs/cgroup"),
        &text,
        &name,
        64 << 20,
        ns(),
        &|_| true,
    )
    .unwrap();
    let mut child = moved_in(&path);
    let events = path.join("cgroup.events");
    let mut calls = 0;
    let emptied = xtask::watch::wait_until(
        &events,
        xtask::watch::WatchMask::MODIFY,
        Duration::from_secs(20),
        &mut || {
            calls += 1;
            if calls == 1 {
                child.kill().unwrap();
                return false;
            }
            !fs::read_to_string(&events).is_ok_and(|t| cgroup::populated(&t))
        },
    );
    let _ = child.wait();
    let _ = cgroup::finish(&path, 64 << 20);
    assert!(emptied.unwrap(), "no modify event on cgroup.events");
}
