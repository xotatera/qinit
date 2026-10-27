// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The parallel proof batch: captured runs, and what it charges against the
//! budget while entries run.
use std::path::Path;
use std::sync::Mutex;

use xtask::batch::{self, Waiting};
use xtask::proofs::{Kind, Proof};
use xtask::{atc::Reserve, gates::proof_run_as};

const G: u64 = 1 << 30;

fn proof(name: &str, kind: Kind, memory: u64) -> Proof {
    Proof {
        name: name.to_string(),
        kind,
        package: "x".to_string(),
        dir: String::new(),
        dirs: vec![String::new()],
        extra_globs: Vec::new(),
        extra_paths: Vec::new(),
        tools: Vec::new(),
        memory,
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

fn command(argv: &[&str]) -> Proof {
    proof(
        "b",
        Kind::Command(argv.iter().map(|a| (*a).to_string()).collect()),
        G,
    )
}

#[test]
fn a_command_entrys_output_is_captured() {
    let (result, log) = proof_run_as(
        &std::env::temp_dir(),
        &command(&["sh", "-c", "echo out; echo err >&2"]),
        1,
        true,
        &Reserve::None,
    );
    assert_eq!(result, Ok(()));
    assert!(log.contains("out\n") && log.contains("err\n"), "{log}");
}

#[test]
fn a_failed_spawn_is_that_entrys_failure() {
    let (result, _) = proof_run_as(
        &std::env::temp_dir(),
        &command(&["/nonexistent/prover"]),
        1,
        true,
        &Reserve::None,
    );
    assert!(result.is_err());
}

/// An entry larger than the whole budget runs alone; when it ends, only what
/// it was charged comes back, so the next entries never get more than the
/// real budget.
#[test]
fn an_oversized_entry_returns_only_what_it_took() {
    let waiting = vec![
        Waiting {
            index: 0,
            proof: proof("big", Kind::Kani, 64 * G),
        },
        Waiting {
            index: 1,
            proof: proof("a", Kind::Kani, 20 * G),
        },
        Waiting {
            index: 2,
            proof: proof("b", Kind::Kani, 20 * G),
        },
    ];
    let seen = Mutex::new(Vec::new());
    let runner = |_: &Path, p: &Proof, jobs: usize| {
        seen.lock().unwrap().push((p.name.clone(), jobs));
        (Ok(()), String::new())
    };
    let mut done = 0;
    batch::run(
        Path::new("."),
        waiting,
        &[0, 1, 2],
        8,
        16 * G,
        &runner,
        &mut |_| done += 1,
    );
    assert_eq!(done, 3);
    let seen = seen.into_inner().unwrap();
    assert!(seen.iter().all(|(_, jobs)| *jobs == 1), "{seen:?}");
}

#[test]
fn a_panicking_entry_is_reported_and_the_batch_finishes() {
    let waiting = vec![
        Waiting {
            index: 0,
            proof: proof("p", Kind::Kani, G),
        },
        Waiting {
            index: 1,
            proof: proof("q", Kind::Kani, G),
        },
    ];
    let runner = |_: &Path, p: &Proof, _: usize| {
        assert!(p.name != "p", "boom");
        (Ok(()), String::new())
    };
    let mut results = Vec::new();
    batch::run(
        Path::new("."),
        waiting,
        &[0, 1],
        4,
        8 * G,
        &runner,
        &mut |d| {
            results.push((d.index, d.result.is_ok()));
        },
    );
    results.sort_unstable();
    assert_eq!(results, [(0, false), (1, true)]);
}

#[test]
fn captured_stdout_and_stderr_keep_their_order() {
    let (result, log) = proof_run_as(
        &std::env::temp_dir(),
        &command(&["sh", "-c", "echo 1; echo 2 >&2; echo 3"]),
        1,
        true,
        &Reserve::None,
    );
    assert_eq!(result, Ok(()));
    assert!(log.contains("1\n2\n3\n"), "{log:?}");
}

#[test]
fn a_panic_keeps_what_was_logged() {
    let (result, log) = xtask::gates::logged(true, |log| {
        log.line("before the panic");
        panic!("boom");
    });
    assert!(result.unwrap_err().contains("panicked"));
    assert!(log.contains("before the panic\n"), "{log}");
}

/// Fail fast: once an entry fails, no queued entry starts; each is reported
/// as not run, so the caller concludes every entry.
#[test]
fn after_a_failure_no_queued_entry_starts() {
    let waiting = vec![
        Waiting {
            index: 0,
            proof: proof("first", Kind::Kani, G),
        },
        Waiting {
            index: 1,
            proof: proof("second", Kind::Kani, G),
        },
        Waiting {
            index: 2,
            proof: proof("third", Kind::Kani, G),
        },
    ];
    let started = Mutex::new(Vec::new());
    let runner = |_: &Path, p: &Proof, _: usize| {
        started.lock().unwrap().push(p.name.clone());
        (Err("fails".to_string()), String::new())
    };
    let mut results = Vec::new();
    // One core: entries start one at a time.
    batch::run(
        Path::new("."),
        waiting,
        &[0, 1, 2],
        1,
        8 * G,
        &runner,
        &mut |d| results.push((d.index, d.ran, d.result.is_ok())),
    );
    assert_eq!(started.into_inner().unwrap(), ["first"]);
    results.sort_unstable();
    assert_eq!(
        results,
        [(0, true, false), (1, false, false), (2, false, false)]
    );
}
