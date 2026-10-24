// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Proofs under the real atc daemon. Skipped when atc does not answer, when
//! this process already runs inside an `atc run` (a project's `gate:test`,
//! where a nested `--ram-max` under an uncapped outer run is refused), or
//! when `ATC_MAX_WAIT` is unset (an unbounded wait could hang the suite). A
//! run that gives up waiting (75) is skipped as busy.
use std::path::PathBuf;

use xtask::atc::{self, Atc, Reserve};
use xtask::gates;
use xtask::proofs::{Kind, Proof};

/// Why the real-atc tests cannot run here, if they cannot.
fn unavailable() -> Option<String> {
    skip_reason(
        atc::held(),
        atc::detect(),
        std::env::var_os("ATC_MAX_WAIT").as_deref(),
    )
}

/// `unavailable` for a given `held`, detection and `ATC_MAX_WAIT`.
fn skip_reason(held: bool, detected: &Atc, max_wait: Option<&std::ffi::OsStr>) -> Option<String> {
    if held {
        return Some("inside an atc run".to_string());
    }
    if let Atc::Absent(why) = detected {
        return Some(format!("atc not available ({why})"));
    }
    if max_wait.is_none_or(std::ffi::OsStr::is_empty) {
        return Some(
            "set ATC_MAX_WAIT (e.g. 3m) to bound the wait for the real daemon".to_string(),
        );
    }
    None
}

/// A run that gave up waiting (exit 75): the host is busy, not the code wrong.
fn busy(result: &Result<(), String>) -> bool {
    result
        .as_ref()
        .is_err_and(|e| e.contains("gave up waiting for atc"))
}

fn repo() -> String {
    format!("disciplines-test-{}", std::process::id())
}

/// Forgets the test's profile when the test ends, pass or fail.
struct Forget(String);
impl Drop for Forget {
    fn drop(&mut self) {
        let _ = std::process::Command::new("atc")
            .args(["profiles", "forget", &self.0])
            .output();
    }
}

fn command(name: &str, argv: &[&str], memory: u64) -> (Proof, Forget) {
    let p = Proof {
        name: name.to_string(),
        kind: Kind::Command(argv.iter().map(|a| (*a).to_string()).collect()),
        package: "c".to_string(),
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
    };
    let forget = Forget(format!("{}/{}", repo(), p.gate_name()));
    (p, forget)
}

fn root() -> PathBuf {
    std::env::temp_dir()
}

#[test]
fn real_atc_tests_skip_inside_an_atc_run() {
    let wait = Some(std::ffi::OsStr::new("3m"));
    assert_eq!(
        skip_reason(true, &Atc::Available, wait),
        Some("inside an atc run".to_string())
    );
    assert_eq!(skip_reason(false, &Atc::Available, wait), None);
    assert_eq!(
        skip_reason(false, &Atc::Absent("not on PATH".to_string()), wait),
        Some("atc not available (not on PATH)".to_string())
    );
    // Unbounded, a busy host would hang the suite.
    let unbounded =
        Some("set ATC_MAX_WAIT (e.g. 3m) to bound the wait for the real daemon".to_string());
    assert_eq!(skip_reason(false, &Atc::Available, None), unbounded);
    assert_eq!(
        skip_reason(false, &Atc::Available, Some(std::ffi::OsStr::new(""))),
        unbounded
    );
}

#[test]
fn an_allocation_past_the_atc_cap_exceeds_it() {
    if let Some(why) = unavailable() {
        eprintln!("skipped: {why}");
        return;
    }
    if !xtask::tools::on_path("python3") {
        eprintln!("skipped: no python3");
        return;
    }
    let (p, _forget) = command(
        "oom",
        &["python3", "-c", "b = bytearray(256 << 20)"],
        64 << 20,
    );
    let (result, _) = gates::proof_run_as(&root(), &p, 1, true, &Reserve::Atc { repo: repo() });
    if busy(&result) {
        eprintln!("skipped: atc busy");
        return;
    }
    assert_eq!(
        result,
        Err(
            "`python3 -c b = bytearray(256 << 20)`: exceeded its memory cap of 64M (atc --ram-max)"
                .to_string()
        )
    );
}

#[test]
fn a_run_within_the_atc_cap_passes_and_reports_its_peak() {
    if let Some(why) = unavailable() {
        eprintln!("skipped: {why}");
        return;
    }
    let (p, _forget) = command("fits", &["true"], 64 << 20);
    let _ = xtask::timing::take();
    let (result, log) = gates::proof_run_as(&root(), &p, 1, true, &Reserve::Atc { repo: repo() });
    if busy(&result) {
        eprintln!("skipped: atc busy");
        return;
    }
    assert_eq!(result, Ok(()));
    assert!(
        log.contains("peak memory") && log.contains("64M limit"),
        "{log}"
    );
    // The run's job events reached this thread (atc protocol 8 and later).
    let steps = xtask::timing::take();
    if events_supported() {
        assert_eq!(steps.len(), 1, "one atc run, one step");
    } else {
        assert_eq!(steps.len(), 0, "an older atc writes no events");
    }
}

/// Whether this atc writes job events: protocol 8 or later, as
/// `atc --version` says (`atc 0.1.0 (protocol 8)`).
fn events_supported() -> bool {
    std::process::Command::new("atc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| {
            let text = String::from_utf8_lossy(&o.stdout).into_owned();
            let n = text
                .split("(protocol ")
                .nth(1)?
                .split(')')
                .next()?
                .trim()
                .parse::<u32>()
                .ok()?;
            Some(n >= 8)
        })
        .unwrap_or(false)
}
