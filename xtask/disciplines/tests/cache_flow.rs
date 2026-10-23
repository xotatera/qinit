// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

use xtask::cache::store::Store;
use xtask::runner::{self, Cache, Outcome, cache_for};
use xtask::{Gate, Inputs};

/// One gate through the runner's two halves, the way `run_wave` drives them.
fn run_gate_with(
    g: &Gate,
    root: &Path,
    cache: &Cache,
    key: &dyn Fn(&Gate) -> Result<String, String>,
    alt: Option<&runner::Alt>,
) -> runner::Report {
    match runner::prepare(g, cache, key, alt) {
        Err(report) => report,
        Ok(pending) => {
            let result = (g.run)(root);
            runner::conclude(g, pending, result, key, alt)
        }
    }
}

fn run_gate(
    g: &Gate,
    root: &Path,
    cache: &Cache,
    key: &dyn Fn(&Gate) -> Result<String, String>,
) -> runner::Report {
    run_gate_with(g, root, cache, key, None)
}

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!("xtask-flow-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

fn gate(name: &'static str, run: fn(&Path) -> Result<(), String>) -> Gate {
    Gate {
        name,
        run: Box::new(run),
        inputs: Inputs::Tree,
        env: &[],
        tools: &[],
        extra_paths: &[],
        cache_paths: &[],
        ignored_inputs: &[],
        cacheable: true,
        cache_on_main: true,
        blocked: None,
        decl: "",
    }
}

// The fake bodies and key fns must match the `Gate::run` and key-callback
// signatures, even when they cannot fail.
#[allow(clippy::unnecessary_wraps)]
fn key_k1(_: &Gate) -> Result<String, String> {
    Ok("k1".to_string())
}

// One counter per test: tests run in parallel.
macro_rules! counted {
    ($runs:ident, $body:ident, $result:expr) => {
        static $runs: AtomicUsize = AtomicUsize::new(0);
        #[allow(clippy::unnecessary_wraps)] // signature fixed by `Gate::run`
        fn $body(_: &Path) -> Result<(), String> {
            $runs.fetch_add(1, SeqCst);
            $result
        }
    };
}

#[test]
fn a_hit_skips_the_run() {
    counted!(RUNS, body, Ok(()));
    let s = scratch("hit");
    let store = Store::at(s.0.join("c"));
    let g = gate("g", body);
    assert_eq!(
        run_gate(&g, &s.0, &Cache::Use(&store), &key_k1).outcome,
        Outcome::Passed
    );
    assert!(matches!(
        run_gate(&g, &s.0, &Cache::Use(&store), &key_k1).outcome,
        Outcome::Cached(_)
    ));
    assert_eq!(RUNS.load(SeqCst), 1);
}

#[test]
fn a_failure_is_never_recorded() {
    counted!(RUNS, body, Err("broken".to_string()));
    let s = scratch("fail");
    let store = Store::at(s.0.join("c"));
    let g = gate("g", body);
    for _ in 0..2 {
        assert_eq!(
            run_gate(&g, &s.0, &Cache::Use(&store), &key_k1).outcome,
            Outcome::Failed("broken".into())
        );
    }
    assert_eq!(RUNS.load(SeqCst), 2);
    assert_eq!(store.hit("g", "k1"), Ok(None));
}

#[test]
fn refresh_runs_and_records() {
    counted!(RUNS, body, Ok(()));
    let s = scratch("refresh");
    let store = Store::at(s.0.join("c"));
    store.record("g", "k1", 1).unwrap();
    let g = gate("g", body);
    assert_eq!(
        run_gate(&g, &s.0, &Cache::Refresh(&store), &key_k1).outcome,
        Outcome::Passed
    );
    assert_eq!(RUNS.load(SeqCst), 1);
    assert!(
        store.hit("g", "k1").unwrap().unwrap() > 1,
        "entry refreshed"
    );
}

#[test]
fn off_always_runs_and_writes_nothing() {
    counted!(RUNS, body, Ok(()));
    let s = scratch("off");
    let g = gate("g", body);
    for _ in 0..2 {
        assert_eq!(
            run_gate(&g, &s.0, &Cache::Off, &key_k1).outcome,
            Outcome::Passed
        );
    }
    assert_eq!(RUNS.load(SeqCst), 2);
    assert!(!s.0.join("c").exists());
}

#[test]
fn uncacheable_gates_always_run() {
    counted!(RUNS, body, Ok(()));
    let s = scratch("uncacheable");
    let store = Store::at(s.0.join("c"));
    let g = Gate {
        cacheable: false,
        ..gate("bench", body)
    };
    for _ in 0..2 {
        assert_eq!(
            run_gate(&g, &s.0, &Cache::Use(&store), &key_k1).outcome,
            Outcome::Passed
        );
    }
    assert_eq!(RUNS.load(SeqCst), 2);
}

#[test]
fn a_blocked_gate_is_skipped_never_run_never_cached() {
    counted!(RUNS, body, Ok(()));
    let s = scratch("blocked");
    let store = Store::at(s.0.join("c"));
    let g = Gate {
        blocked: Some("reformat pending"),
        ..gate("fmt", body)
    };
    assert_eq!(
        run_gate(&g, &s.0, &Cache::Use(&store), &key_k1).outcome,
        Outcome::Skipped("reformat pending")
    );
    assert_eq!(RUNS.load(SeqCst), 0);
    assert_eq!(store.hit("fmt", "k1"), Ok(None));
}

#[test]
fn a_key_error_runs_the_gate_with_a_warning() {
    counted!(RUNS, body, Ok(()));
    let s = scratch("keyerr");
    let store = Store::at(s.0.join("c"));
    let r = run_gate(&gate("g", body), &s.0, &Cache::Use(&store), &|_| {
        Err("no git".to_string())
    });
    assert_eq!(r.outcome, Outcome::Passed);
    assert!(
        r.warnings.iter().any(|w| w.contains("cannot compute key")),
        "{:?}",
        r.warnings
    );
    assert_eq!(RUNS.load(SeqCst), 1);
}

#[test]
fn a_corrupt_entry_runs_the_gate_and_is_replaced() {
    counted!(RUNS, body, Ok(()));
    let s = scratch("corrupt");
    let store = Store::at(s.0.join("c"));
    fs::create_dir_all(store.dir().join("g")).unwrap();
    fs::write(store.dir().join("g/k1"), "garbage").unwrap();
    let r = run_gate(&gate("g", body), &s.0, &Cache::Use(&store), &key_k1);
    assert_eq!(r.outcome, Outcome::Passed);
    assert!(
        r.warnings.iter().any(|w| w.contains("corrupt")),
        "{:?}",
        r.warnings
    );
    assert!(store.hit("g", "k1").unwrap().is_some());
    assert_eq!(RUNS.load(SeqCst), 1);
}

#[test]
fn an_unwritable_store_keeps_the_verdict() {
    counted!(RUNS, body, Ok(()));
    let s = scratch("unwritable");
    fs::write(s.0.join("file"), "x").unwrap();
    let store = Store::at(s.0.join("file/c"));
    let r = run_gate(&gate("g", body), &s.0, &Cache::Use(&store), &key_k1);
    assert_eq!(r.outcome, Outcome::Passed);
    assert!(
        r.warnings.iter().any(|w| w.contains("cannot record")),
        "{:?}",
        r.warnings
    );
}

static KEY_CALLS: AtomicUsize = AtomicUsize::new(0);
#[allow(clippy::unnecessary_wraps)] // signature fixed by the key callback
fn key_changing(_: &Gate) -> Result<String, String> {
    Ok(format!("k{}", KEY_CALLS.fetch_add(1, SeqCst) + 1))
}

#[test]
fn inputs_changed_during_the_run_are_not_recorded() {
    counted!(RUNS, body, Ok(()));
    let s = scratch("changed");
    let store = Store::at(s.0.join("c"));
    let r = run_gate(&gate("g", body), &s.0, &Cache::Use(&store), &key_changing);
    assert_eq!(r.outcome, Outcome::Passed);
    assert!(
        r.warnings
            .iter()
            .any(|w| w == "cache: g: inputs changed during the run; not recorded"),
        "{:?}",
        r.warnings
    );
    assert_eq!(store.hit("g", "k1"), Ok(None));
    assert_eq!(store.hit("g", "k2"), Ok(None));
}

static FLAKY_CALLS: AtomicUsize = AtomicUsize::new(0);
fn key_then_error(_: &Gate) -> Result<String, String> {
    if FLAKY_CALLS.fetch_add(1, SeqCst) == 0 {
        Ok("k1".to_string())
    } else {
        Err("boom".to_string())
    }
}

#[test]
fn a_key_that_cannot_be_recomputed_after_the_run_is_not_recorded() {
    counted!(RUNS, body, Ok(()));
    let s = scratch("recompute");
    let store = Store::at(s.0.join("c"));
    let r = run_gate(&gate("g", body), &s.0, &Cache::Use(&store), &key_then_error);
    assert_eq!(r.outcome, Outcome::Passed);
    assert!(
        r.warnings
            .iter()
            .any(|w| w == "cache: g: cannot recompute key after the run (boom); not recorded"),
        "{:?}",
        r.warnings
    );
    assert_eq!(store.hit("g", "k1"), Ok(None));
}

/// Which `Cache` variant `cache_for` chose.
fn mode(c: &Cache) -> &'static str {
    match c {
        Cache::Off => "off",
        Cache::Use(_) => "use",
        Cache::Refresh(_) => "refresh",
    }
}

#[test]
fn cache_for_decides_per_gate_over_every_combination() {
    counted!(RUNS, body, Ok(()));
    let s = scratch("cache-for");
    let store = Store::at(s.0.join("c"));
    for cache_on_main in [true, false] {
        let g = Gate {
            cache_on_main,
            ..gate("g", body)
        };
        for refresh in [false, true] {
            for main in [false, true] {
                assert_eq!(mode(&cache_for(&g, None, refresh, main)), "off");
                let want = if refresh || (main && !cache_on_main) {
                    "refresh"
                } else {
                    "use"
                };
                assert_eq!(
                    mode(&cache_for(&g, Some(&store), refresh, main)),
                    want,
                    "cache_on_main={cache_on_main} refresh={refresh} main={main}"
                );
            }
        }
    }
}

#[test]
fn a_cargo_gate_with_an_entry_runs_on_main_and_refreshes_it() {
    counted!(RUNS, body, Ok(()));
    let s = scratch("main-runs");
    let store = Store::at(s.0.join("c"));
    let g = Gate {
        cache_on_main: false,
        ..gate("lint", body)
    };
    store.record("lint", "k1", 1).unwrap();
    // A branch run is served from the seeded entry.
    let branch = cache_for(&g, Some(&store), false, false);
    assert_eq!(
        run_gate(&g, &s.0, &branch, &key_k1).outcome,
        Outcome::Cached(1)
    );
    assert_eq!(RUNS.load(SeqCst), 0);
    // On main the entry is not trusted: the gate runs again and re-records.
    let main = cache_for(&g, Some(&store), false, true);
    assert_eq!(run_gate(&g, &s.0, &main, &key_k1).outcome, Outcome::Passed);
    assert_eq!(RUNS.load(SeqCst), 1);
    assert!(matches!(store.hit("lint", "k1"), Ok(Some(t)) if t > 1));
    // A gate that is cached on main still is.
    let g = Gate {
        cache_on_main: true,
        ..g
    };
    let main = cache_for(&g, Some(&store), false, true);
    assert!(matches!(
        run_gate(&g, &s.0, &main, &key_k1).outcome,
        Outcome::Cached(_)
    ));
    assert_eq!(RUNS.load(SeqCst), 1);
}

fn alt_of(key: &dyn Fn() -> Result<String, String>, lookup: bool) -> runner::Alt<'_> {
    runner::Alt {
        record_as: "g~contracts".to_string(),
        key,
        lookup: if lookup { &|| true } else { &|| false },
    }
}

/// The prerequisite check runs only when an alternate lookup can matter:
/// not on a full-key hit, not under `--no-cache`.
#[test]
fn the_alt_lookup_check_runs_only_when_needed() {
    let s = scratch("alt-lazy");
    let store = Store::at(s.0.join("cache"));
    let calls = std::cell::Cell::new(0);
    let check = || {
        calls.set(calls.get() + 1);
        false
    };
    let ak = || Ok("a1".to_string());
    let alt = runner::Alt {
        record_as: "g~contracts".to_string(),
        key: &ak,
        lookup: &check,
    };
    let g = gate("g", |_| Ok(()));
    store.record("g", "k1", 1).unwrap();
    run_gate_with(&g, &s.0, &Cache::Use(&store), &key_k1, Some(&alt));
    run_gate_with(&g, &s.0, &Cache::Refresh(&store), &key_k1, Some(&alt));
    assert_eq!(calls.get(), 0, "full hit and refresh");
    let other = |_: &Gate| Ok("k2".to_string());
    run_gate_with(&g, &s.0, &Cache::Use(&store), &other, Some(&alt));
    assert_eq!(calls.get(), 1, "full miss");
}

#[test]
fn a_pass_records_both_keys_and_an_alt_hit_serves_the_next_run() {
    let s = scratch("alt-record");
    let store = Store::at(s.0.join("cache"));
    let g = gate("g", |_| Ok(()));
    let ak = || Ok("a1".to_string());
    let alt = alt_of(&ak, true);
    let r = run_gate_with(&g, &s.0, &Cache::Use(&store), &key_k1, Some(&alt));
    assert_eq!(r.outcome, Outcome::Passed);
    assert!(store.hit("g", "k1").unwrap().is_some());
    assert!(store.hit("g~contracts", "a1").unwrap().is_some());
    let other_full = |_: &Gate| Ok("k2".to_string());
    let r = run_gate_with(&g, &s.0, &Cache::Use(&store), &other_full, Some(&alt));
    assert!(
        matches!(r.outcome, Outcome::CachedByContracts(_)),
        "{:?}",
        r.outcome
    );
}

#[test]
fn alt_lookup_is_skipped_when_not_allowed() {
    let s = scratch("alt-locked");
    let store = Store::at(s.0.join("cache"));
    store.record("g~contracts", "a1", 1).unwrap();
    let g = gate("g", |_| Ok(()));
    let ak = || Ok("a1".to_string());
    let alt = alt_of(&ak, false);
    let r = run_gate_with(&g, &s.0, &Cache::Use(&store), &key_k1, Some(&alt));
    assert_eq!(r.outcome, Outcome::Passed);
}

#[test]
fn a_full_hit_wins_over_the_alt_key() {
    let s = scratch("alt-full");
    let store = Store::at(s.0.join("cache"));
    store.record("g", "k1", 1).unwrap();
    let g = gate("g", |_| Err("must not run".to_string()));
    let ak = || Err("alt key must not be computed".to_string());
    let alt = alt_of(&ak, true);
    let r = run_gate_with(&g, &s.0, &Cache::Use(&store), &key_k1, Some(&alt));
    assert_eq!(r.outcome, Outcome::Cached(1));
}

#[test]
fn a_failure_records_neither_key() {
    let s = scratch("alt-fail");
    let store = Store::at(s.0.join("cache"));
    let g = gate("g", |_| Err("no".to_string()));
    let ak = || Ok("a1".to_string());
    let alt = alt_of(&ak, true);
    let r = run_gate_with(&g, &s.0, &Cache::Use(&store), &key_k1, Some(&alt));
    assert!(matches!(r.outcome, Outcome::Failed(_)));
    assert_eq!(store.hit("g~contracts", "a1").unwrap(), None);
    assert_eq!(store.hit("g", "k1").unwrap(), None);
}

#[test]
fn an_alt_key_error_is_a_warning_and_the_full_key_still_records() {
    let s = scratch("alt-err");
    let store = Store::at(s.0.join("cache"));
    let g = gate("g", |_| Ok(()));
    let ak = || Err("unreadable spine".to_string());
    let alt = alt_of(&ak, true);
    let r = run_gate_with(&g, &s.0, &Cache::Use(&store), &key_k1, Some(&alt));
    assert_eq!(r.outcome, Outcome::Passed);
    assert!(
        r.warnings.iter().any(|w| w.contains("unreadable spine")),
        "{:?}",
        r.warnings
    );
    assert!(store.hit("g", "k1").unwrap().is_some());
}

#[test]
fn prepare_then_conclude_equals_run_gate() {
    let s = scratch("split");
    let store = Store::at(s.0.join("cache"));
    let g = gate("g", |_| Ok(()));
    let pending = runner::prepare(&g, &Cache::Use(&store), &key_k1, None)
        .ok()
        .unwrap();
    let r = runner::conclude(&g, pending, Ok(()), &key_k1, None);
    assert_eq!(r.outcome, Outcome::Passed);
    assert!(store.hit("g", "k1").unwrap().is_some());
    assert!(matches!(
        runner::prepare(&g, &Cache::Use(&store), &key_k1, None),
        Err(runner::Report {
            outcome: Outcome::Cached(_),
            ..
        })
    ));
}

#[test]
fn a_gate_that_ran_prints_its_wall_time_in_tenths() {
    use std::time::Duration;
    use xtask::timing::Parts;
    let took = |d| Parts::of(d, &[]).suffix(true);
    assert_eq!(took(Duration::from_millis(12_345)), " (12.3s)");
    assert_eq!(took(Duration::ZERO), " (0.0s)");
    assert_eq!(took(Duration::from_secs(95)), " (95.0s)");
}

#[test]
fn the_gate_summary_names_the_three_slowest_and_warns_past_the_budget() {
    use std::time::Duration;
    use xtask::runner::summary;
    let ran = [
        ("fmt", Duration::from_millis(100)),
        ("lint", Duration::from_secs(5)),
        ("test", Duration::from_millis(3200)),
        ("scaffold", Duration::from_secs(21)),
    ];
    let none = Duration::ZERO;
    assert_eq!(
        summary(Duration::from_millis(30_250), none, &ran),
        ["gate total 30.2s; slowest: scaffold 21.0s, lint 5.0s, test 3.2s"]
    );
    assert_eq!(
        summary(Duration::from_millis(400), Duration::from_millis(49), &[]),
        ["gate total 0.4s"],
        "a hold that shows as 0.0s is not shown"
    );
    let late = summary(Duration::from_secs(200), none, &ran);
    assert_eq!(late.len(), 2);
    assert!(
        late[1].starts_with("warning: the gate took 200s, over the 180s merge budget"),
        "{}",
        late[1]
    );
    assert_eq!(
        summary(Duration::from_secs(180), none, &ran).len(),
        1,
        "at the budget: no warning"
    );
    // atc held the run: the total says how much, and the budget compares
    // the run's own time (plan 2026-10-14-atc-step-timing.md R2).
    let held = summary(Duration::from_secs(1198), Duration::from_mins(15), &ran);
    assert_eq!(
        held,
        ["gate total 1198.0s (own 298.0s, held by atc 900.0s); slowest: scaffold 21.0s, lint 5.0s, test 3.2s"
            .to_string(),
        "warning: the gate took 298s of its own, over the 180s merge budget; the slowest gates above are where to look"
            .to_string()]
    );
    assert_eq!(
        summary(Duration::from_secs(1000), Duration::from_mins(15), &ran).len(),
        1,
        "own time under the budget: no warning, however long atc held it"
    );
}
