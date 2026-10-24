// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! What one gate run shares between its gates: which gates it will run, and
//! results computed once for all of them (a `test` gate reusing the
//! instrumented run of a `zero-coverage` gate). Reset when a gate run
//! starts, so nothing crosses runs. Thread-local: gates other than proofs
//! run one at a time on the runner's thread, and tests running gate runs in
//! parallel must not see each other's; asked from another thread,
//! [`will_run`] is `false` and [`shared`] runs its function.
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
struct Scope {
    running: BTreeSet<String>,
    shared: BTreeMap<String, Result<(), String>>,
}

thread_local! {
    static SCOPE: RefCell<Scope> = RefCell::default();
}

/// Forgets the previous run.
pub(crate) fn reset() {
    SCOPE.with(|s| *s.borrow_mut() = Scope::default());
}

/// Records the gates of a wave that will run: selected, not blocked, not
/// cached. Each wave adds its own before running any.
pub(crate) fn add<'a>(gates: impl IntoIterator<Item = &'a str>) {
    SCOPE.with(|s| {
        s.borrow_mut()
            .running
            .extend(gates.into_iter().map(str::to_string));
    });
}

/// Whether the current gate run will run `gate` (or already ran it). A gate
/// of a later wave (proofs) is not known yet: `false`. Between runs it keeps
/// the last run's answer; `false` before this thread's first.
#[must_use]
pub fn will_run(gate: &str) -> bool {
    SCOPE.with(|s| s.borrow().running.contains(gate))
}

/// `f`'s result, computed the first time `key` is asked for in this gate
/// run; every later caller gets the same result without running anything.
/// `f` must not ask for its own `key`: nothing is stored until it returns.
///
/// # Errors
/// `f`'s error, to every caller.
pub fn shared(key: &str, f: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
    if let Some(done) = SCOPE.with(|s| s.borrow().shared.get(key).cloned()) {
        return done;
    }
    // Not borrowed while `f` runs: it may ask `will_run`.
    let result = f();
    SCOPE.with(|s| {
        s.borrow_mut()
            .shared
            .insert(key.to_string(), result.clone());
    });
    result
}
