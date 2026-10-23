// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Running one gate with the cache:
//! - a blocked gate prints `SKIP` and never runs;
//! - a hit (or, for contract-keyed proofs, a hit under the alternate key)
//!   prints `CACHED` and the gate does not run;
//! - otherwise the gate runs, and a pass is recorded.
//!
//! Every cache error is a warning that ends in running the gate.
use crate::Gate;
use crate::cache::store::{self, Store};
use std::fmt::Write as _;
use std::time::Duration;

/// How a run uses the cache.
pub enum Cache<'a> {
    /// No lookup, no recording (no store could be opened).
    Off,
    /// Look up, and record passes.
    Use(&'a Store),
    /// `--no-cache`: always run, but still record passes.
    Refresh(&'a Store),
}

/// The cache mode for one gate. No store means `Off`. `--no-cache`, and a
/// `cache_on_main: false` gate in the main context, run the gate and record
/// its pass (`Refresh`); everything else may be served from the cache.
#[must_use]
pub fn cache_for<'a>(
    gate: &Gate,
    store: Option<&'a Store>,
    refresh: bool,
    main: bool,
) -> Cache<'a> {
    match store {
        None => Cache::Off,
        Some(s) if refresh || (main && !gate.cache_on_main) => Cache::Refresh(s),
        Some(s) => Cache::Use(s),
    }
}

/// The merge budget the gate summary warns past (the user's limit for a
/// merge into main).
pub const GATE_BUDGET: Duration = Duration::from_secs(180);

/// The lines that end a gate run: `gate total 12.3s; slowest: lint 5.0s,
/// test 3.2s, scaffold 2.1s` (the three slowest gates that ran, by their
/// time less atc's holds), and a warning past [`GATE_BUDGET`]. `held` is
/// the time atc held the whole run (`timing::held_total`): when shown, the
/// total says `(own …, held by atc …)` and the budget compares own time
/// (plan `2026-10-14-atc-step-timing.md` R2). Never a failure.
#[must_use]
pub fn summary(total: Duration, held: Duration, ran: &[(&str, Duration)]) -> Vec<String> {
    let mut slow: Vec<&(&str, Duration)> = ran.iter().collect();
    slow.sort_by_key(|(_, d)| std::cmp::Reverse(*d));
    let names: Vec<String> = slow
        .iter()
        .take(3)
        .map(|(name, d)| format!("{name} {}", crate::timing::secs(*d)))
        .collect();
    let own = total.saturating_sub(held);
    let held_shown = crate::timing::shown(held);
    let mut line = format!("gate total {}", crate::timing::secs(total));
    if held_shown {
        let _ = write!(
            line,
            " (own {}, held by atc {})",
            crate::timing::secs(own),
            crate::timing::secs(held)
        );
    }
    if !names.is_empty() {
        line.push_str("; slowest: ");
        line.push_str(&names.join(", "));
    }
    let mut lines = vec![line];
    if own > GATE_BUDGET {
        lines.push(format!(
            "warning: the gate took {:.0}s{}, over the {}s merge budget; the slowest gates above are where to look",
            own.as_secs_f64(),
            if held_shown { " of its own" } else { "" },
            GATE_BUDGET.as_secs()
        ));
    }
    lines
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Skipped(&'static str),
    Cached(u64),
    /// Served by the alternate (spine contracts) key.
    CachedByContracts(u64),
    Passed,
    Failed(String),
}

#[derive(Debug)]
pub struct Report {
    pub outcome: Outcome,
    pub warnings: Vec<String>,
}

/// The alternate key of a contract-keyed proof (`runner.md`, Proof tier).
pub struct Alt<'a> {
    /// Record name for alternate passes: `<gate>~contracts`.
    pub record_as: String,
    pub key: &'a dyn Fn() -> Result<String, String>,
    /// Whether a hit under the alternate key may serve this run; asked only
    /// after a full-key miss under a lookup cache mode.
    pub lookup: &'a dyn Fn() -> bool,
}

/// What a run that wasn't served from the cache must record when it passes.
pub struct Pending<'a> {
    pub warnings: Vec<String>,
    record: Option<(&'a Store, String)>,
    alt_record: Option<(&'a Store, String)>,
}

/// The lookup half: `Err(report)` when the gate is skipped or served from
/// the cache (by its key or, when allowed, its alternate key); otherwise
/// what to record after the run.
///
/// # Errors
/// The final report when the gate does not run: skipped or cached.
pub fn prepare<'a>(
    gate: &Gate,
    cache: &Cache<'a>,
    key: &dyn Fn(&Gate) -> Result<String, String>,
    alt: Option<&Alt>,
) -> Result<Pending<'a>, Report> {
    let mut warnings = Vec::new();
    if let Some(reason) = gate.blocked {
        return Err(Report {
            outcome: Outcome::Skipped(reason),
            warnings,
        });
    }
    let (store, lookup) = match cache {
        Cache::Use(store) if gate.cacheable => (Some(*store), true),
        Cache::Refresh(store) if gate.cacheable => (Some(*store), false),
        _ => (None, false),
    };
    let Some(store) = store else {
        return Ok(Pending {
            warnings,
            record: None,
            alt_record: None,
        });
    };
    let mut record = None;
    match key(gate) {
        Err(e) => warnings.push(format!(
            "cache: {}: cannot compute key ({e}); running it",
            gate.name
        )),
        Ok(k) => {
            if lookup {
                match store.hit(gate.name, &k) {
                    Ok(Some(when)) => {
                        return Err(Report {
                            outcome: Outcome::Cached(when),
                            warnings,
                        });
                    }
                    Ok(None) => {}
                    Err(e) => warnings.push(format!("cache: {e}; running it")),
                }
            }
            record = Some((store, k));
        }
    }
    let mut alt_record = None;
    if let Some(alt) = alt {
        match (alt.key)() {
            Err(e) => warnings.push(format!(
                "cache: {}: cannot compute the contract key ({e})",
                gate.name
            )),
            Ok(k) => {
                if lookup && (alt.lookup)() {
                    match store.hit(&alt.record_as, &k) {
                        Ok(Some(when)) => {
                            return Err(Report {
                                outcome: Outcome::CachedByContracts(when),
                                warnings,
                            });
                        }
                        Ok(None) => {}
                        Err(e) => warnings.push(format!("cache: {e}")),
                    }
                }
                alt_record = Some((store, k));
            }
        }
    }
    Ok(Pending {
        warnings,
        record,
        alt_record,
    })
}

/// The recording half: a pass is recorded under each key that is
/// unchanged after the run.
pub fn conclude(
    gate: &Gate,
    pending: Pending,
    result: Result<(), String>,
    key: &dyn Fn(&Gate) -> Result<String, String>,
    alt: Option<&Alt>,
) -> Report {
    let Pending {
        mut warnings,
        record,
        alt_record,
    } = pending;
    if let Err(msg) = result {
        return Report {
            outcome: Outcome::Failed(msg),
            warnings,
        };
    }
    if let Some((store, k)) = record {
        let after = key(gate);
        if let Err(e) = &after {
            warnings.push(format!(
                "cache: {}: cannot recompute key after the run ({e}); not recorded",
                gate.name
            ));
        } else if after.as_deref() != Ok(k.as_str()) {
            warnings.push(format!(
                "cache: {}: inputs changed during the run; not recorded",
                gate.name
            ));
        } else if let Err(e) = store.record(gate.name, &k, store::now()) {
            warnings.push(format!("cache: cannot record {} ({e})", gate.name));
        }
    }
    if let (Some((store, k)), Some(alt)) = (alt_record, alt)
        && (alt.key)().as_deref() == Ok(k.as_str())
        && let Err(e) = store.record(&alt.record_as, &k, store::now())
    {
        warnings.push(format!("cache: cannot record {} ({e})", alt.record_as));
    }
    Report {
        outcome: Outcome::Passed,
        warnings,
    }
}
