// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! `cargo xtask dup …`: look at duplication outside the gate.
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use super::extract::Function;
use super::{BASELINE, MIN_TOKENS, NO_INPUT, Tier, baseline, describe, groups, scan};

#[derive(Debug, PartialEq, Eq)]
pub enum DupArgs {
    /// Print groups; `loose` is the advisory tier.
    Report {
        path: Option<PathBuf>,
        min_tokens: Option<usize>,
        include_tests: bool,
        loose: bool,
    },
    /// Group counts across floors, to choose `MIN_TOKENS`.
    Sweep { path: Option<PathBuf> },
    /// Narrow the baseline to what still matches.
    Bless,
}

/// The floors `dup sweep` measures.
pub const SWEEP_SIZES: &[usize] = &[10, 20, 30, 40, 60, 80, 120];

const USAGE: &str = "usage: cargo xtask dup report [--path P] [--min-tokens N] [--include-tests] [--loose]\n       cargo xtask dup sweep [--path P]\n       cargo xtask dup bless";

/// # Errors
/// The usage text.
pub fn parse(args: &[&str]) -> Result<DupArgs, String> {
    let usage = || USAGE.to_string();
    let (cmd, rest) = args.split_first().ok_or_else(usage)?;
    let (mut path, mut min_tokens, mut include_tests, mut loose) = (None, None, false, false);
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        match *arg {
            "--path" => path = Some(PathBuf::from(it.next().ok_or_else(usage)?)),
            "--min-tokens" => {
                min_tokens = Some(it.next().ok_or_else(usage)?.parse().map_err(|_| usage())?);
            }
            "--include-tests" => include_tests = true,
            "--loose" => loose = true,
            _ => return Err(usage()),
        }
    }
    let plain = min_tokens.is_none() && !include_tests && !loose;
    match *cmd {
        "report" => Ok(DupArgs::Report {
            path,
            min_tokens,
            include_tests,
            loose,
        }),
        "sweep" if plain => Ok(DupArgs::Sweep { path }),
        "bless" if plain && path.is_none() => Ok(DupArgs::Bless),
        _ => Err(usage()),
    }
}

/// A scan that found functions: an empty one checks nothing.
fn scan_nonempty(root: &Path) -> Result<Vec<Function>, String> {
    let fns = scan(root)?;
    if fns.is_empty() {
        return Err(NO_INPUT.to_string());
    }
    Ok(fns)
}

/// # Errors
/// A scan or baseline error, or no input at all.
pub fn run(args: &DupArgs, root: &Path) -> Result<String, String> {
    let mut out = String::new();
    match args {
        DupArgs::Report {
            path,
            min_tokens,
            include_tests,
            loose,
        } => {
            let fns = scan_nonempty(path.as_deref().unwrap_or(root))?;
            let tier = if *loose { Tier::Loose } else { Tier::Strict };
            let found = groups(&fns, tier, min_tokens.unwrap_or(MIN_TOKENS), *include_tests);
            let _ = writeln!(
                out,
                "{} groups ({} functions scanned)",
                found.len(),
                fns.len()
            );
            for g in &found {
                let _ = writeln!(out, "{} tokens: {}", g.tokens, describe(g));
            }
        }
        DupArgs::Sweep { path } => {
            let fns = scan_nonempty(path.as_deref().unwrap_or(root))?;
            let _ = writeln!(
                out,
                "{} functions\nmin_tokens  strict  strict+tests  loose",
                fns.len()
            );
            for &m in SWEEP_SIZES {
                let count = |tier, tests| groups(&fns, tier, m, tests).len();
                let _ = writeln!(
                    out,
                    "{m:>10}  {:>6}  {:>12}  {:>5}",
                    count(Tier::Strict, false),
                    count(Tier::Strict, true),
                    count(Tier::Loose, false)
                );
            }
        }
        DupArgs::Bless => {
            let file = root.join(BASELINE);
            let base = baseline::load(&file)?;
            let fns = scan_nonempty(root)?;
            let current = groups(&fns, Tier::Strict, MIN_TOKENS, false);
            std::fs::write(&file, baseline::bless(&base, &current))
                .map_err(|e| format!("{}: {e}", file.display()))?;
            let _ = writeln!(out, "wrote {}", file.display());
        }
    }
    Ok(out)
}
