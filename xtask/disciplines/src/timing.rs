// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! A gate's time under atc (plan `2026-10-14-atc-step-timing.md`): each
//! `atc run` the runner starts reports its job events (atc protocol 8,
//! [`EVENTS_ENV`]), so a gate's line splits its wall time into ran, waited
//! and paused, and the run's total into its own time and the time atc held
//! it. Steps are recorded per thread: gates other than proofs run on the
//! runner's thread, each proof of a batch on its own.
use std::cell::RefCell;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;

/// One `atc run`'s job events: `exited`'s totals, and when atc held the
/// job (waiting for admission, paused), as offsets from the run's start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Step {
    pub waited: Duration,
    pub paused: Duration,
    pub cpu: Option<Duration>,
    pub held: Vec<(Duration, Duration)>,
}

/// The step an event stream describes; `None` without a complete `exited`
/// line (an older atc writes none, a stream may be lost). Malformed lines
/// are skipped. A hold opens at the start, on `paused` and on `requeued`,
/// and closes on `admitted`, on `resumed`, or at `exited`.
#[must_use]
pub fn parse(stream: &str) -> Option<Step> {
    let mut held = Vec::new();
    let mut open = Some(Duration::ZERO);
    for line in stream.lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let ms = |k: &str| v.get(k).and_then(Value::as_u64).map(Duration::from_millis);
        let (Some(event), Some(t)) = (v.get("event").and_then(Value::as_str), ms("t_ms")) else {
            continue;
        };
        match event {
            "admitted" | "resumed" => {
                if let Some(from) = open.take() {
                    held.push((from, t));
                }
            }
            "paused" | "requeued" => {
                open.get_or_insert(t);
            }
            "exited" => {
                if let Some(from) = open.take() {
                    held.push((from, t));
                }
                return Some(Step {
                    waited: ms("waited_ms")?,
                    paused: ms("paused_ms")?,
                    cpu: ms("cpu_ms"),
                    held,
                });
            }
            _ => {}
        }
    }
    None
}

/// A gate's time: its wall time, and what atc held of it over its steps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parts {
    pub wall: Duration,
    pub waited: Duration,
    pub paused: Duration,
    /// Summed over the steps that reported it; `None` when none did.
    pub cpu: Option<Duration>,
}

impl Parts {
    #[must_use]
    pub fn of(wall: Duration, steps: &[Step]) -> Parts {
        let cpu = steps.iter().filter_map(|s| s.cpu).reduce(|a, b| a + b);
        Parts {
            wall,
            waited: steps.iter().map(|s| s.waited).sum(),
            paused: steps.iter().map(|s| s.paused).sum(),
            cpu,
        }
    }

    /// The wall time less what atc held, so the parts add up.
    #[must_use]
    pub fn ran(&self) -> Duration {
        self.wall.saturating_sub(self.waited + self.paused)
    }

    /// The suffix after a gate's name: ` (12.3s)`, or
    /// ` (702.1s: ran 90.1s, waited 600.0s, paused 12.0s)` when atc held it,
    /// with `; cpu 3.1s` when `cpu` is asked and reported.
    #[must_use]
    pub fn suffix(&self, cpu: bool) -> String {
        let mut text = secs(self.wall);
        let held: Vec<String> = [("waited", self.waited), ("paused", self.paused)]
            .into_iter()
            .filter(|(_, d)| shown(*d))
            .map(|(name, d)| format!("{name} {}", secs(d)))
            .collect();
        if !held.is_empty() {
            let _ = write!(text, ": ran {}, {}", secs(self.ran()), held.join(", "));
        }
        if cpu && let Some(c) = self.cpu {
            let _ = write!(text, "; cpu {}", secs(c));
        }
        format!(" ({text})")
    }
}

/// Seconds in tenths: `12.3s`.
#[must_use]
pub fn secs(d: Duration) -> String {
    format!("{:.1}s", d.as_secs_f64())
}

/// Whether `d` shows as more than `0.0s`.
#[must_use]
pub fn shown(d: Duration) -> bool {
    d >= Duration::from_millis(50)
}

/// A gate as the run saw it, in offsets from the run's start: when it ran,
/// and when atc held it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    pub start: Duration,
    pub end: Duration,
    pub held: Vec<(Duration, Duration)>,
}

/// The time in which some gate ran and atc held every gate then running:
/// gates running in parallel count once, and a gate that works while
/// another waits keeps the run its own.
#[must_use]
pub fn held_total(spans: &[Span]) -> Duration {
    let mut ends: Vec<Duration> = spans
        .iter()
        .flat_map(|s| {
            [s.start, s.end]
                .into_iter()
                .chain(s.held.iter().flat_map(|h| [h.0, h.1]))
        })
        .collect();
    ends.sort();
    ends.dedup();
    ends.windows(2)
        .filter(|w| {
            let at = w[0];
            let mut running = spans
                .iter()
                .filter(|s| s.start <= at && at < s.end)
                .peekable();
            running.peek().is_some()
                && running.all(|s| s.held.iter().any(|h| h.0 <= at && at < h.1))
        })
        .map(|w| w[1].saturating_sub(w[0]))
        .sum()
}

/// The variable atc (protocol 8) writes an `atc run`'s job events to.
pub const EVENTS_ENV: &str = "ATC_EVENTS_TO";

thread_local! {
    static STEPS: RefCell<Vec<(Instant, Step)>> = RefCell::default();
}

static STREAMS: AtomicU64 = AtomicU64::new(0);

/// The events file of one `atc run` the runner is about to start, removed
/// when dropped.
pub struct Stream {
    path: PathBuf,
    start: Instant,
}

impl Stream {
    /// A stream in the temp directory ([`Stream::new_in`]).
    #[must_use]
    pub fn new(held: bool) -> Option<Stream> {
        Stream::new_in(&std::env::temp_dir(), held)
    }

    /// `None` inside an outer `atc run` (`held`), where a stream of its own
    /// makes `atc run` exit 64 (the outer run's stream covers it), and when
    /// no new file can be made in `dir`: atc exits 64 on a target it cannot
    /// open, and a file someone else made there is not ours to read. The
    /// file is created here, new and private (0600); atc truncates it.
    #[must_use]
    pub fn new_in(dir: &std::path::Path, held: bool) -> Option<Stream> {
        use std::os::unix::fs::OpenOptionsExt;
        if held {
            return None;
        }
        // A name taken (another PID namespace sharing the directory) moves
        // on to the next.
        (0..8).find_map(|_| {
            let path = dir.join(format!(
                "xtask-atc-events-{}-{}",
                std::process::id(),
                STREAMS.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .ok()?;
            Some(Stream {
                path,
                start: Instant::now(),
            })
        })
    }

    /// The variable to set on the `atc run`.
    #[must_use]
    pub fn env(&self) -> (&'static str, &std::path::Path) {
        (EVENTS_ENV, &self.path)
    }

    /// Reads the stream once the run ended, records its step on this
    /// thread and returns it; an empty or incomplete stream records
    /// nothing.
    #[must_use = "the step is also recorded; `let _ =` when only that is wanted"]
    pub fn finish(self) -> Option<Step> {
        let step = parse(&std::fs::read_to_string(&self.path).unwrap_or_default())?;
        STEPS.with(|s| s.borrow_mut().push((self.start, step.clone())));
        Some(step)
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The steps this thread recorded since the last call, with when each
/// started.
#[must_use]
pub fn take() -> Vec<(Instant, Step)> {
    STEPS.with(|s| std::mem::take(&mut *s.borrow_mut()))
}

/// A gate's span from when the run and the gate started, its wall time,
/// and its steps.
#[must_use]
pub fn span(run: Instant, gate: Instant, wall: Duration, steps: &[(Instant, Step)]) -> Span {
    let start = gate.saturating_duration_since(run);
    let end = start + wall;
    let held = steps
        .iter()
        .flat_map(|(at, step)| {
            let offset = at.saturating_duration_since(run);
            step.held.iter().map(move |h| {
                (
                    (offset + h.0).clamp(start, end),
                    (offset + h.1).clamp(start, end),
                )
            })
        })
        .collect();
    Span { start, end, held }
}
