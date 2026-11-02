// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Random compiled graphs under random scripts and random inputs. After every input the
//! invariants the proofs cannot state about the running system are checked against a restatement
//! of spec §4 written here, not taken from the core: hard stop order, no start after shutdown,
//! foragers and the breaker, convergence. At settled points no node is left waiting that could
//! start (the clause of obligation 6 the proofs only state under convergence).
mod common;

use common::try_database;
use qinit_colony::sim::{Call, Script, Sim, advance};
use qinit_colony::text::state_text;
use qinit_colony::{Colony, Error, Request, State, Why};
use qinit_db::{GroupKind, Kind, Mode, RestartPolicy, Target};
use std::collections::BTreeSet;
use std::fmt::Write as _;

/// A deterministic generator (xorshift64*).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

/// A random frame set of `n` nodes whose edges point at lower indices (so it is acyclic), and
/// the roots to enable.
fn frames(rng: &mut Rng, n: usize) -> (String, Vec<String>) {
    let name = |i: usize| format!("n{i:02}");
    let mut out = String::new();
    let mut roots = Vec::new();
    for i in 0..n {
        let kind = match rng.below(10) {
            0 => "brood",
            1 => "forager",
            _ => "worker",
        };
        let _ = writeln!(out, "[{kind}.{}]", name(i));
        if kind != "brood" {
            let _ = writeln!(out, "exec = [\"/bin/{}\"]", name(i));
        }
        if kind == "worker" {
            match rng.below(5) {
                0 | 1 => {}
                2 | 3 => {
                    let _ = writeln!(out, "restart = {{ policy = \"on-failure\", max = 2 }}");
                }
                _ => {
                    let _ = writeln!(out, "restart = {{ policy = \"always\", max = 3 }}");
                }
            }
        }
        let mut groups = Vec::new();
        if i > 0 {
            for _ in 0..rng.below(3) {
                let kind = match rng.below(20) {
                    0..=11 => "require_all",
                    12..=14 => "require_any",
                    15..=17 => "optional_all",
                    _ => "exclude_all",
                };
                let mut targets: Vec<usize> = Vec::new();
                for _ in 0..=rng.below(2) {
                    let t = usize::try_from(rng.below(i as u64)).unwrap();
                    if !targets.contains(&t) {
                        targets.push(t);
                    }
                }
                let edges: Vec<String> = targets
                    .iter()
                    .map(|&t| {
                        let on =
                            ["none", "error", "restart"][usize::try_from(rng.below(3)).unwrap()];
                        let cascade = kind == "require_all" && rng.chance(15);
                        let flag = if cascade { ", cascade = true" } else { "" };
                        format!("{{ to = \"{}\", restart_on = \"{on}\"{flag} }}", name(t))
                    })
                    .collect();
                groups.push(format!(
                    "{{ group = \"{kind}\", edges = [{}] }}",
                    edges.join(", ")
                ));
            }
        }
        if !groups.is_empty() {
            let _ = writeln!(out, "deps = [{}]", groups.join(", "));
        }
        let _ = writeln!(out);
        if kind != "forager" && rng.chance(35) {
            roots.push(name(i));
        }
    }
    (out, roots)
}

fn script(rng: &mut Rng) -> Script {
    Script {
        ready_after_ms: if rng.chance(95) {
            Some(rng.below(20))
        } else {
            None
        },
        exit_after: if rng.chance(25) {
            Some((
                10 + rng.below(2000),
                if rng.chance(70) { Some(1) } else { Some(0) },
            ))
        } else {
            None
        },
        not_ready_after_ms: None,
        spawn_fails: rng.chance(3),
        ignore_term: rng.chance(10),
        stop_fails: rng.chance(2),
    }
}

fn sat(s: Option<State>) -> bool {
    matches!(s, Some(State::Ready | State::Done))
}

/// Restatement of spec §4 for nodes whose groups are all `require_all` or `require_any`:
/// every group satisfied over the observed states.
fn requires_met(c: &Colony<Sim>, i: usize) -> Option<bool> {
    let node = &c.model().nodes[i];
    let mut all = true;
    for g in &node.groups {
        let met: Vec<bool> = g
            .edges
            .iter()
            .map(|e| match (&e.target, e.mode) {
                (Target::Node(t), Mode::Sync) => Some(sat(c.state(*t))),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        all &= match g.kind {
            GroupKind::RequireAll => met.iter().all(|&m| m),
            GroupKind::RequireAny => met.iter().any(|&m| m),
            _ => return None,
        };
    }
    Some(all)
}

/// Hard dependents of `d`: nodes with a sync `require_*` edge to it.
fn hard_dependents(c: &Colony<Sim>, d: u32) -> Vec<usize> {
    c.model()
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| {
            n.groups.iter().any(|g| {
                matches!(g.kind, GroupKind::RequireAll | GroupKind::RequireAny)
                    && g.edges.iter().any(|e| {
                        e.mode == Mode::Sync && matches!(e.target, Target::Node(t) if t == d)
                    })
            })
        })
        .map(|(i, _)| i)
        .collect()
}

/// Checks after one input. `calls_before` is the number of simulation calls before it.
fn check(c: &Colony<Sim>, calls_before: usize, shut: bool, seed: u64, step: usize, what: &str) {
    let ctx = format!("seed {seed} step {step} after {what}");
    let new = &c.effects.calls[calls_before..];
    for call in new {
        match call {
            Call::Stop(d, _, _) => {
                for x in hard_dependents(c, *d) {
                    assert_ne!(
                        c.state(u32::try_from(x).unwrap()),
                        Some(State::Stopping),
                        "{ctx}: Stop({d}) issued while its hard dependent {x} is stopping"
                    );
                }
            }
            Call::Start(n) => assert!(!shut, "{ctx}: Start({n}) after shutdown"),
            _ => {}
        }
    }
    for (i, node) in c.model().nodes.iter().enumerate() {
        let s = c.state(u32::try_from(i).unwrap()).unwrap();
        if node.kind == Kind::Forager {
            assert!(
                !matches!(s, State::Quarantined(_) | State::Waiting(Why::Backoff)),
                "{ctx}: forager {i} is {s:?}"
            );
        }
        if matches!(s, State::Quarantined(qinit_colony::Reason::Breaker)) {
            assert!(
                node.restart.max > 0,
                "{ctx}: node {i} breaker-quarantined with max 0"
            );
            assert_ne!(node.restart.policy, RestartPolicy::Never, "{ctx}: node {i}");
        }
    }
}

/// Lets every pending timer and cell event run (bounded).
fn settle(c: &mut Colony<Sim>) {
    for _ in 0..400 {
        if !c.effects.pending() {
            break;
        }
        advance(c, 700);
    }
}

fn run(seed: u64, seen: &mut BTreeSet<&'static str>) -> bool {
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let n = 3 + usize::try_from(rng.below(8)).unwrap();
    let (text, roots) = frames(&mut rng, n);
    let roots: Vec<&str> = roots.iter().map(String::as_str).collect();
    let Some(bytes) = try_database(&text, &roots) else {
        return false;
    };
    let mut sim = Sim::new();
    for i in 0..n {
        sim.scripts
            .insert(u32::try_from(i).unwrap(), script(&mut rng));
    }
    let (mut c, out) = Colony::load(bytes, &[], sim, 0).expect("loads");
    assert!(
        !out.errors.contains(&Error::Unconverged),
        "seed {seed}: unconverged at load\n{text}"
    );
    let mut shut = false;
    for step in 0..60 {
        let calls_before = c.effects.calls.len();
        let now = c.effects.now();
        let (what, out) = match rng.below(10) {
            0..=4 => {
                let ms = 1 + rng.below(3000);
                ("advance", {
                    advance(&mut c, ms);
                    qinit_colony::Outcome::default()
                })
            }
            5..=8 => {
                let node = u32::try_from(rng.below(n as u64)).unwrap();
                let req = [
                    Request::Start,
                    Request::Stop,
                    Request::Restart,
                    Request::Clear,
                    Request::Run,
                ][usize::try_from(rng.below(5)).unwrap()];
                ("request", c.request(node, req, now))
            }
            _ => {
                let o = c.shutdown(now);
                shut = true;
                ("shutdown", o)
            }
        };
        assert!(
            !out.errors.contains(&Error::Unconverged),
            "seed {seed} step {step}: unconverged after {what}\n{text}"
        );
        // Starts after shutdown: judged against the state before this input.
        check(
            &c,
            calls_before,
            shut && what != "shutdown",
            seed,
            step,
            what,
        );
        for i in 0..n {
            seen.insert(state_text(c.state(u32::try_from(i).unwrap()).unwrap()));
        }
        if step % 15 == 14 {
            settle(&mut c);
            for i in 0..n {
                let st = c.state(u32::try_from(i).unwrap()).unwrap();
                if st == State::Waiting(Why::Deps) && requires_met(&c, i) == Some(true) {
                    panic!(
                        "seed {seed} step {step}: node {i} waits for dependencies that are met\n{}\n{text}",
                        c.status(c.effects.now())
                    );
                }
            }
        }
    }
    true
}

#[test]
fn random_graphs_keep_their_invariants() {
    let mut ran = 0;
    let mut seen = BTreeSet::new();
    for seed in 0..300 {
        if run(seed, &mut seen) {
            ran += 1;
        }
    }
    assert!(ran >= 250, "only {ran} of 300 generated graphs compiled");
    // The graphs must actually reach the interesting states, or the checks prove nothing.
    for want in [
        "off",
        "starting",
        "ready",
        "stopping",
        "done",
        "waiting (dependencies)",
        "waiting (back-off)",
        "quarantined (too many failures)",
    ] {
        assert!(
            seen.contains(want),
            "no random graph reached `{want}`; saw {seen:?}"
        );
    }
}
