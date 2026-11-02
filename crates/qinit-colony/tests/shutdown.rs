// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Ordered shutdown of the whole graph against simulated cells.
mod common;

use common::*;
use qinit_colony::sim::{Call, Script, Sim};
use qinit_colony::{Notice, Report, Request, State};

#[test]
fn shutdown_stops_in_reverse_order_with_a_term_ignoring_cell() {
    let (probe, _) = boot("two.toml", &["a"], Sim::new());
    let (a, b) = (idx(&probe, "a"), idx(&probe, "b"));
    let mut sim = Sim::new();
    // a ignores the polite stop: it is empty only after its 10 s grace.
    sim.scripts.insert(
        a,
        Script {
            ignore_term: true,
            ..Script::default()
        },
    );
    let (mut c, _) = boot("two.toml", &["a"], sim);
    pass(&mut c, 5);
    let t0 = c.effects.now();
    let out = c.shutdown(t0);
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let stops: Vec<u32> = c
        .effects
        .calls
        .iter()
        .filter_map(|call| match call {
            Call::Stop(n, _, _) => Some(*n),
            _ => None,
        })
        .collect();
    assert_eq!(stops, [a], "b waits for a to be empty");
    let early = pass(&mut c, 9999);
    assert!(
        !early
            .iter()
            .any(|n| matches!(n, Notice::Node(_, Report::ShutdownComplete { .. })))
    );
    let notices = pass(&mut c, 2);
    let stops: Vec<u32> = c
        .effects
        .calls
        .iter()
        .filter_map(|call| match call {
            Call::Stop(n, _, _) => Some(*n),
            _ => None,
        })
        .collect();
    assert_eq!(stops, [a, b], "then b");
    assert_eq!(c.state(a), Some(State::Off));
    assert_eq!(c.state(b), Some(State::Off));
    assert!(
        notices.contains(&Notice::Node(
            0,
            Report::ShutdownComplete { still_populated: 0 }
        )),
        "{notices:?}"
    );
}

#[test]
fn shutdown_counts_a_stop_failed_cell() {
    let (probe, _) = boot("two.toml", &["a"], Sim::new());
    let b = idx(&probe, "b");
    let mut sim = Sim::new();
    sim.scripts.insert(
        b,
        Script {
            stop_fails: true,
            ..Script::default()
        },
    );
    let (mut c, _) = boot("two.toml", &["a"], sim);
    pass(&mut c, 5);
    let now = c.effects.now();
    c.shutdown(now);
    let notices = pass(&mut c, 20_000);
    assert!(
        notices.contains(&Notice::Node(
            0,
            Report::ShutdownComplete { still_populated: 1 }
        )),
        "{notices:?}"
    );
    // Nothing starts again, and requests are refused.
    let a = idx(&c, "a");
    let before = c.effects.starts.len();
    let out = c.request(a, Request::Start, c.effects.now());
    assert!(
        out.notices.contains(&Notice::Node(a, Report::Refused)),
        "{:?}",
        out.notices
    );
    assert_eq!(c.effects.starts.len(), before);
}
