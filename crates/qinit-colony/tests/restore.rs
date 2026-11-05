// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Resuming from a saved node table (SP7 R15): what was wanted, quarantined or done stays so.
mod common;

use common::*;
use qinit_cell_core::Report as CellPhase;
use qinit_colony::sim::{Script, Sim};
use qinit_colony::{
    Colony, Counters, Error, Notice, Reason, Report, Request, Restored, RestoredNode,
    SavedTerminal, State,
};

const SOLO: &str = "[worker.solo]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/solo\"]\n";
const JOB: &str = "[forager.job]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/job\"]\n";

/// `old`'s saved table as restore input; `adopt` overrides the phase of the named nodes.
fn table(old: &Colony<Sim>, adopt: &[(&str, Restored)]) -> Vec<RestoredNode> {
    old.saved()
        .into_iter()
        .map(|(name, wanted, end, counters)| RestoredNode {
            node: idx(old, &name),
            wanted,
            phase: adopt.iter().find(|(n, _)| *n == name).map_or_else(
                || match end {
                    None => Restored::Off,
                    Some(SavedTerminal::Done) => Restored::Done,
                    Some(SavedTerminal::Quarantined(r)) => Restored::Quarantined(r),
                },
                |&(_, p)| p,
            ),
            counters,
        })
        .collect()
}

fn script_exit(frames: &str, enable: &[&str], name: &str, status: Option<i32>) -> Sim {
    let (probe, _) = boot(frames, enable, Sim::new());
    let mut sim = Sim::new();
    sim.scripts.insert(
        idx(&probe, name),
        Script {
            exit_after: Some((10, status)),
            ..Script::default()
        },
    );
    sim
}

#[test]
fn a_stopped_enabled_node_stays_stopped() {
    let (mut old, _) = boot(SOLO, &["solo"], Sim::new());
    let n = idx(&old, "solo");
    pass(&mut old, 5);
    let now = old.effects.now();
    old.request(n, Request::Stop, now);
    pass(&mut old, 100);
    assert_eq!(old.state(n), Some(State::Off));
    let (c, out) = Colony::restore(
        database(SOLO, &["solo"]),
        &table(&old, &[]),
        Sim::new(),
        500,
    )
    .expect("restores");
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    assert_eq!(c.state(n), Some(State::Off));
    assert!(
        start_order(&c).is_empty(),
        "the enabled list is not re-applied"
    );
}

#[test]
fn a_quarantine_survives_and_clear_brings_it_back() {
    let sim = script_exit("crashy.toml", &["crashy"], "crashy", Some(1));
    let (mut old, _) = boot("crashy.toml", &["crashy"], sim);
    let n = idx(&old, "crashy");
    pass(&mut old, 20_000);
    assert_eq!(old.state(n), Some(State::Quarantined(Reason::Breaker)));
    let saved = old.saved();
    assert!(
        saved.iter().any(|(name, _, end, c)| name == "crashy"
            && *end == Some(SavedTerminal::Quarantined(Reason::Breaker))
            && c.burst_count == 4),
        "{saved:?}"
    );
    let (mut c, _) = Colony::restore(
        database("crashy.toml", &["crashy"]),
        &table(&old, &[]),
        Sim::new(),
        30_000,
    )
    .expect("restores");
    assert_eq!(c.state(n), Some(State::Quarantined(Reason::Breaker)));
    assert!(start_order(&c).is_empty());
    let out = c.request(n, Request::Clear, 30_001);
    assert!(out.errors.is_empty());
    assert_eq!(start_order(&c), ["crashy"], "clear brings it back");
}

#[test]
fn a_done_oneshot_is_not_run_again() {
    let sim = script_exit(JOB, &["job"], "job", Some(0));
    let (mut old, _) = boot(JOB, &["job"], sim);
    let n = idx(&old, "job");
    pass(&mut old, 100);
    assert_eq!(old.state(n), Some(State::Done));
    let (c, _) = Colony::restore(database(JOB, &["job"]), &table(&old, &[]), Sim::new(), 500)
        .expect("restores");
    assert_eq!(c.state(n), Some(State::Done));
    assert!(start_order(&c).is_empty(), "it ran to completion already");
}

#[test]
fn breaker_counts_carry_over() {
    let sim = script_exit("crashy.toml", &["crashy"], "crashy", Some(1));
    let (probe, _) = boot("crashy.toml", &["crashy"], Sim::new());
    let n = idx(&probe, "crashy");
    let saved = [RestoredNode {
        node: n,
        wanted: true,
        phase: Restored::Off,
        counters: Counters {
            burst_begin_ms: 0,
            burst_count: 3,
            backoff_exp: 2,
            last_start_ms: 0,
            ended_ms: 0,
        },
    }];
    let (mut c, _) =
        Colony::restore(database("crashy.toml", &["crashy"]), &saved, sim, 100).expect("restores");
    pass(&mut c, 60_000);
    assert_eq!(
        c.state(n),
        Some(State::Quarantined(Reason::Breaker)),
        "one more failure is over the limit"
    );
}

#[test]
fn a_restored_table_that_breaks_the_invariant_is_refused() {
    let (probe, _) = boot("crashy.toml", &["crashy"], Sim::new());
    let n = idx(&probe, "crashy");
    let saved = [RestoredNode {
        node: n,
        wanted: true,
        phase: Restored::Quarantined(Reason::Breaker),
        counters: Counters::default(),
    }];
    let err = Colony::restore(database("crashy.toml", &["crashy"]), &saved, Sim::new(), 0).err();
    assert_eq!(err, Some(Error::Restore));
    let outside = [RestoredNode {
        node: 99,
        wanted: true,
        phase: Restored::Off,
        counters: Counters::default(),
    }];
    let err = Colony::restore(
        database("crashy.toml", &["crashy"]),
        &outside,
        Sim::new(),
        0,
    )
    .err();
    assert_eq!(err, Some(Error::UnknownNode(99)));
}

#[test]
fn saved_round_trips_through_restore() {
    let (mut old, _) = boot("two.toml", &["a"], Sim::new());
    pass(&mut old, 3);
    let now = old.effects.now();
    let adopt = [("a", Restored::Ready), ("b", Restored::Ready)];
    let (c, out) = Colony::restore(old.db().to_vec(), &table(&old, &adopt), Sim::new(), now)
        .expect("restores");
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    assert_eq!(c.status(now), old.status(now));
    assert!(
        start_order(&c).is_empty(),
        "both were adopted, none started"
    );
}

#[test]
fn an_adopted_exit_without_status_counts_as_a_failure() {
    let (probe, _) = boot("crashy.toml", &["crashy"], Sim::new());
    let n = idx(&probe, "crashy");
    let saved = [RestoredNode {
        node: n,
        wanted: true,
        phase: Restored::Ready,
        counters: Counters::default(),
    }];
    let (mut c, _) = Colony::restore(
        database("crashy.toml", &["crashy"]),
        &saved,
        Sim::new(),
        100,
    )
    .expect("restores");
    assert_eq!(c.state(n), Some(State::Ready));
    let mut out = c.adopted_exit(n, 200);
    out.notices
        .extend(c.on_cell(n, CellPhase::Empty, 201).notices);
    assert!(
        out.notices.contains(&Notice::Node(n, Report::Failed(None))),
        "{:?}",
        out.notices
    );
    pass(&mut c, 5_000);
    assert_eq!(start_order(&c), ["crashy"], "on-failure restarts it");
}

#[test]
fn seeded_instance_ids_never_go_back() {
    let frames = "[forager.backup]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/backup\"]\n\
                  [forager.backup.launch]\nconcurrency = 2\n";
    let (mut c, _) = boot(frames, &[], Sim::new());
    c.seed_instance_ids(50);
    c.seed_instance_ids(7);
    let args = qinit_colony::LaunchArgs {
        frame: "backup".to_owned(),
        argv_tail: Vec::new(),
        env_add: Vec::new(),
        fds: [None, None, None],
    };
    let (id, _) = c.launch(args, 0).unwrap();
    assert_eq!(id, 50, "a smaller seed does not lower it");
}
