// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Re-adoption: what a new colony makes of the cells and node state an old one left.
mod common;

use common::*;
use qinit_colony::{Counters, Reason, Restored, SavedTerminal};
use qinit_colonyd::readopt::{Held, MainNow, Plan, Procs, plan};
use qinit_colonyd::state::{CellLine, NodeLine};
use qinit_db::{Model, Ready, Route};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::os::fd::{AsRawFd, OwnedFd};

/// The descriptors queen holds, by key; each is a `/dev/null` the test gives a meaning to.
#[derive(Default)]
struct Hold {
    fds: BTreeMap<u64, OwnedFd>,
}

impl Held for Hold {
    fn take(&mut self, key: u64) -> Option<OwnedFd> {
        self.fds.remove(&key)
    }
}

/// What each main's pidfd says: `raw descriptor → (what it says next, cgroup id)`; the last
/// answer is repeated.
#[derive(Default)]
struct Table {
    mains: RefCell<HashMap<i32, (VecDeque<MainNow>, u64)>>,
}

impl Procs for Table {
    fn main_now(&self, fd: &OwnedFd) -> MainNow {
        let mut m = self.mains.borrow_mut();
        let (seq, _) = m
            .get_mut(&fd.as_raw_fd())
            .expect("a main the test described");
        if seq.len() > 1 {
            seq.pop_front().unwrap()
        } else {
            *seq.front().unwrap()
        }
    }

    fn cgroup_id(&self, fd: &OwnedFd) -> Option<u64> {
        self.mains.borrow().get(&fd.as_raw_fd()).map(|m| m.1)
    }
}

/// What queen holds and what the pidfds say.
#[derive(Default)]
struct Scene {
    hold: Hold,
    procs: Table,
}

impl Scene {
    fn dir(&mut self, key: u64) -> &mut Scene {
        let fd: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
        self.hold.fds.insert(key, fd);
        self
    }

    fn main(&mut self, key: u64, nows: &[MainNow], cgroup: u64) -> &mut Scene {
        let fd: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
        self.procs
            .mains
            .borrow_mut()
            .insert(fd.as_raw_fd(), (nows.iter().copied().collect(), cgroup));
        self.hold.fds.insert(key, fd);
        self
    }
}

fn run(
    s: &mut Scene,
    cells: &[CellLine],
    nodes: Option<&[NodeLine]>,
    pipes: &[&str],
    model: &Model,
    ops: &mut FakeCells,
) -> Plan {
    let pipes: BTreeSet<String> = pipes.iter().map(|p| (*p).to_owned()).collect();
    plan(
        cells,
        nodes,
        &pipes,
        model,
        &mut s.hold,
        ops,
        &s.procs,
        1_000,
    )
}

fn cell(name: &str, id: u64, ready: bool, dir_key: u64, main_key: u64) -> CellLine {
    CellLine {
        name: name.into(),
        cgroup_id: id,
        ready,
        dir_key,
        main_key,
    }
}

fn node(name: &str, wanted: bool, terminal: Option<SavedTerminal>) -> NodeLine {
    NodeLine {
        name: name.into(),
        wanted,
        terminal,
        counters: Counters::default(),
    }
}

fn two() -> Model {
    model(vec![worker("a"), worker("b")])
}

#[test]
fn a_ready_cell_with_its_main_is_adopted_ready() {
    let mut ops = FakeCells::default();
    let mut s = Scene::default();
    s.dir(16).main(17, &[MainNow::Alive(300)], 11);
    let p = run(
        &mut s,
        &[cell("a", 11, true, 16, 17)],
        None,
        &[],
        &two(),
        &mut ops,
    );
    assert_eq!(ops.calls, [Call::Adopt("a".into(), 11, true)]);
    assert_eq!(p.restored.len(), 1);
    assert_eq!(
        (
            p.restored[0].node,
            p.restored[0].phase,
            p.restored[0].wanted
        ),
        (0, Restored::Ready, true)
    );
    assert!(p.restart.is_empty() && p.exited.is_empty() && p.clear.is_empty());
    assert_eq!(p.adopted.len(), 1);
    assert_eq!((p.adopted[0].dir_key, p.adopted[0].main_key), (16, 17));
    assert!(p.dropped.is_empty());
}

#[test]
fn an_alive_main_keeps_its_pid() {
    let mut ops = FakeCells::default();
    let mut s = Scene::default();
    s.dir(16).main(17, &[MainNow::Alive(300)], 11);
    let p = run(
        &mut s,
        &[cell("a", 11, true, 16, 17)],
        None,
        &[],
        &two(),
        &mut ops,
    );
    assert_eq!(p.restored[0].pid, Some(300));
}

#[test]
fn a_main_that_exited_while_away_carries_its_status() {
    let mut ops = FakeCells::default();
    let mut s = Scene::default();
    s.dir(16).main(17, &[MainNow::Exited(9)], 11);
    let p = run(
        &mut s,
        &[cell("a", 11, true, 16, 17)],
        None,
        &[],
        &two(),
        &mut ops,
    );
    assert_eq!(
        ops.calls,
        [Call::Adopt("a".into(), 11, false)],
        "adopted without a main"
    );
    assert_eq!(p.exited, [(0, Some(9))]);
    assert_eq!(p.restored[0].pid, None);
    assert_eq!(p.dropped, [17], "queen holds a pidfd nothing names now");
    assert_eq!((p.adopted[0].dir_key, p.adopted[0].main_key), (16, 0));
}

#[test]
fn a_lost_main_counts_as_unknown() {
    // Gone altogether.
    let mut ops = FakeCells::default();
    let mut s = Scene::default();
    s.dir(16).main(17, &[MainNow::Gone], 11);
    let p = run(
        &mut s,
        &[cell("a", 11, true, 16, 17)],
        None,
        &[],
        &two(),
        &mut ops,
    );
    assert_eq!(ops.calls, [Call::Adopt("a".into(), 11, false)]);
    assert_eq!(p.exited, [(0, None)]);
    // Alive, but not in the recorded cgroup: some other process.
    let mut ops = FakeCells::default();
    let mut s = Scene::default();
    s.dir(16).main(17, &[MainNow::Alive(300)], 99);
    let p = run(
        &mut s,
        &[cell("a", 11, true, 16, 17)],
        None,
        &[],
        &two(),
        &mut ops,
    );
    assert_eq!(ops.calls, [Call::Adopt("a".into(), 11, false)]);
    assert_eq!(p.exited, [(0, None)]);
    // No main key, or a key queen no longer holds.
    for main_key in [0, 55] {
        let mut ops = FakeCells::default();
        let mut s = Scene::default();
        s.dir(16);
        let p = run(
            &mut s,
            &[cell("a", 11, true, 16, main_key)],
            None,
            &[],
            &two(),
            &mut ops,
        );
        assert_eq!(ops.calls, [Call::Adopt("a".into(), 11, false)]);
        assert_eq!(p.exited, [(0, None)], "main key {main_key}");
    }
}

#[test]
fn a_main_reaped_during_adoption_is_an_exit() {
    let mut ops = FakeCells::default();
    ops.adopt_script.insert(
        "a".into(),
        Adopt {
            main_gone: true,
            ..Adopt::default()
        },
    );
    let mut s = Scene::default();
    // Alive when looked at, reaped by the time the hand-over is tried, and then it says why.
    s.dir(16)
        .main(17, &[MainNow::Alive(300), MainNow::Exited(7)], 11);
    let p = run(
        &mut s,
        &[cell("a", 11, true, 16, 17)],
        None,
        &[],
        &two(),
        &mut ops,
    );
    assert_eq!(
        ops.calls,
        [
            Call::Adopt("a".into(), 11, true),
            Call::Adopt("a".into(), 11, false)
        ]
    );
    assert_eq!(p.exited, [(0, Some(7))]);
}

#[test]
fn a_one_shot_that_finished_while_away_is_not_restarted() {
    let mut oneshot = worker("a");
    oneshot.ready = Ready::Exit;
    let m = model(vec![oneshot, worker("b")]);
    let mut ops = FakeCells::default();
    let mut s = Scene::default();
    s.dir(16).main(17, &[MainNow::Exited(0)], 11);
    let p = run(
        &mut s,
        &[cell("a", 11, false, 16, 17)],
        None,
        &[],
        &m,
        &mut ops,
    );
    assert!(p.restart.is_empty(), "it finished: nothing to start again");
    assert_eq!(p.exited, [(0, Some(0))]);
    assert_eq!(p.restored[0].phase, Restored::Starting);
}

#[test]
fn a_pipe_ready_cell_still_starting_is_restarted() {
    let mut ops = FakeCells::default();
    let mut s = Scene::default();
    s.dir(16).main(17, &[MainNow::Alive(300)], 11);
    let p = run(
        &mut s,
        &[cell("a", 11, false, 16, 17)],
        None,
        &[],
        &two(),
        &mut ops,
    );
    assert_eq!(p.restored[0].phase, Restored::Starting);
    assert_eq!(
        p.restart,
        [0],
        "its readiness pipe died with the old colony"
    );
    assert!(p.exited.is_empty());
}

#[test]
fn an_exit_ready_cell_still_running_runs_on() {
    let mut oneshot = worker("a");
    oneshot.ready = Ready::Exit;
    let m = model(vec![oneshot, worker("b")]);
    let mut ops = FakeCells::default();
    let mut s = Scene::default();
    s.dir(16).main(17, &[MainNow::Alive(300)], 11);
    let p = run(
        &mut s,
        &[cell("a", 11, false, 16, 17)],
        None,
        &[],
        &m,
        &mut ops,
    );
    assert_eq!(p.restored[0].phase, Restored::Starting);
    assert!(
        p.restart.is_empty(),
        "its exit is still the readiness it waits for"
    );
    // Without its main there is nothing left to wait for: started again.
    let mut ops = FakeCells::default();
    let mut s = Scene::default();
    s.dir(16);
    let p = run(
        &mut s,
        &[cell("a", 11, false, 16, 0)],
        None,
        &[],
        &m,
        &mut ops,
    );
    assert_eq!(p.restart, [0]);
}

fn logger_model() -> Model {
    let mut web = worker("web");
    web.output = Some(0);
    let mut m = model(vec![worker("logd"), web, worker("plain")]);
    m.routes = vec![Route::Pipe(0)];
    m
}

fn logger_scene() -> (Scene, [CellLine; 3]) {
    let mut s = Scene::default();
    s.dir(16).main(17, &[MainNow::Alive(10)], 1);
    s.dir(18).main(19, &[MainNow::Alive(11)], 2);
    s.dir(20).main(21, &[MainNow::Alive(12)], 3);
    (
        s,
        [
            cell("logd", 1, true, 16, 17),
            cell("web", 2, true, 18, 19),
            cell("plain", 3, true, 20, 21),
        ],
    )
}

#[test]
fn a_producer_whose_pipe_is_not_held_is_restarted() {
    let (mut s, cells) = logger_scene();
    let mut ops = FakeCells::default();
    let p = run(&mut s, &cells, None, &[], &logger_model(), &mut ops);
    let mut restart = p.restart.clone();
    restart.sort_unstable();
    assert_eq!(
        restart,
        [0, 1],
        "the logger and its producer, not the plain node"
    );
    assert!(p.restored.iter().all(|r| r.phase == Restored::Ready));
}

#[test]
fn a_producer_with_a_held_pipe_is_not_restarted() {
    let (mut s, cells) = logger_scene();
    let mut ops = FakeCells::default();
    let p = run(&mut s, &cells, None, &["logd"], &logger_model(), &mut ops);
    assert!(p.restart.is_empty(), "{:?}", p.restart);
    assert!(p.restored.iter().all(|r| r.phase == Restored::Ready));
}

#[test]
fn an_instance_cell_is_cleared_and_ids_move_past_it() {
    let mut ops = FakeCells::default();
    let mut s = Scene::default();
    s.dir(16)
        .dir(17)
        .dir(18)
        .main(19, &[MainNow::Alive(300)], 7);
    let cells = [
        cell("backup#3", 5, false, 16, 0),
        cell("~job#9", 6, false, 17, 0),
        cell("a", 7, true, 18, 19),
    ];
    let p = run(&mut s, &cells, None, &[], &two(), &mut ops);
    assert_eq!(p.clear.len(), 2);
    assert_eq!(p.next_instance, 10, "past the highest id seen");
    assert!(
        ops.calls
            .contains(&Call::Adopt("backup#3".into(), 5, false)),
        "adopted without a main, to be stopped and removed"
    );
    assert_eq!(p.restored.len(), 1, "only the node is restored");
    assert!(
        p.dropped.contains(&16) && p.dropped.contains(&17),
        "{:?}",
        p.dropped
    );
}

#[test]
fn a_cell_of_a_removed_node_is_cleared() {
    let mut ops = FakeCells::default();
    let mut s = Scene::default();
    s.dir(16);
    let p = run(
        &mut s,
        &[cell("gone", 5, true, 16, 0)],
        None,
        &[],
        &two(),
        &mut ops,
    );
    assert_eq!(p.clear.len(), 1);
    assert!(p.restored.is_empty());
    assert_eq!(p.next_instance, 1, "a node cell has no instance id");
}

#[test]
fn a_cell_whose_directory_is_not_held_is_dropped() {
    let mut ops = FakeCells::default();
    let mut s = Scene::default();
    s.main(17, &[MainNow::Alive(300)], 11);
    let p = run(
        &mut s,
        &[cell("a", 11, true, 16, 17)],
        None,
        &[],
        &two(),
        &mut ops,
    );
    assert!(ops.calls.is_empty(), "nothing to adopt it from");
    assert!(p.restored.is_empty() && p.adopted.is_empty());
    assert!(
        p.notes.iter().any(|(_, t)| t.contains("directory")),
        "{:?}",
        p.notes
    );
}

#[test]
fn a_mismatched_cgroup_id_is_left_alone() {
    let mut ops = FakeCells::default();
    ops.adopt_script.insert(
        "a".into(),
        Adopt {
            mismatch: true,
            ..Adopt::default()
        },
    );
    let mut s = Scene::default();
    s.dir(16).main(17, &[MainNow::Alive(300)], 11);
    let p = run(
        &mut s,
        &[cell("a", 11, true, 16, 17)],
        None,
        &[],
        &two(),
        &mut ops,
    );
    assert!(p.restored.is_empty() && p.restart.is_empty() && p.exited.is_empty());
    assert!(
        p.clear.is_empty(),
        "something else made it: not ours to stop"
    );
    assert!(
        ops.calls.contains(&Call::Remove(0)),
        "only the table slot is given back (the directory is untouched)"
    );
    assert!(
        p.notes
            .iter()
            .any(|(sev, text)| *sev == qinit_colonyd::syslog::Sev::Err && text.contains('a')),
        "{:?}",
        p.notes
    );
}

#[test]
fn node_state_is_restored_for_nodes_without_cells() {
    let mut ops = FakeCells::default();
    let mut s = Scene::default();
    let lines = [
        node("a", false, None),
        node(
            "b",
            true,
            Some(SavedTerminal::Quarantined(Reason::StartTimeout)),
        ),
    ];
    let p = run(&mut s, &[], Some(&lines), &[], &two(), &mut ops);
    assert_eq!(p.restored.len(), 2);
    assert_eq!(
        (
            p.restored[0].node,
            p.restored[0].phase,
            p.restored[0].wanted
        ),
        (0, Restored::Off, false)
    );
    assert_eq!(
        p.restored[1].phase,
        Restored::Quarantined(Reason::StartTimeout)
    );
    // A node of the entry that the database no longer has is skipped.
    let p = run(
        &mut s,
        &[],
        Some(&[node("zzz", true, None)]),
        &[],
        &two(),
        &mut ops,
    );
    assert!(p.restored.is_empty());
}

#[test]
fn an_adopted_node_takes_its_wanted_flag_and_counters_from_the_entry() {
    let mut ops = FakeCells::default();
    let mut s = Scene::default();
    s.dir(16).main(17, &[MainNow::Alive(300)], 11);
    let mut line = node("a", false, None);
    line.counters.burst_count = 2;
    let p = run(
        &mut s,
        &[cell("a", 11, true, 16, 17)],
        Some(&[line]),
        &[],
        &two(),
        &mut ops,
    );
    assert_eq!(p.restored.len(), 1, "one entry per node");
    assert!(
        !p.restored[0].wanted,
        "an administrator's stop is kept: the scheduler stops it"
    );
    assert_eq!(p.restored[0].counters.burst_count, 2);
    assert_eq!(p.restored[0].phase, Restored::Ready);
}
