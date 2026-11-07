// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Re-adoption: what a new colony makes of the cells and node state an old one left.
mod common;

use common::*;
use qinit_cell::{CellId, Failure, Phase};
use qinit_colony::{Counters, Reason, Restored, SavedTerminal};
use qinit_colonyd::readopt::{Procs, plan};
use qinit_colonyd::state::{CellLine, NodeLine};
use qinit_db::{Model, Ready, Route};
use std::collections::HashMap;
use std::os::fd::OwnedFd;

/// Processes as the test describes them: `pid → (start time, cgroup id)`.
#[derive(Default)]
struct Fake {
    procs: HashMap<i32, (u64, u64)>,
}

impl Fake {
    fn pidfd(&self, pid: i32) -> Option<OwnedFd> {
        self.procs.contains_key(&pid).then_some(())?;
        std::fs::File::open("/dev/null").map(OwnedFd::from).ok()
    }

    fn start_time(&self, pid: i32) -> Option<u64> {
        self.procs.get(&pid).map(|p| p.0)
    }
}

/// The fake process table: the cgroup answer is the one of the pid whose pidfd was opened last.
struct ByPid {
    inner: Fake,
    ids: std::cell::RefCell<Vec<u64>>,
}

impl Procs for ByPid {
    fn pidfd(&self, pid: i32) -> Option<OwnedFd> {
        let fd = self.inner.pidfd(pid)?;
        self.ids.borrow_mut().push(self.inner.procs[&pid].1);
        Some(fd)
    }

    fn start_time(&self, pid: i32) -> Option<u64> {
        self.inner.start_time(pid)
    }

    fn cgroup_id(&self, _fd: &OwnedFd) -> Option<u64> {
        self.ids.borrow().last().copied()
    }
}

fn procs(list: &[(i32, u64, u64)]) -> ByPid {
    ByPid {
        inner: Fake {
            procs: list.iter().map(|&(p, t, c)| (p, (t, c))).collect(),
        },
        ids: std::cell::RefCell::default(),
    }
}

fn cell(name: &str, id: u64, ready: bool, pid: i32, start: u64) -> CellLine {
    CellLine {
        name: name.into(),
        cgroup_id: id,
        ready,
        pid,
        start_time: start,
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
    let p = plan(
        &[cell("a", 11, true, 300, 777)],
        None,
        &two(),
        &mut ops,
        &procs(&[(300, 777, 11)]),
        1_000,
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
}

#[test]
fn a_reused_pid_is_not_taken_for_the_main() {
    // The pid is alive, but it is another process: its start time is not the recorded one.
    let mut ops = FakeCells::default();
    let p = plan(
        &[cell("a", 11, true, 300, 777)],
        None,
        &two(),
        &mut ops,
        &procs(&[(300, 778, 11)]),
        1_000,
    );
    assert_eq!(
        ops.calls,
        [Call::Adopt("a".into(), 11, false)],
        "adopted without a main"
    );
    assert_eq!(p.exited, [0], "the main is taken to have exited");
    // And the same pid with the right start time but another cgroup is not it either.
    let mut ops = FakeCells::default();
    let p = plan(
        &[cell("a", 11, true, 300, 777)],
        None,
        &two(),
        &mut ops,
        &procs(&[(300, 777, 99)]),
        1_000,
    );
    assert_eq!(ops.calls, [Call::Adopt("a".into(), 11, false)]);
    assert_eq!(p.exited, [0]);
    // A pid that is gone altogether.
    let mut ops = FakeCells::default();
    let p = plan(
        &[cell("a", 11, true, 300, 777)],
        None,
        &two(),
        &mut ops,
        &procs(&[]),
        1,
    );
    assert_eq!(ops.calls, [Call::Adopt("a".into(), 11, false)]);
    assert_eq!(p.exited, [0]);
}

#[test]
fn a_pipe_ready_cell_still_starting_is_restarted() {
    let mut ops = FakeCells::default();
    let p = plan(
        &[cell("a", 11, false, 300, 777)],
        None,
        &two(),
        &mut ops,
        &procs(&[(300, 777, 11)]),
        1,
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
    let p = plan(
        &[cell("a", 11, false, 300, 777)],
        None,
        &m,
        &mut ops,
        &procs(&[(300, 777, 11)]),
        1,
    );
    assert_eq!(p.restored[0].phase, Restored::Starting);
    assert!(
        p.restart.is_empty(),
        "its exit is still the readiness it waits for"
    );
    // Without its main there is nothing left to wait for: started again.
    let mut ops = FakeCells::default();
    let p = plan(
        &[cell("a", 11, false, 300, 777)],
        None,
        &m,
        &mut ops,
        &procs(&[]),
        1,
    );
    assert_eq!(p.restart, [0]);
}

#[test]
fn a_logger_and_its_producers_are_restarted() {
    let mut web = worker("web");
    web.output = Some(0);
    let mut m = model(vec![worker("logd"), web, worker("plain")]);
    m.routes = vec![Route::Pipe(0)];
    let mut ops = FakeCells::default();
    let cells = [
        cell("logd", 1, true, 10, 1),
        cell("web", 2, true, 11, 1),
        cell("plain", 3, true, 12, 1),
    ];
    let p = plan(
        &cells,
        None,
        &m,
        &mut ops,
        &procs(&[(10, 1, 1), (11, 1, 2), (12, 1, 3)]),
        1,
    );
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
fn an_instance_cell_is_cleared_and_ids_move_past_it() {
    let mut ops = FakeCells::default();
    let cells = [
        cell("backup#3", 5, false, 0, 0),
        cell("~job#9", 6, false, 0, 0),
        cell("a", 7, true, 300, 1),
    ];
    let p = plan(&cells, None, &two(), &mut ops, &procs(&[(300, 1, 7)]), 1);
    assert_eq!(p.clear.len(), 2);
    assert_eq!(p.next_instance, 10, "past the highest id seen");
    assert!(
        ops.calls
            .contains(&Call::Adopt("backup#3".into(), 5, false)),
        "adopted without a main, to be stopped and removed"
    );
    assert_eq!(p.restored.len(), 1, "only the node is restored");
}

#[test]
fn a_cell_of_a_removed_node_is_cleared() {
    let mut ops = FakeCells::default();
    let p = plan(
        &[cell("gone", 5, true, 1, 1)],
        None,
        &two(),
        &mut ops,
        &procs(&[]),
        1,
    );
    assert_eq!(p.clear.len(), 1);
    assert!(p.restored.is_empty());
    assert_eq!(p.next_instance, 1, "a node cell has no instance id");
}

#[test]
fn a_mismatched_cgroup_id_is_left_alone() {
    let mut ops = FakeCells::default();
    ops.adopt_script.insert(
        "a".into(),
        Adopt {
            mismatch: true,
            populated: true,
        },
    );
    let p = plan(
        &[cell("a", 11, true, 300, 777)],
        None,
        &two(),
        &mut ops,
        &procs(&[(300, 777, 11)]),
        1,
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
    let _ = (Phase::Absent, Failure::Create, CellId(0));
}

#[test]
fn node_state_is_restored_for_nodes_without_cells() {
    let mut ops = FakeCells::default();
    let lines = [
        node("a", false, None),
        node(
            "b",
            true,
            Some(SavedTerminal::Quarantined(Reason::StartTimeout)),
        ),
    ];
    let p = plan(&[], Some(&lines), &two(), &mut ops, &procs(&[]), 1);
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
    // A node of the file that the database no longer has is skipped.
    let p = plan(
        &[],
        Some(&[node("zzz", true, None)]),
        &two(),
        &mut ops,
        &procs(&[]),
        1,
    );
    assert!(p.restored.is_empty());
}

#[test]
fn an_adopted_node_takes_its_wanted_flag_and_counters_from_the_file() {
    let mut ops = FakeCells::default();
    let mut line = node("a", false, None);
    line.counters.burst_count = 2;
    let p = plan(
        &[cell("a", 11, true, 300, 777)],
        Some(&[line]),
        &two(),
        &mut ops,
        &procs(&[(300, 777, 11)]),
        1,
    );
    assert_eq!(p.restored.len(), 1, "one entry per node");
    assert!(
        !p.restored[0].wanted,
        "an administrator's stop is kept: the scheduler stops it"
    );
    assert_eq!(p.restored[0].counters.burst_count, 2);
    assert_eq!(p.restored[0].phase, Restored::Ready);
}

#[test]
fn a_recovered_main_keeps_its_pid_and_a_lost_one_has_none() {
    let cells = [cell("a", 7, true, 41, 500), cell("b", 8, true, 42, 600)];
    let mut ops = FakeCells::default();
    // Only `a`'s main is still there.
    let p = plan(
        &cells,
        None,
        &two(),
        &mut ops,
        &procs(&[(41, 500, 7)]),
        1_000,
    );
    let pid = |node: u32| p.restored.iter().find(|r| r.node == node).unwrap().pid;
    assert_eq!(pid(0), Some(41));
    assert_eq!(pid(1), None);
}
