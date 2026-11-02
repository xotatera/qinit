// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! A harness that drives the scheduler the way the runtime does: build a model, write and
//! validate it, then `load`, `step` and drain `next_action`.
#![allow(dead_code)] // each test binary uses a different part of the helpers

use qinit_colony_core::{
    Action, CellReport, Input, Meta, NodeState, Request, State, TimerKind, load, meta, next_action,
    off, step,
};
use qinit_db::{
    Edge, Group, GroupKind, Kind, Mode, Model, Node, Ready, Restart, RestartOn, RestartPolicy,
    Stop, StopMode, Target, open, write,
};

/// A worker, ready by pipe, no restart.
pub fn worker(name: &str) -> Node {
    Node {
        kind: Kind::Worker,
        name: name.to_owned(),
        exec: vec!["/bin/true".to_owned()],
        ready: Ready::Pipe,
        restart: Restart {
            policy: RestartPolicy::Never,
            max: 0,
            window_ms: 0,
            delay_ms: 1000,
        },
        stop: Stop {
            mode: StopMode::Main,
            grace_ms: 10_000,
        },
        start_timeout_ms: 90_000,
        output: None,
        errors: None,
        cred: None,
        groups: Vec::new(),
        memory_max_kib: 0,
        pids_max: 0,
        instance_of: None,
    }
}

pub fn brood(name: &str) -> Node {
    Node {
        kind: Kind::Brood,
        exec: Vec::new(),
        ready: Ready::Exit,
        start_timeout_ms: 0,
        ..worker(name)
    }
}

pub fn forager(name: &str) -> Node {
    Node {
        kind: Kind::Forager,
        ready: Ready::Exit,
        start_timeout_ms: 0,
        ..worker(name)
    }
}

pub fn restarting(mut n: Node, policy: RestartPolicy, max: u32, window_ms: u32) -> Node {
    n.restart = Restart {
        policy,
        max,
        window_ms,
        delay_ms: 1000,
    };
    n
}

pub fn edge(to: u32) -> Edge {
    Edge {
        target: Target::Node(to),
        mode: Mode::Sync,
        deadline_ms: 0,
        restart_on: RestartOn::Error,
        stop_parallel: false,
        cascade: false,
    }
}

pub fn async_edge(to: u32, deadline_ms: u32) -> Edge {
    Edge {
        mode: Mode::Async,
        deadline_ms,
        ..edge(to)
    }
}

pub fn path_edge(p: &str) -> Edge {
    Edge {
        target: Target::Path(p.to_owned()),
        ..edge(0)
    }
}

pub fn with_restart_on(mut e: Edge, r: RestartOn) -> Edge {
    e.restart_on = r;
    e
}

pub fn group(kind: GroupKind, edges: Vec<Edge>) -> Group {
    Group { kind, edges }
}

pub fn requires(mut n: Node, edges: Vec<Edge>) -> Node {
    n.groups.push(group(GroupKind::RequireAll, edges));
    n
}

/// A model of `nodes` (already in name order), with `enabled` nodes by index.
pub fn model(nodes: Vec<Node>, enabled: &[u32]) -> Model {
    Model {
        nodes,
        creds: Vec::new(),
        routes: Vec::new(),
        enabled: enabled.to_vec(),
        presyslog: Vec::new(),
    }
}

/// The scheduler's state plus the way to drive it.
pub struct Harness {
    pub db: Vec<u8>,
    pub model: Model,
    pub nodes: Vec<NodeState>,
    pub paths: Vec<bool>,
    pub late: Vec<bool>,
    pub meta: Meta,
    /// Every action drained so far, with the time of the input that caused it.
    pub log: Vec<(u64, Action)>,
}

impl Harness {
    /// Writes and validates `m`, then loads it at time 0. Returns the harness and the
    /// actions the load produced.
    pub fn load(m: Model) -> (Harness, Vec<Action>) {
        let db = write(&m).expect("model writes");
        open(&db).expect("database validates");
        let edges: usize = m
            .nodes
            .iter()
            .flat_map(|n| &n.groups)
            .map(|g| g.edges.len())
            .sum();
        let mut h = Harness {
            nodes: vec![off(); m.nodes.len()],
            paths: vec![false; edges],
            late: vec![false; edges],
            meta: meta(),
            log: Vec::new(),
            db,
            model: m,
        };
        assert!(load(
            &h.db,
            &mut h.nodes,
            &h.paths,
            &mut h.late,
            &mut h.meta,
            0
        ));
        let actions = h.drain(0);
        (h, actions)
    }

    fn drain(&mut self, now: u64) -> Vec<Action> {
        let mut out = Vec::new();
        while let Some(a) = next_action(&self.db, &mut self.nodes, &mut self.meta) {
            self.log.push((now, a));
            out.push(a);
            assert!(out.len() <= 7 * self.nodes.len() + 1, "drain does not end");
        }
        out
    }

    /// Applies one input at `now` and returns the actions it caused.
    pub fn input(&mut self, input: Input, now: u64) -> Vec<Action> {
        assert!(
            step(
                &self.db,
                &mut self.nodes,
                &mut self.paths,
                &mut self.late,
                &mut self.meta,
                input,
                now
            ),
            "reconcile did not converge"
        );
        self.drain(now)
    }

    pub fn idx(&self, name: &str) -> u32 {
        u32::try_from(
            self.model
                .nodes
                .iter()
                .position(|n| n.name == name)
                .unwrap_or_else(|| panic!("no node {name}")),
        )
        .unwrap()
    }

    pub fn request(&mut self, name: &str, req: Request, now: u64) -> Vec<Action> {
        let node = self.idx(name);
        self.input(Input::Request { node, req }, now)
    }

    pub fn cell(&mut self, name: &str, report: CellReport, now: u64) -> Vec<Action> {
        let node = self.idx(name);
        self.input(Input::Cell { node, report }, now)
    }

    pub fn deadline(&mut self, name: &str, timer: TimerKind, now: u64) -> Vec<Action> {
        let node = self.idx(name);
        self.input(Input::Deadline { node, timer }, now)
    }

    pub fn state(&self, name: &str) -> State {
        self.nodes[self.idx(name) as usize].state
    }

    pub fn node(&self, name: &str) -> NodeState {
        self.nodes[self.idx(name) as usize]
    }
}

/// Just the `Start` actions, as node names.
pub fn starts(h: &Harness, actions: &[Action]) -> Vec<String> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Start(n) => Some(h.model.nodes[*n as usize].name.clone()),
            _ => None,
        })
        .collect()
}
