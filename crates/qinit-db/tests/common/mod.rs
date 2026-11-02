// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! A sample model shared by the integration tests.
#![allow(dead_code)]

use qinit_db::{
    Cred, Edge, Group, GroupKind, Kind, Mode, Model, Node, Ready, Restart, RestartOn,
    RestartPolicy, Route, Seccomp, Securebits, Target,
};

pub fn node(name: &str, kind: Kind) -> Node {
    Node {
        kind,
        name: name.to_owned(),
        exec: Vec::new(),
        ready: Ready::Exit,
        restart: Restart {
            policy: RestartPolicy::Never,
            max: 0,
            window_ms: 0,
        },
        output: None,
        errors: None,
        cred: None,
        groups: Vec::new(),
        memory_max_kib: 0,
        pids_max: 0,
        instance_of: None,
    }
}

pub fn edge(target: Target, mode: Mode, deadline_ms: u32) -> Edge {
    Edge {
        target,
        mode,
        deadline_ms,
        restart_on: RestartOn::None,
        stop_parallel: false,
    }
}

/// Nodes: 0 firewall (brood), 1 logd (worker), 2 net (forager), 3 sshd (worker).
pub fn sample() -> Model {
    let firewall = node("firewall", Kind::Brood);
    let mut logd = node("logd", Kind::Worker);
    logd.exec = vec!["/bin/logd".into()];
    logd.ready = Ready::Pipe;
    logd.restart = Restart {
        policy: RestartPolicy::Always,
        max: 5,
        window_ms: 10_000,
    };
    logd.output = Some(0);
    let net = node("net", Kind::Forager);
    let mut sshd = node("sshd", Kind::Worker);
    sshd.exec = vec!["/bin/sshd".into(), "-D".into()];
    sshd.ready = Ready::Socket("/run/sshd.sock".into());
    sshd.restart = Restart {
        policy: RestartPolicy::OnFailure,
        max: 3,
        window_ms: 60_000,
    };
    sshd.output = Some(1);
    sshd.errors = Some(0);
    sshd.cred = Some(0);
    sshd.memory_max_kib = 65_536;
    sshd.pids_max = 128;
    sshd.instance_of = Some("sshd@".into());
    let mut net_edge = edge(Target::Node(2), Mode::Async, 1000);
    net_edge.restart_on = RestartOn::Refresh;
    net_edge.stop_parallel = true;
    sshd.groups = vec![
        Group {
            kind: GroupKind::RequireAll,
            edges: vec![
                edge(Target::Node(1), Mode::Sync, 0),
                edge(Target::Node(0), Mode::Sync, 0),
            ],
        },
        Group {
            kind: GroupKind::OptionalAll,
            edges: vec![net_edge],
        },
        Group {
            kind: GroupKind::ExcludeAll,
            edges: vec![edge(Target::Path("/run/maintenance".into()), Mode::Sync, 0)],
        },
    ];
    Model {
        nodes: vec![firewall, logd, net, sshd],
        creds: vec![Cred {
            user: "sshd".into(),
            caps: (1 << 40) | (1 << 10) | 1,
            securebits: Securebits::NorootLocked,
            nnp: true,
            ns: 0b10101,
            seccomp: Seccomp::Default,
            landlock: vec!["ro:/etc".into(), "rw:/run/sshd".into()],
        }],
        routes: vec![Route::Path("/var/log/sshd.log".into()), Route::Pipe(1)],
        enabled: vec![0, 1, 3],
        presyslog: vec![1],
    }
}
