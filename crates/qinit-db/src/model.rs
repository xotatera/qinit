// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The owned, nested form of a database. Node references are indices into `Model::nodes`.

use qinit_graph_core::GEdge;

/// A whole database.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Model {
    /// The nodes, sorted ascending by name.
    pub nodes: Vec<Node>,
    /// Credential sets.
    pub creds: Vec<Cred>,
    /// Output routes.
    pub routes: Vec<Route>,
    /// The enabled closure, ascending node indices.
    pub enabled: Vec<u32>,
    /// The nodes that start before the logger, ascending node indices.
    pub presyslog: Vec<u32>,
}

/// One node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// What the node is.
    pub kind: Kind,
    /// Its name: 1 to 96 bytes, unique.
    pub name: String,
    /// Its argv; elements are non-empty and hold no NUL.
    pub exec: Vec<String>,
    /// How readiness is detected.
    pub ready: Ready,
    /// Its restart policy.
    pub restart: Restart,
    /// How it is stopped.
    pub stop: Stop,
    /// Start timeout in milliseconds; 0 for none.
    pub start_timeout_ms: u32,
    /// Route index for standard output.
    pub output: Option<u32>,
    /// Route index for standard error.
    pub errors: Option<u32>,
    /// Credential index.
    pub cred: Option<u32>,
    /// Its dependency groups.
    pub groups: Vec<Group>,
    /// Memory limit in KiB.
    pub memory_max_kib: u32,
    /// Process limit.
    pub pids_max: u32,
    /// The template this node instantiates; `Some` must be non-empty.
    pub instance_of: Option<String>,
}

/// Node kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A supervised process.
    Worker,
    /// A one-shot action.
    Forager,
    /// A pure grouping node.
    Brood,
}

/// Readiness detection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ready {
    /// Readiness over the notification pipe.
    Pipe,
    /// Ready when the process exits.
    Exit,
    /// Ready when the socket path accepts.
    Socket(String),
    /// Ready when the path exists.
    Path(String),
}

/// Restart behaviour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Restart {
    /// When to restart.
    pub policy: RestartPolicy,
    /// Restarts allowed in the window.
    pub max: u32,
    /// The window in milliseconds.
    pub window_ms: u32,
    /// The base of the restart back-off in milliseconds; at least 100.
    pub delay_ms: u32,
}

/// How a stop asks politely first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopMode {
    /// TERM to the main process.
    Main,
    /// Freeze the cell and TERM every member.
    Cell,
}

/// How a node is stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stop {
    /// The polite mode.
    pub mode: StopMode,
    /// The grace period in milliseconds; at least 100.
    pub grace_ms: u32,
}

/// When a node restarts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartPolicy {
    /// Never.
    Never,
    /// After a failure.
    OnFailure,
    /// Always.
    Always,
}

/// A dependency group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    /// How its edges combine.
    pub kind: GroupKind,
    /// Its edges.
    pub edges: Vec<Edge>,
}

/// Group semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupKind {
    /// Every edge is required.
    RequireAll,
    /// One edge is required.
    RequireAny,
    /// Edges are wanted, not required.
    OptionalAll,
    /// No edge may be active.
    ExcludeAll,
}

/// One dependency edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edge {
    /// What it points at.
    pub target: Target,
    /// Sync or async.
    pub mode: Mode,
    /// Deadline in milliseconds (0 for a sync edge).
    pub deadline_ms: u32,
    /// What the target's restarts do to the dependent.
    pub restart_on: RestartOn,
    /// `stop = "parallel"`.
    pub stop_parallel: bool,
    /// A quarantined target quarantines the dependent (`require_all` node edges only).
    pub cascade: bool,
}

/// An edge target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// A node, by index into `Model::nodes`.
    Node(u32),
    /// A filesystem path.
    Path(String),
}

/// Edge mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Wait for the target.
    Sync,
    /// Do not wait; bounded by the deadline.
    Async,
}

/// Propagation of target restarts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartOn {
    /// None.
    None,
    /// On error.
    Error,
    /// On restart.
    Restart,
    /// On refresh.
    Refresh,
}

/// A credential set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cred {
    /// The user name.
    pub user: String,
    /// Capability set; only bits 0..=40 may be set.
    pub caps: u64,
    /// Securebits preset.
    pub securebits: Securebits,
    /// `no_new_privs`.
    pub nnp: bool,
    /// Namespace bits 0..=4: mount, pid, ipc, uts, net.
    pub ns: u32,
    /// Seccomp filter.
    pub seccomp: Seccomp,
    /// Landlock entries, `ro:/path` or `rw:/path`; non-empty, no NUL.
    pub landlock: Vec<String>,
}

/// Securebits preset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Securebits {
    /// None.
    None,
    /// No root.
    Noroot,
    /// No root, locked.
    NorootLocked,
}

/// Seccomp preset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seccomp {
    /// No filter.
    None,
    /// The default filter.
    Default,
}

/// An output route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// Append to a file.
    Path(String),
    /// Pipe to a logger worker, by node index.
    Pipe(u32),
}

/// The graph edges of `model`, in table order (node, group, edge).
///
/// An edge orders iff its target is a node and its group is `RequireAll`, `RequireAny` or
/// `OptionalAll`. It is hard iff the group is `RequireAll`/`RequireAny` and the mode is sync,
/// and parallel iff `stop_parallel`. `from` is the owning node, `to` the target node.
#[must_use]
pub fn ordering_edges(model: &Model) -> Vec<GEdge> {
    let mut out = Vec::new();
    for (from, node) in model.nodes.iter().enumerate() {
        // Unreachable fallback: `write` limits nodes to 4096, so the index always fits.
        let from = u32::try_from(from).unwrap_or(u32::MAX);
        for group in &node.groups {
            let requires = matches!(group.kind, GroupKind::RequireAll | GroupKind::RequireAny);
            if !requires && group.kind != GroupKind::OptionalAll {
                continue;
            }
            for edge in &group.edges {
                if let Target::Node(to) = edge.target {
                    out.push(GEdge {
                        from,
                        to,
                        hard: requires && edge.mode == Mode::Sync,
                        parallel: edge.stop_parallel,
                    });
                }
            }
        }
    }
    out
}
