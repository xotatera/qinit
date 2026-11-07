// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qctl run --frame FILE` (spec 2026-11-07 §4.3, D54): a file of one frame, compiled by the frame
//! compiler as one more top layer over the usual layers and the policy, so templates, defaults,
//! the amend rules and the policy apply as to any frame. Its node goes through the overseer's
//! request builder, as colony's launch of a frame's instance does, to the request of a `Run`.
use crate::args::{Fds, PolicyChoice};
use crate::compile::{self, Defaults};
use crate::report;
use qinit_client::StopMode;
use qinit_db::{Kind, Model, Node, Ready, Route};
use qinit_frames::compile::{Compiled, compile};
use qinit_frames::error::{Code, Error};
use qinit_frames::layers::LayerInput;
use qinit_frames::provenance::{Provenance, Seg, nearest};
use qinit_overseer::request::{RequestSpec, Routed, deadline_ms, from_instance};
use std::io::Write;
use std::path::{Path, PathBuf};

/// The name of the layer the frame file is, in provenance and errors.
pub const LAYER: &str = "run";
/// Where a `Run`'s streams arrive (`docs/control-protocol.md`, `Run`): stdin, stdout and stderr
/// at 5, 6 and 7, each whether or not the others are sent.
pub const STREAM_FDS: [u32; 3] = [5, 6, 7];
/// The routed number of the readiness pipe: the first that no stream can take. The service
/// finds the pipe at `QINIT_READY_FD` whatever this is.
pub const READY_FD: u32 = 8;

/// What `run --frame` sends: the instance's name, its request and the `Run`'s settings, each
/// the frame's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameRun {
    /// The frame's name, the default of `--name`.
    pub name: String,
    /// The request colony is sent.
    pub spec: RequestSpec,
    /// `cell.memory_max` in KiB, 0 for none.
    pub memory_max_kib: u32,
    /// `cell.pids_max`, 0 for none.
    pub pids_max: u32,
    /// `stop.mode`.
    pub stop_mode: StopMode,
    /// `stop.grace` in milliseconds.
    pub stop_grace_ms: u32,
    /// `ready = "pipe"`: the request routes a readiness pipe, and the run waits for its byte.
    pub wait_ready: bool,
}

/// The routed numbers of the streams `fds` names, and no readiness pipe yet.
#[must_use]
pub fn routed(fds: Fds) -> Routed {
    let [stdin, stdout, stderr] = STREAM_FDS;
    Routed {
        stdin: fds.stdin.then_some(stdin),
        stdout: fds.stdout.then_some(stdout),
        stderr: fds.stderr.then_some(stderr),
        ready: None,
    }
}

/// The run of the one frame in `file`, compiled over the layers and policy of `defaults`.
/// `routed` holds the streams the caller sends ([`routed`]); each takes the place of the
/// frame's route for that stream. Notices and warnings go to `err`.
///
/// # Errors
/// The text to print, one line per problem: the ownership check's refusal; every compile
/// error, as `qctl compile` prints it (`<file>:<line>: <key>: <message>`); a file with no frame
/// or more than one; and, naming the key and the file and line that set it, what a `Run`
/// cannot do: a brood or template, a frame that expands to more or fewer than one node, a pipe
/// route no given stream replaces (a `Run` has no logger), `socket` or `path` readiness, a
/// `launch` table.
pub fn spec(
    file: &Path,
    defaults: &Defaults,
    routed: Routed,
    err: &mut dyn Write,
) -> Result<FrameRun, String> {
    let mut input = compile::checked(&[], &PolicyChoice::Default, defaults, err)?;
    input.layers.push(LayerInput {
        name: LAYER.into(),
        dir: file
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf),
        only: Some(file.to_path_buf()),
    });
    let compiled = compile(&input).map_err(|errs| {
        errs.iter()
            .map(report::error_line)
            .collect::<Vec<_>>()
            .join("\n")
    })?;
    for w in &compiled.warnings {
        let _ = writeln!(err, "{}", report::warning_line(w));
    }
    let (kind, name) = one_frame(file)?;
    let at = At {
        file,
        compiled: &compiled,
        kind: &kind,
        name: &name,
    };
    let model = &compiled.resolved.model;
    let node = at.node(model)?;
    let mut refused = Vec::new();
    if node.launch.is_some() {
        refused.push(at.line(
            node,
            "launch",
            "a frame with a launch table is for qctl launch, not run",
        ));
    }
    match &node.ready {
        Ready::Socket(_) => refused.push(at.line(
            node,
            "ready",
            "a Run has no socket readiness; use \"pipe\" or \"exit\"",
        )),
        Ready::Path(_) => refused.push(at.line(
            node,
            "ready",
            "a Run has no path readiness; use \"pipe\" or \"exit\"",
        )),
        Ready::Pipe | Ready::Exit => {}
    }
    let pipe = |r: Option<u32>| r.and_then(|i| model.routes.get(i as usize));
    let logger = |r: Option<u32>| matches!(pipe(r), Some(Route::Pipe(_)));
    let why = "a Run has no logger: route the stream to a path, or send it with --fds";
    if routed.stdout.is_none() && logger(node.output) {
        refused.push(at.line(node, "output", why));
    }
    // Standard error that follows standard output needs no route of its own.
    let follows = node.output.is_some() && pipe(node.output) == pipe(node.errors);
    if routed.stderr.is_none() && logger(node.errors) && !follows {
        refused.push(at.line(node, "errors", why));
    }
    if !refused.is_empty() {
        return Err(refused.join("\n"));
    }
    let wait_ready = node.ready == Ready::Pipe;
    let routed = Routed {
        ready: wait_ready.then_some(READY_FD),
        ..routed
    };
    let deadline = deadline_ms(node.start_timeout_ms);
    let spec = from_instance(node, model, &routed, &[], &[], deadline)
        .map_err(|e| format!("qctl: {}: {kind}.{name}: no request: {e:?}", file.display()))?;
    if spec.bytes().is_err() {
        return Err(format!(
            "qctl: {}: {kind}.{name}: the request is over 64 KiB once laid out",
            file.display()
        ));
    }
    Ok(FrameRun {
        name,
        spec,
        memory_max_kib: node.memory_max_kib,
        pids_max: node.pids_max,
        stop_mode: match node.stop.mode {
            qinit_db::StopMode::Main => StopMode::Main,
            qinit_db::StopMode::Cell => StopMode::Cell,
        },
        stop_grace_ms: node.stop.grace_ms,
        wait_ready,
    })
}

/// The `(kind, name)` of the one frame in `file`.
fn one_frame(file: &Path) -> Result<(String, String), String> {
    let fail = |why: &dyn std::fmt::Display| format!("qctl: {}: {why}", file.display());
    let text = std::fs::read_to_string(file).map_err(|e| fail(&e))?;
    let table: toml::Table = text.parse().map_err(|e| fail(&e))?;
    let mut frames = Vec::new();
    for (kind, names) in &table {
        for name in names.as_table().into_iter().flat_map(toml::Table::keys) {
            frames.push((kind.clone(), name.clone()));
        }
    }
    match frames.len() {
        1 => Ok(frames.remove(0)),
        0 => Err(fail(&"no frame; run --frame takes a file of one frame")),
        n => {
            let names: Vec<String> = frames.iter().map(|(k, n)| format!("{k}.{n}")).collect();
            Err(fail(&format_args!(
                "{n} frames ({}); run --frame takes one",
                names.join(", ")
            )))
        }
    }
}

/// The frame file's one frame in the compiled result, for errors that name its keys.
struct At<'a> {
    file: &'a Path,
    compiled: &'a Compiled,
    kind: &'a str,
    name: &'a str,
}

impl At<'_> {
    /// The one node the frame expands to.
    fn node<'m>(&self, model: &'m Model) -> Result<&'m Node, String> {
        let merged = &self.compiled.merged.provenance;
        let kind = match self.kind {
            "worker" => Kind::Worker,
            "forager" => Kind::Forager,
            "brood" => {
                return Err(self.error(merged, self.name, &[], "a brood has nothing to run"));
            }
            _ => {
                let why = "a template is no node; run a frame that uses it";
                return Err(self.error(merged, self.name, &[], why));
            }
        };
        let nodes: Vec<&Node> = model
            .nodes
            .iter()
            .filter(|n| n.kind == kind)
            .filter(|n| n.name == self.name || n.instance_of.as_deref() == Some(self.name))
            .collect();
        match nodes.as_slice() {
            [one] => Ok(one),
            [] => Err(self.error(merged, self.name, &[], "the frame expands to no node")),
            more => {
                let why = format!("the frame expands to {} nodes; run takes one", more.len());
                Err(self.error(merged, self.name, &["instances"], &why))
            }
        }
    }

    /// The error line for key `key` of `node`, at the file and line that set it.
    fn line(&self, node: &Node, key: &str, why: &str) -> String {
        self.error(&self.compiled.provenance, &node.name, &[key], why)
    }

    /// The error line for `keys` of the frame (`frame` its name in `prov`), at the file and
    /// line that set them; the frame file when no layer did.
    fn error(&self, prov: &Provenance, frame: &str, keys: &[&str], why: &str) -> String {
        let path: Vec<Seg> = keys.iter().map(|k| Seg::Key((*k).to_owned())).collect();
        let mut key = format!("{}.{}", self.kind, self.name);
        for k in keys {
            key.push('.');
            key.push_str(k);
        }
        let file = nearest(prov, self.kind, frame, &path).map_or(self.file, |o| o.file.as_path());
        report::error_line(&Error::new(Code::BadValue, key, why).in_file(file))
    }
}
