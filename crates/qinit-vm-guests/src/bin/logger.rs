// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Logger pipes on a real kernel (spec 2026-11-06 §9, §11 suite `logger`): colony holds one pipe
//! per logger, both ends; the producer's output goes in at one end and the logger reads from the
//! other. Restarts of either side find the same pipe, so nothing in it is lost, and a refresh
//! keeps the pipe of a logger that is still one.
use qinit_client::Wait;
use qinit_db::{Model, Route};
use qinit_vm_guests::colonyd::{
    Site, await_lines, comb_is_empty, model, procs_of, requires, settled, up, worker,
};
use qinit_vm_guests::{HANG_GUARD, e, run};
use std::os::fd::AsFd;
use std::path::Path;

/// `logd` (node 0) sinks its input to `sink`; `web` (node 1) writes `n` lines named `name` to it
/// and requires it. The logger's role is `logger_role` with its arguments.
fn world(logger_role: &str, logger_args: &[&str], name: &str, n: &str) -> Model {
    let mut web = requires(worker("web", "emit-ready", &[name, n]), &[0]);
    web.output = Some(0);
    let mut m = model(vec![worker("logd", logger_role, logger_args), web], &[0, 1]);
    m.routes = vec![Route::Pipe(0)];
    m
}

fn finish(mut s: Site) -> Result<(), String> {
    let code = s.terminate()?;
    if code != 0 {
        return Err(format!("colony exited with {code}"));
    }
    comb_is_empty()
}

fn lines_reach_the_logger() -> Result<(), String> {
    let sink = "/tmp/logger-sink-1";
    let _ = std::fs::remove_file(sink);
    let (s, mut c) = up("logger-lines", &world("log-sink", &[sink], "web", "3"))?;
    if settled(&mut c, "web")? != 3 {
        return Err("the producer is not ready".into());
    }
    let lines = await_lines(Path::new(sink), 3)?;
    if lines != ["web 1", "web 2", "web 3"] {
        return Err(format!("the logger got {lines:?}"));
    }
    drop(c);
    finish(s)
}

fn a_logger_restart_loses_nothing_buffered() -> Result<(), String> {
    let (sink, gate) = ("/tmp/logger-sink-2", "/tmp/logger-gate-2");
    let _ = std::fs::remove_file(sink);
    let _ = std::fs::remove_file(gate);
    // The logger does not read until the gate opens, so the first producer's three lines sit in
    // the pipe. The logger is then killed; colony restarts it (and, the producer needing it,
    // the producer too). Nothing the first producer wrote is lost: the second logger reads it.
    let mut m = world("log-sink-after", &[gate, sink], "web", "3");
    m.nodes[0].restart = qinit_db::Restart {
        policy: qinit_db::RestartPolicy::OnFailure,
        max: 3,
        window_ms: 60_000,
        delay_ms: 100,
    };
    m.nodes[1].restart = m.nodes[0].restart;
    let (s, mut c) = up("logger-restart", &m)?;
    if settled(&mut c, "web")? != 3 {
        return Err("the producer is not ready".into());
    }
    drop(c);
    let victims = procs_of("logd")?;
    // Killed while the gate is shut: the first logger has read nothing.
    for p in &victims {
        e(qinit_sys::proc::kill(*p, libc::SIGKILL))?;
    }
    e(std::fs::write(gate, b"open"))?;
    let lines = await_lines(Path::new(sink), 6)?;
    let first: Vec<&str> = lines.iter().take(3).map(String::as_str).collect();
    if first != ["web 1", "web 2", "web 3"] || lines.len() != 6 {
        return Err(format!(
            "the logger got {lines:?}, wanted the first run's three and the second's"
        ));
    }
    finish(s)
}

fn a_refresh_keeps_the_pipe() -> Result<(), String> {
    let sink = "/tmp/logger-sink-3";
    let _ = std::fs::remove_file(sink);
    let (s, mut c) = up("logger-refresh", &world("log-sink", &[sink], "one", "2"))?;
    if settled(&mut c, "web")? != 3 {
        return Err("the producer is not ready".into());
    }
    await_lines(Path::new(sink), 2)?;
    let logger_before = procs_of("logd")?;
    // The same graph, the producer changed: it restarts, the logger does not, and the new
    // producer writes into the pipe the logger already reads.
    let db =
        qinit_db::write(&world("log-sink", &[sink], "two", "2")).map_err(|x| format!("{x:?}"))?;
    let fd = e(qinit_sys::memfd::sealed(c"db", &db))?;
    match e(c.refresh(fd.as_fd(), Wait::Settled(HANG_GUARD)))? {
        qinit_client::Outcome::Settled(_) => {}
        other => return Err(format!("the refresh ended as {other:?}")),
    }
    let lines = await_lines(Path::new(sink), 4)?;
    if lines != ["one 1", "one 2", "two 1", "two 2"] {
        return Err(format!("the logger got {lines:?}"));
    }
    if procs_of("logd")? != logger_before {
        return Err("the logger was restarted by the refresh".into());
    }
    drop(c);
    finish(s)
}

fn main() {
    run(
        "logger",
        &[
            ("lines_reach_the_logger", lines_reach_the_logger),
            (
                "a_logger_restart_loses_nothing_buffered",
                a_logger_restart_loses_nothing_buffered,
            ),
            ("a_refresh_keeps_the_pipe", a_refresh_keeps_the_pipe),
        ],
    );
}
