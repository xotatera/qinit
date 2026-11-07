// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Re-adoption after a colony restart on a real kernel (spec 2026-11-06 §8, §11 suite `readopt`):
//! colony is killed with SIGKILL while its workers run, a second colony adopts what the first
//! left, and the cases check what survives: processes, state, counters, and what is restarted or
//! cleared. The guest's init is the reaper of the orphans, as dinit will be.
use qinit_client::{Action, Begun, LaunchArgs, Wait};
use qinit_db::{Kind, Launch, Node, Ready, Route};
use qinit_vm_guests::colonyd::{
    alive, await_cell_gone, await_exit, await_file, await_lines, await_state, await_unpopulated,
    finish, info, model, procs_of, requires, settled, up, worker,
};
use qinit_vm_guests::{COMB, HANG_GUARD, e, run};
use std::path::Path;

/// `restart = on-failure`, `max` failures allowed within a minute, `delay_ms` before the first.
fn restarting(mut n: Node, max: u32, delay_ms: u32) -> Node {
    n.restart = qinit_db::Restart {
        policy: qinit_db::RestartPolicy::OnFailure,
        max,
        window_ms: 60_000,
        delay_ms,
    };
    n
}

fn pidfds(cell: &str) -> Result<Vec<std::os::fd::OwnedFd>, String> {
    procs_of(cell)?
        .into_iter()
        .map(|p| e(qinit_sys::proc::pidfd_open(p)))
        .collect()
}

fn a_second_colony_adopts_without_restarting_and_stops_through_the_main() -> Result<(), String> {
    let note = "/tmp/readopt-note-a";
    let _ = std::fs::remove_file(note);
    let nodes = vec![worker("a", "ready", &[note]), worker("b", "ready", &[])];
    let (mut s, mut c) = up("readopt-adopt", &model(nodes, &[0, 1]))?;
    settled(&mut c, "a")?;
    settled(&mut c, "b")?;
    drop(c);
    let (a_before, b_before) = (procs_of("a")?, procs_of("b")?);
    if a_before.is_empty() || b_before.is_empty() {
        return Err("a worker has no process".into());
    }
    s.kill_hard()?;
    s.start()?;
    let mut c = s.client()?;
    // Ready again at once: adopted, not started.
    if settled(&mut c, "a")? != 3 || settled(&mut c, "b")? != 3 {
        return Err("an adopted worker is not ready".into());
    }
    let (a_after, b_after) = (procs_of("a")?, procs_of("b")?);
    if (a_before.clone(), b_before) != (a_after, b_after) {
        return Err("the workers' processes changed: they were started again".into());
    }
    match e(c.status("a"))? {
        qinit_client::Status::Node(n) if n.pid.is_some_and(|p| a_before.contains(&p)) => {}
        other => return Err(format!("the adopted worker's status is {other:?}")),
    }
    // The main was recovered, so a stop goes to it by its pidfd: the helper notes the TERM.
    match e(c.change("a", Action::Stop, Wait::Settled(HANG_GUARD)))? {
        qinit_client::Outcome::Settled(w) if w.state == 0 => {}
        other => return Err(format!("the stop ended as {other:?}")),
    }
    if !Path::new(note).exists() {
        return Err("TERM never reached the adopted main".into());
    }
    if alive(a_before[0]) {
        return Err(format!(
            "the stopped worker is still running: {:?}; colony said {:?}",
            std::fs::read_to_string(format!("/proc/{}/status", a_before[0])).map(|t| t
                .lines()
                .take(3)
                .map(str::to_owned)
                .collect::<Vec<_>>()),
            s.lines()
        ));
    }
    drop(c);
    finish(s)
}

fn a_main_killed_while_colony_was_away_is_a_failure_and_restarts() -> Result<(), String> {
    let nodes = vec![restarting(worker("w", "ready", &[]), 3, 100)];
    let (mut s, mut c) = up("readopt-killed", &model(nodes, &[0]))?;
    settled(&mut c, "w")?;
    drop(c);
    let before = procs_of("w")?;
    s.kill_hard()?;
    // Colony is away; the guest kills the worker (the guest's reaper reaps it).
    for p in &before {
        e(qinit_sys::proc::kill(*p, libc::SIGKILL))?;
    }
    let _ = s.lines();
    s.start()?;
    let mut c = s.client()?;
    let state = settled(&mut c, "w")?;
    if state != 3 {
        return Err(format!("the worker is in state {state} after the restart"));
    }
    let after = procs_of("w")?;
    if after.is_empty() || after.iter().any(|p| before.contains(p)) {
        return Err(format!(
            "expected a new process, had {before:?} and now {after:?}"
        ));
    }
    let said = s.lines();
    if !said
        .iter()
        .any(|l| l.ends_with("w: failed (status unknown)"))
    {
        return Err(format!(
            "the unknown exit is not a failure in the log: {said:?}"
        ));
    }
    drop(c);
    finish(s)
}

fn stopped_quarantined_and_finished_nodes_survive() -> Result<(), String> {
    let log = "/tmp/readopt-once-log";
    let _ = std::fs::remove_file(log);
    // Nodes in name order: live, once, quar, stopped.
    let mut once = worker("once", "log-exit", &[log, "once"]);
    once.ready = Ready::Exit;
    once.start_timeout_ms = 0;
    let nodes = vec![
        worker("live", "ready", &[]),
        once,
        restarting(worker("quar", "exit-3", &[]), 1, 100),
        worker("stopped", "ready", &[]),
    ];
    let (mut s, mut c) = up("readopt-state", &model(nodes, &[0, 1, 2, 3]))?;
    settled(&mut c, "live")?;
    settled(&mut c, "stopped")?;
    if settled(&mut c, "once")? != 4 {
        return Err("the one-shot did not finish".into());
    }
    drop(await_state(&mut s, "quar", 6)?);
    match e(c.change("stopped", Action::Stop, Wait::Settled(HANG_GUARD)))? {
        qinit_client::Outcome::Settled(w) if w.state == 0 => {}
        other => return Err(format!("the stop ended as {other:?}")),
    }
    drop(c);
    let live_before = procs_of("live")?;
    s.kill_hard()?;
    s.start()?;
    let mut c = s.client()?;
    let state = |name: &str, c: &mut qinit_client::Client| -> Result<(u32, u32), String> {
        let w = info(c, name)?.state;
        Ok((w.state, w.detail))
    };
    for (name, want) in [
        ("live", (3, 0)),
        ("once", (4, 0)),
        ("quar", (6, 0)),
        ("stopped", (0, 0)),
    ] {
        let got = state(name, &mut c)?;
        if got != want {
            return Err(format!("{name} is {got:?} after the restart, not {want:?}"));
        }
    }
    if procs_of("live")? != live_before {
        return Err("the live worker was started again".into());
    }
    if Path::new(COMB).join("stopped").exists() {
        return Err("the stopped worker has a cell again".into());
    }
    let ran = e(std::fs::read_to_string(log))?;
    if ran.lines().count() != 1 {
        return Err(format!("the one-shot ran again: {ran:?}"));
    }
    drop(c);
    finish(s)
}

fn breaker_counts_span_the_kill() -> Result<(), String> {
    // Three failures are allowed, the fourth quarantines; the kill falls after the second.
    let nodes = vec![restarting(worker("crashy", "exit-3", &[]), 3, 500)];
    let mut s = qinit_vm_guests::colonyd::site("readopt-breaker")?;
    s.write_db(&model(nodes, &[0]))?;
    s.start()?;
    let failed = |l: &String| l.ends_with("crashy: failed (exit 3)");
    // The log is the count: a watch opened after the socket appears can miss the first failure.
    // The second failure is half a second in and the third a second after it: the kill falls
    // between them.
    let said = s.await_log(|lines| lines.iter().filter(|l| failed(l)).count() >= 2)?;
    let before = said.iter().filter(|l| failed(l)).count();
    // The log line comes before the state file: wait for the file to hold the second failure
    // (field 5 of the `nodes` line is the burst count) before the kill.
    await_file(&s.run.join("state"), "nodes", |t| {
        t.lines().any(|l| l.split_whitespace().nth(4) == Some("2"))
    })?;
    s.kill_hard()?;
    s.start()?;
    let seen = await_state(&mut s, "crashy", 6)?;
    if seen.detail != 0 {
        return Err(format!(
            "quarantined for reason {}, not the breaker",
            seen.detail
        ));
    }
    let said = s.lines();
    let after = said.iter().filter(|l| failed(l)).count();
    if before != 2 || after != 2 {
        return Err(format!(
            "failures before the kill: {before}, after: {after}; the breaker needs 4 in all; colony said {said:?}; nodes file {:?}",
            std::fs::read_to_string(s.run.join("state/nodes"))
        ));
    }
    finish(s)
}

fn a_pipe_worker_still_starting_is_restarted() -> Result<(), String> {
    let started = "/tmp/readopt-slow-started";
    let _ = std::fs::remove_file(started);
    // Never ready: it is still starting when colony dies, and its readiness pipe dies with it.
    let nodes = vec![worker("slow", "started", &[started, "slow"])];
    let (mut s, c) = up("readopt-slow", &model(nodes, &[0]))?;
    drop(c);
    await_lines(Path::new(started), 1)?;
    let old = pidfds("slow")?;
    s.kill_hard()?;
    s.start()?;
    let c = s.client()?;
    // The old process is stopped and a new one started.
    for fd in &old {
        await_exit(fd)?;
    }
    await_lines(Path::new(started), 2)?;
    drop(c);
    finish(s)
}

fn a_logger_and_its_producer_are_restarted() -> Result<(), String> {
    let started = "/tmp/readopt-logger-started";
    let _ = std::fs::remove_file(started);
    // `logd` (0) is a logger; `web` (1) writes to it and requires it.
    let mut web = requires(worker("web", "started-ready", &[started, "web"]), &[0]);
    web.output = Some(0);
    let mut m = model(
        vec![worker("logd", "started-ready", &[started, "logd"]), web],
        &[0, 1],
    );
    m.routes = vec![Route::Pipe(0)];
    let (mut s, mut c) = up("readopt-logger", &m)?;
    if settled(&mut c, "web")? != 3 {
        return Err("the producer is not ready".into());
    }
    drop(c);
    let old: Vec<_> = pidfds("logd")?.into_iter().chain(pidfds("web")?).collect();
    s.kill_hard()?;
    s.start()?;
    let mut c = s.client()?;
    for fd in &old {
        await_exit(fd)?;
    }
    // Four starts in all: both, then both again; the pipe is new, so neither keeps an old end.
    let lines = await_lines(Path::new(started), 4)?;
    if lines.iter().filter(|l| *l == "logd").count() != 2
        || lines.iter().filter(|l| *l == "web").count() != 2
    {
        return Err(format!("expected both to start twice: {lines:?}"));
    }
    if settled(&mut c, "web")? != 3 {
        return Err("the producer is not ready again".into());
    }
    drop(c);
    finish(s)
}

fn a_cell_with_a_different_id_is_left_alone() -> Result<(), String> {
    let (mut s, mut c) = up("readopt-id", &model(vec![worker("w", "ready", &[])], &[0]))?;
    settled(&mut c, "w")?;
    drop(c);
    let victims = procs_of("w")?;
    s.kill_hard()?;
    // The guest empties the cell and makes a directory of the same name: another cgroup id.
    for p in &victims {
        e(qinit_sys::proc::kill(*p, libc::SIGKILL))?;
    }
    await_unpopulated("w")?;
    let dir = Path::new(COMB).join("w");
    e(std::fs::remove_dir(&dir))?;
    e(std::fs::create_dir(&dir))?;
    let _ = s.lines();
    s.start()?;
    let mut c = s.client()?;
    let said = s.lines();
    if !said
        .iter()
        .any(|l| l.starts_with("<27>") && l.contains("is not the one colony recorded"))
    {
        return Err(format!("the mismatch is not logged as an error: {said:?}"));
    }
    if !dir.is_dir() {
        return Err("colony removed a directory it did not make".into());
    }
    // `w` could not start (its directory is taken): off, and the directory is still ours to remove.
    let state = info(&mut c, "w")?.state.state;
    if state != 0 {
        return Err(format!("w is in state {state}, not off"));
    }
    drop(c);
    e(std::fs::remove_dir(&dir))?;
    finish(s)
}

fn an_instance_cell_is_cleared_and_ids_move_past_it() -> Result<(), String> {
    let mut job = worker("job", "wait-term", &[]);
    job.kind = Kind::Forager;
    job.ready = Ready::Exit;
    job.start_timeout_ms = 0;
    job.launch = Some(Launch {
        concurrency: 2,
        argv_tail: 0,
        env: Vec::new(),
        fds: 0,
    });
    let (mut s, mut c) = up("readopt-instance", &model(vec![job], &[]))?;
    let first = match e(c.begin_launch("job", &LaunchArgs::default(), false, HANG_GUARD))? {
        Begun::Started(st) => st.id,
        Begun::Failed { step, errno } => return Err(format!("the launch failed: {step} {errno}")),
    };
    if first != 1 {
        return Err(format!("the first instance is {first}, not 1"));
    }
    let cell = format!("job#{first}");
    // The server's own reply to the launch comes before the cell map is rewritten (D67): wait for
    // the file to name the cell before killing colony, or the next colony could not know it.
    await_file(&s.run.join("state"), "cells", |t| {
        t.lines().any(|l| l.starts_with(&cell))
    })?;
    let old = pidfds(&cell)?;
    drop(c);
    s.kill_hard()?;
    s.start()?;
    let mut c = s.client()?;
    for fd in &old {
        await_exit(fd)?;
    }
    // The leftover cell is stopped and then removed.
    await_cell_gone(&cell).map_err(|why| format!("{why}; colony said {:?}", s.lines()))?;
    let second = match e(c.begin_launch("job", &LaunchArgs::default(), false, HANG_GUARD))? {
        Begun::Started(st) => st.id,
        Begun::Failed { step, errno } => return Err(format!("the launch failed: {step} {errno}")),
    };
    if second != 2 {
        return Err(format!(
            "the next instance is {second}: ids must pass the one found"
        ));
    }
    drop(c);
    finish(s)
}

fn a_corrupt_nodes_file_is_refused_and_only_cells_are_adopted() -> Result<(), String> {
    let nodes = vec![
        restarting(worker("w", "ready", &[]), 3, 100),
        restarting(worker("x", "ready", &[]), 3, 100),
    ];
    let (mut s, mut c) = up("readopt-corrupt", &model(nodes, &[0]))?;
    settled(&mut c, "w")?;
    drop(c);
    let before = procs_of("w")?;
    s.kill_hard()?;
    // `x` quarantined by its breaker with no failure counted: not a state the scheduler can hold.
    e(std::fs::write(
        s.run.join("state/nodes"),
        "x 1 quarantined:breaker 0 0 0 0 0\n",
    ))?;
    let _ = s.lines();
    s.start()?;
    let mut c = s.client()?;
    if settled(&mut c, "w")? != 3 || procs_of("w")? != before {
        return Err("the cell was not adopted as it stood".into());
    }
    let said = s.lines();
    if !said
        .iter()
        .any(|l| l.starts_with("<27>") && l.contains("saved node state is refused"))
    {
        return Err(format!("the refusal is not logged as an error: {said:?}"));
    }
    if info(&mut c, "x")?.state.state == 6 {
        return Err("the refused file quarantined a node".into());
    }
    drop(c);
    finish(s)
}

fn main() {
    run(
        "readopt",
        &[
            (
                "a_second_colony_adopts_without_restarting_and_stops_through_the_main",
                a_second_colony_adopts_without_restarting_and_stops_through_the_main,
            ),
            (
                "a_main_killed_while_colony_was_away_is_a_failure_and_restarts",
                a_main_killed_while_colony_was_away_is_a_failure_and_restarts,
            ),
            (
                "stopped_quarantined_and_finished_nodes_survive",
                stopped_quarantined_and_finished_nodes_survive,
            ),
            ("breaker_counts_span_the_kill", breaker_counts_span_the_kill),
            (
                "a_pipe_worker_still_starting_is_restarted",
                a_pipe_worker_still_starting_is_restarted,
            ),
            (
                "a_logger_and_its_producer_are_restarted",
                a_logger_and_its_producer_are_restarted,
            ),
            (
                "a_cell_with_a_different_id_is_left_alone",
                a_cell_with_a_different_id_is_left_alone,
            ),
            (
                "an_instance_cell_is_cleared_and_ids_move_past_it",
                an_instance_cell_is_cleared_and_ids_move_past_it,
            ),
            (
                "a_corrupt_nodes_file_is_refused_and_only_cells_are_adopted",
                a_corrupt_nodes_file_is_refused_and_only_cells_are_adopted,
            ),
        ],
    );
}
