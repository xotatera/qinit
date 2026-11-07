// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Re-adoption after a colony restart on a real kernel, under queen (spec 2026-11-07 §8): colony
//! is killed with SIGKILL while its workers run, queen starts a second one at once, and the second
//! adopts what the first left from the descriptors queen held. The cases check what survives:
//! processes, state, counters, logger pipes and exit statuses, and what is restarted or cleared.
//! A round trip to colony before each kill makes sure its last state reached queen: the reply to a
//! request comes after the state of the one before it was saved.
use qinit_client::{Action, Begun, Client, Event, LaunchArgs, Next, Scope, Wait};
use qinit_db::{Kind, Launch, Node, Ready, Route};
use qinit_vm_guests::colonyd::{
    alive, await_exit, await_lines, info, model, procs_of_in, requires, settled, worker,
};
use qinit_vm_guests::queened::{
    self, COMB, await_colony_restart, await_log, colony_pid, fresh, kill_colony, log_count,
    spin_until,
};
use qinit_vm_guests::{HANG_GUARD, e};
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

fn procs(cell: &str) -> Result<Vec<i32>, String> {
    procs_of_in(COMB, cell)
}

fn pidfds(cell: &str) -> Result<Vec<std::os::fd::OwnedFd>, String> {
    procs(cell)?
        .into_iter()
        .map(|p| e(qinit_sys::proc::pidfd_open(p)))
        .collect()
}

/// A round trip: when it returns, colony has saved the state of everything it did before.
fn synced(c: &mut Client, target: &str) -> Result<(), String> {
    e(c.status(target)).map(|_| ())
}

/// Kills colony where it stands and waits for queen's next one.
fn kill_and_follow() -> Result<Client, String> {
    let old = kill_colony()?;
    await_colony_restart(old)
}

/// Watches `name` until it is in `want`; the reason word of that state.
fn watch_state(name: &str, want: u32) -> Result<u32, String> {
    let c = queened::client()?;
    let mut w = e(c.watch(Scope::Target(name)))?;
    loop {
        match e(w.next(Some(HANG_GUARD)))? {
            Next::Event(Event::Node { state, .. }) if state.state == want => {
                return Ok(state.detail);
            }
            Next::Event(_) => {}
            Next::Timeout => return Err(format!("{name} never reached state {want}")),
            Next::Ended(w) => return Err(format!("the watch of {name} ended in {w:?}")),
        }
    }
}

fn await_cell_gone(cell: &str) -> Result<(), String> {
    spin_until(&format!("the cell {cell} gone"), || {
        (!Path::new(COMB).join(cell).exists()).then_some(())
    })
}

fn a_second_colony_adopts_without_restarting_and_stops_through_the_main() -> Result<(), String> {
    let note = "/tmp/readopt-note-a";
    let _ = std::fs::remove_file(note);
    let nodes = vec![worker("a", "ready", &[note]), worker("b", "ready", &[])];
    let mut c = fresh(&model(nodes, &[0, 1]))?;
    settled(&mut c, "a")?;
    settled(&mut c, "b")?;
    let (a_before, b_before) = (procs("a")?, procs("b")?);
    if a_before.is_empty() || b_before.is_empty() {
        return Err("a worker has no process".into());
    }
    synced(&mut c, "a")?;
    drop(c);
    let mut c = kill_and_follow()?;
    // Ready again at once: adopted, not started.
    if settled(&mut c, "a")? != 3 || settled(&mut c, "b")? != 3 {
        return Err("an adopted worker is not ready".into());
    }
    if (a_before.clone(), b_before) != (procs("a")?, procs("b")?) {
        return Err("the workers' processes changed: they were started again".into());
    }
    match e(c.status("a"))? {
        qinit_client::Status::Node(n) if n.pid.is_some_and(|p| a_before.contains(&p)) => {}
        other => return Err(format!("the adopted worker's status is {other:?}")),
    }
    // The main was adopted through its pidfd, so a stop goes to it: the helper notes the TERM.
    match e(c.change("a", Action::Stop, Wait::Settled(HANG_GUARD)))? {
        qinit_client::Outcome::Settled(w) if w.state == 0 => {}
        other => return Err(format!("the stop ended as {other:?}")),
    }
    if !Path::new(note).exists() {
        return Err("TERM never reached the adopted main".into());
    }
    if alive(a_before[0]) {
        return Err("the stopped worker is still running".into());
    }
    Ok(())
}

fn a_main_killed_while_colony_was_away_reports_its_real_status_and_restarts() -> Result<(), String>
{
    let nodes = vec![restarting(worker("w", "ready", &[]), 3, 100)];
    let mut c = fresh(&model(nodes, &[0]))?;
    settled(&mut c, "w")?;
    synced(&mut c, "w")?;
    drop(c);
    let before = procs("w")?;
    let failed = log_count("w: failed");
    // Colony is stopped, so it cannot reap what is killed; then it is killed too, and queen,
    // which inherits the zombies, reaps them and records how they ended.
    let colony = colony_pid().ok_or("no colony")?;
    e(qinit_sys::proc::kill(colony, libc::SIGSTOP))?;
    for p in &before {
        e(qinit_sys::proc::kill(*p, libc::SIGKILL))?;
    }
    e(qinit_sys::proc::kill(colony, libc::SIGKILL))?;
    let mut c = await_colony_restart(colony)?;
    let state = settled(&mut c, "w")?;
    if state != 3 {
        return Err(format!("the worker is in state {state} after the restart"));
    }
    let after = procs("w")?;
    if after.is_empty() || after.iter().any(|p| before.contains(p)) {
        return Err(format!(
            "expected a new process, had {before:?} and now {after:?}"
        ));
    }
    let said = await_log("w: failed", failed + 1)?;
    let line = said
        .iter()
        .rev()
        .find(|l| l.contains("w: failed"))
        .ok_or("no failure line")?;
    if line.contains("unknown") {
        return Err(format!("the status is unknown: {line:?}"));
    }
    Ok(())
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
    let mut c = fresh(&model(nodes, &[0, 1, 2, 3]))?;
    settled(&mut c, "live")?;
    settled(&mut c, "stopped")?;
    if settled(&mut c, "once")? != 4 {
        return Err("the one-shot did not finish".into());
    }
    watch_state("quar", 6)?;
    match e(c.change("stopped", Action::Stop, Wait::Settled(HANG_GUARD)))? {
        qinit_client::Outcome::Settled(w) if w.state == 0 => {}
        other => return Err(format!("the stop ended as {other:?}")),
    }
    synced(&mut c, "live")?;
    drop(c);
    let live_before = procs("live")?;
    let mut c = kill_and_follow()?;
    for (name, want) in [
        ("live", (3, 0)),
        ("once", (4, 0)),
        ("quar", (6, 0)),
        ("stopped", (0, 0)),
    ] {
        let w = info(&mut c, name)?.state;
        if (w.state, w.detail) != want {
            return Err(format!(
                "{name} is {:?} after the restart, not {want:?}",
                (w.state, w.detail)
            ));
        }
    }
    if procs("live")? != live_before {
        return Err("the live worker was started again".into());
    }
    if Path::new(COMB).join("stopped").exists() {
        return Err("the stopped worker has a cell again".into());
    }
    let ran = e(std::fs::read_to_string(log))?;
    if ran.lines().count() != 1 {
        return Err(format!("the one-shot ran again: {ran:?}"));
    }
    Ok(())
}

fn breaker_counts_span_the_kill() -> Result<(), String> {
    // Three failures are allowed, the fourth quarantines; the kill falls after the second.
    let nodes = vec![restarting(worker("crashy", "exit-3", &[]), 3, 500)];
    let before = log_count("crashy: failed (exit 3)");
    let mut c = fresh(&model(nodes, &[0]))?;
    // The second failure is half a second in and the third a second after it: the kill falls
    // between them.
    await_log("crashy: failed (exit 3)", before + 2)?;
    synced(&mut c, "crashy")?;
    drop(c);
    let _c = kill_and_follow()?;
    let detail = watch_state("crashy", 6)?;
    if detail != 0 {
        return Err(format!("quarantined for reason {detail}, not the breaker"));
    }
    let after = log_count("crashy: failed (exit 3)");
    if after != before + 4 {
        return Err(format!(
            "failures in all: {}; the breaker needs 4 across the kill",
            after - before
        ));
    }
    Ok(())
}

fn a_pipe_worker_still_starting_is_restarted() -> Result<(), String> {
    let started = "/tmp/readopt-slow-started";
    let _ = std::fs::remove_file(started);
    // Never ready: it is still starting when colony dies, and its readiness pipe dies with it.
    let nodes = vec![worker("slow", "started", &[started, "slow"])];
    let mut c = fresh(&model(nodes, &[0]))?;
    await_lines(Path::new(started), 1)?;
    synced(&mut c, "slow")?;
    drop(c);
    let old = pidfds("slow")?;
    let _c = kill_and_follow()?;
    // The old process is stopped and a new one started.
    for fd in &old {
        await_exit(fd)?;
    }
    await_lines(Path::new(started), 2)?;
    Ok(())
}

fn a_logger_and_its_producer_keep_running() -> Result<(), String> {
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
    let mut c = fresh(&m)?;
    if settled(&mut c, "web")? != 3 {
        return Err("the producer is not ready".into());
    }
    synced(&mut c, "web")?;
    drop(c);
    let before = (procs("logd")?, procs("web")?);
    let mut c = kill_and_follow()?;
    // Queen held the pipe, so neither side is restarted: the same processes, two starts in all.
    if settled(&mut c, "web")? != 3 {
        return Err("the producer is not ready again".into());
    }
    let after = (procs("logd")?, procs("web")?);
    if before != after {
        return Err(format!("the processes changed: {before:?} then {after:?}"));
    }
    let lines = e(std::fs::read_to_string(started))?;
    if lines.lines().count() != 2 {
        return Err(format!("a worker was started again: {lines:?}"));
    }
    Ok(())
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
    let mut c = fresh(&model(vec![job], &[]))?;
    let first = match e(c.begin_launch("job", &LaunchArgs::default(), false, HANG_GUARD))
        .map_err(|x| format!("first launch: {x}"))?
    {
        Begun::Started(st) => st.id,
        Begun::Failed { step, errno } => return Err(format!("the launch failed: {step} {errno}")),
    };
    if first < 1 {
        return Err(format!("the first instance is {first}"));
    }
    let cell = format!("job#{first}");
    // The server's own reply to the launch comes before the state is saved (D67): a round trip
    // makes sure the next colony can know the cell.
    e(queened::client()?.list(0))?;
    let old = pidfds(&cell)?;
    drop(c);
    let mut c = kill_and_follow()?;
    for fd in &old {
        await_exit(fd)?;
    }
    // The leftover cell is stopped and then removed.
    await_cell_gone(&cell)?;
    let second = match e(c.begin_launch("job", &LaunchArgs::default(), false, HANG_GUARD))
        .map_err(|x| format!("second launch: {x}"))?
    {
        Begun::Started(st) => st.id,
        Begun::Failed { step, errno } => return Err(format!("the launch failed: {step} {errno}")),
    };
    if second != first + 1 {
        return Err(format!(
            "the next instance is {second}: ids must pass the one found"
        ));
    }
    Ok(())
}

fn main() {
    let first = model(vec![worker("w", "ready", &[])], &[0]);
    queened::boot(
        &[
            (
                "a_second_colony_adopts_without_restarting_and_stops_through_the_main",
                a_second_colony_adopts_without_restarting_and_stops_through_the_main,
            ),
            (
                "a_main_killed_while_colony_was_away_reports_its_real_status_and_restarts",
                a_main_killed_while_colony_was_away_reports_its_real_status_and_restarts,
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
                "a_logger_and_its_producer_keep_running",
                a_logger_and_its_producer_keep_running,
            ),
            (
                "an_instance_cell_is_cleared_and_ids_move_past_it",
                an_instance_cell_is_cleared_and_ids_move_past_it,
            ),
        ],
        "readopt",
        &first,
    )
}
