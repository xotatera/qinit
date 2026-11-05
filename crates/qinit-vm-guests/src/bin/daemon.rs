// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The colony program on a real kernel: it boots a graph into real cells, supervises it, limits
//! it and shuts it down (spec 2026-11-06 §11, suite `daemon`). Workers are the guest's own helper
//! programs; colony is the real `/colony` binary, and the cases talk to it over its socket.
use qinit_client::{Action, Client, Event, LaunchArgs, Mode, Next, Outcome, Scope, Status, Wait};
use qinit_vm_guests::colonyd::{
    Site, brood, cell_file, comb_is_empty, model, requires, site, worker,
};
use qinit_vm_guests::{HANG_GUARD, e, run};

/// Starts colony on `model` and connects.
fn up(tag: &str, m: &qinit_db::Model) -> Result<(Site, Client), String> {
    let mut s = site(tag)?;
    s.write_db(m)?;
    s.start()?;
    let c = s.client()?;
    Ok((s, c))
}

/// Waits until `target` has settled after a start request (a parked reply, not a poll).
fn settled(c: &mut Client, target: &str) -> Result<u32, String> {
    match e(c.change(target, Action::Start, Wait::Settled(HANG_GUARD)))? {
        Outcome::Settled(w) => Ok(w.state),
        other => Err(format!("{target} did not settle: {other:?}")),
    }
}

fn info(c: &mut Client, name: &str) -> Result<qinit_client::NodeInfo, String> {
    match e(c.status(name))? {
        Status::Node(n) => Ok(n),
        other @ Status::Instance(_) => Err(format!("{name} is not a node: {other:?}")),
    }
}

/// The cgroup path of process `pid`.
fn cgroup_of(pid: i32) -> Result<String, String> {
    Ok(e(std::fs::read_to_string(format!("/proc/{pid}/cgroup")))?
        .trim()
        .to_owned())
}

fn two_branches_boot_ready() -> Result<(), String> {
    // a2 needs a1, b2 needs b1, and `top` needs both ends: two branches that boot in parallel.
    let nodes = vec![
        worker("a1", "ready", &[]),
        requires(worker("a2", "ready", &[]), &[0]),
        worker("b1", "ready", &[]),
        requires(worker("b2", "ready", &[]), &[2]),
        requires(brood("top"), &[1, 3]),
    ];
    let (mut s, mut c) = up("daemon-branches", &model(nodes, &[0, 1, 2, 3, 4]))?;
    let state = settled(&mut c, "top")?;
    if state != 3 {
        return Err(format!("top is in state {state}, not ready"));
    }
    for name in ["a1", "a2", "b1", "b2"] {
        let n = info(&mut c, name)?;
        if n.state.state != 3 {
            return Err(format!("{name} is in state {:?}", n.state));
        }
        let pid = n.pid.ok_or_else(|| format!("{name} has no pid"))?;
        let want = format!("0::/qinit-test/{name}");
        let got = cgroup_of(pid)?;
        if got != want {
            return Err(format!("{name}'s process {pid} is in {got}, not {want}"));
        }
    }
    drop(c);
    let code = s.terminate()?;
    if code != 0 {
        return Err(format!("colony exited with {code}"));
    }
    comb_is_empty()
}

fn a_crashing_worker_backs_off_then_quarantines() -> Result<(), String> {
    let mut crashy = worker("crashy", "exit-3", &[]);
    crashy.restart = qinit_db::Restart {
        policy: qinit_db::RestartPolicy::OnFailure,
        max: 2,
        window_ms: 60_000,
        delay_ms: 100,
    };
    let (mut s, c) = up("daemon-crash", &model(vec![crashy], &[0]))?;
    let mut w = e(c.watch(Scope::Target("crashy")))?;
    // The watch starts with the state now and streams every change: it ends in quarantine.
    let reason = loop {
        match e(w.next(Some(HANG_GUARD)))? {
            Next::Event(Event::Node { state, .. }) if state.state == 6 => break state.detail,
            Next::Timeout => return Err("never quarantined".into()),
            Next::Ended(w) => return Err(format!("the watch ended in {w:?}")),
            Next::Event(_) => {}
        }
    };
    if reason != 0 {
        return Err(format!("quarantined for reason {reason}, not the breaker"));
    }
    drop(w);
    let mut c = s.client()?;
    let n = info(&mut c, "crashy")?;
    if (n.state.state, n.state.detail) != (6, 0) {
        return Err(format!("status says {:?}", n.state));
    }
    let said: Vec<String> = s.lines();
    if !said
        .iter()
        .any(|l| l.ends_with("crashy: quarantined (too many failures)"))
    {
        return Err(format!("the quarantine is not in the log: {said:?}"));
    }
    if !said.iter().any(|l| l.contains("crashy: failed (exit 3)")) {
        return Err(format!("the failures are not in the log: {said:?}"));
    }
    drop(c);
    let code = s.terminate()?;
    if code != 0 {
        return Err(format!("colony exited with {code}"));
    }
    comb_is_empty()
}

fn limits_read_back_from_the_cells() -> Result<(), String> {
    let mut limited = worker("limited", "ready", &[]);
    limited.memory_max_kib = 4096;
    limited.pids_max = 7;
    let free = worker("free", "ready", &[]);
    let (mut s, mut c) = up("daemon-limits", &model(vec![free, limited], &[0, 1]))?;
    settled(&mut c, "limited")?;
    settled(&mut c, "free")?;
    for (cell, file, want) in [
        ("limited", "memory.max", "4194304"),
        ("limited", "pids.max", "7"),
        ("free", "memory.max", "max"),
        ("free", "pids.max", "max"),
    ] {
        let got = cell_file(cell, file)?;
        if got != want {
            return Err(format!("{cell}/{file} reads {got:?}, not {want:?}"));
        }
    }
    drop(c);
    let code = s.terminate()?;
    if code != 0 {
        return Err(format!("colony exited with {code}"));
    }
    comb_is_empty()
}

fn pipe_exit_and_launch_behave_as_simulated() -> Result<(), String> {
    // `job` is a launchable forager; `oneshot` is ready by exit; `web` is ready by its pipe.
    let mut job = worker("job", "exit-3", &[]);
    job.kind = qinit_db::Kind::Forager;
    job.ready = qinit_db::Ready::Exit;
    job.start_timeout_ms = 0;
    job.launch = Some(qinit_db::Launch {
        concurrency: 1,
        argv_tail: 0,
        env: Vec::new(),
        fds: 0,
    });
    let mut oneshot = worker("oneshot", "exit-0", &[]);
    oneshot.ready = qinit_db::Ready::Exit;
    oneshot.start_timeout_ms = 0;
    let web = worker("web", "ready", &[]);
    let nodes = vec![job, oneshot, web];
    let (mut s, mut c) = up("daemon-modes", &model(nodes, &[1, 2]))?;
    let web_state = settled(&mut c, "web")?;
    let one_state = settled(&mut c, "oneshot")?;
    if web_state != 3 {
        return Err(format!(
            "web (ready by pipe) is in state {web_state}, not ready"
        ));
    }
    if one_state != 4 {
        return Err(format!(
            "oneshot (ready by exit) is in state {one_state}, not done"
        ));
    }
    match e(c.launch("job", &LaunchArgs::default(), HANG_GUARD))? {
        qinit_client::LaunchOutcome::Exited { status, .. } if libc::WEXITSTATUS(status) == 3 => {}
        other => return Err(format!("the launch ended as {other:?}, not exit 3")),
    }
    drop(c);
    let code = s.terminate()?;
    if code != 0 {
        return Err(format!("colony exited with {code}"));
    }
    comb_is_empty()
}

fn sigterm_stops_in_reverse_hard_order_and_exits_0() -> Result<(), String> {
    let order = "/tmp/stop-order";
    let _ = std::fs::remove_file(order);
    // The enabled list is a closure: a2 pulls a1 in. a2 requires a1 (a hard edge): a2 must be gone before a1 is told to stop.
    let nodes = vec![
        worker("a1", "ready-log", &[order, "a1"]),
        requires(worker("a2", "ready-log", &[order, "a2"]), &[0]),
        worker("b1", "ready-log", &[order, "b1"]),
    ];
    let (mut s, mut c) = up("daemon-order", &model(nodes, &[0, 1, 2]))?;
    settled(&mut c, "a2")?;
    settled(&mut c, "b1")?;
    drop(c);
    let code = s.terminate()?;
    if code != 0 {
        return Err(format!("colony exited with {code}, not 0"));
    }
    let logged = e(std::fs::read_to_string(order))?;
    let lines: Vec<&str> = logged.lines().collect();
    let at = |n: &str| lines.iter().position(|l| *l == n);
    match (at("a1"), at("a2"), at("b1")) {
        (Some(a1), Some(a2), Some(_)) if a2 < a1 => {}
        _ => {
            return Err(format!(
                "the stop order was {lines:?}: a2 must precede a1, all present"
            ));
        }
    }
    comb_is_empty()?;
    if s.run.join("state/cells").exists() {
        return Err("state/cells is left after a completed shutdown".into());
    }
    if s.socket().exists() {
        return Err("the socket file is left".into());
    }
    Ok(())
}

fn a_protocol_shutdown_poweroff_exits_10() -> Result<(), String> {
    let nodes = vec![worker("db", "ready", &[])];
    let (mut s, mut c) = up("daemon-poweroff", &model(nodes, &[0]))?;
    settled(&mut c, "db")?;
    e(c.shutdown(Mode::Poweroff, Wait::Now))?;
    let code = s.wait_exit()?;
    if code != 10 {
        return Err(format!("colony exited with {code}, not 10 (poweroff)"));
    }
    comb_is_empty()?;
    Ok(())
}

fn main() {
    run(
        "daemon",
        &[
            ("two_branches_boot_ready", two_branches_boot_ready),
            (
                "a_crashing_worker_backs_off_then_quarantines",
                a_crashing_worker_backs_off_then_quarantines,
            ),
            (
                "limits_read_back_from_the_cells",
                limits_read_back_from_the_cells,
            ),
            (
                "pipe_exit_and_launch_behave_as_simulated",
                pipe_exit_and_launch_behave_as_simulated,
            ),
            (
                "sigterm_stops_in_reverse_hard_order_and_exits_0",
                sigterm_stops_in_reverse_hard_order_and_exits_0,
            ),
            (
                "a_protocol_shutdown_poweroff_exits_10",
                a_protocol_shutdown_poweroff_exits_10,
            ),
        ],
    );
}
