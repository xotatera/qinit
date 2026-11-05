// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Path and socket readiness on a real kernel (spec 2026-11-06 §6, §11 suite `readiness`): a path
//! edge satisfied by a file made later, `ready = { path }` and `ready = { socket }` with stale
//! files and sockets present at the start, and a start timeout when nothing appears. The workers
//! are the guest's helpers; the waits are colony's own timers and the client's parked replies.
use qinit_db::{Edge, Group, GroupKind, Mode, Node, Ready, RestartOn, Target};
use qinit_vm_guests::colonyd::{await_state, comb_is_empty, info, model, settled, up, worker};
use qinit_vm_guests::{e, run};
use std::os::unix::net::UnixListener;
use std::path::Path;

/// A worker ready when `path` (or a socket there) appears, running `role`.
fn waiter(name: &str, ready: Ready, role: &str, args: &[&str]) -> Node {
    Node {
        ready,
        start_timeout_ms: 1500,
        ..worker(name, role, args)
    }
}

fn path_edge(path: &str) -> Group {
    Group {
        kind: GroupKind::RequireAll,
        edges: vec![Edge {
            target: Target::Path(path.to_owned()),
            mode: Mode::Sync,
            deadline_ms: 0,
            restart_on: RestartOn::Error,
            stop_parallel: false,
            cascade: false,
        }],
    }
}

fn finish(mut s: qinit_vm_guests::colonyd::Site) -> Result<(), String> {
    let code = s.terminate()?;
    if code != 0 {
        return Err(format!("colony exited with {code}"));
    }
    comb_is_empty()
}

fn a_path_edge_waits_for_the_file() -> Result<(), String> {
    let dir = "/tmp/rd-edge";
    let _ = std::fs::remove_dir_all(dir);
    let file = format!("{dir}/deep/flag");
    let mut web = worker("web", "ready", &[]);
    web.groups.push(path_edge(&file));
    let (s, mut c) = up("readiness-edge", &model(vec![web], &[0]))?;
    let waiting = info(&mut c, "web")?.state;
    if waiting.state != 1 {
        return Err(format!("web should wait for the file, but is {waiting:?}"));
    }
    // The directories come first, then the file: the watch walks down as they appear.
    e(std::fs::create_dir_all(format!("{dir}/deep")))?;
    let still = info(&mut c, "web")?.state.state;
    if still != 1 {
        return Err(format!(
            "the directories alone are not the file (state {still})"
        ));
    }
    e(std::fs::write(&file, b"x"))?;
    let state = settled(&mut c, "web")?;
    if state != 3 {
        return Err(format!("web is in state {state} after the file appeared"));
    }
    drop(c);
    let _ = std::fs::remove_dir_all(dir);
    finish(s)
}

fn a_stale_ready_file_does_not_count() -> Result<(), String> {
    let dir = "/tmp/rd-stale";
    let _ = std::fs::remove_dir_all(dir);
    e(std::fs::create_dir_all(dir))?;
    let (never, again) = (format!("{dir}/never.pid"), format!("{dir}/again.pid"));
    e(std::fs::write(&never, b"old"))?;
    e(std::fs::write(&again, b"old"))?;
    // `never` leaves its stale file alone; `again` removes it and makes it anew.
    let nodes = vec![
        waiter("again", Ready::Path(again.clone()), "recreate", &[&again]),
        waiter("never", Ready::Path(never.clone()), "wait-term", &[]),
    ];
    let (mut s, mut c) = up("readiness-stale", &model(nodes, &[0, 1]))?;
    let state = settled(&mut c, "again")?;
    if state != 3 {
        return Err(format!(
            "the recreated file did not make `again` ready (state {state})"
        ));
    }
    // The stale file never marks `never` ready: it ends on its start timeout.
    let seen = await_state(&mut s, "never", 6)?;
    if seen.detail != 2 {
        return Err(format!(
            "never was quarantined for reason {}, not the start timeout",
            seen.detail
        ));
    }
    if seen
        .reports
        .iter()
        .any(|r| matches!(r, qinit_client::Report::Ready))
    {
        return Err(format!("never was reported ready: {:?}", seen.reports));
    }
    drop(c);
    let _ = std::fs::remove_dir_all(dir);
    finish(s)
}

fn a_stale_socket_does_not_count_and_a_fresh_bind_does() -> Result<(), String> {
    let dir = "/tmp/rd-sock";
    let _ = std::fs::remove_dir_all(dir);
    e(std::fs::create_dir_all(dir))?;
    let (stale, fresh, plain) = (
        format!("{dir}/stale.sock"),
        format!("{dir}/fresh.sock"),
        format!("{dir}/plain.sock"),
    );
    // Two stale sockets (bound, then closed: the files stay), and a regular file where a third
    // service will put one.
    for p in [&stale, &fresh] {
        drop(e(UnixListener::bind(Path::new(p)))?);
    }
    let nodes = vec![
        waiter(
            "fresh",
            Ready::Socket(fresh.clone()),
            "bind-socket",
            &[&fresh],
        ),
        waiter("plain", Ready::Socket(plain.clone()), "recreate", &[&plain]),
        waiter("stale", Ready::Socket(stale.clone()), "wait-term", &[]),
    ];
    let (mut s, mut c) = up("readiness-socket", &model(nodes, &[0, 1, 2]))?;
    let reached = settled(&mut c, "fresh")?;
    if reached != 3 {
        return Err(format!(
            "a fresh bind did not make `fresh` ready (state {reached})"
        ));
    }
    for (name, why) in [("stale", "a stale socket"), ("plain", "a regular file")] {
        let seen = await_state(&mut s, name, 6)?;
        if seen.detail != 2 {
            return Err(format!(
                "{name} ({why}) was quarantined for reason {}",
                seen.detail
            ));
        }
        if seen
            .reports
            .iter()
            .any(|r| matches!(r, qinit_client::Report::Ready))
        {
            return Err(format!(
                "{name} ({why}) was reported ready: {:?}",
                seen.reports
            ));
        }
    }
    drop(c);
    let _ = std::fs::remove_dir_all(dir);
    finish(s)
}

fn a_path_that_never_appears_times_out() -> Result<(), String> {
    let node = waiter(
        "lost",
        Ready::Path("/tmp/rd-never/missing/x.pid".to_owned()),
        "wait-term",
        &[],
    );
    let (mut s, c) = up("readiness-never", &model(vec![node], &[0]))?;
    drop(c);
    let seen = await_state(&mut s, "lost", 6)?;
    if seen.detail != 2 {
        return Err(format!(
            "quarantined for reason {}, not the start timeout",
            seen.detail
        ));
    }
    // The timed-out node is stopped: its cell is gone.
    let said = s.lines();
    if !said
        .iter()
        .any(|l| l.contains("lost: quarantined (start timeout)"))
    {
        return Err(format!("the timeout is not in the log: {said:?}"));
    }
    finish(s)
}

fn main() {
    run(
        "readiness",
        &[
            (
                "a_path_edge_waits_for_the_file",
                a_path_edge_waits_for_the_file,
            ),
            (
                "a_stale_ready_file_does_not_count",
                a_stale_ready_file_does_not_count,
            ),
            (
                "a_stale_socket_does_not_count_and_a_fresh_bind_does",
                a_stale_socket_does_not_count_and_a_fresh_bind_does,
            ),
            (
                "a_path_that_never_appears_times_out",
                a_path_that_never_appears_times_out,
            ),
        ],
    );
}
