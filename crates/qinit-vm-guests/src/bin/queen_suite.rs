// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Queen as a real PID 1 (spec 2026-11-07 §8, suite `queen`). The guest's init is queen; the
//! driver is its child. Zero is a stand-in that logs its command line and starts queen over, so
//! one guest runs boot after boot. Each case starts on a colony of its own: the one before it is
//! asked to halt, which ends in zero, which starts queen again over the database the case wrote.
use qinit_client::{Mode, Wait};
use qinit_db::Model;
use qinit_vm_guests::colonyd::{model, settled, worker};
use qinit_vm_guests::orphan;
use qinit_vm_guests::queened::{
    COMB, REPAIRED, RESCUE, RESCUE_LOG, ZERO, await_colony_restart, await_kmsg, await_zero_lines,
    clear_comb, client, colony_pid, fresh, kill_colony, kmsg_count, limits, rescue_role,
    signal_queen, spin_until, wait_until, write_db, zero_lines,
};
use qinit_vm_guests::{e, queened};

/// Limits every case but the bound cases runs under: the rescue minimum is short enough to wait
/// out (the 400 ms of a `late` rescue is above it, a `now` one below).
const DEFAULT: (u64, u64, u64) = (300_000, 5_000, 300);

fn basic() -> Model {
    model(vec![worker("w", "ready", &[])], &[0])
}

/// One worker that ignores `TERM` and has `grace_ms` of grace: it holds a shutdown open.
fn holding(grace_ms: u32) -> Model {
    let mut n = worker("w", "ready-ignore-term", &[]);
    n.stop.grace_ms = grace_ms;
    model(vec![n], &[0])
}

fn rescue_lines() -> Vec<String> {
    std::fs::read_to_string(RESCUE_LOG)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn await_rescue_lines(n: usize) -> Result<Vec<String>, String> {
    wait_until("a line of rescue's log", &["/tmp"], || {
        let l = rescue_lines();
        (l.len() >= n).then_some(l)
    })
}

/// Kills colony once its worker is up and its state has reached queen (a request and its reply
/// come after the state of the one before is saved). A colony killed between making a cell and
/// putting its directory in queen's store leaves a cell nobody can adopt, so every kill waits.
fn kill_when_saved(c: &mut qinit_client::Client) -> Result<i32, String> {
    settled(c, "w")?;
    e(c.status("w"))?;
    kill_colony()
}

/// Kills colony until the sixth exit in a minute trips the limit and rescue runs with `role`.
fn trip_limit(role: &str) -> Result<usize, String> {
    rescue_role(role)?;
    let mut c = fresh(&basic())?;
    let before = rescue_lines().len();
    for _ in 0..5 {
        let old = kill_when_saved(&mut c)?;
        c = await_colony_restart(old)?;
    }
    kill_when_saved(&mut c)?;
    await_rescue_lines(before + 1)?;
    Ok(before)
}

/// Waits until queen has logged one more hold, checks no colony runs, and brings colony back
/// with Ctrl-Alt-Del (`SIGINT`).
fn hold_then_back(holds_before: usize) -> Result<(), String> {
    await_kmsg("nothing runs, holding", holds_before + 1)?;
    if colony_pid().is_some() {
        return Err("a colony runs in the hold".into());
    }
    signal_queen(libc::SIGINT)?;
    let _ = client()?;
    Ok(())
}

fn boots_and_serves() -> Result<(), String> {
    let mut c = fresh(&basic())?;
    if settled(&mut c, "w")? != 3 {
        return Err("the worker is not ready".into());
    }
    Ok(())
}

fn an_orphan_is_reaped() -> Result<(), String> {
    let _c = fresh(&basic())?;
    let o = orphan::start()?;
    o.exit()?;
    o.await_reaped()?;
    if std::path::Path::new(&format!("/proc/{}", o.pid)).exists() {
        return Err("the orphan is still in the process table".into());
    }
    Ok(())
}

/// Sixteen orphans let go at once exit within a few milliseconds of each other, and their
/// `SIGCHLD`s coalesce: queen must reap until nothing is left, not once per wake-up.
fn a_burst_of_orphans_is_reaped_whole() -> Result<(), String> {
    let _c = fresh(&basic())?;
    let orphans = (0..16)
        .map(|_| orphan::start())
        .collect::<Result<Vec<_>, _>>()?;
    for o in &orphans {
        o.release()?;
    }
    for o in &orphans {
        o.await_exit()?;
    }
    for o in &orphans {
        o.await_reaped()?;
    }
    Ok(())
}

fn a_killed_colony_is_restarted_and_workers_keep_their_pids() -> Result<(), String> {
    let mut c = fresh(&basic())?;
    settled(&mut c, "w")?;
    let pids = qinit_vm_guests::colonyd::procs_of_in(COMB, "w")?;
    drop(c);
    let old = kill_colony()?;
    let mut c = await_colony_restart(old)?;
    if settled(&mut c, "w")? != 3 {
        return Err("the adopted worker is not ready".into());
    }
    if qinit_vm_guests::colonyd::procs_of_in(COMB, "w")? != pids {
        return Err("the worker's processes changed: it was started again".into());
    }
    Ok(())
}

fn a_crash_loop_trips_the_limit() -> Result<(), String> {
    let holds = kmsg_count("nothing runs, holding")?;
    trip_limit("fail")?;
    if kmsg_count("colony keeps ending")? == 0 {
        return Err("the limit was not logged".into());
    }
    hold_then_back(holds)
}

fn rescue_is_a_session_leader_on_the_console() -> Result<(), String> {
    let holds = kmsg_count("nothing runs, holding")?;
    trip_limit("now")?;
    let line = rescue_lines().pop().ok_or("rescue logged nothing")?;
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() != 3 || f[0] != f[1] || f[2] == "0" {
        return Err(format!("rescue's session, pid, tty: {line:?}"));
    }
    hold_then_back(holds)
}

fn rescue_exiting_zero_late_brings_colony_back() -> Result<(), String> {
    trip_limit("late")?;
    // No hold, no Ctrl-Alt-Del: colony comes back by itself.
    let mut c = client()?;
    settled(&mut c, "w")?;
    Ok(())
}

fn a_clean_rescue_makes_colony_read_the_repaired_database() -> Result<(), String> {
    // The repaired file runs a worker the held copy has not: colony runs it only if it read the
    // file, and queen dropped the copy it held.
    let repaired = model(vec![worker("w2", "ready", &[])], &[0]);
    let bytes = qinit_db::write(&repaired).map_err(|x| format!("write the database: {x:?}"))?;
    e(std::fs::write(REPAIRED, bytes))?;
    trip_limit("repair")?;
    let mut c = client()?;
    settled(&mut c, "w2").map(drop)
}

fn rescue_exiting_non_zero_holds() -> Result<(), String> {
    let holds = kmsg_count("nothing runs, holding")?;
    trip_limit("fail")?;
    hold_then_back(holds)
}

fn rescue_exiting_zero_at_once_holds() -> Result<(), String> {
    let holds = kmsg_count("nothing runs, holding")?;
    trip_limit("now")?;
    hold_then_back(holds)
}

fn a_missing_rescue_holds() -> Result<(), String> {
    let holds = kmsg_count("nothing runs, holding")?;
    let away = format!("{RESCUE}.away");
    e(std::fs::rename(RESCUE, &away))?;
    let r = (|| {
        rescue_role("fail")?;
        let mut c = fresh(&basic())?;
        for _ in 0..5 {
            let old = kill_when_saved(&mut c)?;
            c = await_colony_restart(old)?;
        }
        kill_when_saved(&mut c)?;
        await_kmsg("nothing runs, holding", holds + 1)
    })();
    e(std::fs::rename(&away, RESCUE))?;
    r?;
    hold_then_back(holds)
}

fn a_corrupt_database_goes_straight_to_rescue() -> Result<(), String> {
    let holds = kmsg_count("nothing runs, holding")?;
    let started = kmsg_count("colony started")?;
    rescue_role("fail")?;
    let mut c = fresh(&basic())?;
    let before = zero_lines().len();
    e(std::fs::write(queened::DB, b"not a database"))?;
    e(c.shutdown(Mode::Halt, Wait::Now))?;
    drop(c);
    await_zero_lines(before + 1)?;
    await_kmsg("nothing runs, holding", holds + 1)?;
    // The fresh() above started one colony, the corrupt database a second that ended with 3
    // (768 as a wait status) and was not started again.
    if kmsg_count("colony started")? != started + 2 {
        return Err(format!(
            "colonies started since: {}",
            kmsg_count("colony started")? - started
        ));
    }
    if kmsg_count("colony ended, status   768")? == 0 {
        return Err("exit 3 was not seen".into());
    }
    write_db(&basic())?;
    signal_queen(libc::SIGINT)?;
    let _ = client()?;
    Ok(())
}

fn qctl_reboot_poweroff_and_halt_reach_zero() -> Result<(), String> {
    for (mode, word) in [
        (Mode::Reboot, "final reboot"),
        (Mode::Poweroff, "final poweroff"),
        (Mode::Halt, "final halt"),
    ] {
        let mut c = fresh(&basic())?;
        let before = zero_lines().len();
        e(c.shutdown(mode, Wait::Now))?;
        drop(c);
        let lines = await_zero_lines(before + 1)?;
        if lines.last().map(String::as_str) != Some(word) {
            return Err(format!("zero was run as {:?}, want {word:?}", lines.last()));
        }
        let _ = client()?;
    }
    Ok(())
}

fn a_reboot_during_a_poweroff_reaches_zero_as_reboot() -> Result<(), String> {
    reboot_during_poweroff().map_err(|why| {
        let queen: Vec<String> = queened::kmsg()
            .unwrap_or_default()
            .into_iter()
            .filter(|l| l.starts_with("queen:"))
            .collect();
        let from = queen.len().saturating_sub(14);
        format!(
            "{why}; colony said {:?}; queen said {:?}",
            queened::log_tail(6),
            &queen[from..]
        )
    })
}

fn reboot_during_poweroff() -> Result<(), String> {
    let mut c = fresh(&holding(2_000))?;
    let state = settled(&mut c, "w")?;
    let before = zero_lines().len();
    let t0 = std::time::Instant::now();
    e(c.shutdown(Mode::Poweroff, Wait::Now)).map_err(|x| format!("the poweroff request: {x}"))?;
    let t1 = t0.elapsed();
    // The second request comes on a connection of its own, as a second `qctl` would.
    let mut second = client()?;
    let t2 = t0.elapsed();
    e(second.shutdown(Mode::Reboot, Wait::Now)).map_err(|x| {
        format!("the reboot request: {x} (w was in state {state}; first request {t1:?}, connected {t2:?}, colony runs: {:?})", colony_pid())
    })?;
    drop(c);
    let lines = await_zero_lines(before + 1)?;
    if lines.last().map(String::as_str) != Some("final reboot") {
        return Err(format!(
            "zero was run as {:?} (w was in state {state}; first request {t1:?}, connected {t2:?}, now {:?}); comb {:?}; colony said {:?}",
            lines.last(),
            t0.elapsed(),
            std::fs::read_dir(COMB)
                .map(|d| d
                    .flatten()
                    .map(|x| x.file_name().to_string_lossy().into_owned())
                    .collect::<Vec<_>>())
                .unwrap_or_default(),
            queened::log_tail(14)
        ));
    }
    let _ = client()?;
    Ok(())
}

fn cad_state() -> Result<String, String> {
    Ok(e(std::fs::read_to_string("/proc/sys/kernel/ctrl-alt-del"))?
        .trim()
        .to_owned())
}

fn sigint_to_pid_1_reboots_in_order_and_turns_cad_on() -> Result<(), String> {
    let mut c = fresh(&holding(2_000))?;
    settled(&mut c, "w")?;
    drop(c);
    if cad_state()? != "0" {
        return Err("Ctrl-Alt-Del reboots before any shutdown".into());
    }
    let before = zero_lines().len();
    signal_queen(libc::SIGINT)?;
    // The shutdown is held open by the worker: Ctrl-Alt-Del is on while it runs.
    spin_until("Ctrl-Alt-Del switched on", || {
        (cad_state().ok()? == "1").then_some(())
    })?;
    let lines = await_zero_lines(before + 1)?;
    if lines.last().map(String::as_str) != Some("final reboot") {
        return Err(format!("zero was run as {:?}", lines.last()));
    }
    let _ = client()?;
    if cad_state()? != "0" {
        return Err("queen did not switch it off again at its start".into());
    }
    Ok(())
}

fn sigpwr_powers_off() -> Result<(), String> {
    let _c = fresh(&basic())?;
    let before = zero_lines().len();
    signal_queen(libc::SIGPWR)?;
    let lines = await_zero_lines(before + 1)?;
    if lines.last().map(String::as_str) != Some("final poweroff") {
        return Err(format!("zero was run as {:?}", lines.last()));
    }
    let _ = client()?;
    Ok(())
}

fn sigterm_is_ignored_and_logged() -> Result<(), String> {
    let _c = fresh(&basic())?;
    let said = kmsg_count("signal 15 ignored")?;
    let pid = colony_pid();
    signal_queen(libc::SIGTERM)?;
    await_kmsg("signal 15 ignored", said + 1)?;
    if colony_pid() != pid || pid.is_none() {
        return Err("colony changed: SIGTERM did something".into());
    }
    Ok(())
}

fn a_real_time_signal_is_ignored_and_logged() -> Result<(), String> {
    let _c = fresh(&basic())?;
    let sig = libc::SIGRTMIN() + 6;
    let line = format!("signal {sig} ignored");
    let said = kmsg_count(&line)?;
    let pid = colony_pid();
    signal_queen(sig)?;
    await_kmsg(&line, said + 1)?;
    if colony_pid() != pid || pid.is_none() {
        return Err("colony changed: a real-time signal did something".into());
    }
    Ok(())
}

fn a_colony_killed_during_a_shutdown_is_not_restarted() -> Result<(), String> {
    killed_during_a_shutdown()
        .map_err(|why| format!("{why}; colony said {:?}", queened::log_tail(15)))
}

fn killed_during_a_shutdown() -> Result<(), String> {
    let mut c = fresh(&holding(60_000))?;
    settled(&mut c, "w")?;
    let before = zero_lines().len();
    let handed = kmsg_count("handing over to zero")?;
    e(c.shutdown(Mode::Halt, Wait::Now))?;
    drop(c);
    kill_colony()?;
    await_zero_lines(before + 1)?;
    if kmsg_count("handing over to zero")? <= handed {
        return Err("queen did not hand over".into());
    }
    clear_comb();
    let _ = client()?;
    Ok(())
}

fn a_colony_that_never_finishes_is_killed_at_the_bound() -> Result<(), String> {
    limits(500, 500, DEFAULT.2)?;
    let r = (|| {
        let mut c = fresh(&holding(60_000))?;
        settled(&mut c, "w")?;
        let before = zero_lines().len();
        e(c.shutdown(Mode::Halt, Wait::Now))?;
        drop(c);
        await_zero_lines(before + 1)?;
        Ok::<(), String>(())
    })();
    clear_comb();
    limits(DEFAULT.0, DEFAULT.1, DEFAULT.2)?;
    r?;
    let _ = fresh(&basic())?;
    Ok(())
}

fn a_missing_zero_runs_rescue_then_holds() -> Result<(), String> {
    rescue_role("fail")?;
    let mut c = fresh(&basic())?;
    let holds = kmsg_count("nothing runs, holding")?;
    let failed = kmsg_count("zero did not start")?;
    let rescued = rescue_lines().len();
    let away = format!("{ZERO}.away");
    e(std::fs::rename(ZERO, &away))?;
    let r = (|| {
        e(c.shutdown(Mode::Halt, Wait::Now))?;
        await_kmsg("zero did not start", failed + 1)?;
        await_rescue_lines(rescued + 1)?;
        await_kmsg("nothing runs, holding", holds + 1)
    })();
    e(std::fs::rename(&away, ZERO))?;
    r?;
    // Put back, Pwr ends the hold: zero is run as poweroff and queen starts over.
    let before = zero_lines().len();
    signal_queen(libc::SIGPWR)?;
    await_zero_lines(before + 1)?;
    let _ = client()?;
    Ok(())
}

fn main() {
    queened::boot(
        &[
            ("boots_and_serves", boots_and_serves),
            ("an_orphan_is_reaped", an_orphan_is_reaped),
            (
                "a_burst_of_orphans_is_reaped_whole",
                a_burst_of_orphans_is_reaped_whole,
            ),
            (
                "a_killed_colony_is_restarted_and_workers_keep_their_pids",
                a_killed_colony_is_restarted_and_workers_keep_their_pids,
            ),
            ("a_crash_loop_trips_the_limit", a_crash_loop_trips_the_limit),
            (
                "rescue_is_a_session_leader_on_the_console",
                rescue_is_a_session_leader_on_the_console,
            ),
            (
                "rescue_exiting_zero_late_brings_colony_back",
                rescue_exiting_zero_late_brings_colony_back,
            ),
            (
                "a_clean_rescue_makes_colony_read_the_repaired_database",
                a_clean_rescue_makes_colony_read_the_repaired_database,
            ),
            (
                "rescue_exiting_non_zero_holds",
                rescue_exiting_non_zero_holds,
            ),
            (
                "rescue_exiting_zero_at_once_holds",
                rescue_exiting_zero_at_once_holds,
            ),
            ("a_missing_rescue_holds", a_missing_rescue_holds),
            (
                "a_corrupt_database_goes_straight_to_rescue",
                a_corrupt_database_goes_straight_to_rescue,
            ),
            (
                "qctl_reboot_poweroff_and_halt_reach_zero",
                qctl_reboot_poweroff_and_halt_reach_zero,
            ),
            (
                "a_reboot_during_a_poweroff_reaches_zero_as_reboot",
                a_reboot_during_a_poweroff_reaches_zero_as_reboot,
            ),
            (
                "sigint_to_pid_1_reboots_in_order_and_turns_cad_on",
                sigint_to_pid_1_reboots_in_order_and_turns_cad_on,
            ),
            ("sigpwr_powers_off", sigpwr_powers_off),
            (
                "sigterm_is_ignored_and_logged",
                sigterm_is_ignored_and_logged,
            ),
            (
                "a_real_time_signal_is_ignored_and_logged",
                a_real_time_signal_is_ignored_and_logged,
            ),
            (
                "a_colony_killed_during_a_shutdown_is_not_restarted",
                a_colony_killed_during_a_shutdown_is_not_restarted,
            ),
            (
                "a_colony_that_never_finishes_is_killed_at_the_bound",
                a_colony_that_never_finishes_is_killed_at_the_bound,
            ),
            (
                "a_missing_zero_runs_rescue_then_holds",
                a_missing_zero_runs_rescue_then_holds,
            ),
        ],
        "queen",
        &basic(),
    )
}
