// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Colony's own messages on a real kernel (spec 2026-11-06 §10, §11 suite `syslog`): lines reach
//! a datagram socket; with the socket gone they go to the console path and the kernel log has a
//! marker; a full socket drops lines and reports how many.
use qinit_client::Action;
use qinit_client::Wait;
use qinit_vm_guests::colonyd::{comb_is_empty, kmsg, model, settled, site, up, worker};
use qinit_vm_guests::{HANG_GUARD, e, run};

fn lines_reach_the_socket() -> Result<(), String> {
    let (mut s, mut c) = up(
        "syslog-lines",
        &model(vec![worker("db", "ready", &[])], &[0]),
    )?;
    settled(&mut c, "db")?;
    let said = s.await_log(|l| l.iter().any(|x| x.ends_with("db: ready")))?;
    let pid = s.colony_pid()?;
    let want = format!("<30>colony[{pid}]: db: ready");
    if !said.contains(&want) {
        return Err(format!("expected {want:?} among {said:?}"));
    }
    drop(c);
    let code = s.terminate()?;
    if code != 0 {
        return Err(format!("colony exited with {code}"));
    }
    comb_is_empty()
}

fn a_missing_socket_falls_back_to_the_console_with_a_kmsg_marker() -> Result<(), String> {
    let mut s = site("syslog-missing")?;
    s.write_db(&model(vec![worker("db", "ready", &[])], &[0]))?;
    s.drop_syslog();
    s.start()?;
    let mut c = s.client()?;
    settled(&mut c, "db")?;
    let console = e(std::fs::read_to_string(&s.console))?;
    if !console
        .lines()
        .any(|l| l.starts_with("<30>colony[") && l.ends_with("db: ready"))
    {
        return Err(format!("the console has {console:?}"));
    }
    let marker = format!(
        "colony: syslog unavailable, writing to {}",
        s.console.display()
    );
    let kernel = kmsg()?;
    if kernel.iter().filter(|l| **l == marker).count() != 1 {
        return Err(format!(
            "expected one marker {marker:?} in the kernel log, got {:?}",
            kernel.iter().rev().take(8).collect::<Vec<_>>()
        ));
    }
    // The socket comes back: the next message goes to it, and the kernel log hears of the return.
    s.restore_syslog()?;
    e(c.change("db", Action::Stop, Wait::Settled(HANG_GUARD)))?;
    let said = s.await_log(|l| l.iter().any(|x| x.ends_with("db: stopped")))?;
    if !said
        .iter()
        .any(|l| l.starts_with("<30>colony[") && l.ends_with("db: stopped"))
    {
        return Err(format!("the socket got {said:?}"));
    }
    if !kmsg()?.iter().any(|l| l == "colony: syslog back") {
        return Err("the kernel log has no marker for the return".into());
    }
    drop(c);
    let code = s.terminate()?;
    if code != 0 {
        return Err(format!("colony exited with {code}"));
    }
    comb_is_empty()
}

fn a_full_socket_drops_and_reports_a_count() -> Result<(), String> {
    let mut s = site("syslog-full")?;
    s.write_db(&model(vec![worker("db", "ready", &[])], &[0]))?;
    // The receiver does not read: its queue is full before colony says a word.
    let fitted = s.fill_syslog()?;
    if fitted == 0 {
        return Err("nothing fitted in the socket".into());
    }
    s.start()?;
    let mut c = s.client()?;
    settled(&mut c, "db")?;
    // Colony has said at least three things (started, starting, ready) and all were dropped.
    // Make room for exactly one datagram, then give colony something to say.
    s.take_one()?;
    e(c.change("db", Action::Stop, Wait::Settled(HANG_GUARD)))?;
    let said = s.await_log(|l| l.iter().any(|x| x.contains("(dropped ")))?;
    let line = said
        .iter()
        .find(|x| x.contains("(dropped "))
        .ok_or("no line carries a count")?;
    let count: u32 = line
        .rsplit_once("(dropped ")
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| format!("no count in {line:?}"))?;
    if count < 3 {
        return Err(format!(
            "the count is {count}, colony had said at least 3 things: {line:?}"
        ));
    }
    if !line.starts_with("<30>colony[") {
        return Err(format!("not a syslog line: {line:?}"));
    }
    // A full socket is not a failure: the console stays untouched and the kernel log quiet.
    if !e(std::fs::read_to_string(&s.console))?.is_empty() {
        return Err("a full socket sent lines to the console".into());
    }
    drop(c);
    let code = s.terminate()?;
    if code != 0 {
        return Err(format!("colony exited with {code}"));
    }
    comb_is_empty()
}

fn main() {
    run(
        "syslog",
        &[
            ("lines_reach_the_socket", lines_reach_the_socket),
            (
                "a_missing_socket_falls_back_to_the_console_with_a_kmsg_marker",
                a_missing_socket_falls_back_to_the_console_with_a_kmsg_marker,
            ),
            (
                "a_full_socket_drops_and_reports_a_count",
                a_full_socket_drops_and_reports_a_count,
            ),
        ],
    );
}
