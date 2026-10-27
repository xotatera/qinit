// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! `Kernel`'s handling of a handed-over main on the host: no cgroup is touched (the comb is
//! only opened), and nothing above the 6.13 floor is used (pidfd polling is Linux 5.3).
use qinit_cell::effects::Effects;
use qinit_cell::kernel::Kernel;
use qinit_cell_drive::{Source, token};
use qinit_event::Ready;
use qinit_sys::proc;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

fn kernel() -> Kernel {
    Kernel::open(&std::env::temp_dir()).unwrap()
}

/// Waits until the loop reports slot 0's main pidfd readable.
fn await_main_exit(k: &mut Kernel) {
    let main = token(0, Source::Main);
    loop {
        let got = k.wait().unwrap();
        if got
            .iter()
            .any(|r| matches!(r, Ready::Readable(t) | Ready::Hangup(t) if *t == main))
        {
            return;
        }
        assert!(got.is_empty(), "unexpected results {got:?}");
    }
}

#[test]
fn a_handed_over_main_that_is_not_a_child_is_watched_without_reaping() {
    // A grandchild: its parent shell exits at once, so it is not this process's child. It
    // runs until its stdin closes.
    let mut sh = Command::new("sh")
        .args(["-c", "cat <&0 >/dev/null & echo $!"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(sh.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let stdin = sh.stdin.take().unwrap();
    assert!(sh.wait().unwrap().success());
    let pid: libc::pid_t = line.trim().parse().unwrap();
    let mut k = kernel();
    k.adopt_main(0, proc::pidfd_open(pid).unwrap()).unwrap();
    drop(stdin);
    await_main_exit(&mut k);
    k.close(0, Source::Main);
    assert!(
        k.take_reaped().is_empty(),
        "not a child: nothing reaped here"
    );
}

#[test]
fn a_handed_over_child_let_go_is_reaped_and_reported() {
    let mut child = Command::new("sh")
        .args(["-c", "read x; exit 3"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id() as libc::pid_t;
    let mut k = kernel();
    k.adopt_main(0, proc::pidfd_open(pid).unwrap()).unwrap();
    drop(child.stdin.take());
    await_main_exit(&mut k);
    k.close(0, Source::Main);
    assert_eq!(k.take_reaped(), [(pid, 3 << 8)]);
    // `child` is never waited for by std: `close` reaped it.
    std::mem::forget(child);
}
