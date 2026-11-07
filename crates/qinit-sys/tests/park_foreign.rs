// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! A fault signal another process sends does not park (`kill -SEGV 1` must not stop PID 1). This
//! test has no harness: its process has one thread, so a park stops all of it, and the answer the
//! child gives after the signal proves it did not park. The binary runs itself as the child.
use qinit_sys::{proc, signal};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsFd;
use std::process::{Command, Stdio};

fn child() {
    let out = std::io::stdout();
    signal::set_park_fd(out.as_fd());
    signal::install_fault_park().unwrap();
    let _ = qinit_sys::fd::write_all(out.as_fd(), b"ready\n");
    let mut stdin = std::io::stdin();
    let mut byte = [0u8; 1];
    while let Ok(n) = stdin.read(&mut byte) {
        if n == 0 {
            break;
        }
        let _ = qinit_sys::fd::write_all(out.as_fd(), b"alive\n");
    }
}

fn parent() {
    for sig in signal::FATAL {
        let mut c = Command::new(std::env::current_exe().unwrap())
            .env("QINIT_SYS_ROLE", "foreign")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = i32::try_from(c.id()).unwrap();
        let mut out = BufReader::new(c.stdout.take().unwrap());
        let mut line = String::new();
        out.read_line(&mut line).unwrap();
        assert!(line.starts_with("ready"), "{line:?}");
        proc::kill(pid, sig).unwrap();
        let mut stdin = c.stdin.take().unwrap();
        stdin.write_all(b"x").unwrap();
        line.clear();
        let n = out.read_line(&mut line).unwrap();
        assert!(n > 0 && line.starts_with("alive"), "signal {sig}: {line:?}");
        drop(stdin);
        assert!(c.wait().unwrap().success(), "signal {sig}");
    }
    println!("test a_fault_signal_from_another_process_does_not_park ... ok");
}

fn main() {
    if std::env::var_os("QINIT_SYS_ROLE").is_some() {
        child();
    } else {
        parent();
    }
}
