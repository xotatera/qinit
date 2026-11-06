// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Colony's own messages: the syslog socket, a full queue, and the console fallback.
use qinit_colonyd::syslog::{Sev, Syslog, line};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;

/// A temporary directory removed when it goes out of scope.
struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Tmp {
        let d = std::env::temp_dir().join(format!("qinit-syslog-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Tmp(d)
    }

    fn at(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// An empty file standing in for a device node, which the writer opens but never creates.
    fn device(&self, name: &str) -> PathBuf {
        let p = self.at(name);
        std::fs::write(&p, b"").unwrap();
        p
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn lines(path: &PathBuf) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn syslog_line_format() {
    assert_eq!(
        line(42, Sev::Info, "db: ready"),
        "<30>colony[42]: db: ready"
    );
    assert_eq!(line(42, Sev::Err, "boom"), "<27>colony[42]: boom");
    assert_eq!(line(1, Sev::Debug, "orphan 9"), "<31>colony[1]: orphan 9");
}

#[test]
fn a_message_reaches_the_syslog_socket() {
    let t = Tmp::new("ok");
    let rx = UnixDatagram::bind(t.at("log")).unwrap();
    let mut log = Syslog::new(&t.at("log"), &t.at("console"), &t.at("kmsg"));
    log.log(Sev::Info, "db: ready");
    let mut buf = [0u8; 256];
    let n = rx.recv(&mut buf).unwrap();
    let want = format!("<30>colony[{}]: db: ready", std::process::id());
    assert_eq!(&buf[..n], want.as_bytes());
    assert!(lines(&t.at("console")).is_empty(), "nothing on the console");
    assert!(lines(&t.at("kmsg")).is_empty(), "and no marker");
}

#[test]
fn a_full_socket_drops_and_counts() {
    let t = Tmp::new("full");
    let rx = UnixDatagram::bind(t.at("log")).unwrap();
    // Fill the receiver's queue from another socket until it would block.
    let filler = UnixDatagram::unbound().unwrap();
    filler.connect(t.at("log")).unwrap();
    filler.set_nonblocking(true).unwrap();
    while filler.send(b"x").is_ok() {}
    let mut log = Syslog::new(&t.at("log"), &t.at("console"), &t.at("kmsg"));
    log.log(Sev::Info, "lost one");
    log.log(Sev::Info, "lost two");
    assert!(
        lines(&t.at("console")).is_empty(),
        "a full queue is not a failure"
    );
    assert!(lines(&t.at("kmsg")).is_empty());
    // Make room for exactly one message.
    let mut buf = [0u8; 256];
    rx.recv(&mut buf).unwrap();
    log.log(Sev::Info, "db: ready");
    let mut last = Vec::new();
    rx.set_nonblocking(true).unwrap();
    while let Ok(n) = rx.recv(&mut buf) {
        last = buf[..n].to_vec();
    }
    let text = String::from_utf8(last).unwrap();
    assert!(text.ends_with("db: ready (dropped 2 lines)"), "{text}");
}

#[test]
fn a_missing_socket_falls_back_to_the_console_and_marks_kmsg_once() {
    let t = Tmp::new("missing");
    t.device("console");
    t.device("kmsg");
    let mut log = Syslog::new(&t.at("log"), &t.at("console"), &t.at("kmsg"));
    log.log(Sev::Info, "first");
    log.log(Sev::Err, "second");
    let console = lines(&t.at("console"));
    assert_eq!(console.len(), 2, "{console:?}");
    assert!(console[0].contains("]: first"), "{console:?}");
    assert!(console[1].starts_with("<27>colony["), "{console:?}");
    let kmsg = lines(&t.at("kmsg"));
    assert_eq!(kmsg.len(), 1, "one marker on the way down: {kmsg:?}");
    assert!(kmsg[0].contains("syslog unavailable"), "{kmsg:?}");
    assert!(
        kmsg[0].contains(t.at("console").to_str().unwrap()),
        "{kmsg:?}"
    );
    // The socket appears: the next message goes to it, and kmsg hears the return.
    let rx = UnixDatagram::bind(t.at("log")).unwrap();
    log.log(Sev::Info, "third");
    let mut buf = [0u8; 256];
    let n = rx.recv(&mut buf).unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).contains("]: third"));
    assert_eq!(
        lines(&t.at("console")).len(),
        2,
        "the console is quiet again"
    );
    let kmsg = lines(&t.at("kmsg"));
    assert_eq!(kmsg.len(), 2, "{kmsg:?}");
    assert!(kmsg[1].contains("syslog back"), "{kmsg:?}");
}

#[test]
fn a_console_nobody_reads_does_not_stop_the_daemon() {
    let t = Tmp::new("stuck");
    // A FIFO with no reader blocks a plain `open` for writing for ever, like a console whose
    // line is held by flow control.
    let console = t.at("console");
    let c = std::ffi::CString::new(console.to_str().unwrap()).unwrap();
    qinit_sys::fd::mkfifo(&c, 0o600).unwrap();
    let kmsg = t.at("kmsg");
    let (log, socket) = (t.at("nolog"), t.at("nolog"));
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut s = Syslog::new(&socket, &console, &kmsg);
        s.log(Sev::Err, "nobody is listening");
        let _ = tx.send(());
    });
    assert!(
        rx.recv_timeout(std::time::Duration::from_secs(3)).is_ok(),
        "logging waited on a console that cannot be written (socket {log:?})"
    );
}
