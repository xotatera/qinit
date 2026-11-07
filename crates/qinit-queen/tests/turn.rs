// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Queen's turn against a fake system: scripted receive and reap queues.
use qinit_queen::run::{Io, Message, Queen, Recv, Sent, Wake};
use qinit_queen_core::machine::{LIMITS, Phase};
use qinit_queen_core::{FromColony, Mode, ToColony, decode_to_colony, encode_from_colony};
use qinit_sys::Errno;
use std::collections::VecDeque;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};

#[derive(Debug, PartialEq)]
enum Ev {
    Recv,
    Reap,
    SpawnColony,
    SpawnRescue,
    Kill(i32),
    Arm(Option<u64>),
    CadOn,
    ExecZero(Mode),
    Log(String),
    Send(Option<ToColony>, bool),
}

#[derive(Default)]
struct Fake {
    events: Vec<Ev>,
    recv_q: VecDeque<Recv>,
    reap_q: VecDeque<(i32, i32)>,
    /// What each send answers, in order; `Ok` once the queue is empty.
    send_q: VecDeque<Sent>,
    next_pid: i32,
    writable: Vec<bool>,
    spawn_fails: bool,
}

impl Io for Fake {
    fn now_ms(&mut self) -> u64 {
        1_000
    }
    fn spawn_colony(&mut self) -> Result<i32, Errno> {
        self.events.push(Ev::SpawnColony);
        if self.spawn_fails {
            return Err(Errno(libc::EAGAIN));
        }
        self.next_pid += 1;
        Ok(100 + self.next_pid)
    }
    fn spawn_rescue(&mut self) -> Result<i32, Errno> {
        self.events.push(Ev::SpawnRescue);
        self.next_pid += 1;
        Ok(200 + self.next_pid)
    }
    fn exec_zero(&mut self, mode: Mode) -> Errno {
        self.events.push(Ev::ExecZero(mode));
        Errno(libc::ENOENT)
    }
    fn kill(&mut self, pid: i32) {
        self.events.push(Ev::Kill(pid));
    }
    fn cad_on(&mut self) {
        self.events.push(Ev::CadOn);
    }
    fn arm(&mut self, ms: Option<u64>) {
        self.events.push(Ev::Arm(ms));
    }
    fn log(&mut self, line: &[u8]) {
        self.events
            .push(Ev::Log(String::from_utf8_lossy(line).into_owned()));
    }
    fn reap(&mut self) -> Option<(i32, i32)> {
        self.events.push(Ev::Reap);
        self.reap_q.pop_front()
    }
    fn recv(&mut self) -> Recv {
        self.events.push(Ev::Recv);
        self.recv_q.pop_front().unwrap_or(Recv::Empty)
    }
    fn send(&mut self, record: &[u8; 16], fd: Option<BorrowedFd<'_>>) -> Sent {
        let r = self.send_q.pop_front().unwrap_or(Sent::Ok);
        let rec = decode_to_colony(record, usize::from(fd.is_some()));
        self.events.push(Ev::Send(rec, r == Sent::Ok));
        r
    }
    fn want_writable(&mut self, on: bool) {
        self.writable.push(on);
    }
}

fn devnull() -> OwnedFd {
    std::fs::File::open("/dev/null").unwrap().into()
}

fn put_message(key: u64, fd: OwnedFd) -> Recv {
    let rec = encode_from_colony(FromColony::Put { key });
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&rec);
    Recv::Message(Message {
        bytes,
        len: 16,
        fds: vec![fd],
        truncated: false,
    })
}

fn plain_message(r: FromColony) -> Recv {
    let rec = encode_from_colony(r);
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&rec);
    Recv::Message(Message {
        bytes,
        len: 16,
        fds: Vec::new(),
        truncated: false,
    })
}

fn wake(signals: &[u32]) -> Wake<'_> {
    Wake {
        signals,
        channel: false,
        timer: false,
        writable: false,
    }
}

fn queen() -> Queen<Fake> {
    let q = Queen::new(Fake::default(), LIMITS);
    assert_eq!(q.state().colony, 101);
    q
}

fn index_of(events: &[Ev], e: &Ev) -> usize {
    events
        .iter()
        .position(|x| x == e)
        .unwrap_or_else(|| panic!("{e:?} in {events:?}"))
}

const CHLD: u32 = libc::SIGCHLD as u32;

#[test]
fn records_queued_before_a_death_are_read_first() {
    let mut q = queen();
    q.io().recv_q.push_back(put_message(16, devnull()));
    q.io().reap_q.push_back((101, 9));
    q.io().events.clear();
    q.turn(&wake(&[CHLD]));
    assert!(
        q.table().iter().any(|e| e.key == 16),
        "the Put reached the store"
    );
    let ev = &q.io().events;
    assert!(
        index_of(ev, &Ev::Recv) < index_of(ev, &Ev::Reap),
        "the channel is read before the reap: {ev:?}"
    );
    assert!(
        index_of(ev, &Ev::Reap) < index_of(ev, &Ev::SpawnColony),
        "{ev:?}"
    );
    assert_eq!(q.state().colony, 102, "colony restarted");
}

#[test]
fn sigchld_coalesced_reaps_everything() {
    let mut q = queen();
    for pid in [900, 901, 902] {
        q.io().reap_q.push_back((pid, 0));
    }
    q.turn(&wake(&[CHLD]));
    assert!(q.io().reap_q.is_empty());
    let reaps = q
        .io()
        .events
        .iter()
        .filter(|e| matches!(e, Ev::Reap))
        .count();
    assert_eq!(reaps, 4, "three pids and the empty answer");
}

#[test]
fn an_orphan_sets_the_reaped_wake_and_logs_one_line() {
    let mut q = queen();
    // Hand-over done: only HeldEnd is owed, and it is sent.
    q.turn(&wake(&[]));
    q.io().events.clear();
    for pid in [900, 901] {
        q.io().reap_q.push_back((pid, 0));
    }
    q.turn(&wake(&[CHLD]));
    let ev = &q.io().events;
    let lines: Vec<&String> = ev
        .iter()
        .filter_map(|e| if let Ev::Log(l) = e { Some(l) } else { None })
        .collect();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].contains("reaped") && lines[0].contains("901"),
        "{lines:?}"
    );
    assert!(
        ev.contains(&Ev::Send(Some(ToColony::Reaped), true)),
        "{ev:?}"
    );
}

#[test]
fn a_blocked_socket_resumes_on_writable() {
    let mut q = queen();
    q.turn(&wake(&[]));
    q.io().events.clear();
    q.io().recv_q.push_back(put_message(16, devnull()));
    q.io().recv_q.push_back(put_message(17, devnull()));
    q.turn(&wake(&[]));
    // Now a restart: two entries and HeldEnd are owed to the new colony.
    q.io().reap_q.push_back((101, 9));
    q.io().send_q.push_back(Sent::Ok);
    q.io().send_q.push_back(Sent::Again);
    q.io().events.clear();
    q.turn(&wake(&[CHLD]));
    let sent = q
        .io()
        .events
        .iter()
        .filter(|e| matches!(e, Ev::Send(..)))
        .count();
    assert_eq!(sent, 2, "one went, one met a full socket");
    assert_eq!(q.io().writable.last(), Some(&true));
    q.io().events.clear();
    q.turn(&Wake {
        signals: &[],
        channel: true,
        timer: false,
        writable: true,
    });
    let sent: Vec<_> = q
        .io()
        .events
        .iter()
        .filter_map(|e| {
            if let Ev::Send(r, true) = e {
                Some(*r)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        sent.len(),
        2,
        "the refused record again, then HeldEnd: {sent:?}"
    );
    assert_eq!(sent[1], Some(ToColony::HeldEnd { count: 2 }));
    assert_eq!(
        q.io().writable.last(),
        Some(&false),
        "nothing left to wait for"
    );
}

#[test]
fn sigterm_is_logged_and_ignored() {
    let mut q = queen();
    q.io().events.clear();
    q.turn(&wake(&[libc::SIGTERM as u32]));
    q.turn(&wake(&[libc::SIGTERM as u32]));
    let ev = &q.io().events;
    let lines: Vec<&Ev> = ev.iter().filter(|e| matches!(e, Ev::Log(_))).collect();
    assert_eq!(lines.len(), 1, "once a minute: {ev:?}");
    assert!(
        !ev.iter()
            .any(|e| matches!(e, Ev::SpawnColony | Ev::Kill(_) | Ev::ExecZero(_)))
    );
    assert_eq!(q.state().phase, Phase::Running);
    assert!(!q.state().stopped);
}

#[test]
fn a_record_that_does_not_decode_kills_colony() {
    let mut q = queen();
    let mut bytes = [0u8; 32];
    bytes[0] = 99;
    q.io().recv_q.push_back(Recv::Message(Message {
        bytes,
        len: 16,
        fds: vec![devnull()],
        truncated: false,
    }));
    q.io().events.clear();
    q.turn(&wake(&[]));
    assert!(q.io().events.contains(&Ev::Kill(101)));
}

#[test]
fn a_truncated_message_kills_colony_and_its_descriptors_are_closed() {
    let mut q = queen();
    let fd = devnull();
    let raw = fd.as_raw_fd();
    q.io().recv_q.push_back(Recv::Message(Message {
        bytes: [0; 32],
        len: 16,
        fds: vec![fd],
        truncated: true,
    }));
    q.turn(&wake(&[]));
    assert!(q.io().events.contains(&Ev::Kill(101)));
    assert!(q.descriptors().get(raw).is_none());
}

#[test]
fn a_put_holds_the_descriptor_and_a_drop_closes_it() {
    let mut q = queen();
    let fd = devnull();
    let raw = fd.as_raw_fd();
    q.io().recv_q.push_back(put_message(16, fd));
    q.turn(&wake(&[]));
    assert!(q.descriptors().get(raw).is_some());
    q.io()
        .recv_q
        .push_back(plain_message(FromColony::Drop { key: 16 }));
    q.turn(&wake(&[]));
    assert!(q.descriptors().get(raw).is_none());
    assert!(!q.table().iter().any(|e| e.key == 16));
}

#[test]
fn a_replaced_put_closes_the_old_descriptor() {
    let mut q = queen();
    let (a, b) = (devnull(), devnull());
    let (ra, rb) = (a.as_raw_fd(), b.as_raw_fd());
    q.io().recv_q.push_back(put_message(16, a));
    q.io().recv_q.push_back(put_message(16, b));
    q.turn(&wake(&[]));
    assert!(q.descriptors().get(ra).is_none());
    assert!(q.descriptors().get(rb).is_some());
}

#[test]
fn a_cad_asks_colony_to_reboot_and_the_timer_is_armed() {
    let mut q = queen();
    q.turn(&wake(&[]));
    q.io().events.clear();
    q.turn(&wake(&[libc::SIGINT as u32]));
    let ev = &q.io().events;
    assert!(ev.contains(&Ev::CadOn));
    assert!(ev.contains(&Ev::Arm(Some(LIMITS.shutdown_ms))));
    assert!(
        ev.contains(&Ev::Send(
            Some(ToColony::Request { mode: Mode::Reboot }),
            true
        )),
        "{ev:?}"
    );
}

#[test]
fn a_failed_exec_of_zero_is_fed_back_and_runs_rescue() {
    let mut q = queen();
    q.io().reap_q.push_back((101, 10 << 8));
    q.turn(&wake(&[CHLD]));
    let ev = &q.io().events;
    assert!(ev.contains(&Ev::ExecZero(Mode::Poweroff)));
    assert!(ev.contains(&Ev::SpawnRescue), "{ev:?}");
    assert_eq!(q.state().phase, Phase::Rescue);
}

#[test]
fn a_colony_that_cannot_be_spawned_is_counted_until_rescue() {
    let mut q = queen();
    q.io().spawn_fails = true;
    q.io().reap_q.push_back((101, 9));
    q.turn(&wake(&[CHLD]));
    let spawns = q
        .io()
        .events
        .iter()
        .filter(|e| matches!(e, Ev::SpawnColony))
        .count();
    assert_eq!(spawns, 1 + 5, "the first, then five failed restarts");
    assert!(q.io().events.contains(&Ev::SpawnRescue));
    assert_eq!(q.state().phase, Phase::Rescue);
}
