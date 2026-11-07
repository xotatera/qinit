// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Colony's client of queen's store, against a fake queen over a real socket pair.
mod common;

use common::FakeQueen;
use qinit_colony::ShutdownMode;
use qinit_colonyd::store::{KEY_CELLS, KEY_DB, KEY_NODES, Store};
use qinit_ipc::memfd::{ALL_SEALS, read_all, sealed, seals};
use qinit_queen_core::{Mode, ToColony};
use std::os::fd::AsFd;
use std::time::{Duration, Instant};

fn memfd(text: &str) -> std::os::fd::OwnedFd {
    sealed(c"test", text.as_bytes()).unwrap()
}

#[test]
fn attach_reads_until_held_end() {
    let (mut q, link) = FakeQueen::new();
    q.held.insert(KEY_DB, memfd("db"));
    q.held.insert(20, memfd("twenty"));
    q.held.insert(21, memfd("twenty-one"));
    drop(link);
    let mut store = q.reattach();
    let fd = store.take(20).unwrap();
    assert_eq!(read_all(fd.as_fd(), 100).unwrap(), b"twenty");
    assert!(store.take(20).is_none(), "taken once");
    assert_eq!(store.load(KEY_DB), Some(b"db".to_vec()));
    assert_eq!(
        store.load(KEY_DB),
        Some(b"db".to_vec()),
        "a load keeps the entry"
    );
    assert!(store.take(99).is_none());
}

#[test]
fn attach_refuses_a_count_that_does_not_match() {
    let (peer, link) = qinit_ipc::seqpacket_pair().unwrap();
    for key in [20, 21] {
        let fd = memfd("x");
        qinit_ipc::send(
            peer.as_fd(),
            &qinit_queen_core::encode_to_colony(ToColony::Held { key }),
            &[fd.as_fd()],
        )
        .unwrap();
    }
    qinit_ipc::send(
        peer.as_fd(),
        &qinit_queen_core::encode_to_colony(ToColony::HeldEnd { count: 3 }),
        &[],
    )
    .unwrap();
    let e = Store::attach(link).err().expect("refused");
    assert!(e.contains("count"), "{e}");
}

#[test]
fn attach_refuses_a_bad_record() {
    let (peer, link) = qinit_ipc::seqpacket_pair().unwrap();
    qinit_ipc::send(peer.as_fd(), &[0xff; 16], &[]).unwrap();
    assert!(Store::attach(link).is_err());
}

#[test]
fn attach_refuses_a_closed_channel() {
    let (peer, link) = qinit_ipc::seqpacket_pair().unwrap();
    drop(peer);
    assert!(Store::attach(link).is_err());
}

#[test]
fn allocate_moves_past_every_held_key() {
    let (mut q, _link) = FakeQueen::new();
    let mut none = q.reattach();
    assert_eq!(none.allocate(), 16);
    assert_eq!(none.allocate(), 17);
    q.held.insert(KEY_DB, memfd("a"));
    q.held.insert(40, memfd("b"));
    let mut some = q.reattach();
    assert_eq!(some.allocate(), 41);
    assert_eq!(some.allocate(), 42);
}

#[test]
fn save_sends_a_sealed_memfd_that_loads_back() {
    let (mut q, _link) = FakeQueen::new();
    let mut store = q.reattach();
    store.save(KEY_NODES, b"hello");
    q.pump();
    let fd = &q.held[&KEY_NODES];
    assert_eq!(seals(fd.as_fd()).unwrap() & ALL_SEALS, ALL_SEALS);
    assert_eq!(read_all(fd.as_fd(), 100).unwrap(), b"hello");
    let mut again = q.reattach();
    assert_eq!(again.load(KEY_NODES), Some(b"hello".to_vec()));
    assert_eq!(again.load(KEY_CELLS), None);
}

#[test]
fn a_second_save_replaces_the_first() {
    let (mut q, _link) = FakeQueen::new();
    let mut store = q.reattach();
    store.save(KEY_CELLS, b"one");
    store.save(KEY_CELLS, b"two");
    q.pump();
    assert_eq!(q.held.len(), 1);
    assert_eq!(read_all(q.held[&KEY_CELLS].as_fd(), 100).unwrap(), b"two");
}

#[test]
fn put_and_forget_reach_queen() {
    let (mut q, _link) = FakeQueen::new();
    let mut store = q.reattach();
    let key = store.allocate();
    let fd = memfd("dir");
    store.put(key, fd.as_fd());
    q.pump();
    assert!(q.held.contains_key(&key));
    store.forget(key);
    q.pump();
    assert!(!q.held.contains_key(&key));
}

#[test]
fn clear_drops_everything_colony_knows_queen_holds() {
    let (mut q, _link) = FakeQueen::new();
    q.held.insert(20, memfd("held at the start"));
    let mut store = q.reattach();
    store.save(KEY_CELLS, b"c");
    let key = store.allocate();
    store.put(key, memfd("d").as_fd());
    store.clear();
    q.pump();
    assert!(q.held.is_empty(), "{:?}", q.held.keys().collect::<Vec<_>>());
}

#[test]
fn a_shutdown_is_announced_in_its_mode() {
    let (mut q, _link) = FakeQueen::new();
    let mut store = q.reattach();
    store.announce(ShutdownMode::Reboot);
    store.announce(ShutdownMode::Halt);
    q.pump();
    assert_eq!(q.shutdowns, [Mode::Reboot, Mode::Halt]);
}

#[test]
fn next_gives_what_queen_sends_after_the_hand_over() {
    let (mut q, _link) = FakeQueen::new();
    let mut store = q.reattach();
    assert_eq!(store.next(), Ok(None));
    q.send(
        ToColony::Request {
            mode: Mode::Poweroff,
        },
        None,
    );
    q.send(ToColony::Reaped, None);
    assert_eq!(
        store.next(),
        Ok(Some(ToColony::Request {
            mode: Mode::Poweroff
        }))
    );
    assert_eq!(store.next(), Ok(Some(ToColony::Reaped)));
    assert_eq!(store.next(), Ok(None));
    q.send(ToColony::HeldEnd { count: 0 }, None);
    assert!(store.next().is_err(), "a hand-over record is out of place");
}

#[test]
fn a_refusal_makes_colony_forget_the_key() {
    let (mut q, _link) = FakeQueen::new();
    let mut store = q.reattach();
    store.put(30, memfd("x").as_fd());
    q.send(ToColony::Refused { key: 30 }, None);
    assert_eq!(store.next(), Ok(Some(ToColony::Refused { key: 30 })));
    store.clear();
    q.pump();
    // Dropping 30 was not sent: queen closed it already, and a Drop of an unknown key is moot.
    assert!(q.shutdowns.is_empty());
}

#[test]
fn standalone_does_nothing() {
    let mut s = Store::standalone();
    assert!(s.take(KEY_DB).is_none());
    assert_eq!(s.load(KEY_DB), None);
    s.save(KEY_CELLS, b"x");
    s.put(20, memfd("y").as_fd());
    s.forget(20);
    s.announce(ShutdownMode::Halt);
    s.clear();
    assert!(s.link().is_none());
    assert_eq!(s.next(), Ok(None));
    assert_eq!(s.allocate(), 16);
    assert_eq!(s.warnings(), None);
}

#[test]
fn a_queen_that_stops_reading_does_not_stall_colony() {
    let (mut q, _link) = FakeQueen::new();
    let mut store = q.reattach();
    let started = Instant::now();
    let mut worst = Duration::ZERO;
    let mut puts = 0;
    while store.warnings_pending() == 0 {
        let t = Instant::now();
        store.save(KEY_CELLS, b"state");
        worst = worst.max(t.elapsed());
        puts += 1;
        assert!(puts < 100_000, "the socket never filled");
    }
    assert!(worst < Duration::from_secs(3), "one save waited {worst:?}");
    assert!(started.elapsed() < Duration::from_secs(30));
    assert!(store.warnings().is_some_and(|l| l.contains("queen")));
    assert_eq!(store.warnings(), None, "said once");
    // Once stalled, a further save does not wait out the bound again.
    let t = Instant::now();
    store.save(KEY_CELLS, b"state");
    assert!(
        t.elapsed() < Duration::from_millis(500),
        "{:?}",
        t.elapsed()
    );
    // Queen reads again: saves go through, and the next stall would warn again.
    q.pump();
    store.save(KEY_NODES, b"fresh");
    q.pump();
    assert_eq!(read_all(q.held[&KEY_NODES].as_fd(), 100).unwrap(), b"fresh");
}

#[test]
fn a_queen_that_went_away_leaves_colony_standing() {
    let (mut q, _link) = FakeQueen::new();
    let mut store = q.reattach();
    drop(q);
    store.save(KEY_CELLS, b"x");
    assert!(store.warnings().is_some_and(|l| l.contains("closed")));
    assert!(store.link().is_none());
    assert_eq!(store.next(), Ok(None));
}
