// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The real channel: a send that fails for good drops it.
use qinit_ipc::seqpacket_pair;
use qinit_queen::real::RealIo;
use qinit_queen::run::{Io, Sent};
use qinit_sys::event;
use std::os::fd::OwnedFd;

fn devnull() -> OwnedFd {
    std::fs::File::open("/dev/null").unwrap().into()
}

fn io() -> RealIo {
    RealIo::new(
        event::epoll().unwrap(),
        devnull(),
        devnull(),
        devnull(),
        devnull(),
    )
}

#[test]
fn a_send_to_a_closed_peer_drops_the_channel() {
    let mut io = io();
    let (mine, theirs) = seqpacket_pair().unwrap();
    io.attach_channel(mine).unwrap();
    drop(theirs);
    assert_eq!(io.send(&[0; 16], None), Sent::Gone);
    assert_eq!(
        io.channel_fd(),
        None,
        "the broken channel stays registered and would wake queen for nothing"
    );
}

#[test]
fn a_send_to_a_full_socket_keeps_the_channel() {
    let mut io = io();
    let (mine, theirs) = seqpacket_pair().unwrap();
    io.attach_channel(mine).unwrap();
    let mut sent = 0;
    while io.send(&[0; 16], None) == Sent::Ok {
        sent += 1;
        assert!(sent < 1_000_000, "the socket never filled");
    }
    assert!(io.channel_fd().is_some());
    drop(theirs);
}
