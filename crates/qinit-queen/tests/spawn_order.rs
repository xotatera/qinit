// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! A channel queen cannot watch leaves no colony behind. This file holds one test: it asks the
//! process for its children, which any other test spawning one would disturb.
use qinit_queen::real::RealIo;
use qinit_queen::run::Io;
use qinit_sys::proc;
use std::os::fd::OwnedFd;

fn devnull() -> OwnedFd {
    std::fs::File::open("/dev/null").unwrap().into()
}

#[test]
fn a_channel_that_cannot_be_watched_starts_no_colony() {
    // /dev/null is not an epoll instance, so registering the channel fails.
    let mut io = RealIo::new(devnull(), devnull(), devnull(), devnull(), devnull());
    assert!(io.spawn_colony().is_err());
    assert_eq!(io.channel_fd(), None);
    // A colony started before the failure would be a child by now (its exec fails, so it exits
    // at once and is reaped here); with none, there is no child to wait for.
    assert_eq!(proc::wait_any().unwrap(), None, "a colony was left running");
}
