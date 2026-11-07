// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `queen` binary: PID 1. Start-up runs in the order of the spec's section 3.1; after it
//! nothing in this file returns or exits except the exec of zero.
use qinit_queen::real::{CHANNEL, RealIo, SIGNALS, TIMER};
use qinit_queen::run::{NOFILE, Queen, Wake};
use qinit_sys::limits::{RLIMIT_NOFILE, chdir, set_rlimit};
use qinit_sys::{event, fd, proc, signal};
use std::ffi::CStr;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

/// Logs `what` to the park descriptor and parks: nothing past PID 1's start-up may return.
fn die(what: &str) -> ! {
    let line = format!("<2>queen: {what}\n");
    signal::park(line.as_bytes())
}

fn open_console() -> OwnedFd {
    for path in [c"/dev/console", c"/dev/null"] {
        if let Ok(f) = fd::open_cloexec(path, libc::O_RDWR | libc::O_NOCTTY, 0) {
            return f;
        }
    }
    die("no console and no /dev/null")
}

/// Every signal queen reads from its signalfd: all the standard ones except the fault signals.
fn read_signals() -> Vec<i32> {
    (1..=31)
        .filter(|s| !signal::FATAL.contains(s) && *s != libc::SIGKILL && *s != libc::SIGSTOP)
        .collect()
}

fn main() {
    // 1. Every signal blocked but the fatal ones, which park; panics park too.
    let _ = signal::block_all_but_fatal();
    let _ = signal::install_fault_park();
    std::panic::set_hook(Box::new(|_| signal::park(b"<2>queen: panic\n")));
    // 2. PID 1 only: anything else is an administrator's mistake, and a mistake must not park.
    if proc::pid() != 1 {
        eprintln!("queen: must run as PID 1");
        std::process::exit(2);
    }
    let console = open_console();
    signal::set_park_fd(console.as_fd());
    // 3. Ctrl-Alt-Del arrives as SIGINT.
    if proc::cad_off().is_err() {
        die("cannot switch ctrl-alt-del off");
    }
    // 4. No mount is pinned by the working directory; the log is /dev/kmsg.
    let root: &CStr = c"/";
    if chdir(root).is_err() {
        die("cannot enter /");
    }
    let log_fd = fd::open_cloexec(c"/dev/kmsg", libc::O_WRONLY | libc::O_NOCTTY, 0)
        .or_else(|_| fd::dup_above(console.as_fd(), 3))
        .unwrap_or_else(|_| die("no log descriptor"));
    signal::set_park_fd(log_fd.as_fd());
    // 5. The whole store plus queen's own descriptors.
    let nofile = u64::try_from(NOFILE).unwrap_or(65_536);
    if set_rlimit(RLIMIT_NOFILE, nofile, nofile).is_err() {
        die("cannot raise the descriptor limit");
    }
    // 6. The tables, the signalfd, the timerfd and the epoll instance.
    let Ok(sigfd) = event::signalfd_blocking(&read_signals()) else {
        die("cannot make the signalfd")
    };
    let Ok(timerfd) = event::timer_unarmed() else {
        die("cannot make the timerfd")
    };
    let Ok(ep) = event::epoll() else {
        die("cannot make the epoll instance")
    };
    if event::epoll_add(&ep, sigfd.as_raw_fd(), libc::EPOLLIN as u32, SIGNALS).is_err()
        || event::epoll_add(&ep, timerfd.as_raw_fd(), libc::EPOLLIN as u32, TIMER).is_err()
    {
        die("cannot watch the signalfd and timerfd");
    }
    // 7. Colony.
    let mut queen = Queen::new(
        RealIo::new(ep, sigfd, timerfd, log_fd, console),
        qinit_queen::limits(),
    );
    loop {
        wait_and_turn(&mut queen);
    }
}

/// One epoll wait, and one turn for what it found. Nothing here allocates.
fn wait_and_turn(queen: &mut Queen<RealIo>) {
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 8];
    let Ok(n) = event::epoll_wait(&queen.io().ep, &mut events) else {
        die("epoll_wait failed")
    };
    let mut signals = [0u32; 64];
    let (mut nsig, mut channel, mut timer, mut writable) = (0, false, false, false);
    for ev in &events[..n] {
        let (flags, token) = (ev.events, ev.u64);
        match token {
            SIGNALS => {
                while nsig < signals.len() {
                    let Some(s) = event::read_signal(&queen.io().sigfd) else {
                        break;
                    };
                    signals[nsig] = s;
                    nsig += 1;
                }
            }
            TIMER => {
                let mut sink = [0u8; 8];
                let _ = event::read(&queen.io().timerfd, &mut sink);
                timer = true;
            }
            CHANNEL => {
                channel = true;
                writable |= flags & libc::EPOLLOUT as u32 != 0;
            }
            _ => {}
        }
    }
    queen.turn(&Wake {
        signals: &signals[..nsig],
        channel,
        timer,
        writable,
    });
}
