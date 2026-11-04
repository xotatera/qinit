// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The server over a real `SOCK_SEQPACKET` socket in a temp directory, against `Colony<Sim>`.
#[path = "../../qinit-colony/tests/common/mod.rs"]
mod common;

use common::*;
use qinit_colony::sim::{Script, Sim, advance_outcome};
use qinit_colony::{Colony, Peer, State};
use qinit_ipc::{MAX_FDS, connect_seqpacket, listen_seqpacket, recv, send, send_unchecked};
use qinit_proto::testing::Driver;
use qinit_proto::{Limits, MAX_DB_READ};
use qinit_proto_core::{H_VERSION, HEADER_WORDS, MAX_MESSAGE};
use qinit_wire::{Action, ErrorCode, Mode, Msg, Rep, Req, StateWord, StrList, decode, encode};
use std::ffi::CString;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::MetadataExt;

fn frames() -> String {
    "[worker.db]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/db\"]\n\
     [worker.app]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/app\"]\n\
     deps = [{ group = \"require_all\", edges = [{ to = \"db\" }] }]\n\
     [forager.backup]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/backup\"]\n\
     [forager.backup.launch]\nconcurrency = 2\nargv_tail = 2\nenv = [\"TARGET\"]\nfds = [\"stdout\"]\n"
        .to_owned()
}

struct Rig {
    colony: Colony<Sim>,
    driver: Driver,
    path: CString,
    _dir: std::path::PathBuf,
}

fn rig(enable: &[&str], limits: Limits, sim: Sim) -> Rig {
    let dir = std::env::temp_dir().join(format!(
        "qinit-proto-{}-{}",
        std::process::id(),
        std::thread::current()
            .name()
            .unwrap_or("t")
            .replace("::", "-")
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = CString::new(dir.join("colony").to_str().unwrap()).unwrap();
    let listener = listen_seqpacket(&path, 128).unwrap();
    let (colony, _) = boot(&frames(), enable, sim);
    let driver = Driver::new(listener, limits).unwrap();
    Rig {
        colony,
        driver,
        path,
        _dir: dir,
    }
}

impl Rig {
    fn now(&self) -> u64 {
        self.colony.effects.now()
    }

    fn pump(&mut self) {
        let now = self.now();
        self.driver.pump(&mut self.colony, now).unwrap();
    }

    fn connect(&mut self) -> OwnedFd {
        let fd = connect_seqpacket(&self.path).unwrap();
        qinit_sys::fd::set_nonblocking(&fd).unwrap();
        self.pump();
        fd
    }

    /// Lets time pass and delivers what the events owe to waiting connections.
    fn advance(&mut self, ms: u64) {
        let out = advance_outcome(&mut self.colony, ms);
        self.driver.deliver(&out, &mut self.colony).unwrap();
        self.pump();
    }

    fn root(&mut self) {
        self.driver.identity = Some(Peer {
            uid: 0,
            gid: 0,
            pid: 1,
        });
    }
}

fn send_msg(client: &OwnedFd, msg: &Msg<'_>, fds: &[std::os::fd::BorrowedFd<'_>]) {
    let mut out: Box<[u8; MAX_MESSAGE]> = vec![0u8; MAX_MESSAGE].try_into().unwrap();
    let n = encode(msg, u32::try_from(fds.len()).unwrap(), &mut out).unwrap();
    send(client.as_fd(), &out[..n], fds).unwrap();
}

fn request(rig: &mut Rig, client: &OwnedFd, req: Req<'_>) {
    send_msg(client, &Msg::Req(req), &[]);
    rig.pump();
}

/// The next message on `client`, handed to `f`; `None` when nothing is waiting.
fn read<R>(client: &OwnedFd, f: impl FnOnce(Rep<'_>) -> R) -> Option<R> {
    let mut buf = vec![0u8; MAX_MESSAGE];
    let got = recv(client.as_fd(), &mut buf).ok()?;
    if got.len == 0 {
        return None;
    }
    match decode(&buf[..got.len], got.fds.len()).expect("a reply decodes") {
        Msg::Rep(r) => Some(f(r)),
        Msg::Req(_) => panic!("a request came back"),
    }
}

/// Whether the server closed its end: `recv` reads 0 bytes.
fn closed(client: &OwnedFd) -> bool {
    let mut buf = [0u8; 16];
    matches!(recv(client.as_fd(), &mut buf), Ok(g) if g.len == 0)
}

fn error_of(client: &OwnedFd) -> (ErrorCode, u32, u32) {
    read(client, |r| match r {
        Rep::Error {
            code,
            detail,
            version,
        } => (code, detail, version),
        other => panic!("expected an error, got {other:?}"),
    })
    .expect("a reply")
}

fn status(target: &str) -> Req<'_> {
    Req::Status { target }
}

fn my_uid() -> u32 {
    std::fs::metadata("/proc/self").unwrap().uid()
}

#[test]
fn status_over_the_socket() {
    let mut r = rig(&["db"], Limits::default(), Sim::new());
    r.advance(5);
    let c = r.connect();
    request(&mut r, &c, status("db"));
    let (name, state) = read(&c, |rep| match rep {
        Rep::NodeStatus(n) => (n.name.to_owned(), n.state),
        other => panic!("{other:?}"),
    })
    .unwrap();
    assert_eq!(name, "db");
    assert_eq!(
        state,
        StateWord {
            state: 3,
            detail: 0
        }
    );
    // The connection stays open for the next request.
    request(&mut r, &c, status("app"));
    assert!(read(&c, |rep| matches!(rep, Rep::NodeStatus(_))).unwrap());
}

#[test]
fn a_second_request_in_flight_closes_the_connection() {
    let mut sim = Sim::new();
    let (probe, _) = boot(&frames(), &[], Sim::new());
    sim.scripts.insert(
        idx(&probe, "db"),
        Script {
            ready_after_ms: None,
            ..Script::default()
        },
    );
    let mut r = rig(&[], Limits::default(), sim);
    r.root();
    let c = r.connect();
    request(
        &mut r,
        &c,
        Req::Change {
            target: "db",
            action: Action::Start,
            settled: true,
            wait_ms: 60_000,
        },
    );
    assert!(read(&c, |rep| matches!(rep, Rep::Accepted)).unwrap());
    // The first request has not been answered finally: a second one is a protocol error.
    request(&mut r, &c, status("db"));
    let (code, detail, _) = error_of(&c);
    assert_eq!(code, ErrorCode::BadRequest);
    assert_eq!(detail, 6);
    assert!(closed(&c));
    assert_eq!(r.driver.server.connections(), 0);
    // The first request's effect stands.
    assert_eq!(r.colony.state(idx(&r.colony, "db")), Some(State::Starting));
}

#[test]
fn a_wait_settled_by_the_request_itself_is_still_answered() {
    let mut r = rig(&["db"], Limits::default(), Sim::new());
    r.root();
    r.advance(5);
    let c = r.connect();
    request(
        &mut r,
        &c,
        Req::Change {
            target: "db",
            action: Action::Start,
            settled: true,
            wait_ms: 5000,
        },
    );
    // The node is ready already: the acceptance and the settled reply both arrive.
    assert!(read(&c, |rep| matches!(rep, Rep::Accepted)).unwrap());
    assert!(read(&c, |rep| matches!(rep, Rep::Settled(w) if w.state == 3)).unwrap());
    // And the connection is free for the next request.
    request(&mut r, &c, status("db"));
    assert!(read(&c, |rep| matches!(rep, Rep::NodeStatus(_))).unwrap());
}

#[test]
fn a_client_that_leaves_during_a_wait_leaves_no_wait_behind() {
    let mut sim = Sim::new();
    let (probe, _) = boot(&frames(), &[], Sim::new());
    sim.scripts.insert(
        idx(&probe, "db"),
        Script {
            ready_after_ms: Some(1000),
            ..Script::default()
        },
    );
    let mut r = rig(&[], Limits::default(), sim);
    r.root();
    let c = r.connect();
    request(
        &mut r,
        &c,
        Req::Change {
            target: "db",
            action: Action::Start,
            settled: true,
            wait_ms: 60_000,
        },
    );
    assert!(read(&c, |rep| matches!(rep, Rep::Accepted)).unwrap());
    drop(c);
    r.pump();
    assert_eq!(r.driver.server.connections(), 0);
    assert!(
        r.colony
            .effects
            .calls
            .iter()
            .any(|call| matches!(call, qinit_colony::sim::Call::CancelWait(_)))
    );
    // Nothing is sent to a reused descriptor: the node settles, and no reply is owed.
    r.advance(5000);
    let fresh = r.connect();
    assert!(read(&fresh, |_| ()).is_none());
}

#[test]
fn fd_count_mismatch_closes_every_received_fd() {
    let mut r = rig(&[], Limits::default(), Sim::new());
    let c = r.connect();
    let (pipe_r, pipe_w) = qinit_sys::fd::pipe(libc_cloexec()).unwrap();
    // A status request declares no descriptor, but one travels with it.
    let mut out: Box<[u8; MAX_MESSAGE]> = vec![0u8; MAX_MESSAGE].try_into().unwrap();
    let n = encode(&Msg::Req(status("db")), 0, &mut out).unwrap();
    send(c.as_fd(), &out[..n], &[pipe_w.as_fd()]).unwrap();
    drop(pipe_w);
    r.pump();
    let (code, detail, _) = error_of(&c);
    assert_eq!((code, detail), (ErrorCode::BadRequest, 7));
    assert!(closed(&c));
    // The server closed its copy: the read end sees the end of the pipe.
    let mut file = std::fs::File::from(pipe_r);
    let mut one = [0u8; 1];
    assert_eq!(file.read(&mut one).unwrap(), 0);
}

fn libc_cloexec() -> i32 {
    0o2_000_000
}

fn launch_with(roles: u32, declared: u32, travelling: usize) -> (ErrorCode, u32) {
    let mut r = rig(&[], Limits::default(), Sim::new());
    r.root();
    let c = r.connect();
    let (pipe_r, pipe_w) = qinit_sys::fd::pipe(libc_cloexec()).unwrap();
    let mut out: Box<[u8; MAX_MESSAGE]> = vec![0u8; MAX_MESSAGE].try_into().unwrap();
    let req = Req::Launch {
        frame: "backup",
        argv_tail: StrList::new(b""),
        env_add: StrList::new(b""),
        fd_roles: roles,
        wait_ms: 1000,
        flags: 0,
    };
    let n = encode(&Msg::Req(req), roles.count_ones(), &mut out).unwrap();
    out[4 * 4] = u8::try_from(declared).unwrap();
    let fds = [pipe_w.as_fd(); 1];
    send(c.as_fd(), &out[..n], &fds[..travelling]).unwrap();
    drop(pipe_w);
    r.pump();
    let (code, detail, _) = error_of(&c);
    assert!(closed(&c));
    assert!(
        r.colony.effects.instance_fds.is_empty(),
        "nothing was launched"
    );
    let mut one = [0u8; 1];
    assert_eq!(std::fs::File::from(pipe_r).read(&mut one).unwrap(), 0);
    (code, detail)
}

#[test]
fn a_launch_with_fewer_fds_than_roles_or_fds_without_roles_is_bad_request() {
    // Roles say one descriptor but the header says none, and none travels.
    assert_eq!(launch_with(2, 0, 0), (ErrorCode::BadRequest, 7));
    // Roles say none, the header says none, but one travels.
    assert_eq!(launch_with(0, 0, 1), (ErrorCode::BadRequest, 7));
    // Roles say one and the header says one, but none travels.
    assert_eq!(launch_with(2, 1, 0), (ErrorCode::BadRequest, 7));
}

#[test]
fn a_truncated_control_message_is_bad_request() {
    let mut r = rig(&[], Limits::default(), Sim::new());
    let c = r.connect();
    let pipes: Vec<(OwnedFd, OwnedFd)> = (0..=MAX_FDS)
        .map(|_| qinit_sys::fd::pipe(libc_cloexec()).unwrap())
        .collect();
    let fds: Vec<_> = pipes.iter().map(|p| p.1.as_fd()).collect();
    let mut out: Box<[u8; MAX_MESSAGE]> = vec![0u8; MAX_MESSAGE].try_into().unwrap();
    let n = encode(&Msg::Req(status("db")), 0, &mut out).unwrap();
    send_unchecked(c.as_fd(), &out[..n], &fds).unwrap();
    r.pump();
    let (code, detail, _) = error_of(&c);
    assert_eq!((code, detail), (ErrorCode::BadRequest, 7));
    assert!(closed(&c));
}

#[test]
fn an_oversize_datagram_is_bad_request() {
    let mut r = rig(&[], Limits::default(), Sim::new());
    let c = r.connect();
    send(c.as_fd(), &vec![0u8; MAX_MESSAGE + 1000], &[]).unwrap();
    r.pump();
    let (code, detail, _) = error_of(&c);
    assert_eq!((code, detail), (ErrorCode::BadRequest, 1));
    assert!(closed(&c));
}

#[test]
fn a_version_2_message_gets_version_with_the_servers_version() {
    let mut r = rig(&[], Limits::default(), Sim::new());
    let c = r.connect();
    let mut out: Box<[u8; MAX_MESSAGE]> = vec![0u8; MAX_MESSAGE].try_into().unwrap();
    let n = encode(&Msg::Req(status("db")), 0, &mut out).unwrap();
    out[4 * H_VERSION] = 2;
    send(c.as_fd(), &out[..n], &[]).unwrap();
    r.pump();
    let (code, _, version) = error_of(&c);
    assert_eq!((code, version), (ErrorCode::Version, 1));
    assert!(closed(&c));
}

#[test]
fn a_reply_type_as_a_request_is_bad_request() {
    let mut r = rig(&[], Limits::default(), Sim::new());
    let c = r.connect();
    send_msg(&c, &Msg::Rep(Rep::Accepted), &[]);
    r.pump();
    let (code, detail, _) = error_of(&c);
    assert_eq!((code, detail), (ErrorCode::BadRequest, 3));
    assert!(closed(&c));
}

#[test]
fn the_65th_connection_gets_full() {
    let mut r = rig(&[], Limits::default(), Sim::new());
    r.root();
    let kept: Vec<OwnedFd> = (0..64).map(|_| r.connect()).collect();
    assert_eq!(r.driver.server.connections(), 64);
    let extra = r.connect();
    assert_eq!(error_of(&extra).0, ErrorCode::Full);
    assert!(closed(&extra));
    assert_eq!(r.driver.server.connections(), 64);
    drop(kept);
}

#[test]
fn the_5th_connection_of_a_non_root_uid_gets_full() {
    if my_uid() == 0 {
        eprintln!("skipped: the per-user limit does not apply to root");
        return;
    }
    let mut r = rig(&[], Limits::default(), Sim::new());
    let kept: Vec<OwnedFd> = (0..4).map(|_| r.connect()).collect();
    let fifth = r.connect();
    assert_eq!(error_of(&fifth).0, ErrorCode::Full);
    assert!(closed(&fifth));
    drop(kept);
}

#[test]
fn non_root_change_launch_refresh_and_shutdown_are_denied() {
    if my_uid() == 0 {
        eprintln!("skipped: the test needs a non-root user");
        return;
    }
    let mut r = rig(&["db"], Limits::default(), Sim::new());
    let c = r.connect();
    for req in [
        Req::Change {
            target: "db",
            action: Action::Stop,
            settled: false,
            wait_ms: 0,
        },
        Req::Shutdown {
            mode: Mode::Halt,
            settled: false,
            wait_ms: 0,
        },
    ] {
        request(&mut r, &c, req);
        assert_eq!(error_of(&c).0, ErrorCode::Denied);
    }
    assert!(r.colony.shutdown_mode().is_none());
}

#[test]
fn non_root_status_shows_no_credentials() {
    let mut r = rig(&["db"], Limits::default(), Sim::new());
    r.advance(5);
    let c = r.connect();
    request(&mut r, &c, status("db"));
    let mut buf = vec![0u8; MAX_MESSAGE];
    let got = recv(c.as_fd(), &mut buf).unwrap();
    let bytes = &buf[..got.len];
    // The record holds 13 words and the name `db`; the group's target is empty.
    assert_eq!(bytes.len(), 4 * (HEADER_WORDS + 13) + "db".len());
    for secret in [&b"/bin/db"[..], b"svc"] {
        assert!(!bytes.windows(secret.len()).any(|w| w == secret));
    }
}

#[test]
fn a_cursor_past_the_end_is_an_empty_page() {
    let mut r = rig(&[], Limits::default(), Sim::new());
    let c = r.connect();
    request(
        &mut r,
        &c,
        Req::List {
            cursor: 9999,
            kind: 0,
        },
    );
    let (count, next) = read(&c, |rep| match rep {
        Rep::ListPage { entries, next } => (entries.len(), next),
        other => panic!("{other:?}"),
    })
    .unwrap();
    assert_eq!((count, next), (0, None));
}

#[test]
fn a_launch_with_stdout_routes_the_callers_pipe() {
    let mut r = rig(&[], Limits::default(), Sim::new());
    r.root();
    r.colony.effects.instance_script = Script {
        ready_after_ms: None,
        ..Script::default()
    };
    let c = r.connect();
    let (pipe_r, pipe_w) = qinit_sys::fd::pipe(libc_cloexec()).unwrap();
    send_msg(
        &c,
        &Msg::Req(Req::Launch {
            frame: "backup",
            argv_tail: StrList::new(b""),
            env_add: StrList::new(b""),
            fd_roles: 2,
            wait_ms: 60_000,
            flags: 0,
        }),
        &[pipe_w.as_fd()],
    );
    drop(pipe_w);
    r.pump();
    let id = read(&c, |rep| match rep {
        Rep::Launched { id } => id,
        other => panic!("{other:?}"),
    })
    .unwrap();
    assert_eq!(id, 1);
    // The Sim holds the descriptor the server received: writing through it reaches our end.
    let mut held = r.colony.effects.instance_fds.remove(&0).unwrap();
    assert_eq!(held.len(), 1);
    let mut writer = std::fs::File::from(held.remove(0));
    writer.write_all(b"hello").unwrap();
    drop(writer);
    let mut text = String::new();
    std::fs::File::from(pipe_r)
        .read_to_string(&mut text)
        .unwrap();
    assert_eq!(text, "hello");
}

fn memfd(bytes: &[u8]) -> OwnedFd {
    qinit_sys::memfd::sealed(c"db", bytes).unwrap()
}

fn refresh(r: &mut Rig, c: &OwnedFd, fd: &OwnedFd) {
    send_msg(
        c,
        &Msg::Req(Req::Refresh {
            settled: false,
            wait_ms: 0,
        }),
        &[fd.as_fd()],
    );
    r.pump();
}

#[test]
fn a_refresh_fd_is_read_and_swapped() {
    let mut r = rig(&["db"], Limits::default(), Sim::new());
    r.root();
    r.advance(5);
    let c = r.connect();
    let changed = frames().replace("/bin/db", "/bin/db2");
    refresh(&mut r, &c, &memfd(&database(&changed, &["db"])));
    assert!(read(&c, |rep| matches!(rep, Rep::Accepted)).unwrap());
    r.advance(100);
    assert_eq!(
        r.colony.model().nodes[idx(&r.colony, "db") as usize].exec,
        ["/bin/db2"]
    );
}

#[test]
fn a_refresh_fd_is_read_from_the_start_whatever_its_offset() {
    let mut r = rig(&["db"], Limits::default(), Sim::new());
    r.root();
    r.advance(5);
    let c = r.connect();
    let changed = frames().replace("/bin/db", "/bin/db2");
    let fd = memfd(&database(&changed, &["db"]));
    // The sender left the shared file offset at the end.
    let mut file = std::fs::File::from(fd.try_clone().unwrap());
    let end = file.seek(SeekFrom::End(0)).unwrap();
    refresh(&mut r, &c, &fd);
    assert!(read(&c, |rep| matches!(rep, Rep::Accepted)).unwrap());
    // And the server's read did not move it.
    assert_eq!(file.stream_position().unwrap(), end);
}

#[test]
fn a_client_that_never_reads_is_closed_and_the_server_never_blocks() {
    let mut r = rig(&["db"], Limits::default(), Sim::new());
    r.root();
    let c = r.connect();
    // Replies pile up unread; once the client's queue is full the connection is dropped.
    for _ in 0..100_000 {
        if r.driver.server.connections() == 0 {
            break;
        }
        send_msg(&c, &Msg::Req(Req::Status { target: "db" }), &[]);
        r.pump();
    }
    assert_eq!(r.driver.server.connections(), 0);
}

#[test]
fn a_refresh_fd_of_garbage_is_invalid() {
    let mut r = rig(&["db"], Limits::default(), Sim::new());
    r.root();
    r.advance(5);
    let c = r.connect();
    // A regular file that is not a database: the validator's verdict.
    refresh(&mut r, &c, &memfd(&[7u8; 10]));
    let (code, detail, _) = error_of(&c);
    assert_eq!(code, ErrorCode::Invalid);
    assert!((2..=18).contains(&detail), "{detail}");
    // A pipe is not read at all (it might never end).
    let (pipe_r, pipe_w) = qinit_sys::fd::pipe(libc_cloexec()).unwrap();
    std::fs::File::from(pipe_w).write_all(&[7u8; 10]).unwrap();
    refresh(&mut r, &c, &pipe_r);
    assert_eq!(error_of(&c), (ErrorCode::Invalid, 20, 1));
    assert_eq!(r.colony.state(idx(&r.colony, "db")), Some(State::Ready));
}

#[test]
fn a_refresh_fd_over_max_db_read_is_invalid() {
    let mut r = rig(&[], Limits::default(), Sim::new());
    r.root();
    let c = r.connect();
    refresh(&mut r, &c, &memfd(&vec![0u8; MAX_DB_READ + 1]));
    assert_eq!(error_of(&c), (ErrorCode::Invalid, 19, 1));
}

#[test]
fn the_idle_driver_returns_without_sleeping() {
    let mut r = rig(&[], Limits::default(), Sim::new());
    r.pump();
    r.pump();
    assert_eq!(r.driver.server.connections(), 0);
}

#[test]
fn launched_carries_the_pidfd_over_the_socket() {
    let mut sim = Sim::new();
    sim.instance_script = Script {
        ready_after_ms: None,
        ..Script::default()
    };
    // The sim hands out the read end of a pipe in place of a pidfd.
    let (pipe_r, pipe_w) = qinit_sys::fd::pipe(libc_cloexec()).unwrap();
    sim.pidfds.push_back(pipe_r);
    let mut r = rig(&[], Limits::default(), sim);
    r.root();
    let c = r.connect();
    let req = Req::Launch {
        frame: "backup",
        argv_tail: StrList::new(b""),
        env_add: StrList::new(b""),
        fd_roles: 0,
        wait_ms: 1000,
        flags: 1,
    };
    send_msg(&c, &Msg::Req(req), &[]);
    r.pump();
    let mut buf = vec![0u8; MAX_MESSAGE];
    let got = recv(c.as_fd(), &mut buf).unwrap();
    assert_eq!(got.fds.len(), 1, "the pidfd travels with Launched");
    let Msg::Rep(Rep::Launched { id }) = decode(&buf[..got.len], got.fds.len()).unwrap() else {
        panic!("expected Launched");
    };
    assert_eq!(id, 1);
    // The descriptor is the pipe: writing to it is seen by the read end the client got.
    let mut w = std::fs::File::from(pipe_w);
    w.write_all(b"x").unwrap();
    let mut file = std::fs::File::from(got.fds.into_iter().next().unwrap());
    let mut one = [0u8; 1];
    assert_eq!(file.read(&mut one).unwrap(), 1);
    // Without the flag no descriptor travels.
    let c2 = r.connect();
    let plain = Req::Launch {
        frame: "backup",
        argv_tail: StrList::new(b""),
        env_add: StrList::new(b""),
        fd_roles: 0,
        wait_ms: 1000,
        flags: 0,
    };
    send_msg(&c2, &Msg::Req(plain), &[]);
    r.pump();
    let got = recv(c2.as_fd(), &mut buf).unwrap();
    assert!(got.fds.is_empty());
}
