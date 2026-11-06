// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Logger pipes: one per logger, held by colony, routed into producers and the logger.
mod common;

use common::*;
use qinit_cell::ReadyMode;
use qinit_colony::{Effects, NodeSpec};
use qinit_colonyd::effects::RealEffects;
use qinit_colonyd::pipes::Pipes;
use qinit_db::{Model, Route};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt;

/// `logd` is node 0 and `web` node 1; `web` writes both streams to `logd`'s pipe.
fn with_logger() -> Model {
    let mut web = worker("web");
    web.output = Some(0);
    web.errors = Some(0);
    let mut m = model(vec![worker("logd"), web]);
    m.routes = vec![Route::Pipe(0)];
    m
}

/// The same graph with `extra` unrelated nodes in front, so every index moves.
fn renumbered(extra: usize) -> Model {
    let mut web = worker("web");
    web.output = Some(0);
    web.errors = Some(0);
    let mut nodes: Vec<_> = (0..extra).map(|i| worker(&format!("a{i}"))).collect();
    nodes.push(worker("logd"));
    nodes.push(web);
    let mut m = model(nodes);
    m.routes = vec![Route::Pipe(u32::try_from(extra).unwrap())];
    m
}

fn id(fd: BorrowedFd<'_>) -> (u64, u64) {
    let m = std::fs::File::from(fd.try_clone_to_owned().unwrap())
        .metadata()
        .unwrap();
    (m.dev(), m.ino())
}

fn ino(fd: &OwnedFd) -> (u64, u64) {
    id(fd.as_fd())
}

fn nonblocking_read(fd: BorrowedFd<'_>) -> Result<usize, qinit_sys::Errno> {
    let mut b = [0u8; 8];
    qinit_sys::event::read(fd, &mut b)
}

#[test]
fn one_pipe_per_logger_and_both_ends_held() {
    let mut p = Pipes::default();
    p.rebuild(&with_logger()).unwrap();
    let (w, r) = (p.writer(0).unwrap(), p.reader(0).unwrap());
    assert_ne!(w.as_raw_fd(), r.as_raw_fd());
    assert!(p.writer(1).is_none(), "a producer is not a logger");
    assert!(p.reader(1).is_none());
    qinit_sys::fd::write_all(w, b"hi").unwrap();
    qinit_sys::fd::set_nonblocking(r).unwrap();
    assert_eq!(
        nonblocking_read(r),
        Ok(2),
        "one pipe: what goes in comes out"
    );
}

#[test]
fn a_refresh_keeps_a_kept_loggers_pipe() {
    let mut p = Pipes::default();
    p.rebuild(&with_logger()).unwrap();
    let before = id(p.writer(0).unwrap());
    p.rebuild(&renumbered(3)).unwrap();
    assert!(p.writer(0).is_none(), "its old index is something else now");
    assert_eq!(
        id(p.writer(3).unwrap()),
        before,
        "the same pipe under its new index"
    );
    assert_eq!(id(p.reader(3).unwrap()).0, before.0);
}

#[test]
fn a_removed_logger_loses_its_pipe() {
    let mut p = Pipes::default();
    p.rebuild(&with_logger()).unwrap();
    // A duplicate of the read end only: it sees end-of-file once every writer is closed.
    let r = qinit_sys::fd::dup_above(p.reader(0).unwrap(), 0).unwrap();
    qinit_sys::fd::set_nonblocking(&r).unwrap();
    assert_eq!(
        nonblocking_read(r.as_fd()),
        Err(qinit_sys::Errno(libc::EAGAIN))
    );
    p.rebuild(&model(vec![worker("web")])).unwrap();
    assert!(p.writer(0).is_none() && p.reader(0).is_none());
    assert_eq!(
        nonblocking_read(r.as_fd()),
        Ok(0),
        "the held write end was closed"
    );
}

#[test]
fn remap_moves_the_index_not_the_pipe() {
    let mut p = Pipes::default();
    p.rebuild(&with_logger()).unwrap();
    let before = id(p.writer(0).unwrap());
    p.remap(&[u32::MAX, 0]);
    assert_eq!(id(p.writer(1).unwrap()), before);
    assert!(p.writer(0).is_none());
    p.remap(&[u32::MAX, u32::MAX]);
    assert!(
        p.writer(1).is_none(),
        "a node absent from the map has no pipe"
    );
}

fn rig(m: &Model, tmp: &Tmp) -> RealEffects<FakeCells> {
    let events = qinit_event::Loop::new().unwrap();
    let mut fx = RealEffects::new(
        FakeCells::default(),
        "/usr/lib/qinit/overseer".into(),
        tmp.0.clone(),
        events,
        9,
    )
    .unwrap();
    fx.pipes.rebuild(m).unwrap();
    fx
}

fn spec(m: &Model, i: usize) -> NodeSpec {
    spec_of(m, i)
}

#[test]
fn a_producer_routes_the_loggers_write_end() {
    let tmp = Tmp::new("producer");
    let m = with_logger();
    let mut fx = rig(&m, &tmp);
    let pipe = id(fx.pipes.writer(0).unwrap());
    fx.start(1, &spec(&m, 1), &m).unwrap();
    let sp = &fx.cells.spawned[0];
    let numbers: Vec<i32> = sp.fds.iter().map(|(_, n)| *n).collect();
    assert_eq!(
        numbers,
        [3, 4, 6],
        "stderr follows stdout: one descriptor, not two"
    );
    assert_eq!(
        ino(&sp.fds[2].0),
        pipe,
        "the descriptor at 6 is the logger's pipe"
    );
    assert!(fx.pipes.writer(0).is_some(), "colony kept its own end");
    let req = qinit_ipc::memfd::read_all(sp.fds[0].0.as_fd(), 1 << 20).unwrap();
    assert_eq!(qinit_overseer_core::decode(&req), Ok(()));
}

#[test]
fn the_logger_reads_its_pipe_as_standard_input() {
    let tmp = Tmp::new("logger");
    let m = with_logger();
    let mut fx = rig(&m, &tmp);
    let pipe = id(fx.pipes.reader(0).unwrap());
    fx.start(0, &spec(&m, 0), &m).unwrap();
    let sp = &fx.cells.spawned[0];
    let numbers: Vec<i32> = sp.fds.iter().map(|(_, n)| *n).collect();
    assert_eq!(numbers, [3, 4, 6]);
    assert_eq!(ino(&sp.fds[2].0), pipe, "the read end, as stdin");
    assert_eq!(fx.cells.calls[2], common::Call::Spawn(0, ReadyMode::Pipe));
}

#[test]
fn a_producer_without_its_loggers_pipe_does_not_start() {
    let tmp = Tmp::new("missing");
    let m = with_logger();
    let events = qinit_event::Loop::new().unwrap();
    let mut fx =
        RealEffects::new(FakeCells::default(), "/o".into(), tmp.0.clone(), events, 9).unwrap();
    assert!(
        fx.start(1, &spec(&m, 1), &m).is_err(),
        "no rebuild, no pipe"
    );
    assert!(fx.cells.calls.is_empty(), "nothing was created");
}

#[test]
fn separate_output_and_error_routes_get_two_descriptors() {
    let tmp = Tmp::new("two");
    let mut web = worker("web");
    web.output = Some(0);
    web.errors = Some(1);
    let mut m = model(vec![worker("logd"), worker("logd2"), web]);
    m.routes = vec![Route::Pipe(0), Route::Pipe(1)];
    let mut fx = rig(&m, &tmp);
    let (out, err) = (
        id(fx.pipes.writer(0).unwrap()),
        id(fx.pipes.writer(1).unwrap()),
    );
    fx.start(2, &spec(&m, 2), &m).unwrap();
    let sp = &fx.cells.spawned[0];
    let numbers: Vec<i32> = sp.fds.iter().map(|(_, n)| *n).collect();
    assert_eq!(numbers, [3, 4, 6, 7]);
    assert_eq!(ino(&sp.fds[2].0), out);
    assert_eq!(ino(&sp.fds[3].0), err);
}

#[test]
fn a_frame_instance_without_caller_streams_uses_its_loggers_pipe() {
    let tmp = Tmp::new("instpipe");
    let mut job = worker("job");
    job.kind = qinit_db::Kind::Forager;
    job.ready = qinit_db::Ready::Exit;
    job.output = Some(0);
    let mut m = model(vec![job, worker("logd")]);
    m.routes = vec![Route::Pipe(1)];
    let mut fx = rig(&m, &tmp);
    let pipe = id(fx.pipes.writer(1).unwrap());
    let spec = qinit_colony::InstanceSpec {
        name: "job#1".into(),
        frame: 0,
        node: spec_of(&m, 0),
        argv_tail: Vec::new(),
        env_add: Vec::new(),
        fds: [None, None, None],
        request: None,
        memory_max_kib: 0,
        pids_max: 0,
        ready_fd: None,
    };
    fx.start_instance(0, spec, &m).unwrap();
    let sp = &fx.cells.spawned[0];
    let numbers: Vec<i32> = sp.fds.iter().map(|(_, n)| *n).collect();
    assert_eq!(numbers, [3, 4, 6]);
    assert_eq!(ino(&sp.fds[2].0), pipe);
}
