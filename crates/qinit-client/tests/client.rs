// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! The client against the real server, over a real socket, with the colony on a thread.
#[path = "common/served.rs"]
mod served;

use qinit_client::{
    Action, Begun, ClientError, ErrorCode, Event, LaunchArgs, LaunchOutcome, Mode, Next, Outcome,
    Report, Scope, Started, Status, Wait,
};
use qinit_colony::sim::Script;
use served::common::*;
use served::*;
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::time::Duration;

fn my_uid() -> u32 {
    std::fs::metadata("/proc/self").unwrap().uid()
}

#[test]
fn client_status_and_list() {
    let s = Served::start(&["db"], false, instant(None));
    let mut c = s.client();
    let Status::Node(n) = c.status("db").unwrap() else {
        panic!("not a node")
    };
    assert_eq!((n.name.as_str(), n.state.state), ("db", 3));
    let names: Vec<String> = c.list(0).unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, ["app", "backup", "db"]);
    let foragers = c.list(2).unwrap();
    assert_eq!(foragers.len(), 1);
    assert_eq!(
        c.status("nothing").unwrap_err(),
        ClientError::Server(ErrorCode::UnknownNode, 0)
    );
}

#[test]
fn client_change_settled() {
    let s = Served::start(&[], true, instant(None));
    let mut c = s.client();
    let out = c
        .change("app", Action::Start, Wait::Settled(Duration::from_secs(5)))
        .unwrap();
    assert!(
        matches!(out, Outcome::Settled(w) if w.state == 3),
        "{out:?}"
    );
    assert_eq!(
        c.change("db", Action::Stop, Wait::Now).unwrap(),
        Outcome::Accepted
    );
}

#[test]
fn a_wait_longer_than_the_protocol_allows_is_clamped() {
    let s = Served::start(&[], true, instant(None));
    let mut c = s.client();
    let hour = Wait::Settled(Duration::from_secs(3600));
    let out = c.change("app", Action::Start, hour).unwrap();
    assert!(
        matches!(out, Outcome::Settled(w) if w.state == 3),
        "{out:?}"
    );
}

#[test]
fn client_launch_exits() {
    let s = Served::start(&[], true, instant(Some(7)));
    let mut c = s.client();
    let got = c
        .launch("backup", &LaunchArgs::default(), Duration::from_secs(5))
        .unwrap();
    assert_eq!(got, LaunchOutcome::Exited { id: 1, status: 7 });
}

#[test]
fn client_launch_routes_a_pipe_for_stdout() {
    let s = Served::start(&[], true, instant(Some(0)));
    let mut c = s.client();
    let (r, w) = qinit_sys::fd::pipe(0o2_000_000).unwrap();
    let args = LaunchArgs {
        stdout: Some(w.as_fd()),
        ..LaunchArgs::default()
    };
    let got = c.launch("backup", &args, Duration::from_secs(5)).unwrap();
    assert!(matches!(got, LaunchOutcome::Exited { status: 0, .. }));
    drop(w);
    drop(c);
    // The server's copy went with the instance's cell: the pipe ends.
    let colony = s.finish();
    drop(colony);
    let mut text = String::new();
    std::fs::File::from(r).read_to_string(&mut text).unwrap();
    assert_eq!(text, "");
}

#[test]
fn client_refresh() {
    let s = Served::start(&["db"], true, instant(None));
    let mut c = s.client();
    let changed = frames().replace("/bin/db", "/bin/db2");
    let memfd = qinit_sys::memfd::sealed(c"db", &database(&changed, &["db"])).unwrap();
    let out = c
        .refresh(memfd.as_fd(), Wait::Settled(Duration::from_secs(5)))
        .unwrap();
    assert!(matches!(out, Outcome::Settled(_)), "{out:?}");
    drop(c);
    let colony = s.finish();
    assert_eq!(
        colony.model().nodes[colony.node_index("db").unwrap() as usize].exec,
        ["/bin/db2"]
    );
}

#[test]
fn client_shutdown() {
    let s = Served::start(&["db"], true, instant(None));
    let mut c = s.client();
    let out = c
        .shutdown(Mode::Reboot, Wait::Settled(Duration::from_secs(5)))
        .unwrap();
    assert!(matches!(out, Outcome::Settled(_)), "{out:?}");
    drop(c);
    let colony = s.finish();
    assert_eq!(
        colony.shutdown_mode(),
        Some(qinit_colony::ShutdownMode::Reboot)
    );
}

#[test]
fn server_errors_surface_as_client_errors() {
    if my_uid() == 0 {
        eprintln!("skipped: the test needs a non-root user");
        return;
    }
    let s = Served::start(&["db"], false, instant(None));
    let mut c = s.client();
    assert_eq!(
        c.change("db", Action::Stop, Wait::Now).unwrap_err(),
        ClientError::Server(ErrorCode::Denied, 0)
    );
    // Reading still works on the same connection.
    assert!(matches!(c.status("db").unwrap(), Status::Node(_)));
}

#[test]
fn begin_launch_returns_the_pidfd_and_finish_the_end() {
    // The sim stands a pipe in for the pidfd: its read end is what the client receives.
    let (pipe_r, pipe_w) = qinit_sys::fd::pipe(0o2_000_000).unwrap();
    let s = Served::start_with(&[], true, instant(Some(5)), vec![pipe_r]);
    let mut c = s.client();
    let args = LaunchArgs::default();
    let Begun::Started(Started { id, pidfd }) = c
        .begin_launch("backup", &args, true, Duration::from_secs(5))
        .unwrap()
    else {
        panic!("the launch failed");
    };
    let pidfd = pidfd.expect("a pidfd came with Launched");
    let mut w = std::fs::File::from(pipe_w);
    std::io::Write::write_all(&mut w, b"y").unwrap();
    let mut one = [0u8; 1];
    assert_eq!(std::fs::File::from(pidfd).read(&mut one).unwrap(), 1);
    assert_eq!(
        c.finish(id).unwrap(),
        LaunchOutcome::Exited { id, status: 5 }
    );
}

#[test]
fn begin_launch_without_the_flag_has_no_pidfd_and_a_failed_launch_none() {
    let s = Served::start(&[], true, instant(Some(0)));
    let mut c = s.client();
    let Begun::Started(started) = c
        .begin_launch(
            "backup",
            &LaunchArgs::default(),
            false,
            Duration::from_secs(5),
        )
        .unwrap()
    else {
        panic!()
    };
    assert!(started.pidfd.is_none());
    c.finish(started.id).unwrap();
    let (pipe_r, _pipe_w) = qinit_sys::fd::pipe(0o2_000_000).unwrap();
    let failing = Script {
        spawn_fails: true,
        ..Script::default()
    };
    let s = Served::start_with(&[], true, failing, vec![pipe_r]);
    let mut c = s.client();
    let got = c
        .begin_launch(
            "backup",
            &LaunchArgs::default(),
            true,
            Duration::from_secs(5),
        )
        .unwrap();
    assert!(matches!(got, Begun::Failed { errno: 2, .. }), "{got:?}");
}

#[test]
fn begin_run_sends_the_sealed_request_first() {
    use qinit_client::RunArgs;
    use qinit_launch::RequestSpec;
    let s = Served::start(&[], true, instant(Some(0)));
    let mut c = s.client();
    let request = RequestSpec {
        argv: vec!["/bin/job".into()],
        user: "svc".into(),
        ..RequestSpec::default()
    };
    // The server read the memfd and the decoder accepted it; the colony has no policy, so the
    // policy refuses (clause 1, no policy): the request travelled intact and first.
    let got = c.begin_run(
        "job",
        &request,
        &RunArgs::default(),
        false,
        Duration::from_secs(5),
    );
    assert_eq!(got.err(), Some(ClientError::Server(ErrorCode::Denied, 1)));
    // A stream descriptor the request does not name is refused before the policy: detail 0.
    let (_r, w) = qinit_sys::fd::pipe(0o2_000_000).unwrap();
    let mut c = s.client();
    let args = RunArgs {
        stdout: Some(w.as_fd()),
        ..RunArgs::default()
    };
    let got = c.run("job", &request, &args, Duration::from_secs(5));
    assert_eq!(got.err(), Some(ClientError::Server(ErrorCode::Denied, 0)));
}

#[test]
fn begin_run_bytes_sends_the_given_bytes_sealed() {
    use qinit_client::RunArgs;
    use qinit_launch::RequestSpec;
    let s = Served::start(&[], true, instant(Some(0)));
    let mut c = s.client();
    // The client's descriptor is the socket, idle between calls.
    assert!(!qinit_ipc::poll_readable(c.as_fd(), 0).unwrap());
    let bytes = RequestSpec {
        argv: vec!["/bin/job".into()],
        user: "svc".into(),
        ..RequestSpec::default()
    }
    .bytes()
    .unwrap();
    // The bytes decode: the policy refuses them (clause 1, no policy), as with `begin_run`.
    let got = c.begin_run_bytes(
        "job",
        &bytes,
        &RunArgs::default(),
        false,
        Duration::from_secs(5),
    );
    assert_eq!(got.err(), Some(ClientError::Server(ErrorCode::Denied, 1)));
    // Bytes that are not a request: refused as a header that does not decode (detail 1).
    let mut c = s.client();
    let got = c.begin_run_bytes(
        "job",
        b"not a request",
        &RunArgs::default(),
        false,
        Duration::from_secs(5),
    );
    assert_eq!(got.err(), Some(ClientError::Server(ErrorCode::Invalid, 1)));
}

#[test]
fn pidfd_exit_is_exported_and_works_on_a_spawned_child() {
    let mut child = std::process::Command::new("sh")
        .args(["-c", "exit 5"])
        .spawn()
        .unwrap();
    let fd = qinit_sys::proc::pidfd_open(child.id().cast_signed()).unwrap();
    let live = qinit_client::pidfd_exit(&fd).unwrap();
    assert!(matches!(
        live,
        qinit_client::PidfdExit::Running | qinit_client::PidfdExit::Unsupported
    ));
    child.wait().unwrap();
    match qinit_client::pidfd_exit(&fd).unwrap() {
        qinit_client::PidfdExit::Exited(status) => assert_eq!((status >> 8) & 0xff, 5),
        other => assert_eq!(other, qinit_client::PidfdExit::Unsupported),
    }
}

#[test]
fn begin_run_wait_ready_sets_flag_bit_1_and_finish_returns_ready() {
    use qinit_client::RunArgs;
    use qinit_launch::RequestSpec;
    let ready = Script {
        ready_after_ms: Some(0),
        ..Script::default()
    };
    let s = Served::start_policy(&[], true, ready, Vec::new(), Some("default = \"allow\"\n"));
    let request = RequestSpec {
        argv: vec!["/bin/job".into()],
        user: "svc".into(),
        ready_fd: Some(8),
        ..RequestSpec::default()
    };
    // Without the flag a readiness pipe is refused (detail 0).
    let got = s
        .client()
        .run("job", &request, &RunArgs::default(), Duration::from_secs(5));
    assert_eq!(got.err(), Some(ClientError::Server(ErrorCode::Denied, 0)));
    // With it the server accepts, and `finish` reads the `Settled` reply as `Ready`.
    let args = RunArgs {
        wait_ready: true,
        ..RunArgs::default()
    };
    let mut c = s.client();
    let Begun::Started(Started { id, .. }) = c
        .begin_run("job", &request, &args, false, Duration::from_secs(5))
        .unwrap()
    else {
        panic!("not started")
    };
    assert_eq!(c.finish(id).unwrap(), LaunchOutcome::Ready { id });
}

#[test]
fn watch_one_node_gets_current_then_the_change() {
    let s = Served::start(&["db"], true, instant(None));
    let mut w = s.client().watch(Scope::Target("db")).unwrap();
    assert!(
        matches!(w.next(Some(Duration::from_secs(5))).unwrap(), Next::Event(Event::Node { ref name, report: Report::Current, .. }) if name == "db")
    );
    s.client().change("db", Action::Stop, Wait::Now).unwrap();
    let mut saw_stop = false;
    for _ in 0..8 {
        if let Next::Event(Event::Node {
            report: Report::Stopped,
            ..
        }) = w.next(Some(Duration::from_secs(5))).unwrap()
        {
            saw_stop = true;
            break;
        }
    }
    assert!(saw_stop);
}

#[test]
fn watch_next_times_out_without_an_event() {
    let s = Served::start(&["db"], true, instant(None));
    let mut w = s.client().watch(Scope::All).unwrap();
    // Notices still in flight from the harness's start-up (boot and timer reports) come first,
    // then silence.
    let mut quiet = false;
    for _ in 0..16 {
        if matches!(
            w.next(Some(Duration::from_millis(50))).unwrap(),
            Next::Timeout
        ) {
            quiet = true;
            break;
        }
    }
    assert!(quiet);
}

#[test]
fn an_instance_watch_ends_at_the_exit() {
    let s = Served::start(&[], true, instant(Some(5)));
    let mut c = s.client();
    let Begun::Started(Started { id, .. }) = c
        .begin_launch(
            "backup",
            &LaunchArgs::default(),
            false,
            Duration::from_secs(5),
        )
        .unwrap()
    else {
        panic!("the launch failed");
    };
    let mut w = s
        .client()
        .watch(Scope::Target(&format!("backup#{id}")))
        .unwrap();
    match w.next(Some(Duration::from_secs(5))).unwrap() {
        // The exit as it happens, or (an instance that had already exited) at once; either
        // way the first notice says exited, with the status, and ends the stream.
        Next::Event(Event::Instance {
            report: Report::Exited,
            state: 4,
            status: Some(5),
            ..
        }) => {}
        Next::Ended(st) => assert_eq!(st.state, 4),
        other => panic!("unexpected first item {other:?}"),
    }
    assert_eq!(
        w.next(Some(Duration::from_secs(1))).unwrap_err(),
        ClientError::Unexpected
    );
}

#[test]
fn a_refused_watch_returns_the_client() {
    let s = Served::start(&["db"], true, instant(None));
    let Err(refused) = s.client().watch(Scope::Target("nope")) else {
        panic!("an unknown target is refused");
    };
    assert_eq!(
        refused.error,
        ClientError::Server(ErrorCode::UnknownNode, 0)
    );
    let mut c = refused.client.expect("the connection is still good");
    assert!(matches!(c.status("db"), Ok(Status::Node(_))));
}

#[test]
fn a_lost_connection_returns_no_client() {
    let s = Served::start(&["db"], true, instant(None));
    let c = s.client();
    // Colony goes away, and its end of the connection with it.
    drop(s.finish());
    let Err(refused) = c.watch(Scope::All) else {
        panic!("a closed connection cannot watch");
    };
    assert!(refused.client.is_none());
    assert!(matches!(
        ClientError::from(refused),
        ClientError::Unexpected | ClientError::Io(_)
    ));
}

#[test]
fn a_watch_of_everything_keeps_watching_after_an_instance_exit() {
    let s = Served::start(&["db"], true, instant(Some(0)));
    // `watch` returns after `Accepted`: the watcher is in place before the launch.
    let mut w = s.client().watch(Scope::All).unwrap();
    let got = s
        .client()
        .launch("backup", &LaunchArgs::default(), Duration::from_secs(5))
        .unwrap();
    assert!(matches!(got, LaunchOutcome::Exited { .. }), "{got:?}");
    loop {
        if let Next::Event(Event::Instance {
            report: Report::Exited,
            ..
        }) = w.next(Some(Duration::from_secs(5))).unwrap()
        {
            break;
        }
    }
    // The stream goes on: a change after the exit still arrives.
    s.client().change("db", Action::Stop, Wait::Now).unwrap();
    loop {
        match w.next(Some(Duration::from_secs(5))).unwrap() {
            Next::Event(Event::Node {
                ref name,
                report: Report::Stopped,
                ..
            }) if name == "db" => break,
            Next::Timeout => panic!("no notice after the exit"),
            _ => {}
        }
    }
}
