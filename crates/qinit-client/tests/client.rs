// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! The client against the real server, over a real socket, with the colony on a thread.
#[path = "../../qinit-colony/tests/common/mod.rs"]
mod common;

use common::*;
use qinit_client::{
    Action, Begun, Client, ClientError, ErrorCode, LaunchArgs, LaunchOutcome, Mode, Outcome,
    Started, Status, Wait,
};
use qinit_colony::sim::{Script, Sim, advance_outcome};
use qinit_colony::{Colony, Peer};
use qinit_ipc::listen_seqpacket;
use qinit_proto::Limits;
use qinit_proto::testing::Driver;
use std::ffi::CString;
use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::thread::JoinHandle;
use std::time::Duration;

fn frames() -> String {
    "[worker.db]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/db\"]\n\
     [worker.app]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/app\"]\n\
     deps = [{ group = \"require_all\", edges = [{ to = \"db\" }] }]\n\
     [forager.backup]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/backup\"]\n\
     [forager.backup.launch]\nconcurrency = 2\nargv_tail = 2\nenv = [\"TARGET\"]\nfds = [\"stdout\"]\n"
        .to_owned()
}

/// A server on a thread, until dropped.
struct Served {
    path: PathBuf,
    stop: Option<OwnedFd>,
    thread: Option<JoinHandle<Colony<Sim>>>,
    _dir: PathBuf,
}

impl Served {
    fn start(enable: &[&str], root: bool, instance: Script) -> Served {
        Served::start_with(enable, root, instance, Vec::new())
    }

    /// As [`Served::start`], with the pidfds the simulated effects hand out.
    fn start_with(enable: &[&str], root: bool, instance: Script, pidfds: Vec<OwnedFd>) -> Served {
        let dir = std::env::temp_dir().join(format!(
            "qinit-client-{}-{}",
            std::process::id(),
            std::thread::current()
                .name()
                .unwrap_or("t")
                .replace("::", "-")
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("colony");
        let c = CString::new(path.to_str().unwrap()).unwrap();
        let listener = listen_seqpacket(&c, 16).unwrap();
        let (mut colony, _) = boot(&frames(), enable, Sim::new());
        colony.effects.instance_script = instance;
        colony.effects.pidfds.extend(pidfds);
        let mut driver = Driver::new(listener, Limits::default()).unwrap();
        if root {
            driver.identity = Some(Peer {
                uid: 0,
                gid: 0,
                pid: 1,
            });
        }
        let (stop_r, stop_w) = qinit_sys::fd::pipe(0o2_000_000).unwrap();
        let thread = std::thread::spawn(move || {
            driver
                .serve_until(&mut colony, stop_r.as_fd(), |c| {
                    let out = advance_outcome(c, 0);
                    (c.effects.now(), out)
                })
                .unwrap();
            colony
        });
        Served {
            path,
            stop: Some(stop_w),
            thread: Some(thread),
            _dir: dir,
        }
    }

    fn client(&self) -> Client {
        Client::connect(&self.path).unwrap()
    }

    fn finish(mut self) -> Colony<Sim> {
        drop(self.stop.take());
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn instant(exit: Option<i32>) -> Script {
    Script {
        ready_after_ms: None,
        exit_after: exit.map(|s| (0, Some(s))),
        ..Script::default()
    }
}

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
