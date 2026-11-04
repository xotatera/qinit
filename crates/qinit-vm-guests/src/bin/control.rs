// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The control protocol with real peers on a real kernel (spec 2026-11-04 §8): root and a user
//! other than root connect to the server over a `SOCK_SEQPACKET` socket, and the server takes
//! each peer's `SO_PEERCRED` and `SO_PEERPIDFD`. Colony runs on simulated cells here; the real
//! cells are sub-project 7's. No threads: the server is this process, and each client is a
//! forked process whose exit status is the verdict.
use qinit_client::{Action, Client, ClientError, ErrorCode, Status, Wait};
use qinit_colony::Colony;
use qinit_colony::sim::{Sim, advance_outcome};
use qinit_db::{
    Cred, Kind, Model, Node, Ready, Restart, RestartPolicy, Seccomp, Securebits, Stop, StopMode,
    write,
};
use qinit_ipc::listen_seqpacket;
use qinit_proto::Limits;
use qinit_proto::testing::Driver;
use qinit_vm_guests::run;
use std::ffi::CString;
use std::os::fd::AsFd;
use std::path::Path;

const SOCKET: &str = "/tmp/colony";

fn node(name: &str, kind: Kind) -> Node {
    Node {
        kind,
        name: name.to_owned(),
        exec: vec![format!("/bin/{name}")],
        ready: Ready::Exit,
        restart: Restart {
            policy: RestartPolicy::Never,
            max: 0,
            window_ms: 0,
            delay_ms: 1000,
        },
        stop: Stop {
            mode: StopMode::Main,
            grace_ms: 10_000,
        },
        start_timeout_ms: 0,
        output: None,
        errors: None,
        cred: Some(0),
        groups: Vec::new(),
        memory_max_kib: 0,
        pids_max: 0,
        instance_of: None,
        env: Vec::new(),
        cwd: "/".into(),
        umask: 0o027,
        rlimits: [None; 16],
        reload: None,
        launch: None,
    }
}

fn world() -> Result<Colony<Sim>, String> {
    let model = Model {
        nodes: vec![node("db", Kind::Worker)],
        creds: vec![Cred {
            user: "svc".into(),
            caps: 0,
            securebits: Securebits::None,
            nnp: true,
            ns: 0,
            seccomp: Seccomp::None,
            paths: Vec::new(),
        }],
        routes: Vec::new(),
        enabled: vec![0],
        presyslog: Vec::new(),
    };
    let bytes = write(&model).map_err(|e| format!("{e:?}"))?;
    let (colony, _) =
        Colony::load(bytes, &[], Sim::new(), 0).map_err(|e| format!("load: {e:?}"))?;
    Ok(colony)
}

/// Runs the server in this process until the forked client `client` exits, and returns the
/// client's exit status (0 is success).
fn serve_while(client: impl FnOnce() -> i32) -> Result<(), String> {
    let _ = std::fs::remove_file(SOCKET);
    let path = CString::new(SOCKET).map_err(|e| e.to_string())?;
    // connect(2) needs write permission on the socket file: let the unprivileged clients in.
    let _ = qinit_sys::limits::umask(0);
    let listener = listen_seqpacket(&path, 16).map_err(|e| format!("listen: {e}"))?;
    let mut colony = world()?;
    let mut driver = Driver::new(listener, Limits::default()).map_err(|e| format!("{e}"))?;
    let pid = qinit_sys::proc::fork().map_err(|e| format!("fork: {e}"))?;
    if pid == 0 {
        qinit_sys::proc::exit_now(client());
    }
    let pidfd = qinit_sys::proc::pidfd_open(pid).map_err(|e| format!("pidfd: {e}"))?;
    driver
        .serve_until(&mut colony, pidfd.as_fd(), |c| {
            let out = advance_outcome(c, 0);
            (c.effects.now(), out)
        })
        .map_err(|e| format!("serve: {e}"))?;
    let status = qinit_sys::proc::wait_pidfd(&pidfd).map_err(|e| format!("wait: {e}"))?;
    if status == 0 {
        Ok(())
    } else {
        Err(format!("the client failed (wait status {status})"))
    }
}

fn connect() -> Result<Client, String> {
    Client::connect(Path::new(SOCKET)).map_err(|e| format!("connect: {e}"))
}

/// Runs `body` in a forked process that has become `uid`; its exit status is 0 or 1.
fn as_user(uid: u32, body: impl FnOnce() -> bool) -> bool {
    let Ok(pid) = qinit_sys::proc::fork() else {
        return false;
    };
    if pid == 0 {
        let dropped = qinit_sys::cred::setgroups(&[]).is_ok()
            && qinit_sys::cred::setresgid(uid).is_ok()
            && qinit_sys::cred::setresuid(uid).is_ok();
        qinit_sys::proc::exit_now(i32::from(!(dropped && body())));
    }
    let Ok(pidfd) = qinit_sys::proc::pidfd_open(pid) else {
        return false;
    };
    matches!(qinit_sys::proc::wait_pidfd(&pidfd), Ok(0))
}

fn denied(r: Result<qinit_client::Outcome, ClientError>) -> bool {
    r == Err(ClientError::Server(ErrorCode::Denied, 0))
}

fn root_may_change_and_non_root_is_denied() -> Result<(), String> {
    serve_while(|| {
        let Ok(mut root) = connect() else { return 1 };
        let changed = root.change("db", Action::Stop, Wait::Now);
        let listed = root.status("db").is_ok();
        let user_ok = as_user(1000, || {
            let Ok(mut c) = connect() else { return false };
            denied(c.change("db", Action::Start, Wait::Now))
                && denied(c.shutdown(qinit_client::Mode::Halt, Wait::Now))
                && matches!(c.status("db"), Ok(Status::Node(_)))
        });
        i32::from(!(changed.is_ok() && listed && user_ok))
    })
}

fn both_peers_get_a_pidfd() -> Result<(), String> {
    // A connection whose pidfd cannot be had is closed (R2): every peer here is served.
    serve_while(|| {
        let root_ok = connect().is_ok_and(|mut c| c.status("db").is_ok());
        let user_ok = as_user(1000, || connect().is_ok_and(|mut c| c.status("db").is_ok()));
        i32::from(!(root_ok && user_ok))
    })
}

fn root_is_not_limited_per_uid() -> Result<(), String> {
    serve_while(|| {
        let clients: Vec<Option<Client>> = (0..5).map(|_| connect().ok()).collect();
        let all = clients
            .into_iter()
            .all(|c| c.is_some_and(|mut c| c.status("db").is_ok()));
        let fifth_user = as_user(1000, || {
            let held: Vec<Option<Client>> = (0..5).map(|_| connect().ok()).collect();
            // Four are served; the fifth connection of one user gets `Full`.
            let served = held
                .into_iter()
                .map(|c| c.is_some_and(|mut c| c.status("db").is_ok()))
                .filter(|ok| *ok)
                .count();
            served == 4
        });
        i32::from(!(all && fifth_user))
    })
}

fn main() {
    run(
        "control",
        &[
            (
                "root_may_change_and_non_root_is_denied",
                root_may_change_and_non_root_is_denied,
            ),
            ("both_peers_get_a_pidfd", both_peers_get_a_pidfd),
            ("root_is_not_limited_per_uid", root_is_not_limited_per_uid),
        ],
    )
}
