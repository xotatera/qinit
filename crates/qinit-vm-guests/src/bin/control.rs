// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The control protocol with real peers on a real kernel (spec 2026-11-04 §8): root and a user
//! other than root connect to the server over a `SOCK_SEQPACKET` socket, and the server takes
//! each peer's `SO_PEERCRED` and `SO_PEERPIDFD`. Colony runs on simulated cells here; the real
//! cells are sub-project 7's. The server is this process, single-threaded, and each client is a
//! forked process whose exit status is the verdict (the `qctl watch` case runs its watch on a
//! thread of that client). `qctl` itself runs in-process, as root, for its compile and control
//! cases (spec 2026-11-05 §5).
use qinit_client::{
    Action, Begun, Client, ClientError, ErrorCode, Event, LaunchArgs, Next, Report, Scope, Started,
    StateWord, Status, Wait,
};
use qinit_colony::Colony;
use qinit_colony::sim::{Sim, advance_outcome};
use qinit_db::{
    Cred, Kind, Launch, Model, Node, Ready, Restart, RestartPolicy, Seccomp, Securebits, Stop,
    StopMode, UserMap, write,
};
use qinit_ipc::listen_seqpacket;
use qinit_proto::Limits;
use qinit_proto::testing::Driver;
use qinit_vm_guests::run;
use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::path::Path;
use std::time::Duration;

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
        nodes: vec![
            Node {
                launch: Some(Launch {
                    concurrency: 1,
                    argv_tail: 0,
                    env: Vec::new(),
                    fds: 0,
                }),
                ..node("backup", Kind::Forager)
            },
            node("db", Kind::Worker),
            // Ready by pipe, so a start reports `ready` (db, ready by exit, ends in `done`).
            Node {
                ready: Ready::Pipe,
                ..node("web", Kind::Worker)
            },
        ],
        creds: vec![Cred {
            user: "svc".into(),
            caps: 0,
            securebits: Securebits::None,
            nnp: true,
            ns: 0,
            seccomp: Seccomp::None,
            paths: Vec::new(),
            user_map: UserMap::Own,
            inside_uid: 0,
            inside_gid: 0,
        }],
        routes: Vec::new(),
        enabled: vec![1],
        presyslog: Vec::new(),
        policy: Some(qinit_db::Policy {
            allow_by_default: false,
            ceiling: [None; 16],
            rules: Vec::new(),
        }),
    };
    let bytes = write(&model).map_err(|e| format!("{e:?}"))?;
    let (colony, _) =
        Colony::load(bytes, &[], Sim::new(), 0).map_err(|e| format!("load: {e:?}"))?;
    Ok(colony)
}

/// Runs the server in this process until the forked client `client` exits, and returns the
/// client's exit status (0 is success).
fn serve_while(client: impl FnOnce() -> i32) -> Result<(), String> {
    serve_with(|_| Ok(()), client, |_| Ok(()))
}

/// As [`serve_while`], with `prepare` run on the colony before the client starts.
fn serve_with(
    prepare: impl FnOnce(&mut Colony<Sim>) -> Result<(), String>,
    client: impl FnOnce() -> i32,
    after: impl FnOnce(&mut Colony<Sim>) -> Result<(), String>,
) -> Result<(), String> {
    let _ = std::fs::remove_file(SOCKET);
    let path = CString::new(SOCKET).map_err(|e| e.to_string())?;
    // connect(2) needs write permission on the socket file: let the unprivileged clients in.
    let _ = qinit_sys::limits::umask(0);
    let listener = listen_seqpacket(&path, 16).map_err(|e| format!("listen: {e}"))?;
    let mut colony = world()?;
    prepare(&mut colony)?;
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
    if status != 0 {
        return Err(format!("the client failed (wait status {status})"));
    }
    after(&mut colony)
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

/// Whether `fd` polls readable within `ms` milliseconds; `None` when the poll itself failed.
fn readable(fd: BorrowedFd<'_>, ms: u64) -> Option<bool> {
    use qinit_sys::event::{epoll, epoll_add, epoll_wait, timer};
    let ep = epoll().ok()?;
    let clock = timer(Duration::from_millis(ms)).ok()?;
    epoll_add(&ep, fd.as_raw_fd(), libc::EPOLLIN as u32, 1).ok()?;
    epoll_add(&ep, clock.as_raw_fd(), libc::EPOLLIN as u32, 2).ok()?;
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 2];
    let n = epoll_wait(&ep, &mut events).ok()?;
    Some(events[..n].iter().any(|e| e.u64 == 1))
}

/// A launch with the pidfd flag hands the client a pidfd that is readable once the process ends.
fn a_launch_pidfd_polls_readable_at_exit() -> Result<(), String> {
    // The sim's stand-in for the instance's main process: a child that waits to be killed.
    let victim = qinit_sys::proc::fork().map_err(|e| format!("fork: {e}"))?;
    if victim == 0 {
        loop {
            qinit_sys::proc::pause();
        }
    }
    let victim_fd = qinit_sys::proc::pidfd_open(victim).map_err(|e| format!("pidfd: {e}"))?;
    let result = serve_with(
        |colony| {
            colony.effects.pidfds.push_back(victim_fd);
            Ok(())
        },
        || {
            let Ok(mut c) = connect() else { return 1 };
            let Ok(Begun::Started(Started {
                pidfd: Some(pidfd), ..
            })) = c.begin_launch(
                "backup",
                &LaunchArgs::default(),
                true,
                Duration::from_secs(60),
            )
            else {
                return 2;
            };
            let readable = |ms: u64| readable(pidfd.as_fd(), ms);
            // Alive: not readable (the 100 ms timer fires first).
            if readable(100) != Some(false) {
                return 3;
            }
            if qinit_sys::proc::pidfd_signal(&pidfd, libc::SIGKILL).is_err() {
                return 4;
            }
            // Dead: readable within the hang guard.
            i32::from(readable(30_000) != Some(true)) * 5
        },
        |_| Ok(()),
    );
    let _ = qinit_sys::proc::kill(victim, libc::SIGKILL);
    result
}

/// A `Run` of a whole request reaches the executor intact and the helper it names runs.
fn run_request_reaches_the_executor_and_runs() -> Result<(), String> {
    use qinit_vm_guests::{run_fd_to_end, spec};
    let request = spec("svc", "exit-0", &[]);
    let expected = request.bytes().map_err(|e| format!("{e:?}"))?;
    serve_with(
        |_| Ok(()),
        move || {
            let Ok(mut c) = connect() else { return 1 };
            // The sim's clock stands still, so the wait never ends: read only the start.
            let got = c.begin_run(
                "job",
                &request,
                &qinit_client::RunArgs::default(),
                false,
                std::time::Duration::from_secs(60),
            );
            i32::from(!matches!(got, Ok(qinit_client::Begun::Started(_))))
        },
        |colony| {
            // The sim captured the memfd the client sent: those are the request's bytes, and the
            // executor runs them.
            let fd = colony
                .effects
                .instance_requests
                .remove(&0)
                .ok_or("the sim saw no request")?;
            let got = qinit_sys::memfd::read_all(fd.as_fd(), 65536).map_err(|e| e.to_string())?;
            if got != expected {
                return Err("the request changed on the way".into());
            }
            let o = run_fd_to_end("run-job", fd)?;
            if o.failure.is_some() || o.exit != Some(0) {
                return Err(format!(
                    "the executor ran it badly: exit {:?}, failure {:?}",
                    o.exit, o.failure
                ));
            }
            Ok(())
        },
    )
}

/// A `Run` with `wait_ready` starts the instance with a readiness pipe at the request's
/// descriptor, and the executor routes that pipe to the service, whose byte the cell reports.
fn run_wait_ready_reaches_the_executor() -> Result<(), String> {
    use qinit_cell::{Polite, ReadyMode, Report};
    use qinit_vm_guests::{HANG_GUARD, cells, e, expect, launch_fd, remove, spec};
    let mut request = spec("svc", "ready", &[]);
    request.ready_fd = Some(5);
    let expected = request.bytes().map_err(|x| format!("{x:?}"))?;
    serve_with(
        |_| Ok(()),
        move || {
            let Ok(mut c) = connect() else { return 1 };
            let args = qinit_client::RunArgs {
                wait_ready: true,
                ..qinit_client::RunArgs::default()
            };
            // The sim's clock stands still: read only the start.
            let got = c.begin_run(
                "job",
                &request,
                &args,
                false,
                std::time::Duration::from_secs(60),
            );
            i32::from(!matches!(got, Ok(qinit_client::Begun::Started(_))))
        },
        |colony| {
            if colony.effects.instance_ready != [(0, Some(5))] {
                return Err(format!(
                    "the pipe was not asked for: {:?}",
                    colony.effects.instance_ready
                ));
            }
            let fd = colony
                .effects
                .instance_requests
                .remove(&0)
                .ok_or("the sim saw no request")?;
            let got = qinit_sys::memfd::read_all(fd.as_fd(), 65536).map_err(|x| x.to_string())?;
            if got != expected {
                return Err("the request changed on the way".into());
            }
            // The cell the real layer would create: readiness by pipe at descriptor 5.
            let mut cells = cells()?;
            let l = launch_fd(&mut cells, "run-ready", fd, Vec::new(), ReadyMode::Pipe)?;
            expect(&mut cells, l.id, Report::Ready)?;
            e(cells.stop(l.id, Polite::Main, HANG_GUARD, HANG_GUARD))?;
            expect(&mut cells, l.id, Report::Empty)?;
            remove(&mut cells, l.id)
        },
    )
}

/// With a deny default and no rule for it, a privileged `Run` is refused with the clause.
fn run_is_refused_without_a_run_rule() -> Result<(), String> {
    use qinit_vm_guests::spec;
    let mut privileged = spec("root", "exit-0", &[]);
    privileged.nnp = true;
    serve_while(move || {
        let Ok(mut c) = connect() else { return 1 };
        let got = c.run(
            "job",
            &privileged,
            &qinit_client::RunArgs::default(),
            std::time::Duration::from_secs(1),
        );
        // Clause 8: no rule matches and the default is deny.
        i32::from(got.err() != Some(ClientError::Server(ErrorCode::Denied, 8)))
    })
}

fn watch_sees_a_change_from_a_second_connection() -> Result<(), String> {
    serve_while(|| {
        let Some(mut w) = connect()
            .ok()
            .and_then(|c| c.watch(Scope::Target("db")).ok())
        else {
            return 1;
        };
        let five = Some(Duration::from_secs(5));
        let current = matches!(
            w.next(five),
            Ok(Next::Event(Event::Node {
                report: Report::Current,
                ..
            }))
        );
        // Let the start-up notices pass: after a quiet moment only the stop can report. At most
        // 64 of them; a stream that never goes quiet fails the case instead of holding it.
        let quiet = Some(Duration::from_millis(300));
        let drained = (0..64).find_map(|_| match w.next(quiet) {
            Ok(Next::Timeout) => Some(true),
            Ok(Next::Event(_)) => None,
            _ => Some(false),
        }) == Some(true);
        let stopped = connect().is_ok_and(|mut c| c.change("db", Action::Stop, Wait::Now).is_ok());
        let saw = (0..8).any(|_| {
            // db is ready by exit and the simulated process never exits, so the stop leaves
            // the node done: the report is `Done` (or `Stopped`) and the state word is 4, done.
            matches!(
                w.next(five),
                Ok(Next::Event(Event::Node {
                    report: Report::Stopped | Report::Done,
                    state: StateWord { state: 4, .. },
                    ..
                }))
            )
        });
        i32::from(!(current && drained && stopped && saw))
    })
}

/// `qctl <args>` run in this process: the exit code, the output and the error text.
fn qctl(args: &[&str]) -> (i32, String, String) {
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = qctl::run(&args, &mut out, &mut err);
    (
        code,
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
    )
}

/// The layer tree of the compile case.
const QCTL_TREE: &str = "/run/qctl-l";

/// Sets the mode of `path` outright (an earlier case left the umask at 0).
fn chmod(path: &str, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod {path}: {e}"))
}

/// Puts back the modes it saved and removes the layer tree when dropped, on every path out of
/// the compile case (an error, an early return or a panic the suite runner catches). Each step is
/// best-effort: one failure does not stop the others, and the case's result stays its own.
struct Restore {
    modes: Vec<(&'static str, u32)>,
}

impl Drop for Restore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(QCTL_TREE);
        for (path, mode) in self.modes.drain(..).rev() {
            if let Err(e) = chmod(path, mode) {
                eprintln!("restore: {e}");
            }
        }
    }
}

/// A compile as root (the guest's) refuses a layer file others may write, and takes it once it
/// is 0644.
fn qctl_compile_as_root_refuses_a_world_writable_layer() -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    // The guest's `/` and `/run` are the initramfs's, mode 1777, which the ancestor rule refuses
    // as well: give them a host's mode for the case; the guard puts the old ones back.
    let mut restore = Restore { modes: Vec::new() };
    for a in ["/", "/run"] {
        let m = std::fs::metadata(a).map_err(|e| format!("{a}: {e}"))?;
        // Saved before the change, so the guard covers a failed or partial chmod too.
        restore.modes.push((a, m.permissions().mode() & 0o7777));
        chmod(a, 0o755)?;
    }
    compile_twice()
}

/// The two compiles of [`qctl_compile_as_root_refuses_a_world_writable_layer`].
fn compile_twice() -> Result<(), String> {
    let _ = std::fs::remove_dir_all(QCTL_TREE);
    let vendor = format!("{QCTL_TREE}/vendor");
    std::fs::create_dir_all(&vendor).map_err(|e| e.to_string())?;
    chmod(QCTL_TREE, 0o755)?;
    chmod(&vendor, 0o755)?;
    let file = format!("{vendor}/x.toml");
    std::fs::write(
        &file,
        "[worker.x]\nexec = [\"/bin/x\"]\ncredentials = { uid = \"root\" }\n",
    )
    .map_err(|e| e.to_string())?;
    let db = format!("{QCTL_TREE}/out.db");
    let layer = format!("vendor={vendor}");
    let args = ["compile", "--layer", &layer, "--no-policy", "--output", &db];
    chmod(&file, 0o666)?;
    let (code, _, err) = qctl(&args);
    // The refusal names the file itself, not an ancestor.
    let refused = err.starts_with(&format!("qctl: {file}: owned by uid 0, mode 666: "))
        && err.contains("must be root's and not writable by group or other");
    if code != 1 || !refused || Path::new(&db).exists() {
        return Err(format!("0666 was not refused: exit {code}, {err:?}"));
    }
    chmod(&file, 0o644)?;
    let (code, _, err) = qctl(&args);
    let written = Path::new(&db).exists();
    if code != 0 || !written {
        return Err(format!(
            "0644 refused: exit {code}, written {written}, {err:?}"
        ));
    }
    Ok(())
}

/// `qctl status` and `stop --wait` against the served colony, then `qctl watch` on a thread
/// writing into a pipe sees the `start` the client asks for reach `ready`. The start is web's:
/// db is ready by exit, so its start never reports `ready`.
fn qctl_status_start_and_watch_in_the_guest() -> Result<(), String> {
    use std::io::Read;
    serve_while(|| {
        let (code, out, _) = qctl(&["--socket", SOCKET, "status", "db"]);
        if code != 0 || !out.contains("state:") {
            return 1;
        }
        let (code, out, _) = qctl(&["--socket", SOCKET, "stop", "db", "--wait", "5000"]);
        if code != 0 || !out.starts_with("settled") {
            return 2;
        }
        let Ok((r, w)) = qinit_sys::fd::pipe(libc::O_CLOEXEC) else {
            return 3;
        };
        // The watch blocks until the process exits, which is fine: this client is a forked
        // process and exits with its verdict below.
        std::thread::spawn(move || {
            let mut out = std::fs::File::from(w);
            let mut err = Vec::new();
            qctl::run(
                &["--socket", SOCKET, "watch", "web"].map(str::to_owned),
                &mut out,
                &mut err,
            )
        });
        let mut r = std::fs::File::from(r);
        let mut seen = String::new();
        // Read until a line of the stream starts with `want`, each read bounded by 5 s.
        let mut until = |want: &str| -> bool {
            let mut buf = [0u8; 512];
            for _ in 0..16 {
                if seen.lines().any(|l| l.starts_with(want)) {
                    return true;
                }
                if readable(r.as_fd(), 5000) != Some(true) {
                    return false;
                }
                match r.read(&mut buf) {
                    Ok(n) if n > 0 => seen.push_str(&String::from_utf8_lossy(&buf[..n])),
                    _ => return false,
                }
            }
            seen.lines().any(|l| l.starts_with(want))
        };
        // The current state first: the watch is in place before the start.
        if !until("node web current off") {
            return 4;
        }
        if qctl(&["--socket", SOCKET, "start", "web"]).0 != 0 {
            return 5;
        }
        let ready = until("node web ready ready");
        if !ready {
            eprintln!("qctl watch printed: {seen:?}");
        }
        i32::from(!ready) * 6
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
            (
                "a_launch_pidfd_polls_readable_at_exit",
                a_launch_pidfd_polls_readable_at_exit,
            ),
            (
                "run_request_reaches_the_executor_and_runs",
                run_request_reaches_the_executor_and_runs,
            ),
            (
                "run_wait_ready_reaches_the_executor",
                run_wait_ready_reaches_the_executor,
            ),
            (
                "run_is_refused_without_a_run_rule",
                run_is_refused_without_a_run_rule,
            ),
            (
                "watch_sees_a_change_from_a_second_connection",
                watch_sees_a_change_from_a_second_connection,
            ),
            (
                "qctl_compile_as_root_refuses_a_world_writable_layer",
                qctl_compile_as_root_refuses_a_world_writable_layer,
            ),
            (
                "qctl_status_start_and_watch_in_the_guest",
                qctl_status_start_and_watch_in_the_guest,
            ),
        ],
    )
}
