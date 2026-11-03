// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The launch primitives an unprivileged process can observe. Cases that change process state
//! (umask, rlimits, `no_new_privs`, seccomp, the alarm) run in a child: the test binary re-runs
//! itself with `QINIT_SYS_ROLE` set, and `child_roles` dispatches the role before any test.
use qinit_sys::cred::{no_new_privs, set_no_new_privs};
use qinit_sys::fd::{file_type, open_cloexec};
use qinit_sys::landlock::abi;
use qinit_sys::limits::{RLIMIT_NOFILE, set_rlimit, umask};
use qinit_sys::memfd::{self, sealed, seals};
use qinit_sys::seccomp::{Insn, install};
use qinit_sys::sock::connect_unix;
use qinit_sys::timer::arm_alarm;
use qinit_sys::{Errno, fd, proc, spawn};
use std::ffi::{CString, OsStr};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

/// Runs this binary again as `role` and returns its status.
fn child_status(role: &str) -> ExitStatus {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_roles"])
        .env("QINIT_SYS_ROLE", role)
        .status()
        .unwrap()
}

fn in_child(role: &str) -> i32 {
    child_status(role).code().unwrap_or(-1)
}

/// A BPF program: load the syscall number, return `EPERM` for `nr`, allow everything else.
fn deny_one(nr: u32) -> [Insn; 4] {
    const LD_W_ABS: u16 = 0x20;
    const JEQ_K: u16 = 0x15;
    const RET_K: u16 = 0x06;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    [
        Insn {
            code: LD_W_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        },
        Insn {
            code: JEQ_K,
            jt: 0,
            jf: 1,
            k: nr,
        },
        Insn {
            code: RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | u32::try_from(libc::EPERM).unwrap(),
        },
        Insn {
            code: RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
    ]
}

fn role(name: &str) -> i32 {
    match name {
        "umask" => {
            let old = umask(0o027);
            let got = umask(old);
            i32::from(got != 0o027 || umask(old) != old)
        }
        "nofile" => {
            set_rlimit(RLIMIT_NOFILE, 64, 64).unwrap();
            let mut lim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: getrlimit writes the two-field struct.
            let r = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut lim) };
            assert_eq!(r, 0);
            i32::from(lim.rlim_cur != 64 || lim.rlim_max != 64)
        }
        "nnp" => {
            set_no_new_privs().unwrap();
            i32::from(!no_new_privs().unwrap())
        }
        "alarm" => {
            arm_alarm(50).unwrap();
            loop {
                proc::pause();
            }
        }
        "seccomp" => {
            set_no_new_privs().unwrap();
            install(&deny_one(110)).unwrap();
            // The raw call: glibc's `getppid` wrapper treats the call as infallible and does
            // not set errno.
            // SAFETY: getppid takes no arguments.
            let r = unsafe { libc::syscall(libc::SYS_getppid) };
            let denied = r == -1 && Errno::last() == Errno(libc::EPERM);
            // SAFETY: getpid takes no arguments.
            let allowed = unsafe { libc::syscall(libc::SYS_getpid) } > 0;
            i32::from(!(denied && allowed))
        }
        "close-from" => {
            let (r, w) = fd::pipe(0).unwrap();
            let hi = fd::dup_above(r.as_fd(), 700).unwrap();
            let n = hi.as_raw_fd();
            std::mem::forget(hi);
            fd::close_from(n).unwrap();
            i32::from(fd::is_open(n) || !fd::is_open(r.as_raw_fd()) || !fd::is_open(w.as_raw_fd()))
        }
        _ => 99,
    }
}

#[test]
fn child_roles() {
    if let Ok(r) = std::env::var("QINIT_SYS_ROLE") {
        std::process::exit(role(&r));
    }
}

#[test]
fn a_sealed_memfd_cannot_grow_shrink_or_be_written() {
    let fd = sealed(c"req", b"hello").unwrap();
    let all = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL;
    assert_eq!(seals(fd.as_fd()).unwrap() & all, all);
    let mut text = String::new();
    let mut file = std::fs::File::from(fd);
    file.read_to_string(&mut text).unwrap();
    assert_eq!(text, "hello");
    assert!(file.write_all(b"x").is_err(), "sealed against writes");
}

#[test]
fn umask_returns_the_previous_mask() {
    assert_eq!(in_child("umask"), 0);
}

#[test]
fn rlimit_nofile_can_be_lowered() {
    assert_eq!(in_child("nofile"), 0);
}

#[test]
fn no_new_privs_is_set_in_the_child_only() {
    assert_eq!(in_child("nnp"), 0);
    assert!(!no_new_privs().unwrap());
}

#[test]
fn an_alarm_ends_the_child_by_sigalrm() {
    assert_eq!(child_status("alarm").signal(), Some(libc::SIGALRM));
}

#[test]
fn a_seccomp_program_denies_a_listed_call() {
    assert_eq!(in_child("seccomp"), 0);
}

#[test]
fn connect_unix_reaches_a_stream_listener_and_refuses_a_dgram_mismatch() {
    let dir = std::env::temp_dir().join(format!("qinit-sys-sock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("s");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let c = CString::new(path.to_str().unwrap()).unwrap();
    let fd = connect_unix(&c, libc::SOCK_STREAM).unwrap();
    assert_eq!(file_type(fd.as_fd()).unwrap(), libc::S_IFSOCK);
    let (_peer, _) = listener.accept().unwrap();
    assert_eq!(
        connect_unix(&c, libc::SOCK_DGRAM).unwrap_err(),
        Errno(libc::EPROTOTYPE)
    );
    assert_eq!(
        connect_unix(c"/nonexistent/qinit.sock", libc::SOCK_STREAM).unwrap_err(),
        Errno(libc::ENOENT)
    );
    drop(listener);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn file_type_tells_regular_fifo_socket_and_char() {
    let dir = std::env::temp_dir().join(format!("qinit-sys-types-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let reg = CString::new(dir.join("f").to_str().unwrap()).unwrap();
    let f = open_cloexec(&reg, libc::O_WRONLY | libc::O_CREAT, 0o600).unwrap();
    assert_eq!(file_type(f.as_fd()).unwrap(), libc::S_IFREG);
    let fifo = CString::new(dir.join("p").to_str().unwrap()).unwrap();
    // SAFETY: a NUL-terminated path that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let p = open_cloexec(&fifo, libc::O_RDONLY | libc::O_NONBLOCK, 0).unwrap();
    assert_eq!(file_type(p.as_fd()).unwrap(), libc::S_IFIFO);
    let sock = dir.join("s");
    let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let s = CString::new(sock.to_str().unwrap()).unwrap();
    let s = open_cloexec(&s, libc::O_PATH, 0).unwrap();
    assert_eq!(file_type(s.as_fd()).unwrap(), libc::S_IFSOCK);
    let null = open_cloexec(c"/dev/null", libc::O_WRONLY, 0).unwrap();
    assert_eq!(file_type(null.as_fd()).unwrap(), libc::S_IFCHR);
    // O_CLOEXEC and O_NOCTTY are always added.
    // SAFETY: F_GETFD only reads the flags.
    let flags = unsafe { libc::fcntl(null.as_raw_fd(), libc::F_GETFD) };
    assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dup2_places_a_descriptor_at_a_number_without_cloexec() {
    let (r, _w) = fd::pipe(libc::O_CLOEXEC).unwrap();
    let hole = fd::dup_above(r.as_fd(), 10).unwrap();
    let n = hole.as_raw_fd();
    drop(hole);
    fd::dup2(r.as_fd(), n).unwrap();
    assert!(fd::is_open(n));
    // SAFETY: F_GETFD only reads the flags.
    let flags = unsafe { libc::fcntl(n, libc::F_GETFD) };
    assert_eq!(flags & libc::FD_CLOEXEC, 0);
    // SAFETY: the number was placed by dup2 above and is owned by this test.
    unsafe { libc::close(n) };
}

#[test]
fn clear_nonblocking_drops_the_flag() {
    let (r, _w) = fd::pipe(libc::O_CLOEXEC | libc::O_NONBLOCK).unwrap();
    fd::clear_nonblocking(r.as_fd()).unwrap();
    // SAFETY: F_GETFL only reads the flags.
    let flags = unsafe { libc::fcntl(r.as_raw_fd(), libc::F_GETFL) };
    assert_eq!(flags & libc::O_NONBLOCK, 0);
}

#[test]
fn landlock_abi_is_at_least_3_or_reports_absence() {
    match abi() {
        Ok(v) => assert!(v >= 3, "abi {v}"),
        Err(e) => assert!(matches!(e.0, libc::ENOSYS | libc::EOPNOTSUPP), "{e}"),
    }
}

#[test]
fn exec_by_descriptor_runs_the_program() {
    let Ok(exe) = open_cloexec(c"/bin/true", libc::O_RDONLY, 0) else {
        eprintln!("no /bin/true on this host; skipping");
        return;
    };
    let p = spawn::Prepared::with_fd(exe.as_fd(), &[OsStr::new("true")], &[], &[]).unwrap();
    let (err_r, err_w) = fd::pipe(libc::O_CLOEXEC).unwrap();
    let (_pid, pidfd) = spawn::spawn(&p, None, err_w.as_fd()).unwrap();
    drop(err_w);
    let mut bytes = Vec::new();
    std::fs::File::from(err_r).read_to_end(&mut bytes).unwrap();
    assert!(bytes.is_empty(), "exec failed: {bytes:?}");
    assert_eq!(libc::WEXITSTATUS(proc::wait_pidfd(&pidfd).unwrap()), 0);
}

#[test]
fn exec_by_descriptor_of_a_non_executable_reports_eacces() {
    let exe = open_cloexec(c"/etc/hostname", libc::O_RDONLY, 0)
        .or_else(|_| open_cloexec(c"/etc/passwd", libc::O_RDONLY, 0))
        .unwrap();
    let p = spawn::Prepared::with_fd(exe.as_fd(), &[OsStr::new("x")], &[], &[]).unwrap();
    let (err_r, err_w) = fd::pipe(libc::O_CLOEXEC).unwrap();
    let (_pid, pidfd) = spawn::spawn(&p, None, err_w.as_fd()).unwrap();
    drop(err_w);
    let mut bytes = Vec::new();
    std::fs::File::from(err_r).read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, libc::EACCES.to_ne_bytes());
    assert_eq!(libc::WEXITSTATUS(proc::wait_pidfd(&pidfd).unwrap()), 127);
}

#[test]
fn read_all_returns_the_content_from_offset_zero_and_refuses_more_than_max() {
    let fd = sealed(c"req", b"hello world").unwrap();
    assert_eq!(memfd::read_all(fd.as_fd(), 64).unwrap(), b"hello world");
    assert_eq!(memfd::read_all(fd.as_fd(), 11).unwrap(), b"hello world");
    assert_eq!(
        memfd::read_all(fd.as_fd(), 10).unwrap_err(),
        Errno(libc::EFBIG)
    );
}

#[test]
fn write_all_delivers_every_byte_through_a_pipe() {
    let (r, w) = fd::pipe(libc::O_CLOEXEC).unwrap();
    fd::write_all(w.as_fd(), b"0123456789").unwrap();
    drop(w);
    let mut got = Vec::new();
    std::fs::File::from(r).read_to_end(&mut got).unwrap();
    assert_eq!(got, b"0123456789");
}

#[test]
fn inherit_refuses_a_closed_number_and_dup2_raw_copies_between_numbers() {
    assert_eq!(fd::inherit(900).unwrap_err(), Errno(libc::EBADF));
    let (r, _w) = fd::pipe(libc::O_CLOEXEC).unwrap();
    let hole = fd::dup_above(r.as_fd(), 910).unwrap();
    let n = hole.as_raw_fd();
    drop(hole);
    fd::dup2_raw(r.as_raw_fd(), n).unwrap();
    assert!(fd::is_open(n));
    drop(fd::inherit(n).unwrap());
    assert!(!fd::is_open(n));
}

#[test]
fn close_from_closes_every_descriptor_at_or_above_a_number() {
    assert_eq!(in_child("close-from"), 0);
}

#[test]
fn a_landlock_rule_on_a_file_drops_the_directory_only_rights() {
    use qinit_sys::landlock::{LANDLOCK_ACCESS_FS_ALL_V3, add_path_rule, ruleset};
    if abi().is_err() {
        eprintln!("no Landlock on this host; skipping");
        return;
    }
    let rs = ruleset(LANDLOCK_ACCESS_FS_ALL_V3).unwrap();
    add_path_rule(rs.as_fd(), c"/etc/passwd", LANDLOCK_ACCESS_FS_ALL_V3).unwrap();
    add_path_rule(rs.as_fd(), c"/etc", LANDLOCK_ACCESS_FS_ALL_V3).unwrap();
}

#[test]
fn listen_unix_queues_a_connection_that_connect_unix_reaches() {
    let dir = std::env::temp_dir().join(format!("qinit-sys-listen-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = CString::new(dir.join("s").to_str().unwrap()).unwrap();
    let listener = qinit_sys::sock::listen_unix(&path, 1).unwrap();
    let client = connect_unix(&path, libc::SOCK_STREAM).unwrap();
    assert_eq!(file_type(client.as_fd()).unwrap(), libc::S_IFSOCK);
    drop(listener);
    let _ = std::fs::remove_dir_all(&dir);
}
