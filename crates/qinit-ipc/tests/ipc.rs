// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0

use qinit_ipc::{
    Errno, MAX_FDS, accept, connect_seqpacket, listen_seqpacket, peer_cred, peer_pidfd, recv, send,
    send_nowait, seqpacket_pair,
};
use std::ffi::CString;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [0; 2];
    // SAFETY: pipe2 writes two descriptors into the array; the tests own them.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: both descriptors were just created and nothing else owns them.
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    // SAFETY: as above.
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    (read, write)
}

fn socket_path(test: &str) -> CString {
    let dir = std::env::temp_dir().join(format!("qinit-ipc-{}-{test}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    CString::new(dir.join("s").to_str().unwrap()).unwrap()
}

#[test]
fn a_message_and_its_fds_arrive_together() {
    let (a, b) = seqpacket_pair().unwrap();
    let (r1, w1) = pipe();
    let (r2, w2) = pipe();
    send(a.as_fd(), b"hello", &[w1.as_fd(), w2.as_fd()]).unwrap();
    let mut buf = [0u8; 64];
    let got = recv(b.as_fd(), &mut buf).unwrap();
    assert_eq!((got.len, got.fds.len()), (5, 2));
    assert_eq!(&buf[..5], b"hello");
    assert!(!got.truncated && !got.ctrunc);
    let mut wire = std::fs::File::from(got.fds.into_iter().next().unwrap());
    wire.write_all(b"x").unwrap();
    drop((wire, w1, w2));
    let mut seen = String::new();
    std::fs::File::from(r1).read_to_string(&mut seen).unwrap();
    assert_eq!(seen, "x");
    drop(r2);
}

#[test]
fn message_boundaries_are_kept() {
    let (a, b) = seqpacket_pair().unwrap();
    send(a.as_fd(), b"abc", &[]).unwrap();
    send(a.as_fd(), b"defg", &[]).unwrap();
    let mut buf = [0u8; 64];
    assert_eq!(recv(b.as_fd(), &mut buf).unwrap().len, 3);
    assert_eq!(recv(b.as_fd(), &mut buf).unwrap().len, 4);
}

#[test]
fn a_short_buffer_reports_truncation() {
    let (a, b) = seqpacket_pair().unwrap();
    send(a.as_fd(), &[7u8; 100], &[]).unwrap();
    let mut buf = [0u8; 10];
    let got = recv(b.as_fd(), &mut buf).unwrap();
    assert!(got.truncated);
    assert_eq!(got.len, 10);
}

#[test]
fn send_refuses_more_than_max_fds() {
    let (a, _b) = seqpacket_pair().unwrap();
    let pipes: Vec<_> = (0..=MAX_FDS).map(|_| pipe()).collect();
    let fds: Vec<_> = pipes.iter().map(|p| p.1.as_fd()).collect();
    assert_eq!(send(a.as_fd(), b"x", &fds), Err(Errno(libc::EINVAL)));
}

#[test]
fn peer_cred_names_this_process() {
    let path = socket_path("cred");
    let listener = listen_seqpacket(&path, 4).unwrap();
    let client = connect_seqpacket(&path).unwrap();
    let server = accept(listener.as_fd()).unwrap();
    let cred = peer_cred(server.as_fd()).unwrap();
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    // SAFETY: getpid has no preconditions.
    let pid = unsafe { libc::getpid() };
    assert_eq!((cred.uid, cred.pid), (uid, pid));
    drop(client);
}

#[test]
fn peer_pidfd_is_a_pidfd_of_this_process() {
    let path = socket_path("pidfd");
    let listener = listen_seqpacket(&path, 4).unwrap();
    let client = connect_seqpacket(&path).unwrap();
    let server = accept(listener.as_fd()).unwrap();
    let pidfd = peer_pidfd(server.as_fd()).unwrap();
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd())).unwrap();
    // SAFETY: getpid has no preconditions.
    let pid = unsafe { libc::getpid() };
    assert!(info.contains(&format!("Pid:\t{pid}")), "{info}");
    drop(client);
}

#[test]
fn a_closed_peer_reads_as_zero_length() {
    let (a, b) = seqpacket_pair().unwrap();
    drop(a);
    let mut buf = [0u8; 8];
    assert_eq!(recv(b.as_fd(), &mut buf).unwrap().len, 0);
}

#[test]
#[allow(clippy::multiple_unsafe_ops_per_block)] // a hand-built SCM_RIGHTS message is the point of this test
fn a_received_fd_beyond_the_buffer_sets_ctrunc() {
    let (a, b) = seqpacket_pair().unwrap();
    let pipes: Vec<_> = (0..4).map(|_| pipe()).collect();
    let raws: Vec<libc::c_int> = pipes.iter().map(|p| p.1.as_raw_fd()).collect();
    let mut data = *b"x";
    let mut vec = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0u64; 8];
    // SAFETY: msghdr is a plain C struct; zeroed is a valid value.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut vec;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    // SAFETY: pure arithmetic on the sizes.
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(16) } as usize;
    // SAFETY: the control buffer is aligned and large enough for one header.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
    // SAFETY: cmsg points into `control`, which holds the header and four ints.
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(16) as usize;
        std::ptr::copy_nonoverlapping(raws.as_ptr(), libc::CMSG_DATA(cmsg).cast(), 4);
    }
    // SAFETY: msg points at valid buffers for the call.
    let sent = unsafe { libc::sendmsg(a.as_raw_fd(), &raw const msg, 0) };
    assert_eq!(sent, 1);
    let mut buf = [0u8; 8];
    let got = recv(b.as_fd(), &mut buf).unwrap();
    assert!(got.ctrunc);
    assert!(got.fds.len() <= MAX_FDS);
}

#[test]
fn send_nowait_reports_a_full_queue_instead_of_blocking() {
    let (a, b) = seqpacket_pair().unwrap();
    let mut full = false;
    for _ in 0..100_000 {
        match send_nowait(a.as_fd(), &[0u8; 1024], &[]) {
            Ok(()) => {}
            Err(e) => {
                assert_eq!(e, Errno(libc::EAGAIN));
                full = true;
                break;
            }
        }
    }
    assert!(full, "the queue never filled");
    drop(b);
}
