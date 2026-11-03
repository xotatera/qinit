// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Output routes by file type (spec R7).
use qinit_overseer::output::open_route;
use qinit_sys::Errno;
use qinit_sys::fd::file_type;
use std::ffi::CString;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixDatagram, UnixListener};
use std::path::{Path, PathBuf};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("qinit-overseer-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn c(p: &Path) -> CString {
    CString::new(p.to_str().unwrap()).unwrap()
}

#[test]
fn open_route_appends_to_a_regular_file_and_creates_it_0640_under_umask_027() {
    let dir = scratch("reg");
    let path = dir.join("out.log");
    let old = qinit_sys::limits::umask(0o027);
    let first = open_route(&c(&path));
    let _ = qinit_sys::limits::umask(old);
    let mut file = std::fs::File::from(first.unwrap());
    file.write_all(b"one\n").unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o640
    );
    let mut again = std::fs::File::from(open_route(&c(&path)).unwrap());
    again.write_all(b"two\n").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "one\ntwo\n");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn open_route_opens_a_char_device() {
    let fd = open_route(c"/dev/null").unwrap();
    assert_eq!(file_type(fd.as_fd()).unwrap(), libc::S_IFCHR);
}

#[test]
fn open_route_connects_a_stream_then_a_dgram_socket() {
    let dir = scratch("sock");
    let stream = dir.join("stream");
    let listener = UnixListener::bind(&stream).unwrap();
    let fd = open_route(&c(&stream)).unwrap();
    assert_eq!(file_type(fd.as_fd()).unwrap(), libc::S_IFSOCK);
    let (mut peer, _) = listener.accept().unwrap();
    let mut file = std::fs::File::from(fd);
    file.write_all(b"hi").unwrap();
    drop(file);
    let mut got = String::new();
    std::io::Read::read_to_string(&mut peer, &mut got).unwrap();
    assert_eq!(got, "hi");
    let dgram = dir.join("dgram");
    let server = UnixDatagram::bind(&dgram).unwrap();
    let fd = open_route(&c(&dgram)).unwrap();
    let mut file = std::fs::File::from(fd);
    file.write_all(b"dg").unwrap();
    let mut buf = [0u8; 8];
    let n = server.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"dg");
    let _ = std::fs::remove_dir_all(&dir);
}

fn mkfifo(path: &Path) {
    qinit_sys::fd::mkfifo(&c(path), 0o600).unwrap();
}

#[test]
fn open_route_refuses_a_fifo_without_a_reader_with_enxio() {
    let dir = scratch("fifo-none");
    let path = dir.join("p");
    mkfifo(&path);
    assert_eq!(open_route(&c(&path)).unwrap_err(), Errno(libc::ENXIO));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn open_route_opens_a_fifo_with_a_reader_and_clears_nonblock() {
    let dir = scratch("fifo-reader");
    let path = dir.join("p");
    mkfifo(&path);
    let reader = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags_nonblock()
        .open(&path)
        .unwrap();
    let fd = open_route(&c(&path)).unwrap();
    assert!(!qinit_sys::fd::is_nonblocking(fd.as_fd()).unwrap());
    drop(reader);
    let _ = std::fs::remove_dir_all(&dir);
}

trait NonblockOpen {
    fn custom_flags_nonblock(&mut self) -> &mut Self;
}

impl NonblockOpen for std::fs::OpenOptions {
    fn custom_flags_nonblock(&mut self) -> &mut Self {
        std::os::unix::fs::OpenOptionsExt::custom_flags(self, libc::O_NONBLOCK)
    }
}

#[test]
fn a_directory_is_enotsup() {
    let dir = scratch("dir");
    assert_eq!(open_route(&c(&dir)).unwrap_err(), Errno(libc::ENOTSUP));
    let _ = std::fs::remove_dir_all(&dir);
}
