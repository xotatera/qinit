// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0

//! One message with descriptors: `sendmsg` and `recvmsg` with `SCM_RIGHTS`.
use crate::{Errno, Result};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

/// The most descriptors one message carries.
pub const MAX_FDS: usize = 4;

/// The data bytes of a full `SCM_RIGHTS` message (`MAX_FDS` ints).
const FDS_BYTES: u32 = 16;

/// `CMSG_SPACE` for `MAX_FDS` descriptors, rounded up for alignment.
const CONTROL_BYTES: usize = 64;

/// A control buffer aligned for `cmsghdr`.
#[repr(C)]
struct Control {
    align: [libc::cmsghdr; 0],
    bytes: [u8; CONTROL_BYTES],
}

impl Control {
    fn new() -> Control {
        Control {
            align: [],
            bytes: [0; CONTROL_BYTES],
        }
    }
}

fn iov(bytes: &[u8]) -> libc::iovec {
    libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    }
}

#[allow(clippy::unnecessary_cast)] // the control length is `usize` on glibc and `u32` on musl
fn header(iov: &mut libc::iovec, control: &mut Control) -> libc::msghdr {
    // SAFETY: msghdr is a plain C struct; zeroed is a valid value.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.bytes.as_mut_ptr().cast();
    msg.msg_controllen = CONTROL_BYTES as _;
    msg
}

/// The `index`th descriptor slot in the data area of `cmsg`.
fn slot(cmsg: *mut libc::cmsghdr, index: usize) -> *mut u8 {
    // SAFETY: cmsg points at a header inside a control buffer.
    let data = unsafe { libc::CMSG_DATA(cmsg) };
    // SAFETY: the caller keeps `index` inside the data area of the header.
    unsafe { data.add(index * core::mem::size_of::<libc::c_int>()) }
}

fn put_fd(cmsg: *mut libc::cmsghdr, index: usize, fd: libc::c_int) {
    let bytes = fd.to_ne_bytes();
    // SAFETY: the slot has room for one int and does not overlap `bytes`.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), slot(cmsg, index), bytes.len()) };
}

fn get_fd(cmsg: *mut libc::cmsghdr, index: usize) -> libc::c_int {
    let mut bytes = [0u8; core::mem::size_of::<libc::c_int>()];
    // SAFETY: the slot holds one int and does not overlap `bytes`.
    unsafe { core::ptr::copy_nonoverlapping(slot(cmsg, index), bytes.as_mut_ptr(), bytes.len()) };
    libc::c_int::from_ne_bytes(bytes)
}

fn check_long(r: libc::ssize_t) -> Result<usize> {
    usize::try_from(r).map_err(|_| Errno::last())
}

/// Sends `bytes` as one message with `fds` attached (`EINVAL` for more than [`MAX_FDS`]).
///
/// # Errors
/// `EINVAL` for too many descriptors, else the errno of `sendmsg`.
pub fn send(fd: BorrowedFd<'_>, bytes: &[u8], fds: &[BorrowedFd<'_>]) -> Result<()> {
    if fds.len() > MAX_FDS {
        return Err(Errno(libc::EINVAL));
    }
    send_unchecked(fd, bytes, fds)
}

/// As [`send`], but never blocks: `EAGAIN` when the peer's receive queue is full. For a server
/// that must not stall on a client that does not read its replies.
///
/// # Errors
/// `EINVAL` for too many descriptors, `EAGAIN` for a full queue, else the errno of `sendmsg`.
pub fn send_nowait(fd: BorrowedFd<'_>, bytes: &[u8], fds: &[BorrowedFd<'_>]) -> Result<()> {
    if fds.len() > MAX_FDS {
        return Err(Errno(libc::EINVAL));
    }
    send_flags(fd, bytes, fds, libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT)
}

/// As [`send`], without the limit of [`MAX_FDS`] (up to eight descriptors fit): for tests of
/// a receiver that must refuse a sender that ignores the limit.
pub fn send_unchecked(fd: BorrowedFd<'_>, bytes: &[u8], fds: &[BorrowedFd<'_>]) -> Result<()> {
    send_flags(fd, bytes, fds, libc::MSG_NOSIGNAL)
}

#[allow(clippy::unnecessary_cast, clippy::cast_possible_truncation)] // the field types differ between glibc and musl; the values are small
fn send_flags(
    fd: BorrowedFd<'_>,
    bytes: &[u8],
    fds: &[BorrowedFd<'_>],
    flags: libc::c_int,
) -> Result<()> {
    if fds.len() > 8 {
        return Err(Errno(libc::EINVAL));
    }
    let mut vec = iov(bytes);
    let mut control = Control::new();
    let mut msg = header(&mut vec, &mut control);
    if fds.is_empty() {
        msg.msg_control = core::ptr::null_mut();
        msg.msg_controllen = 0;
    } else {
        let payload = fds.len() * core::mem::size_of::<libc::c_int>();
        let payload = u32::try_from(payload).map_err(|_| Errno(libc::EINVAL))?;
        // SAFETY: pure arithmetic on the sizes.
        let space = unsafe { libc::CMSG_SPACE(payload) };
        // SAFETY: pure arithmetic on the sizes.
        let len = unsafe { libc::CMSG_LEN(payload) };
        msg.msg_controllen = space as _;
        // SAFETY: msg_control points at an aligned buffer with room for the header.
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
        // SAFETY: cmsg points into the control buffer, which is large enough for MAX_FDS.
        unsafe { (*cmsg).cmsg_level = libc::SOL_SOCKET };
        // SAFETY: as above.
        unsafe { (*cmsg).cmsg_type = libc::SCM_RIGHTS };
        // SAFETY: as above.
        unsafe { (*cmsg).cmsg_len = len as _ };
        for (i, f) in fds.iter().enumerate() {
            put_fd(cmsg, i, f.as_raw_fd());
        }
    }
    // SAFETY: msg points at valid iovec and control buffers for the call.
    let sent = check_long(unsafe { libc::sendmsg(fd.as_raw_fd(), &raw const msg, flags) })?;
    if sent == bytes.len() {
        Ok(())
    } else {
        Err(Errno(libc::EMSGSIZE))
    }
}

/// What one `recv` brought.
#[derive(Debug)]
pub struct Received {
    /// Bytes written into the caller's buffer; 0 means the peer closed.
    pub len: usize,
    /// The descriptors that came with the message, close-on-exec.
    pub fds: Vec<OwnedFd>,
    /// The message was longer than the buffer.
    pub truncated: bool,
    /// The kernel dropped descriptors that did not fit the control buffer.
    pub ctrunc: bool,
}

/// Receives one message into `buf`.
#[allow(clippy::unnecessary_cast, clippy::cast_possible_truncation)] // the field types differ between glibc and musl; the values are small
pub fn recv(fd: BorrowedFd<'_>, buf: &mut [u8]) -> Result<Received> {
    let mut vec = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut control = Control::new();
    let mut msg = header(&mut vec, &mut control);
    // Room for exactly MAX_FDS descriptors: a fourth is dropped and reported as `ctrunc`.
    // SAFETY: pure arithmetic on the sizes.
    msg.msg_controllen = unsafe { libc::CMSG_LEN(FDS_BYTES) } as _;
    // SAFETY: msg points at valid iovec and control buffers for the call.
    let got =
        check_long(unsafe { libc::recvmsg(fd.as_raw_fd(), &raw mut msg, libc::MSG_CMSG_CLOEXEC) })?;
    let mut fds = Vec::new();
    // SAFETY: msg was filled in by recvmsg and its control buffer is still live.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
    while !cmsg.is_null() {
        // SAFETY: cmsg is a header inside the control buffer.
        let level = unsafe { (*cmsg).cmsg_level };
        // SAFETY: as above.
        let kind = unsafe { (*cmsg).cmsg_type };
        // SAFETY: as above.
        let len = unsafe { (*cmsg).cmsg_len } as usize;
        if level == libc::SOL_SOCKET && kind == libc::SCM_RIGHTS {
            // SAFETY: pure arithmetic on the sizes.
            let header = unsafe { libc::CMSG_LEN(0) } as usize;
            let count = len.saturating_sub(header) / core::mem::size_of::<libc::c_int>();
            for i in 0..count {
                // SAFETY: the kernel installed this descriptor for this process; nothing else owns it.
                fds.push(unsafe { OwnedFd::from_raw_fd(get_fd(cmsg, i)) });
            }
        }
        // SAFETY: cmsg is a header inside the control buffer of msg.
        cmsg = unsafe { libc::CMSG_NXTHDR(&raw const msg, cmsg) };
    }
    Ok(Received {
        len: got.min(buf.len()),
        fds,
        truncated: msg.msg_flags & libc::MSG_TRUNC != 0,
        ctrunc: msg.msg_flags & libc::MSG_CTRUNC != 0,
    })
}

/// Waits until `fd` is readable (or hung up), at most `timeout_ms` (negative: no limit);
/// `true` when it is. `EINTR` is retried.
///
/// # Errors
/// The errno of `poll`.
pub fn poll_readable(fd: BorrowedFd<'_>, timeout_ms: i32) -> Result<bool> {
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: p is one valid pollfd for the call.
        let r = unsafe { libc::poll(&raw mut p, 1, timeout_ms) };
        if r >= 0 {
            return Ok(r > 0);
        }
        let e = Errno::last();
        if e.0 != libc::EINTR {
            return Err(e);
        }
    }
}

/// Waits until `fd` is writable (or hung up), at most `timeout_ms` (negative: no limit);
/// `true` when it is. `EINTR` is retried.
///
/// # Errors
/// The errno of `poll`.
pub fn poll_writable(fd: BorrowedFd<'_>, timeout_ms: i32) -> Result<bool> {
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    loop {
        // SAFETY: p is one valid pollfd for the call.
        let r = unsafe { libc::poll(&raw mut p, 1, timeout_ms) };
        if r >= 0 {
            return Ok(r > 0);
        }
        let e = Errno::last();
        if e.0 != libc::EINTR {
            return Err(e);
        }
    }
}
