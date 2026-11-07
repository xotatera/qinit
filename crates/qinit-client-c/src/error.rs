// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! The error model: a function returns the kind of its failure, and `qinit_last_error` gives the
//! kind with its code and detail.
use ::qinit_client::ClientError;
use std::ffi::c_int;

/// A system call failed; `code` is the errno.
pub const QINIT_E_ERRNO: c_int = 1;
/// The server's message is not a message of the format; `code` is the decode error number.
pub const QINIT_E_PROTOCOL: c_int = 2;
/// The server refused the request; `code` is the protocol error code, `detail` its detail.
pub const QINIT_E_SERVER: c_int = 3;
/// The server closed the connection or sent a reply that does not answer the request.
pub const QINIT_E_UNEXPECTED: c_int = 4;
/// A null pointer where one is required, a string over its length limit or not UTF-8, an enum
/// word out of range, or a call the client cannot make now (anything but `qinit_watch_next`,
/// `qinit_fd`, `qinit_last_error` and `qinit_close` after `qinit_watch`, and anything but the last
/// three after a watch that lost the connection). Nothing was sent.
pub const QINIT_E_ARGUMENT: c_int = 5;

/// The failure of the last call on a client: `kind` 0 for none, else a `QINIT_E_*`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)] // the C name
pub struct qinit_error {
    pub kind: i32,
    pub code: i32,
    pub detail: u32,
}

impl qinit_error {
    /// No failure.
    pub(crate) const NONE: qinit_error = qinit_error {
        kind: 0,
        code: 0,
        detail: 0,
    };
}

/// A failed call, as `qinit_last_error` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Fail(pub(crate) qinit_error);

impl Fail {
    /// A bad argument.
    pub(crate) const ARGUMENT: Fail = Fail::kind(QINIT_E_ARGUMENT);
    /// The connection is gone or the reply does not fit.
    pub(crate) const UNEXPECTED: Fail = Fail::kind(QINIT_E_UNEXPECTED);

    const fn kind(kind: c_int) -> Fail {
        Fail(qinit_error {
            kind,
            code: 0,
            detail: 0,
        })
    }

    /// An errno.
    pub(crate) const fn errno(code: i32) -> Fail {
        Fail(qinit_error {
            kind: QINIT_E_ERRNO,
            code,
            detail: 0,
        })
    }
}

impl From<ClientError> for Fail {
    fn from(e: ClientError) -> Fail {
        match e {
            ClientError::Io(code) => Fail::errno(code),
            ClientError::Protocol(d) => Fail(qinit_error {
                kind: QINIT_E_PROTOCOL,
                code: d as i32,
                detail: 0,
            }),
            ClientError::Server(c, detail) => Fail(qinit_error {
                kind: QINIT_E_SERVER,
                // The codes are 1 to 12.
                code: i32::try_from(c.word()).unwrap_or(i32::MAX),
                detail,
            }),
            ClientError::Unexpected => Fail::UNEXPECTED,
        }
    }
}
