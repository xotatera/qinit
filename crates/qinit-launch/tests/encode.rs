// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! The encoder's output is what the overseer core's decoder accepts.
use qinit_launch::{EncodeError, RequestSpec, Stream};
use qinit_overseer_core::decode;

#[test]
fn the_default_request_decodes() {
    let spec = RequestSpec {
        argv: vec!["/x".into()],
        user: "svc".into(),
        ..Default::default()
    };
    assert_eq!(decode(&spec.bytes().unwrap()), Ok(()));
}

#[test]
fn a_same_stdout_is_bad_stream() {
    let spec = RequestSpec {
        argv: vec!["/x".into()],
        user: "svc".into(),
        stdout: Stream::Same,
        ..Default::default()
    };
    assert_eq!(spec.bytes(), Err(EncodeError::BadStream));
}
