// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! The examples of `docs/launch-request.md` decode, and are what the encoder makes of the
//! request each one describes.
use qinit_launch::{RequestSpec, Seccomp, Securebits, Stream, UserMap};
use qinit_overseer_core::decode;
use std::fmt::Write as _;

/// The bytes of every ```` ```qlr1 ```` block of the document, in order.
fn examples() -> Vec<Vec<u8>> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/launch-request.md");
    let text = std::fs::read_to_string(path).expect("the launch request document");
    let mut out = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if line.trim() != "```qlr1" {
            continue;
        }
        let mut hex = String::new();
        for body in lines.by_ref() {
            if body.trim() == "```" {
                break;
            }
            hex.extend(body.split('#').next().unwrap_or("").split_whitespace());
        }
        assert_eq!(hex.len() % 2, 0, "whole bytes");
        out.push(
            (0..hex.len() / 2)
                .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex digits"))
                .collect(),
        );
    }
    out
}

/// The request each example describes, in document order.
fn described() -> Vec<RequestSpec> {
    vec![
        RequestSpec {
            argv: vec!["/bin/true".into()],
            user: "svc".into(),
            ..Default::default()
        },
        RequestSpec {
            argv: vec!["/usr/bin/job".into(), "--once".into()],
            env: vec!["LANG=C".into()],
            cwd: "/work".into(),
            user: "svc".into(),
            securebits: Securebits::NorootLocked,
            ns: 1 | 32,
            user_map: UserMap::Range,
            inside_uid: 1000,
            inside_gid: 1000,
            seccomp: Seccomp::Default,
            paths: vec!["ro:/usr".into(), "rw:/work".into()],
            stdout: Stream::Fd(6),
            die_with_parent: true,
            deadline_ms: 5000,
            ..Default::default()
        },
    ]
}

#[test]
fn every_example_decodes_and_round_trips() {
    let found = examples();
    let want = described();
    assert_eq!(found.len(), want.len(), "one example per described request");
    for (bytes, spec) in found.iter().zip(&want) {
        assert_eq!(decode(bytes), Ok(()), "{spec:?}");
        assert_eq!(&spec.bytes().unwrap(), bytes, "{spec:?}");
    }
}

/// Prints each example's bytes as one `HEX` line, for writing the document:
/// `cargo test -p qinit-launch --test doc -- --ignored --nocapture`.
#[test]
#[ignore = "a generator for the document, not a check"]
fn print_the_examples() {
    for spec in described() {
        let mut hex = String::new();
        for x in spec.bytes().unwrap() {
            write!(hex, "{x:02x}").unwrap();
        }
        println!("HEX {hex}");
    }
}
