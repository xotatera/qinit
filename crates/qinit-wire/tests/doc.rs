// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! The examples of `docs/control-protocol.md` decode, and encode back to the same bytes.
use qinit_proto_core::*;
use qinit_wire::*;

/// One example: the descriptors it travels with, and its bytes.
struct Example {
    fds: usize,
    bytes: Vec<u8>,
}

fn examples() -> Vec<Example> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/control-protocol.md"
    );
    let text = std::fs::read_to_string(path).expect("the protocol document");
    let mut out = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if line.trim() != "```qcp1" {
            continue;
        }
        let mut fds = None;
        let mut hex = String::new();
        for body in lines.by_ref() {
            if body.trim() == "```" {
                break;
            }
            if let Some(n) = body.trim().strip_prefix("# fds:") {
                fds = Some(n.trim().parse::<usize>().expect("a descriptor count"));
            }
            hex.extend(body.split('#').next().unwrap_or("").split_whitespace());
        }
        assert_eq!(hex.len() % 2, 0, "whole bytes");
        let bytes = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex digits"))
            .collect();
        out.push(Example {
            fds: fds.expect("a `# fds:` line"),
            bytes,
        });
    }
    out
}

#[test]
fn every_example_in_the_spec_decodes_and_reencodes_identically() {
    let examples = examples();
    let mut seen = std::collections::BTreeSet::new();
    for e in &examples {
        let msg = decode(&e.bytes, e.fds).expect("the example decodes");
        let mut out: Box<[u8; MAX_MESSAGE]> = vec![0u8; MAX_MESSAGE].try_into().unwrap();
        let n = encode(&msg, u32::try_from(e.fds).unwrap(), &mut out).expect("it encodes");
        assert_eq!(&out[..n], &e.bytes[..], "{msg:?}");
        seen.insert(message_type(&e.bytes));
    }
    let want: std::collections::BTreeSet<u32> = RECORD_WORDS.iter().map(|(t, _)| *t).collect();
    assert_eq!(seen, want, "one example per message type");
    assert!(examples.len() >= 17);
}
