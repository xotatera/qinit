// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Deterministic fuzzing: random frame sets through the whole pipeline, and mutated golden
//! databases through the reader (Review Focus 3: never a panic, never a malformed accept).
mod common;

use common::{Tree, golden_input};
use qinit_db::{Model, crc32, open, write};
use qinit_frames::compile::compile;
use std::fmt::Write as _;

/// Byte offset of the CRC word in the header.
const CRC_AT: usize = 12;

/// xorshift64 with a fixed seed, so every run sees the same cases.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// A value in `0..n` (`n > 0`).
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).expect("fits")
    }

    fn one_in(&mut self, n: usize) -> bool {
        self.below(n) == 0
    }
}

const GROUPS: [&str; 4] = ["require_all", "require_any", "optional_all", "exclude_all"];
const RESTART_ON: [&str; 4] = ["none", "error", "restart", "refresh"];

/// One random edge from worker `i` of `n`: mostly to a lower index (acyclic), sometimes to any
/// worker or past `n` (a name with no frame), so cycles and missing targets occur.
fn edge(rng: &mut Rng, i: usize, n: usize) -> String {
    let to = if i > 0 && !rng.one_in(12) {
        rng.below(i)
    } else {
        rng.below(n + 1)
    };
    let mut e = format!("{{ to = \"w{to}\"");
    if rng.one_in(2) {
        e.push_str(", mode = \"async\"");
        if rng.one_in(2) {
            let _ = write!(e, ", deadline = \"{}ms\"", rng.below(5000));
        }
    }
    if rng.one_in(3) {
        let _ = write!(e, ", restart_on = \"{}\"", RESTART_ON[rng.below(4)]);
    }
    if rng.one_in(24) {
        e.push_str(", stop = \"parallel\"");
    }
    e.push_str(" }");
    e
}

/// A random frame set of 1 to 12 workers `w0..`, plus an `enable.toml`.
fn frames(rng: &mut Rng) -> (String, String) {
    let n = 1 + rng.below(12);
    let mut src = String::new();
    for i in 0..n {
        let _ = write!(src, "[worker.w{i}]\nexec = [\"/w{i}\"]\n");
        // w0 has no lower worker: it gets edges or a pipe only now and then, so cycles stay rare.
        let wild = i == 0 && rng.one_in(6);
        if (i > 0 || wild) && rng.one_in(4) {
            let to = if i > 0 && !rng.one_in(12) {
                rng.below(i)
            } else {
                rng.below(n)
            };
            let _ = writeln!(src, "output = {{ pipe = \"w{to}\" }}");
        }
        let count = if i > 0 || wild { rng.below(4) } else { 0 };
        let groups: Vec<String> = (0..count)
            .map(|_| {
                let edges: Vec<String> = (0..=rng.below(3)).map(|_| edge(rng, i, n)).collect();
                let g = GROUPS[rng.below(4)];
                format!("{{ group = \"{g}\", edges = [{}] }}", edges.join(", "))
            })
            .collect();
        if !groups.is_empty() {
            let _ = writeln!(src, "deps = [{}]", groups.join(", "));
        }
    }
    let roots: Vec<String> = (0..n)
        .filter(|_| rng.one_in(3))
        .map(|i| format!("\"w{i}\""))
        .collect();
    let syslog = if rng.one_in(3) { "\"w0\"" } else { "" };
    let enable = format!("enable = [{}]\nsyslog = [{syslog}]\n", roots.join(", "));
    (src, enable)
}

/// `bytes` open; decoding and re-writing reproduce a database that opens to the same model.
fn round_trips(bytes: &[u8]) -> Model {
    let m = open(bytes).expect("validates").decode();
    let again = write(&m).expect("re-writes");
    assert_eq!(open(&again).expect("re-validates").decode(), m);
    m
}

#[test]
fn random_frame_sets_compile_validate_and_round_trip() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let t = Tree::new("fuzz-frames");
    let (mut ok, mut refused) = (0, 0);
    for case in 0..300 {
        let (src, enable) = frames(&mut rng);
        let layer = format!("c{case}");
        t.file(&layer, "f.toml", &src);
        t.file(&layer, "enable.toml", &enable);
        match compile(&t.input(&[layer.as_str()])) {
            Ok(c) => {
                ok += 1;
                let m = round_trips(&c.bytes);
                assert_eq!(
                    write(&m).expect("re-writes"),
                    c.bytes,
                    "case {case}:\n{src}"
                );
            }
            Err(es) => {
                refused += 1;
                assert!(!es.is_empty(), "case {case}: empty error list");
            }
        }
    }
    // The generator must exercise both outcomes.
    assert!(ok > 30 && refused > 30, "ok {ok}, refused {refused}");
}

/// Recompute the CRC word after a patch.
fn reseal(bytes: &mut [u8]) {
    bytes[CRC_AT..CRC_AT + 4].fill(0);
    let crc = crc32(bytes);
    bytes[CRC_AT..CRC_AT + 4].copy_from_slice(&crc.to_le_bytes());
}

/// The golden bytes after 4000 single-byte flips (CRC resealed unless the flip hit the CRC
/// word), then after 400 truncations (resealed when the CRC word survives); `true` marks a
/// truncation.
fn mutations() -> Vec<(bool, Vec<u8>)> {
    let golden = compile(&golden_input()).expect("golden compiles").bytes;
    round_trips(&golden);
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    let mut out = Vec::new();
    for _ in 0..4000 {
        let mut copy = golden.clone();
        let at = rng.below(copy.len());
        copy[at] ^= u8::try_from(1 + rng.below(255)).expect("byte");
        if !(CRC_AT..CRC_AT + 4).contains(&at) {
            reseal(&mut copy);
        }
        out.push((false, copy));
    }
    for _ in 0..400 {
        let mut copy = golden[..rng.below(golden.len())].to_vec();
        if copy.len() >= CRC_AT + 4 {
            reseal(&mut copy);
        }
        out.push((true, copy));
    }
    out
}

#[test]
fn mutated_databases_never_panic_the_reader() {
    // Review Focus 3: open is total, and decode is total on whatever open accepts.
    let mut accepted = 0;
    for (truncated, bytes) in mutations() {
        if let Ok(r) = open(&bytes) {
            assert!(!truncated, "a truncation was accepted");
            accepted += 1;
            let _ = r.decode();
        }
    }
    // Most flips land in data the validator checks; some (a name byte, a path) stay valid.
    assert!(accepted < 4000, "every flip was accepted");
}

#[test]
fn mutated_databases_are_rejected_or_well_formed() {
    for (truncated, bytes) in mutations() {
        if open(&bytes).is_ok() {
            assert!(!truncated, "a truncation was accepted");
            round_trips(&bytes);
        }
    }
}
