// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! `include/qinit_client.h` is what cbindgen makes of the crate now. `UPDATE_HEADER=1 cargo test
//! -p qinit-client-c --test header regenerate_header` rewrites it (and then fails on purpose);
//! re-run without `UPDATE_HEADER` and commit the header with the change.
use std::fmt::Write;

fn generated() -> String {
    let dir = env!("CARGO_MANIFEST_DIR");
    let config = cbindgen::Config::from_file(format!("{dir}/cbindgen.toml")).unwrap();
    let generated = cbindgen::Builder::new()
        .with_crate(dir)
        .with_config(config)
        .generate()
        .unwrap();
    let mut out = Vec::new();
    generated.write(&mut out);
    String::from_utf8(out).unwrap()
}

fn header_path() -> String {
    format!("{}/include/qinit_client.h", env!("CARGO_MANIFEST_DIR"))
}

/// The lines where `have` and `want` part, from the first difference: up to 20 lines of each
/// side, `-` for the file's and `+` for the generated, with their line numbers.
fn diff(have: &str, want: &str) -> String {
    let (h, w): (Vec<&str>, Vec<&str>) = (have.lines().collect(), want.lines().collect());
    let first = h.iter().zip(&w).take_while(|(a, b)| a == b).count();
    let mut out = format!("first difference at line {}:\n", first + 1);
    for (i, l) in h.iter().enumerate().skip(first).take(20) {
        let _ = writeln!(out, "-{:>5} {l}", i + 1);
    }
    for (i, l) in w.iter().enumerate().skip(first).take(20) {
        let _ = writeln!(out, "+{:>5} {l}", i + 1);
    }
    out
}

#[test]
fn header_is_current() {
    let want = generated();
    let have = std::fs::read_to_string(header_path()).unwrap_or_default();
    assert!(
        have == want,
        "include/qinit_client.h is stale; regenerate it with:\n  cbindgen --config crates/qinit-client-c/cbindgen.toml --crate qinit-client-c --output crates/qinit-client-c/include/qinit_client.h\n(or run the `regenerate_header` test with UPDATE_HEADER=1)\n{}",
        diff(&have, &want)
    );
}

#[test]
fn the_diff_names_the_first_differing_line() {
    let d = diff("a\nb\nc\n", "a\nx\nc\n");
    assert!(d.starts_with("first difference at line 2:\n"), "{d}");
    assert!(d.contains("-    2 b\n") && d.contains("+    2 x\n"), "{d}");
}

#[test]
fn regenerate_header() {
    if std::env::var_os("UPDATE_HEADER").is_some_and(|v| v == "1") {
        std::fs::write(header_path(), generated()).unwrap();
        panic!("include/qinit_client.h updated; re-run without UPDATE_HEADER");
    }
}
