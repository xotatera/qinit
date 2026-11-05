// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! `include/qinit_client.h` is what cbindgen makes of the crate now. `UPDATE_HEADER=1 cargo test
//! -p qinit-client-c --test header regenerate_header` rewrites it (and then fails on purpose);
//! re-run without `UPDATE_HEADER` and commit the header with the change.

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

#[test]
fn header_is_current() {
    let want = generated();
    let have = std::fs::read_to_string(header_path()).unwrap_or_default();
    assert!(
        have == want,
        "include/qinit_client.h is stale; regenerate it with:\n  cbindgen --config crates/qinit-client-c/cbindgen.toml --crate qinit-client-c --output crates/qinit-client-c/include/qinit_client.h\n(or run the `regenerate_header` test with UPDATE_HEADER=1)"
    );
}

#[test]
fn regenerate_header() {
    if std::env::var_os("UPDATE_HEADER").is_some_and(|v| v == "1") {
        std::fs::write(header_path(), generated()).unwrap();
        panic!("include/qinit_client.h updated; re-run without UPDATE_HEADER");
    }
}
