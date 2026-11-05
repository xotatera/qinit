// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! Compiles the C smoke program against the header and links the object into the crate's test
//! binaries (`cargo test` never builds the staticlib or cdylib).
//!
//! A build script cannot tell a test build from a library build, so this one never fails the
//! build: without a `cc` that compiles the program it prints a cargo warning and sets the cfg
//! `smoke_c_unavailable`, and the smoke test fails in place of the C program. Warnings do not stop
//! the build either; the warning-free compile under `-Werror` is a test of its own
//! (`tests/smoke.rs`), so a newer compiler's new warning fails a test, not the library.
//!
//! `rustc-link-arg-tests` links the object into every test binary of this crate, not only
//! `smoke`. It is linked after the rlibs, so a test that calls `qinit_smoke` also needs a `KEEP`
//! table of the exported functions, as `tests/smoke.rs` has; the other test binaries never call
//! into it.
use std::process::Command;

fn main() {
    println!("cargo::rerun-if-changed=tests/c/smoke.c");
    println!("cargo::rerun-if-changed=include/qinit_client.h");
    println!("cargo::rustc-check-cfg=cfg(smoke_c_unavailable)");
    let out = std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo");
    let object = format!("{out}/smoke.o");
    let result = Command::new("cc")
        .args([
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-I",
            "include",
            "-c",
            "tests/c/smoke.c",
            "-o",
            &object,
        ])
        .output();
    match result {
        Ok(r) if r.status.success() => println!("cargo::rustc-link-arg-tests={object}"),
        Ok(r) => unavailable(&format!(
            "cc failed on tests/c/smoke.c ({}): {}",
            r.status,
            String::from_utf8_lossy(&r.stderr).replace('\n', " ")
        )),
        Err(e) => unavailable(&format!("cc did not run: {e}")),
    }
}

/// The smoke program could not be built: say why, and let the smoke test fail in its place.
fn unavailable(why: &str) {
    println!("cargo::warning=the C smoke test cannot run: {why}");
    println!("cargo::rustc-cfg=smoke_c_unavailable");
}
