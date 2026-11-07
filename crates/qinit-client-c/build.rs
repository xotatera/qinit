// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! Compiles the C programs of `tests/c` (the smoke program and the request builder's) against the
//! header and links the objects into the crate's test binaries (`cargo test` never builds the
//! staticlib or cdylib).
//!
//! A build script cannot tell a test build from a library build, so this one never fails the
//! build: without a `cc` that compiles the programs it prints a cargo warning and sets the cfg
//! `smoke_c_unavailable`, and the C tests fail in place of the C programs. Warnings do not stop
//! the build either; the warning-free compile under `-Werror` is a test of its own
//! (`tests/smoke.rs`), so a newer compiler's new warning fails a test, not the library.
//!
//! The programs are compiled with the undefined-behaviour sanitizer in trap mode: a check that
//! fails executes a trap instruction and kills the test binary, and no sanitizer run-time library
//! is needed in the Rust test binary (the address sanitizer would need one).
//!
//! `rustc-link-arg-tests` links the objects into every test binary of this crate, not only
//! `smoke`. They are linked after the rlibs, so a test that calls `qinit_smoke` or `qinit_builder`
//! also needs a `KEEP` table of the exported functions, as `tests/smoke.rs` has; the other test
//! binaries never call into them.
use std::process::Command;

/// The C programs, by the name of their source in `tests/c`.
const PROGRAMS: [&str; 2] = ["smoke", "builder"];

fn main() {
    for program in PROGRAMS {
        println!("cargo::rerun-if-changed=tests/c/{program}.c");
    }
    println!("cargo::rerun-if-changed=include/qinit_client.h");
    println!("cargo::rustc-check-cfg=cfg(smoke_c_unavailable)");
    let out = std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo");
    let mut objects = Vec::new();
    for program in PROGRAMS {
        let object = format!("{out}/{program}.o");
        let source = format!("tests/c/{program}.c");
        let result = Command::new("cc")
            .args([
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-fsanitize=undefined",
                "-fsanitize-trap=undefined",
                "-I",
                "include",
                "-c",
                &source,
                "-o",
                &object,
            ])
            .output();
        match result {
            Ok(r) if r.status.success() => objects.push(object),
            Ok(r) => {
                return unavailable(&format!(
                    "cc failed on {source} ({}): {}",
                    r.status,
                    String::from_utf8_lossy(&r.stderr).replace('\n', " ")
                ));
            }
            Err(e) => return unavailable(&format!("cc did not run: {e}")),
        }
    }
    for object in objects {
        println!("cargo::rustc-link-arg-tests={object}");
    }
}

/// A C program could not be built: say why, and let the C tests fail in its place.
fn unavailable(why: &str) {
    println!("cargo::warning=the C tests cannot run: {why}");
    println!("cargo::rustc-cfg=smoke_c_unavailable");
}
