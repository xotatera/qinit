// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! Compiles the C smoke program against the header under the strictest flags and links the
//! object into the crate's test binaries (`cargo test` never builds the staticlib or cdylib).
use std::process::Command;

fn main() {
    println!("cargo::rerun-if-changed=tests/c/smoke.c");
    println!("cargo::rerun-if-changed=include/qinit_client.h");
    let out = std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo");
    let object = format!("{out}/smoke.o");
    let result = Command::new("cc")
        .args([
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-I",
            "include",
            "-c",
            "tests/c/smoke.c",
            "-o",
            &object,
        ])
        .output()
        .expect("cc runs");
    assert!(
        result.status.success(),
        "cc failed on tests/c/smoke.c ({}):\n{}{}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    println!("cargo::rustc-link-arg-tests={object}");
}
