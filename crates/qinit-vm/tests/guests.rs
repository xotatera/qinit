// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use qinit_vm::guests::{GUEST_RUSTFLAGS, cargo_command};
use std::path::Path;

#[test]
fn the_guest_build_ignores_the_callers_cargo_settings() {
    let c = cargo_command(Path::new("/w"));
    let env: Vec<_> = c.get_envs().collect();
    for gone in [
        "RUSTFLAGS",
        "RUSTC_WRAPPER",
        "CARGO_BUILD_TARGET",
        "CARGO_TARGET_DIR",
        "CARGO_ENCODED_RUSTFLAGS",
    ] {
        let v = env
            .iter()
            .find(|(k, _)| *k == gone)
            .unwrap_or_else(|| panic!("{gone} untouched"));
        if gone == "RUSTFLAGS" {
            assert_eq!(v.1, Some(std::ffi::OsStr::new(GUEST_RUSTFLAGS)));
        } else {
            assert_eq!(v.1, None, "{gone} must be removed");
        }
    }
    assert!(GUEST_RUSTFLAGS.contains("crt-static") && !GUEST_RUSTFLAGS.contains("native"));
}

#[test]
fn the_guest_build_includes_the_executor_and_the_colony_program() {
    let c = cargo_command(Path::new("/w"));
    let args: Vec<_> = c
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let packages: Vec<&str> = args
        .windows(2)
        .filter(|w| w[0] == "-p")
        .map(|w| w[1].as_str())
        .collect();
    assert_eq!(
        packages,
        [
            "qinit-vm-guests",
            "qinit-overseer",
            "qinit-colonyd",
            "qinit-queen"
        ],
        "the initrd carries the overseer, the colony program and queen beside the suite"
    );
    assert!(
        args.windows(2)
            .any(|w| w[0] == "--features" && w[1] == "qinit-queen/testing"),
        "queen is built for the guests with its testing feature: {args:?}"
    );
}
