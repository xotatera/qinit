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
