// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use qinit_vm::kernel;
use std::ffi::OsString;
use std::path::PathBuf;

#[test]
fn the_pin_is_the_planned_release() {
    assert_eq!(kernel::VERSION, "6.18.59");
    assert_eq!(
        kernel::URL,
        "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.59.tar.xz"
    );
    assert_eq!(
        kernel::SHA256,
        "53a55ac9863a5547e292b8e381d4e4c2240dd1127d5428a7c44dbc550be23963"
    );
}

#[test]
fn the_cache_follows_xdg_then_home() {
    assert_eq!(
        kernel::cache_root(Some(OsString::from("/x")), Some(OsString::from("/h"))).unwrap(),
        PathBuf::from("/x/qinit")
    );
    assert_eq!(
        kernel::cache_root(None, Some(OsString::from("/h"))).unwrap(),
        PathBuf::from("/h/.cache/qinit")
    );
    assert_eq!(
        kernel::cache_root(Some(OsString::new()), Some(OsString::from("/h"))).unwrap(),
        PathBuf::from("/h/.cache/qinit"),
        "an empty XDG_CACHE_HOME is unset"
    );
    assert!(kernel::cache_root(None, None).is_err());
}

#[test]
fn a_tarball_with_the_wrong_checksum_is_refused() {
    let f = std::env::temp_dir().join(format!("qinit-vm-tar-{}", std::process::id()));
    std::fs::write(&f, b"not a kernel").unwrap();
    let e = kernel::verify(&f, kernel::SHA256).unwrap_err();
    assert!(e.contains(kernel::SHA256), "{e}");
    assert!(e.contains("does not match"), "{e}");
    std::fs::remove_file(&f).unwrap();
}

#[test]
fn a_tarball_with_the_right_checksum_passes() {
    let f = std::env::temp_dir().join(format!("qinit-vm-ok-{}", std::process::id()));
    std::fs::write(&f, b"abc").unwrap();
    kernel::verify(
        &f,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )
    .unwrap();
    std::fs::remove_file(&f).unwrap();
}

#[test]
fn no_tarball_offline_names_the_remedy() {
    let m = kernel::download_failed(kernel::URL, "curl: (6) Could not resolve host");
    assert!(m.contains("QINIT_KERNEL_TARBALL"), "{m}");
    assert!(m.contains("linux-6.18.59.tar.xz"), "{m}");
}

#[test]
fn options_the_build_dropped_are_named() {
    let fragment = "# comment\nCONFIG_A=y\nCONFIG_B=y\n";
    assert!(kernel::missing_options(fragment, "CONFIG_A=y\nCONFIG_B=y\n").is_empty());
    assert_eq!(
        kernel::missing_options(fragment, "CONFIG_A=y\n# CONFIG_B is not set\n"),
        ["CONFIG_B=y"]
    );
    assert!(
        kernel::missing_options(kernel::FRAGMENT, "").len() > 10,
        "the real fragment parses"
    );
}
