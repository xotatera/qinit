// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Unit-suffix parsing.
use qinit_frames::units::{duration_ms, size_kib};

#[test]
fn durations_parse() {
    assert_eq!(duration_ms("250ms"), Some(250));
    assert_eq!(duration_ms("1s"), Some(1000));
    assert_eq!(duration_ms("5m"), Some(300_000));
    assert_eq!(duration_ms("2h"), Some(7_200_000));
    assert_eq!(duration_ms("0s"), Some(0));
}

#[test]
fn bad_durations_are_none() {
    for s in [
        "1.5s",
        "s",
        "",
        "-1s",
        "1d",
        "99999999999h",
        "5",
        "1 s",
        "+1s",
        " 1s",
        "1s ",
        "\u{661}s",
    ] {
        assert_eq!(duration_ms(s), None, "{s:?}");
    }
}

#[test]
fn sizes_parse() {
    assert_eq!(size_kib("512M"), Some(524_288));
    assert_eq!(size_kib("2G"), Some(2_097_152));
    assert_eq!(size_kib("4K"), Some(4));
    assert_eq!(size_kib("512K"), Some(512));
}

#[test]
fn bad_sizes_are_none() {
    for s in [
        "512",
        "1T",
        "4294967296K",
        "",
        "K",
        "1.5M",
        "-1K",
        "4096G",
        "+1K",
        " 1K",
        "\u{661}K",
    ] {
        assert_eq!(size_kib(s), None, "{s:?}");
    }
}

#[test]
fn the_largest_representable_size_parses() {
    assert_eq!(size_kib("4294967295K"), Some(u32::MAX));
}
