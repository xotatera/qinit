// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Duration and size strings with a mandatory unit suffix (digits only, no fractions).

/// Split `s` into its leading decimal digits (as a number) and the rest.
fn split(s: &str) -> Option<(u64, &str)> {
    let end = s
        .bytes()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(s.len());
    let (digits, unit) = s.split_at(end);
    if digits.is_empty() {
        return None;
    }
    Some((digits.parse::<u64>().ok()?, unit))
}

/// Parse `250ms`, `1s`, `5m` or `2h` into milliseconds; `None` on any other shape or overflow.
#[must_use]
pub fn duration_ms(s: &str) -> Option<u32> {
    let (n, unit) = split(s)?;
    let factor: u64 = match unit {
        "ms" => 1,
        "s" => 1000,
        "m" => 60_000,
        "h" => 3_600_000,
        _ => return None,
    };
    u32::try_from(n.checked_mul(factor)?).ok()
}

/// Parse `512K`, `512M` or `2G` into KiB; `None` on any other shape or overflow.
#[must_use]
pub fn size_kib(s: &str) -> Option<u32> {
    let (n, unit) = split(s)?;
    let factor: u64 = match unit {
        "K" => 1,
        "M" => 1024,
        "G" => 1024 * 1024,
        _ => return None,
    };
    u32::try_from(n.checked_mul(factor)?).ok()
}

/// Parse `512K`, `512M` or `2G` into bytes; `None` on any other shape or overflow of `u64`.
#[must_use]
pub fn size_bytes(s: &str) -> Option<u64> {
    let (n, unit) = split(s)?;
    let factor: u64 = match unit {
        "K" => 1 << 10,
        "M" => 1 << 20,
        "G" => 1 << 30,
        _ => return None,
    };
    n.checked_mul(factor)
}
