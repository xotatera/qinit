// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! An initrd in the kernel's `newc` cpio format, written here (no `cpio` tool). Every field is
//! fixed (owner 0, time 0), so the same entries give the same bytes.
/// One archive member; `mode` carries the file type bits (`0o040_000` directory,
/// `0o100_000` regular file).
pub struct Entry {
    pub path: String,
    pub mode: u32,
    pub data: Vec<u8>,
}

fn header(out: &mut Vec<u8>, ino: u32, mode: u32, nlink: u32, size: usize, name: &str) {
    let size = u32::try_from(size).unwrap_or(u32::MAX);
    let namesize = u32::try_from(name.len() + 1).unwrap_or(u32::MAX);
    out.extend_from_slice(b"070701");
    for v in [ino, mode, 0, 0, nlink, 0, size, 0, 0, 0, 0, namesize, 0] {
        out.extend_from_slice(format!("{v:08x}").as_bytes());
    }
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    pad(out);
}

fn pad(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// The archive of `entries` in order, then the trailer.
#[must_use]
pub fn newc(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let nlink = if e.mode & 0o170_000 == 0o040_000 {
            2
        } else {
            1
        };
        let ino = u32::try_from(i + 1).unwrap_or(u32::MAX);
        header(&mut out, ino, e.mode, nlink, e.data.len(), &e.path);
        out.extend_from_slice(&e.data);
        pad(&mut out);
    }
    header(&mut out, 0, 0, 1, 0, "TRAILER!!!");
    out
}
