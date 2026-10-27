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
    let size = field32(size, "data", name);
    let namesize = field32(name.len() + 1, "name", name);
    out.extend_from_slice(b"070701");
    for v in [ino, mode, 0, 0, nlink, 0, size, 0, 0, 0, 0, namesize, 0] {
        out.extend_from_slice(format!("{v:08x}").as_bytes());
    }
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    pad(out);
}

/// A newc size field is 8 hex digits; a member beyond that cannot be archived.
fn field32(v: usize, what: &str, name: &str) -> u32 {
    u32::try_from(v).unwrap_or_else(|_| {
        panic!("initrd member {name:?}: {what} of {v} bytes does not fit a newc field (4 GiB - 1)")
    })
}

fn pad(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// The archive of `entries` in order, then the trailer.
///
/// # Panics
/// When a member's data or name is too large for a newc size field (4 GiB - 1): saturating it
/// would write an archive the kernel unpacks wrongly.
#[must_use]
pub fn newc(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let nlink = if e.mode & 0o170_000 == 0o040_000 {
            2
        } else {
            1
        };
        let ino = field32(i + 1, "inode", &e.path);
        header(&mut out, ino, e.mode, nlink, e.data.len(), &e.path);
        out.extend_from_slice(&e.data);
        pad(&mut out);
    }
    header(&mut out, 0, 0, 1, 0, "TRAILER!!!");
    out
}
