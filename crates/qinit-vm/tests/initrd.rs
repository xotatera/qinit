// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use qinit_vm::initrd::{Entry, newc};

/// Reads back `(name, mode, data)` of each entry, checking magic and alignment.
fn parse(mut b: &[u8]) -> Vec<(String, u32, Vec<u8>)> {
    let field = |h: &[u8], i: usize| {
        u32::from_str_radix(std::str::from_utf8(&h[6 + i * 8..14 + i * 8]).unwrap(), 16).unwrap()
    };
    let total = b.len();
    let mut out = Vec::new();
    loop {
        assert_eq!((total - b.len()) % 4, 0, "every header starts 4-aligned");
        assert_eq!(&b[..6], b"070701");
        let (mode, size, namesize) = (field(b, 1), field(b, 6) as usize, field(b, 11) as usize);
        let name = std::str::from_utf8(&b[110..110 + namesize - 1])
            .unwrap()
            .to_string();
        assert_eq!(b[110 + namesize - 1], 0, "names are NUL-terminated");
        let data_at = (110 + namesize).next_multiple_of(4);
        let data = b[data_at..data_at + size].to_vec();
        b = &b[(data_at + size).next_multiple_of(4)..];
        if name == "TRAILER!!!" {
            assert!(b.is_empty(), "the trailer is last");
            return out;
        }
        out.push((name, mode, data));
    }
}

#[test]
fn entries_round_trip_with_a_trailer() {
    let bytes = newc(&[
        Entry {
            path: "sbin".into(),
            mode: 0o040_755,
            data: Vec::new(),
        },
        Entry {
            path: "init".into(),
            mode: 0o100_755,
            data: b"\x7fELF...".to_vec(),
        },
    ]);
    assert_eq!(
        parse(&bytes),
        [
            ("sbin".to_string(), 0o040_755, Vec::new()),
            ("init".to_string(), 0o100_755, b"\x7fELF...".to_vec()),
        ]
    );
}

#[test]
fn the_archive_is_reproducible() {
    let e = [Entry {
        path: "init".into(),
        mode: 0o100_755,
        data: vec![1, 2, 3],
    }];
    assert_eq!(newc(&e), newc(&e));
}

#[test]
fn a_dynamic_elf_is_recognised() {
    use qinit_vm::guests::has_interp;
    // An ELF64 LE header with one program header of type PT_INTERP (3) at offset 64.
    let mut elf = vec![0u8; 64 + 56];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
    elf[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
    elf[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
    elf[64..68].copy_from_slice(&3u32.to_le_bytes());
    assert_eq!(has_interp(&elf), Ok(true));
    elf[64..68].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(has_interp(&elf), Ok(false));
    assert!(has_interp(b"#!/bin/sh").is_err());
}

#[test]
fn cargo_json_names_each_binary() {
    use qinit_vm::guests::executables;
    let json = concat!(
        r#"{"reason":"compiler-artifact","target":{"name":"probe","kind":["bin"]},"executable":"/b/probe"}"#,
        "\n",
        r#"{"reason":"compiler-artifact","target":{"name":"qinit_vm_guests","kind":["lib"]},"executable":null}"#,
        "\n",
        r#"{"reason":"build-finished","success":true}"#,
        "\n",
    );
    let m = executables(json);
    assert_eq!(m.len(), 1);
    assert_eq!(m["probe"], std::path::PathBuf::from("/b/probe"));
}
