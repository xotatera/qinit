// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use qinit_vm::qemu::{Accel, args};
use std::path::Path;

#[test]
fn kvm_and_tcg_differ_only_in_accelerator_and_cpu() {
    let k = args(Accel::Kvm, Path::new("/k"), Path::new("/i"));
    let t = args(Accel::Tcg, Path::new("/k"), Path::new("/i"));
    let s = |v: &[std::ffi::OsString]| {
        v.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    };
    let (k, t) = (s(&k), s(&t));
    assert!(k.contains("accel=kvm") && k.contains("-cpu host"), "{k}");
    assert!(t.contains("accel=tcg") && t.contains("-cpu max"), "{t}");
    for a in [&k, &t] {
        assert!(a.contains("-kernel /k -initrd /i"), "{a}");
        assert!(
            a.contains("-no-reboot") && a.contains("-serial stdio"),
            "{a}"
        );
        assert!(
            a.contains("console=ttyS0") && a.contains("panic=-1") && a.contains("rdinit=/init"),
            "{a}"
        );
    }
}
