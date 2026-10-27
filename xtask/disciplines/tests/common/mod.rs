// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

/// Avoid ETXTBSY: parallel forks must never inherit a write fd for an executable.
/// Only the install child opens the destination for writing.
pub fn exe(path: &std::path::Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let source = path.with_extension("source");
    std::fs::write(&source, text).unwrap();
    assert!(
        std::process::Command::new("install")
            .args(["-m", "755"])
            .arg(&source)
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
    std::fs::remove_file(source).unwrap();
}
