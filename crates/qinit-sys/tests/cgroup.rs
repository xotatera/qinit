// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The dirfd wrappers on a plain directory: cgroup semantics are tested in guests (plan P7).
use qinit_sys::cgroup;
use std::ffi::CString;
use std::os::unix::fs::MetadataExt;

#[test]
fn directories_and_files_through_a_dirfd() {
    let root = std::env::temp_dir().join(format!("qinit-sys-cg-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let dir = cgroup::open_dir(&root).unwrap();
    let name = CString::new("cell").unwrap();
    cgroup::mkdir_at(&dir, &name, 0o755).unwrap();
    let cell = cgroup::open_dir_at(&dir, &name).unwrap();
    assert_eq!(
        cgroup::inode(&cell).unwrap(),
        std::fs::metadata(root.join("cell")).unwrap().ino()
    );
    let file = CString::new("cgroup.freeze").unwrap();
    std::fs::write(root.join("cell/cgroup.freeze"), b"0").unwrap();
    cgroup::write_file_at(&cell, &file, b"1").unwrap();
    let f = cgroup::open_file_at(&cell, &file, libc::O_RDONLY).unwrap();
    let mut buf = [0u8; 8];
    let n = cgroup::read_from_start(&f, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"1");
    std::fs::remove_file(root.join("cell/cgroup.freeze")).unwrap();
    cgroup::rmdir_at(&dir, &name).unwrap();
    assert!(!root.join("cell").exists());
    std::fs::remove_dir(&root).unwrap();
}
