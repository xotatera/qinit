// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! D26: the ownership check.
use qctl::owner::{Entry, Refusal, check, collect, judge};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

fn entry(path: &str, uid: u32, mode: u32) -> Entry {
    Entry {
        path: path.into(),
        uid,
        mode,
        symlink: false,
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("qctl-owner-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn a_world_writable_ancestor_fails() {
    let e = [
        entry("/", 0, 0o755),
        entry("/tmp", 0, 0o1777),
        entry("/tmp/l", 0, 0o755),
        entry("/tmp/l/a.toml", 0, 0o644),
    ];
    assert!(matches!(judge(&e), Err(Refusal::Owner { ref path, .. }) if path == Path::new("/tmp")));
}

#[test]
fn group_writable_and_non_root_and_symlink_each_fail_and_a_clean_tree_passes() {
    let clean = [entry("/", 0, 0o755), entry("/etc", 0, 0o755)];
    assert!(judge(&clean).is_ok());
    assert!(judge(&[]).is_ok());

    let group = [entry("/", 0, 0o755), entry("/etc", 0, 0o775)];
    assert!(matches!(
        judge(&group),
        Err(Refusal::Owner { ref path, uid: 0, mode: 0o775 }) if path == Path::new("/etc")
    ));

    let other = [entry("/etc", 0, 0o757)];
    assert!(matches!(judge(&other), Err(Refusal::Owner { .. })));

    let user = [entry("/", 0, 0o755), entry("/etc/p.toml", 1000, 0o644)];
    assert!(matches!(
        judge(&user),
        Err(Refusal::Owner { ref path, uid: 1000, mode: 0o644 }) if path == Path::new("/etc/p.toml")
    ));

    let mut link = entry("/etc/l", 0, 0o777);
    link.symlink = true;
    assert!(matches!(
        judge(&[entry("/", 0, 0o755), link]),
        Err(Refusal::Symlink(ref p)) if p == Path::new("/etc/l")
    ));
}

#[test]
fn the_first_failure_is_reported() {
    let e = [entry("/a", 5, 0o755), entry("/b", 6, 0o755)];
    assert!(matches!(judge(&e), Err(Refusal::Owner { uid: 5, .. })));
}

#[test]
fn the_messages_are_the_specified_text() {
    let r = Refusal::Owner {
        path: "/etc/qinit".into(),
        uid: 1000,
        mode: 0o775,
    };
    assert_eq!(
        r.to_string(),
        "qctl: /etc/qinit: owned by uid 1000, mode 775: the policy and the layers must be root's and not writable by group or other"
    );
    assert_eq!(
        Refusal::Symlink("/etc/l".into()).to_string(),
        "qctl: /etc/l: is a symbolic link"
    );
    let io = Refusal::Io("/x".into(), std::io::Error::from_raw_os_error(2));
    assert!(io.to_string().starts_with("qctl: /x: "), "{io}");
}

#[test]
fn not_root_prints_the_notice_and_passes() {
    let mut err = Vec::new();
    assert!(check(&[Path::new("/nonexistent")], 1000, &mut err).is_ok());
    assert_eq!(
        String::from_utf8(err).unwrap(),
        "qctl: not root: the ownership of the policy and layers is not checked\n"
    );
}

#[test]
fn root_runs_collect_and_judge_and_prints_no_notice() {
    let mut err = Vec::new();
    let r = check(&[Path::new("/nonexistent-qctl-owner")], 0, &mut err);
    assert!(matches!(r, Err(Refusal::Io(..))));
    assert!(err.is_empty());
}

#[test]
fn collect_walks_descendants_and_ancestors() {
    let d = temp_dir("walk");
    let layer = d.join("layer");
    std::fs::create_dir_all(layer.join("sub")).unwrap();
    std::fs::write(layer.join("a.toml"), "").unwrap();
    std::fs::write(layer.join("sub/b.toml"), "").unwrap();
    let policy = d.join("policy.toml");
    std::fs::write(&policy, "").unwrap();
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();

    let got = collect(&[&layer, &policy]).unwrap();
    let paths: Vec<&Path> = got.iter().map(|e| e.path.as_path()).collect();
    for p in [
        layer.clone(),
        layer.join("sub"),
        layer.join("a.toml"),
        layer.join("sub/b.toml"),
        policy.clone(),
        d.clone(),
        PathBuf::from("/"),
    ] {
        assert!(paths.contains(&p.as_path()), "{} missing", p.display());
    }
    for a in d.ancestors() {
        assert!(paths.contains(&a), "ancestor {} missing", a.display());
    }
    let p = got.iter().find(|e| e.path == policy).unwrap();
    assert_eq!(p.mode & 0o7777, 0o600);
    assert!(!p.symlink);
}

#[test]
fn collect_records_symlinks_and_does_not_follow_them() {
    let d = temp_dir("link");
    let layer = d.join("layer");
    let elsewhere = d.join("elsewhere");
    std::fs::create_dir_all(&layer).unwrap();
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::write(elsewhere.join("secret.toml"), "").unwrap();
    symlink(&elsewhere, layer.join("l")).unwrap();
    let got = collect(&[&layer]).unwrap();
    let l = got.iter().find(|e| e.path == layer.join("l")).unwrap();
    assert!(l.symlink);
    assert!(!got.iter().any(|e| e.path.ends_with("secret.toml")));
    let links: Vec<Entry> = got.into_iter().filter(|e| e.symlink).collect();
    assert!(matches!(judge(&links), Err(Refusal::Symlink(_))));
}

#[test]
fn a_symlink_root_is_recorded_as_a_symlink() {
    let d = temp_dir("rootlink");
    std::fs::create_dir_all(d.join("real")).unwrap();
    symlink(d.join("real"), d.join("l")).unwrap();
    let got = collect(&[&d.join("l")]).unwrap();
    assert!(got.iter().any(|e| e.path == d.join("l") && e.symlink));
}

#[test]
fn a_missing_root_and_an_unreadable_directory_are_io_refusals() {
    let d = temp_dir("io");
    assert!(matches!(
        collect(&[&d.join("nope")]),
        Err(Refusal::Io(ref p, _)) if p == &d.join("nope")
    ));
    let layer = d.join("layer");
    std::fs::create_dir_all(layer.join("closed")).unwrap();
    std::fs::set_permissions(layer.join("closed"), std::fs::Permissions::from_mode(0o000)).unwrap();
    let closed = layer.join("closed");
    let readable_anyway = std::fs::read_dir(&closed).is_ok(); // root reads it regardless
    let r = collect(&[&layer]);
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o755)).unwrap();
    if readable_anyway {
        assert!(r.is_ok());
    } else {
        assert!(
            matches!(r, Err(Refusal::Io(ref p, _)) if p == &closed),
            "{r:?}"
        );
    }
}
