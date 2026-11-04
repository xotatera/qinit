// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The pure part of the path view: which listed entry decides how a later entry is opened.
use qinit_overseer::view::writable_ancestor;

#[test]
fn a_writable_parent_is_the_nearest_ancestor() {
    let list = ["rw:/a", "ro:/a/b", "ro:/a/b/c"];
    assert_eq!(writable_ancestor(&list, 0), None);
    assert_eq!(writable_ancestor(&list, 1), Some(0));
    assert_eq!(writable_ancestor(&list, 2), Some(0));
}

#[test]
fn a_read_only_parent_is_no_ancestor() {
    assert_eq!(writable_ancestor(&["ro:/a", "ro:/a/b"], 1), None);
}

#[test]
fn only_whole_components_count() {
    assert_eq!(writable_ancestor(&["rw:/ab", "ro:/a/b"], 1), None);
    assert_eq!(writable_ancestor(&["rw:/a", "ro:/a"], 1), None);
}

#[test]
fn the_nearest_writable_one_wins() {
    let list = ["rw:/a", "rw:/a/b", "ro:/a/b/c"];
    assert_eq!(writable_ancestor(&list, 2), Some(1));
}

#[test]
fn the_six_modes_split_and_answer_their_questions() {
    use qinit_overseer::view::{Mode, split};
    // (entry, read_only, writable, idmapped, follows)
    for (e, m, ro, idmapped, follows) in [
        ("ro:/a", Mode::Ro, true, false, false),
        ("rw:/a", Mode::Rw, false, false, false),
        ("ri:/a", Mode::Ri, true, true, false),
        ("wi:/a", Mode::Wi, false, true, false),
        ("rs:/a", Mode::Rs, true, false, true),
        ("ws:/a", Mode::Ws, false, false, true),
    ] {
        let (got, path) = split(e).unwrap();
        assert_eq!((got, path), (m, "/a"), "{e}");
        assert_eq!(
            (m.read_only(), m.writable(), m.idmapped(), m.follows()),
            (ro, !ro, idmapped, follows),
            "{e}"
        );
    }
    for bad in ["rx:/a", "ws/a", "wo:/a", "/a", "r", ""] {
        assert!(split(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn every_writable_mode_makes_an_ancestor() {
    for w in ["rw:/a", "wi:/a", "ws:/a"] {
        assert_eq!(writable_ancestor(&[w, "ro:/a/b"], 1), Some(0), "{w}");
    }
    for r in ["ro:/a", "ri:/a", "rs:/a"] {
        assert_eq!(writable_ancestor(&[r, "ro:/a/b"], 1), None, "{r}");
    }
}
