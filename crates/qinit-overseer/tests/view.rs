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
