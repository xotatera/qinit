// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The id maps of a user namespace and the check that the inside ids are in them.
use qinit_overseer::identity::{Identity, IdentityError, check_inside};
use qinit_overseer::userns::map_text;

fn account(range: Option<(u32, u32)>) -> Identity {
    Identity {
        uid: 1000,
        gid: 1001,
        groups: Vec::new(),
        home: "/home/svc".into(),
        subuid: range,
        subgid: range,
    }
}

#[test]
fn own_map_maps_the_chosen_inside_id() {
    let (gids, uids) = map_text(&account(None), false, (1000, 1001)).unwrap();
    assert_eq!(
        (gids.as_str(), uids.as_str()),
        ("1001 1001 1\n", "1000 1000 1\n")
    );
    let (gids, uids) = map_text(&account(None), false, (0, 0)).unwrap();
    assert_eq!((gids.as_str(), uids.as_str()), ("0 1001 1\n", "0 1000 1\n"));
}

#[test]
fn range_map_keeps_zero_and_the_subordinate_range() {
    let (gids, uids) = map_text(&account(Some((100_000, 65_536))), true, (0, 0)).unwrap();
    assert_eq!(gids, "0 1001 1\n1 100000 65536\n");
    assert_eq!(uids, "0 1000 1\n1 100000 65536\n");
    // The inside ids do not change what is mapped; they only have to be inside it.
    let (gids, uids) = map_text(&account(Some((100_000, 65_536))), true, (1000, 1000)).unwrap();
    assert_eq!(gids, "0 1001 1\n1 100000 65536\n");
    assert_eq!(uids, "0 1000 1\n1 100000 65536\n");
}

#[test]
fn a_range_map_without_the_ranges_is_invalid() {
    assert!(map_text(&account(None), true, (0, 0)).is_err());
}

#[test]
fn range_inside_id_above_count_is_erange() {
    let id = account(Some((100_000, 65_536)));
    assert_eq!(check_inside(&id, true, (0, 0)), Ok(()));
    assert_eq!(check_inside(&id, true, (65_536, 65_536)), Ok(()));
    assert_eq!(
        check_inside(&id, true, (65_537, 0)),
        Err(IdentityError::InsideRange)
    );
    assert_eq!(
        check_inside(&id, true, (0, 65_537)),
        Err(IdentityError::InsideRange)
    );
    // An own map has one mapping, so any id up to 4294967294 will do.
    assert_eq!(
        check_inside(&account(None), false, (4_294_967_294, 4_294_967_294)),
        Ok(())
    );
}
