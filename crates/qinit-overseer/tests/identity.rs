// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The strict passwd and group parser (spec R6).
use qinit_overseer::identity::{IdentityError, parse};

const PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\nsvc:x:1000:1000:svc:/home/svc:/bin/sh\nsvc2:x:1001:1001::/:/bin/sh\ntoor:x:0:0::/:/bin/sh\nnobody:x:65534:65534::/:/bin/sh\n";
const GROUP: &str = "root:x:0:\nsvc:x:1000:\nwheel:x:10:svc,svc2\naudio:x:995:svc\n";

#[test]
fn a_known_user_resolves_with_its_groups() {
    let i = parse("svc", PASSWD, GROUP).unwrap();
    assert_eq!((i.uid, i.gid, i.home.as_str()), (1000, 1000, "/home/svc"));
    assert_eq!(i.groups, [10, 995]);
}

#[test]
fn a_prefix_name_does_not_match_a_longer_account() {
    assert_eq!(
        parse("sv", PASSWD, GROUP).unwrap_err(),
        IdentityError::Unknown
    );
    let i = parse("svc2", PASSWD, GROUP).unwrap();
    assert_eq!(i.uid, 1001);
    assert_eq!(i.groups, [10]);
}

#[test]
fn uid_zero_under_another_name_is_refused() {
    assert_eq!(
        parse("toor", PASSWD, GROUP).unwrap_err(),
        IdentityError::RootAlias
    );
    assert_eq!(parse("root", PASSWD, GROUP).unwrap().uid, 0);
}

#[test]
fn a_name_outside_the_alphabet_is_refused_before_lookup() {
    for n in ["0day", "Root", "a b", "", "x".repeat(33).as_str(), "../etc"] {
        assert_eq!(
            parse(n, PASSWD, GROUP).unwrap_err(),
            IdentityError::BadName,
            "{n:?}"
        );
    }
}

#[test]
fn a_duplicate_account_is_ambiguous() {
    assert_eq!(
        parse("svc", &format!("{PASSWD}svc:x:7:7::/:/bin/sh\n"), GROUP).unwrap_err(),
        IdentityError::Ambiguous
    );
}

#[test]
fn a_passwd_line_with_the_wrong_field_count_is_an_error() {
    assert_eq!(
        parse("svc", "svc:x:1000:1000:/home/svc\n", GROUP).unwrap_err(),
        IdentityError::Malformed(1)
    );
    assert_eq!(
        parse("svc", PASSWD, "wheel:x:ten:svc\n").unwrap_err(),
        IdentityError::Malformed(1)
    );
}

#[test]
fn a_group_membership_is_matched_by_whole_name_and_listed_once() {
    let group = "a:x:5:svc,svc2\nb:x:5:svc\nc:x:6:svc3,svc\nd:x:7:\n";
    let i = parse("svc", PASSWD, group).unwrap();
    assert_eq!(i.groups, [5, 6]);
}

#[test]
fn a_non_root_user_in_group_zero_is_refused() {
    let primary = PASSWD.replace("svc:x:1000:1000", "svc:x:1000:0");
    assert_eq!(
        parse("svc", &primary, GROUP).unwrap_err(),
        IdentityError::RootGroup
    );
    let member = GROUP.replace("root:x:0:", "root:x:0:svc");
    assert_eq!(
        parse("svc", PASSWD, &member).unwrap_err(),
        IdentityError::RootGroup
    );
    // root itself may be in group zero
    assert!(parse("root", PASSWD, &member).is_ok());
}
