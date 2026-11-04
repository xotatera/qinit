// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! The QCP1 decoder: every rule of `accepted`, one patch at a time.
mod common;

use common::W::{N, S};
use common::*;
use qinit_proto_core::*;

fn ok(t: u32) -> (Vec<u8>, usize) {
    valid(t)
}

#[test]
fn every_valid_default_is_accepted() {
    for t in TYPES {
        let (b, fds) = ok(t);
        assert_eq!(check(&b, fds), Ok(()), "type {t}");
    }
}

#[test]
fn a_wrong_magic_is_header_and_version_2_is_version() {
    let (b, fds) = ok(T_LIST);
    assert_eq!(
        check(&with(&b, |w| w[H_MAGIC] += 1), fds).unwrap_err(),
        DecodeError::Header
    );
    assert_eq!(
        check(&with(&b, |w| w[H_VERSION] = 2), fds).unwrap_err(),
        DecodeError::Version
    );
    assert_eq!(check(&b[..10], fds).unwrap_err(), DecodeError::Header);
    assert_eq!(check(&[], 0).unwrap_err(), DecodeError::Header);
}

#[test]
fn a_total_length_that_disagrees_is_header() {
    let (b, fds) = ok(T_STATUS);
    let short = with(&b, |w| w[H_TOTAL_LEN] -= 1);
    assert_eq!(check(&short, fds).unwrap_err(), DecodeError::Header);
    let mut longer = b.clone();
    longer.push(0);
    assert_eq!(check(&longer, fds).unwrap_err(), DecodeError::Header);
}

#[test]
fn a_message_over_the_limit_is_header() {
    let big = vec![0u8; MAX_MESSAGE + 4];
    assert_eq!(check(&big, 0).unwrap_err(), DecodeError::Header);
}

#[test]
fn a_record_that_does_not_fit_is_header() {
    let (b, fds) = ok(T_CHANGE);
    let cut = HEADER_WORDS * 4 + 8;
    let b = with(&b[..cut], |w| w[H_TOTAL_LEN] = n(cut));
    assert_eq!(check(&b, fds).unwrap_err(), DecodeError::Header);
}

fn n(x: usize) -> u32 {
    u32::try_from(x).unwrap()
}

#[test]
fn an_unknown_type_is_type() {
    let (b, fds) = ok(T_LIST);
    for t in [0, 8, 63, 75, 1000] {
        let b = with(&b, |w| w[H_TYPE] = t);
        assert_eq!(check(&b, fds).unwrap_err(), DecodeError::Type, "type {t}");
    }
}

#[test]
fn a_string_inside_the_record_is_pool() {
    let (b, fds) = ok(T_STATUS);
    let b = with(&b, |w| w[at(ST_TARGET_OFF)] = 8);
    assert_eq!(check(&b, fds).unwrap_err(), DecodeError::Pool);
}

#[test]
fn a_string_past_the_message_is_pool() {
    let (b, fds) = ok(T_STATUS);
    let b1 = with(&b, |w| w[at(ST_TARGET_LEN)] = u32::MAX);
    assert_eq!(check(&b1, fds).unwrap_err(), DecodeError::Pool);
    let b2 = with(&b, |w| w[at(ST_TARGET_OFF)] = u32::MAX);
    assert_eq!(check(&b2, fds).unwrap_err(), DecodeError::Pool);
}

#[test]
fn invalid_utf8_is_pool() {
    let (mut b, fds) = ok(T_STATUS);
    let i = pool_at(&b);
    b[i] = 0xff;
    assert_eq!(check(&b, fds).unwrap_err(), DecodeError::Pool);
}

#[test]
fn a_list_with_an_empty_element_is_pool() {
    let b = build(
        T_LAUNCH,
        0,
        &[S("backup"), S("a\0\0b"), S(""), N(0), N(1000), N(0)],
        &[],
    );
    assert_eq!(check(&b, 0).unwrap_err(), DecodeError::Pool);
}

#[test]
fn a_97_byte_name_is_consistency() {
    let name: &'static str = Box::leak("n".repeat(97).into_boxed_str());
    let b = build(
        T_LAUNCH,
        0,
        &[S(name), S(""), S(""), N(0), N(1000), N(0)],
        &[],
    );
    assert_eq!(check(&b, 0).unwrap_err(), DecodeError::Consistency);
    let name: &'static str = Box::leak("n".repeat(96).into_boxed_str());
    let b = build(
        T_LAUNCH,
        0,
        &[S(name), S(""), S(""), N(0), N(1000), N(0)],
        &[],
    );
    assert!(check(&b, 0).is_ok());
    let empty = build(
        T_LAUNCH,
        0,
        &[S(""), S(""), S(""), N(0), N(1000), N(0)],
        &[],
    );
    assert_eq!(check(&empty, 0).unwrap_err(), DecodeError::Consistency);
}

#[test]
fn a_target_is_at_most_107_bytes() {
    let long: &'static str = Box::leak("t".repeat(107).into_boxed_str());
    assert!(check(&build(T_STATUS, 0, &[S(long)], &[]), 0).is_ok());
    let longer: &'static str = Box::leak("t".repeat(108).into_boxed_str());
    assert_eq!(
        check(&build(T_STATUS, 0, &[S(longer)], &[]), 0).unwrap_err(),
        DecodeError::Consistency
    );
}

#[test]
fn enums_are_bounded() {
    for (t, w, v) in [
        (T_CHANGE, CH_ACTION, 6),
        (T_CHANGE, CH_SETTLED, 2),
        (T_SHUTDOWN, SH_MODE, 3),
        (T_LIST, LI_KIND, 4),
        (T_ERROR, ER_CODE, 13),
        (T_ERROR, ER_CODE, 0),
        (T_LAUNCH, LA_FD_ROLES, 8),
        (T_REFRESH, RF_SETTLED, 2),
        (T_NODE_STATUS, NS_KIND, 3),
        (T_NODE_STATUS, NS_STATE, 7),
        (T_INSTANCE_STATUS, IS_STATE, 1),
        (T_INSTANCE_STATUS, IS_STATE, 6),
        (T_SETTLED, SW_STATE, 7),
        (T_PENDING, SW_STATE, 7),
        (T_SUPERSEDED, SW_STATE, 7),
    ] {
        let (b, fds) = ok(t);
        let b = with(&b, |x| x[at(w)] = v);
        assert_eq!(
            check(&b, fds).unwrap_err(),
            DecodeError::Enum,
            "type {t} word {w} = {v}"
        );
    }
}

#[test]
fn a_list_entry_enum_out_of_range_is_enum() {
    let (b, fds) = ok(T_LIST_PAGE);
    let first = HEADER_WORDS + LP_FIXED_WORDS;
    let kind = with(&b, |x| x[first + EN_KIND] = 3);
    assert_eq!(check(&kind, fds).unwrap_err(), DecodeError::Enum);
    let state = with(&b, |x| x[first + ENTRY_WORDS + EN_STATE] = 7);
    assert_eq!(check(&state, fds).unwrap_err(), DecodeError::Enum);
}

#[test]
fn wait_ms_0_with_settled_and_600001_are_consistency() {
    for (t, settled_word, wait_word) in [
        (T_CHANGE, CH_SETTLED, CH_WAIT_MS),
        (T_REFRESH, RF_SETTLED, RF_WAIT_MS),
        (T_SHUTDOWN, SH_SETTLED, SH_WAIT_MS),
    ] {
        let (b, fds) = ok(t);
        let zero = with(&b, |x| x[at(wait_word)] = 0);
        assert_eq!(check(&zero, fds).unwrap_err(), DecodeError::Consistency);
        let over = with(&b, |x| x[at(wait_word)] = MAX_WAIT_MS + 1);
        assert_eq!(check(&over, fds).unwrap_err(), DecodeError::Consistency);
        let top = with(&b, |x| x[at(wait_word)] = MAX_WAIT_MS);
        assert!(check(&top, fds).is_ok());
        let unsettled = with(&b, |x| x[at(settled_word)] = 0);
        assert_eq!(
            check(&unsettled, fds).unwrap_err(),
            DecodeError::Consistency,
            "an unsettled request waits 0"
        );
        let none = with(&b, |x| {
            x[at(settled_word)] = 0;
            x[at(wait_word)] = 0;
        });
        assert!(check(&none, fds).is_ok());
    }
    let (b, fds) = ok(T_LAUNCH);
    let zero = with(&b, |x| x[at(LA_WAIT_MS)] = 0);
    assert_eq!(check(&zero, fds).unwrap_err(), DecodeError::Consistency);
}

#[test]
fn fd_count_must_match_the_received_and_the_roles() {
    let (b, _) = ok(T_LAUNCH);
    assert!(check(&b, 2).is_ok());
    assert_eq!(check(&b, 1).unwrap_err(), DecodeError::FdCount);
    assert_eq!(check(&b, 3).unwrap_err(), DecodeError::FdCount);
    let three = with(&b, |x| x[H_FD_COUNT] = 3);
    assert_eq!(check(&three, 3).unwrap_err(), DecodeError::FdCount);
    let (r, _) = ok(T_REFRESH);
    assert!(check(&r, 1).is_ok());
    assert_eq!(check(&r, 0).unwrap_err(), DecodeError::FdCount);
    let none = with(&r, |x| x[H_FD_COUNT] = 0);
    assert_eq!(check(&none, 0).unwrap_err(), DecodeError::FdCount);
    let (s, _) = ok(T_STATUS);
    assert_eq!(check(&s, 1).unwrap_err(), DecodeError::FdCount);
    let one = with(&s, |x| x[H_FD_COUNT] = 1);
    assert_eq!(check(&one, 1).unwrap_err(), DecodeError::FdCount);
}

#[test]
fn a_launch_with_no_roles_carries_no_fd() {
    let b = build(
        T_LAUNCH,
        0,
        &[S("backup"), S(""), S(""), N(0), N(1000), N(0)],
        &[],
    );
    assert!(check(&b, 0).is_ok());
    assert_eq!(check(&b, 1).unwrap_err(), DecodeError::FdCount);
}

#[test]
fn unused_fields_must_be_zero() {
    let (b, fds) = ok(T_INSTANCE_STATUS);
    let status_without_exit = with(&b, |x| {
        x[at(IS_STATE)] = 3;
        x[at(IS_HAS_STATUS)] = 0;
    });
    assert_eq!(
        check(&status_without_exit, fds).unwrap_err(),
        DecodeError::Consistency
    );
    let running = with(&b, |x| {
        x[at(IS_STATE)] = 3;
        x[at(IS_HAS_STATUS)] = 0;
        x[at(IS_STATUS)] = 0;
    });
    assert!(check(&running, fds).is_ok());
    let exited_without_flag = with(&b, |x| x[at(IS_HAS_STATUS)] = 0);
    assert_eq!(
        check(&exited_without_flag, fds).unwrap_err(),
        DecodeError::Consistency
    );
    let node = build(
        T_NODE_STATUS,
        0,
        &[
            S("sshd"),
            N(0),
            N(1),
            N(0),
            N(NONE),
            S("stray"),
            N(0),
            N(0),
            N(0),
            N(0),
            N(0),
        ],
        &[],
    );
    assert_eq!(check(&node, 0).unwrap_err(), DecodeError::Consistency);
}

#[test]
fn argv_tail_of_65_is_consistency() {
    let many: &'static str = Box::leak(vec!["a"; 65].join("\0").into_boxed_str());
    let b = build(
        T_LAUNCH,
        0,
        &[S("backup"), S(many), S(""), N(0), N(1000), N(0)],
        &[],
    );
    assert_eq!(check(&b, 0).unwrap_err(), DecodeError::Consistency);
    let ok64: &'static str = Box::leak(vec!["a"; 64].join("\0").into_boxed_str());
    let b = build(
        T_LAUNCH,
        0,
        &[S("backup"), S(ok64), S(""), N(0), N(1000), N(0)],
        &[],
    );
    assert!(check(&b, 0).is_ok());
}

#[test]
fn env_additions_are_entries_and_at_most_64() {
    let bad = build(
        T_LAUNCH,
        0,
        &[S("backup"), S(""), S("NOEQ"), N(0), N(1000), N(0)],
        &[],
    );
    assert_eq!(check(&bad, 0).unwrap_err(), DecodeError::Consistency);
    let keyless = build(
        T_LAUNCH,
        0,
        &[S("backup"), S(""), S("=v"), N(0), N(1000), N(0)],
        &[],
    );
    assert_eq!(check(&keyless, 0).unwrap_err(), DecodeError::Consistency);
    let many: &'static str = Box::leak(vec!["K=v"; 65].join("\0").into_boxed_str());
    let b = build(
        T_LAUNCH,
        0,
        &[S("backup"), S(""), S(many), N(0), N(1000), N(0)],
        &[],
    );
    assert_eq!(check(&b, 0).unwrap_err(), DecodeError::Consistency);
}

#[test]
fn a_list_page_is_bounded() {
    let (b, fds) = ok(T_LIST_PAGE);
    let too_many = with(&b, |x| x[at(LP_COUNT)] = 257);
    assert_eq!(check(&too_many, fds).unwrap_err(), DecodeError::Consistency);
    let past = with(&b, |x| x[at(LP_COUNT)] = 3);
    assert_eq!(check(&past, fds).unwrap_err(), DecodeError::Header);
    let empty = build(T_LIST_PAGE, 0, &[N(0), N(NONE)], &[]);
    assert!(check(&empty, 0).is_ok());
}

#[test]
fn a_list_entry_with_a_bad_name_is_refused() {
    let (b, fds) = ok(T_LIST_PAGE);
    let first = HEADER_WORDS + LP_FIXED_WORDS;
    let empty_name = with(&b, |x| x[first + EN_NAME_LEN] = 0);
    assert_eq!(
        check(&empty_name, fds).unwrap_err(),
        DecodeError::Consistency
    );
    let inside = with(&b, |x| x[first + EN_NAME_OFF] = 8);
    assert_eq!(check(&inside, fds).unwrap_err(), DecodeError::Pool);
}

#[test]
fn the_record_table_matches_the_function() {
    assert_eq!(RECORD_WORDS.len(), 18);
    for (t, n) in RECORD_WORDS {
        assert_eq!(record_words(t), n, "type {t}");
        assert!(known_type(t));
    }
    assert!(!known_type(0) && !known_type(8) && !known_type(75));
}

#[test]
fn launch_flags_above_1_are_enum() {
    let (b, fds) = ok(T_LAUNCH);
    for flags in [0, 1] {
        assert!(check(&with(&b, |x| x[at(LA_FLAGS)] = flags), fds).is_ok());
    }
    for flags in [2, 3, 0x8000_0000] {
        assert_eq!(
            check(&with(&b, |x| x[at(LA_FLAGS)] = flags), fds).unwrap_err(),
            DecodeError::Enum,
            "flags {flags:#x}"
        );
    }
    assert_eq!(FLAG_PIDFD, 1);
    assert_eq!(LA_FLAGS, 8);
}

#[test]
fn launched_with_one_fd_is_accepted_and_two_is_fd_count() {
    let (b, _) = ok(T_LAUNCHED);
    assert!(check(&b, 0).is_ok());
    let one = with(&b, |x| x[H_FD_COUNT] = 1);
    assert!(check(&one, 1).is_ok());
    assert_eq!(check(&one, 0).unwrap_err(), DecodeError::FdCount);
    let two = with(&b, |x| x[H_FD_COUNT] = 2);
    assert_eq!(check(&two, 2).unwrap_err(), DecodeError::FdCount);
}

#[test]
fn every_other_reply_with_an_fd_is_fd_count() {
    for t in TYPES.into_iter().filter(|t| *t >= 64 && *t != T_LAUNCHED) {
        let (b, _) = ok(t);
        let one = with(&b, |x| x[H_FD_COUNT] = 1);
        assert_eq!(
            check(&one, 1).unwrap_err(),
            DecodeError::FdCount,
            "type {t}"
        );
    }
}

#[test]
fn run_is_root_only() {
    assert!(authorized(Op::Run, PeerId { uid: 0 }));
    assert!(!authorized(Op::Run, PeerId { uid: 1000 }));
    assert_eq!(T_RUN, 7);
    assert_eq!(MAX_FDS, 4);
}

fn run_with(name: &'static str, roles: u32, grace: u32, wait: u32) -> Vec<u8> {
    build(
        T_RUN,
        1 + roles.count_ones(),
        &[S(name), N(roles), N(0), N(0), N(0), N(0), N(grace), N(wait)],
        &[],
    )
}

#[test]
fn run_name_96_is_consistency() {
    let ok95: &'static str = Box::leak("a".repeat(95).into_boxed_str());
    let bad96: &'static str = Box::leak("a".repeat(96).into_boxed_str());
    assert!(check(&run_with(ok95, 0, 1000, 5000), 1).is_ok());
    assert_eq!(
        check(&run_with(bad96, 0, 1000, 5000), 1).unwrap_err(),
        DecodeError::Consistency
    );
    assert_eq!(
        check(&run_with("", 0, 1000, 5000), 1).unwrap_err(),
        DecodeError::Consistency
    );
}

#[test]
fn run_needs_one_fd_plus_its_roles() {
    assert!(check(&run_with("job", 0, 1000, 5000), 1).is_ok());
    assert!(check(&run_with("job", 7, 1000, 5000), 4).is_ok());
    assert!(check(&run_with("job", 2, 1000, 5000), 2).is_ok());
    assert_eq!(
        check(&run_with("job", 0, 1000, 5000), 0).unwrap_err(),
        DecodeError::FdCount
    );
    assert_eq!(
        check(&run_with("job", 7, 1000, 5000), 3).unwrap_err(),
        DecodeError::FdCount
    );
}

#[test]
fn run_grace_99_is_consistency() {
    assert!(check(&run_with("job", 0, 100, 5000), 1).is_ok());
    assert_eq!(
        check(&run_with("job", 0, 99, 5000), 1).unwrap_err(),
        DecodeError::Consistency
    );
    assert_eq!(
        check(&run_with("job", 0, 1000, 0), 1).unwrap_err(),
        DecodeError::Consistency
    );
}

#[test]
fn run_enums_are_bounded() {
    let (b, fds) = ok(T_RUN);
    for (w, v) in [(RU_FD_ROLES, 8), (RU_FLAGS, 2), (RU_STOP_MODE, 2)] {
        assert_eq!(
            check(&with(&b, |x| x[at(w)] = v), fds).unwrap_err(),
            DecodeError::Enum,
            "word {w}"
        );
    }
}
