// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use qinit_cell_core::Timer;
use qinit_cell_drive::{CAPACITY, Source, first_free, route, source_timer, timer_source, token};

const SOURCES: [Source; 6] = [
    Source::Main,
    Source::Ready,
    Source::ExecError,
    Source::Events,
    Source::Grace,
    Source::Kill,
];

#[test]
fn every_token_routes_back_and_no_two_collide() {
    let mut seen = std::collections::BTreeSet::new();
    for slot in 0..CAPACITY {
        for s in SOURCES {
            let t = token(slot, s);
            assert_eq!(route(t), Some((slot, s)));
            assert!(seen.insert(t), "token {t} reused");
        }
    }
}

#[test]
fn tokens_outside_the_table_route_nowhere() {
    assert_eq!(route(u64::from(CAPACITY) << 3), None, "slot past the table");
    assert_eq!(route(6), None, "unused source kind");
    assert_eq!(route(7), None, "unused source kind");
    assert_eq!(route(u64::MAX), None, "the orphan token is never a cell's");
}

#[test]
fn timers_map_to_their_sources_and_back() {
    for t in [Timer::Grace, Timer::Kill] {
        assert_eq!(source_timer(timer_source(t)), Some(t));
    }
    assert_eq!(source_timer(Source::Main), None);
}

#[test]
fn the_first_unused_slot_is_chosen() {
    assert_eq!(first_free(&[true, false, false]), Some(1));
    assert_eq!(first_free(&[false]), Some(0));
    assert_eq!(first_free(&[true, true]), None);
    assert_eq!(first_free(&[]), None);
}
