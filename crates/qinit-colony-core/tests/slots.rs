// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The instance slot pool: a frame never has more live slots than its cap, the pool never
//! holds more than `MAX_SLOTS`, and a slot is freed exactly once.
use qinit_colony_core::*;

fn pool() -> Vec<Slot> {
    vec![free_slot(); MAX_SLOTS]
}

#[test]
fn a_claim_takes_the_first_free_slot_as_starting() {
    let mut p = pool();
    assert_eq!(claim(&mut p, 7, 2, 100), Some(0));
    assert_eq!(
        p[0],
        Slot {
            frame: 7,
            id: 100,
            state: SlotState::Starting
        }
    );
    assert_eq!(claim(&mut p, 8, 2, 101), Some(1));
    assert_eq!(live_of(&p, 7), 1);
    assert_eq!(live_of(&p, 8), 1);
}

#[test]
fn a_frame_stops_at_its_cap_and_another_frame_does_not() {
    let mut p = pool();
    assert!(claim(&mut p, 1, 2, 1).is_some());
    assert!(claim(&mut p, 1, 2, 2).is_some());
    assert_eq!(claim(&mut p, 1, 2, 3), None);
    assert!(claim(&mut p, 2, 1, 4).is_some());
    assert_eq!(live_of(&p, 1), 2);
}

#[test]
fn a_cap_of_zero_claims_nothing() {
    let mut p = pool();
    assert_eq!(claim(&mut p, 1, 0, 1), None);
    assert_eq!(live_of(&p, 1), 0);
}

#[test]
fn the_pool_is_bounded_by_max_slots() {
    let mut p = pool();
    for i in 0..MAX_SLOTS {
        let frame = u32::try_from(i % 8).unwrap();
        assert_eq!(claim(&mut p, frame, 64, u32::try_from(i).unwrap()), Some(i));
    }
    assert_eq!(claim(&mut p, 9, 64, 999), None);
    let total: usize = (0..8).map(|f| live_of(&p, f) as usize).sum();
    assert_eq!(total, MAX_SLOTS);
}

#[test]
fn a_release_frees_the_slot_for_the_next_claim() {
    let mut p = pool();
    assert_eq!(claim(&mut p, 1, 1, 1), Some(0));
    assert_eq!(claim(&mut p, 1, 1, 2), None);
    release(&mut p, 0);
    assert_eq!(p[0].state, SlotState::Free);
    assert_eq!(live_of(&p, 1), 0);
    assert_eq!(claim(&mut p, 1, 1, 3), Some(0));
    assert_eq!(p[0].id, 3);
}

#[test]
fn a_state_change_touches_only_its_slot() {
    let mut p = pool();
    claim(&mut p, 1, 4, 1);
    claim(&mut p, 1, 4, 2);
    set_state(&mut p, 1, SlotState::Running);
    assert_eq!(p[0].state, SlotState::Starting);
    assert_eq!(p[1].state, SlotState::Running);
    assert_eq!(live_of(&p, 1), 2);
    set_state(&mut p, 1, SlotState::Stopping);
    assert_eq!(live_of(&p, 1), 2);
}

#[test]
fn a_slot_of_a_released_frame_is_found_by_id() {
    let mut p = pool();
    claim(&mut p, 5, 4, 41);
    claim(&mut p, 5, 4, 42);
    assert_eq!(slot_of(&p, 42), Some(1));
    release(&mut p, 1);
    assert_eq!(slot_of(&p, 42), None);
    assert_eq!(slot_of(&p, 41), Some(0));
}
