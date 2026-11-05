// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! One queue for every colony timer: node timers and the waits of parked requests.
use qinit_colony_core::TimerKind;
use qinit_colonyd::deadlines::{Deadlines, Key};

fn node(i: u32, t: TimerKind) -> Key {
    Key::Node(i, t)
}

#[test]
fn due_in_time_then_arm_order() {
    let mut d = Deadlines::default();
    d.arm(node(2, TimerKind::Backoff), 30);
    d.arm(Key::Wait(7), 10);
    d.arm(node(1, TimerKind::StartTimeout), 30);
    d.arm(node(0, TimerKind::Edge), 90);
    assert_eq!(d.due(9), []);
    assert_eq!(
        d.due(30),
        [
            Key::Wait(7),
            node(2, TimerKind::Backoff),
            node(1, TimerKind::StartTimeout)
        ],
        "earliest first, equal times in the order they were armed"
    );
    assert_eq!(d.due(30), [], "each fires once");
    assert_eq!(d.due(1000), [node(0, TimerKind::Edge)]);
}

#[test]
fn a_rearm_replaces() {
    let mut d = Deadlines::default();
    let k = node(3, TimerKind::Backoff);
    d.arm(k, 10);
    d.arm(k, 50);
    assert_eq!(d.next(), Some(50));
    assert_eq!(d.due(20), []);
    assert_eq!(d.due(50), [k]);
}

#[test]
fn cancel_removes_and_next_moves() {
    let mut d = Deadlines::default();
    assert_eq!(d.next(), None);
    d.arm(Key::Wait(1), 5);
    d.arm(Key::Wait(2), 8);
    assert_eq!(d.next(), Some(5));
    d.cancel(Key::Wait(1));
    assert_eq!(d.next(), Some(8));
    d.cancel(Key::Wait(1));
    d.cancel(Key::Wait(2));
    assert_eq!(d.next(), None);
}

#[test]
fn remap_moves_node_keys_and_keeps_waits() {
    let mut d = Deadlines::default();
    d.arm(node(0, TimerKind::Backoff), 10);
    d.arm(node(1, TimerKind::Edge), 20);
    d.arm(node(2, TimerKind::StartTimeout), 30);
    d.arm(Key::Wait(9), 40);
    // New node 0 is new, new 1 was 2, new 2 was 0; old node 1 is gone.
    d.remap(&[u32::MAX, 2, 0]);
    assert_eq!(
        d.due(100),
        [
            node(2, TimerKind::Backoff),
            node(1, TimerKind::StartTimeout),
            Key::Wait(9)
        ]
    );
}
