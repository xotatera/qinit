// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The instance slot pool (spec 2026-11-04 §6.3, obligation 4): the live instances of a
//! launchable forager. A frame never has more live slots than the cap its caller names, the pool
//! never holds more than [`MAX_SLOTS`], and a slot is freed exactly once (`release` requires a
//! live slot). The instance's cell, its pid and its exit record belong to the runtime.
use vstd::prelude::*;

verus! {

/// Instances alive at once, over all frames.
pub const MAX_SLOTS: usize = 256;

/// Where an instance is. A slot holds one of the first four; `Exited` is what a released
/// instance is reported as, with its wait status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotState {
    Free,
    Starting,
    Running,
    Stopping,
    Exited(i32),
}

/// One slot: the frame node it belongs to and the instance id it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    pub frame: u32,
    pub id: u32,
    pub state: SlotState,
}

/// A slot nobody holds.
#[must_use]
pub fn free_slot() -> (r: Slot)
    ensures
        r == free_slot_spec(),
{
    Slot { frame: 0, id: 0, state: SlotState::Free }
}

/// `free_slot` as a specification.
pub open spec fn free_slot_spec() -> Slot {
    Slot { frame: 0, id: 0, state: SlotState::Free }
}

/// The slot holds a live instance.
pub open spec fn live(s: Slot) -> bool {
    s.state is Starting || s.state is Running || s.state is Stopping
}

/// Live slots of `frame` among the first `n`.
pub open spec fn live_upto(pool: Seq<Slot>, frame: int, n: nat) -> int
    decreases n,
{
    if n == 0 {
        0
    } else {
        live_upto(pool, frame, (n - 1) as nat) + if live(pool[n - 1]) && pool[n - 1].frame
            == frame {
            1int
        } else {
            0int
        }
    }
}

/// Live slots of `frame`.
pub open spec fn live_of_spec(pool: Seq<Slot>, frame: int) -> int {
    live_upto(pool, frame, pool.len())
}

/// Changing one slot changes the count by the change in that slot.
proof fn lemma_live_update(pool: Seq<Slot>, j: int, v: Slot, frame: int, n: nat)
    requires
        0 <= j < pool.len(),
        n <= pool.len(),
    ensures
        live_upto(pool.update(j, v), frame, n) == live_upto(pool, frame, n) + if j < n {
            (if live(v) && v.frame == frame {
                1int
            } else {
                0int
            }) - (if live(pool[j]) && pool[j].frame == frame {
                1int
            } else {
                0int
            })
        } else {
            0int
        },
    decreases n,
{
    if n > 0 {
        lemma_live_update(pool, j, v, frame, (n - 1) as nat);
    }
}

/// The count of live slots is at most the number of slots looked at.
proof fn lemma_live_bound(pool: Seq<Slot>, frame: int, n: nat)
    ensures
        0 <= live_upto(pool, frame, n) <= n,
    decreases n,
{
    if n > 0 {
        lemma_live_bound(pool, frame, (n - 1) as nat);
    }
}

/// How many slots of `frame` are live.
#[must_use]
pub fn live_of(pool: &[Slot], frame: u32) -> (n: u32)
    requires
        pool@.len() <= MAX_SLOTS,
    ensures
        n as int == live_of_spec(pool@, frame as int),
{
    let mut i: usize = 0;
    let mut n: u32 = 0;
    while i < pool.len()
        invariant
            i <= pool@.len() <= MAX_SLOTS,
            n as int == live_upto(pool@, frame as int, i as nat),
            n <= i,
        decreases pool@.len() - i,
    {
        let s = pool[i];
        if (matches!(s.state, SlotState::Starting | SlotState::Running | SlotState::Stopping))
            && s.frame == frame {
            n += 1;
        }
        i += 1;
    }
    n
}

/// Takes the first free slot for a new instance `id` of `frame`, unless `frame` already has
/// `cap` live slots or the pool is full. The slot starts as `Starting`.
pub fn claim(pool: &mut [Slot], frame: u32, cap: u32, id: u32) -> (r: Option<usize>)
    requires
        old(pool)@.len() == MAX_SLOTS,
    ensures
        final(pool)@.len() == MAX_SLOTS,
        r is Some ==> {
            let i = r.unwrap() as int;
            &&& 0 <= i < MAX_SLOTS
            &&& !live(old(pool)@[i])
            &&& final(pool)@[i] == (Slot { frame, id, state: SlotState::Starting })
            &&& forall|j: int| 0 <= j < MAX_SLOTS && j != i ==> final(pool)@[j] == old(pool)@[j]
            &&& live_of_spec(final(pool)@, frame as int) == live_of_spec(old(pool)@, frame as int)
                + 1
            &&& live_of_spec(final(pool)@, frame as int) <= cap
        },
        r is None ==> final(pool)@ == old(pool)@,
        r is None ==> live_of_spec(old(pool)@, frame as int) >= cap || forall|j: int|
            0 <= j < MAX_SLOTS ==> live(#[trigger] old(pool)@[j]),
{
    let have = live_of(pool, frame);
    if have >= cap {
        return None;
    }
    let mut i: usize = 0;
    while i < pool.len()
        invariant
            i <= pool@.len() == MAX_SLOTS,
            pool@ == old(pool)@,
            forall|j: int| 0 <= j < i ==> live(#[trigger] pool@[j]),
            have as int == live_of_spec(pool@, frame as int),
            have < cap,
        decreases pool@.len() - i,
    {
        let s = pool[i];
        if matches!(s.state, SlotState::Free | SlotState::Exited(_)) {
            let ghost before = pool@;
            let v = Slot { frame, id, state: SlotState::Starting };
            pool[i] = v;
            proof {
                lemma_live_update(before, i as int, v, frame as int, before.len());
                assert(!live(before[i as int]));
            }
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Frees the live slot `i`: exactly once, since it requires the slot to be live.
#[allow(clippy::semicolon_if_nothing_returned)]  // a `proof` block ends the function
pub fn release(pool: &mut [Slot], i: usize)
    requires
        old(pool)@.len() == MAX_SLOTS,
        i < MAX_SLOTS,
        live(old(pool)@[i as int]),
    ensures
        final(pool)@.len() == MAX_SLOTS,
        final(pool)@[i as int] == free_slot_spec(),
        forall|j: int| 0 <= j < MAX_SLOTS && j != i ==> final(pool)@[j] == old(pool)@[j],
        forall|f: int|
            live_of_spec(final(pool)@, f) == live_of_spec(old(pool)@, f) - if old(
                pool,
            )@[i as int].frame == f {
                1int
            } else {
                0int
            },
{
    let ghost before = pool@;
    pool[i] = free_slot();
    proof {
        assert forall|f: int|
            live_of_spec(pool@, f) == live_of_spec(before, f) - if before[i as int].frame == f {
                1int
            } else {
                0int
            } by {
            lemma_live_update(before, i as int, free_slot_spec(), f, before.len());
        }
    }
}

/// Moves the live slot `i` to the live state `state`.
#[allow(clippy::semicolon_if_nothing_returned)]  // a `proof` block ends the function
pub fn set_state(pool: &mut [Slot], i: usize, state: SlotState)
    requires
        old(pool)@.len() == MAX_SLOTS,
        i < MAX_SLOTS,
        live(old(pool)@[i as int]),
        state is Starting || state is Running || state is Stopping,
    ensures
        final(pool)@.len() == MAX_SLOTS,
        final(pool)@[i as int] == (Slot { state, ..old(pool)@[i as int] }),
        forall|j: int| 0 <= j < MAX_SLOTS && j != i ==> final(pool)@[j] == old(pool)@[j],
        forall|f: int| live_of_spec(final(pool)@, f) == live_of_spec(old(pool)@, f),
{
    let ghost before = pool@;
    let s = pool[i];
    let v = Slot { state, ..s };
    pool[i] = v;
    proof {
        assert forall|f: int| live_of_spec(pool@, f) == live_of_spec(before, f) by {
            lemma_live_update(before, i as int, v, f, before.len());
        }
    }
}

/// The index of the live slot that holds instance `id`.
#[must_use]
pub fn slot_of(pool: &[Slot], id: u32) -> (r: Option<usize>)
    ensures
        r is Some ==> r.unwrap() < pool@.len() && live(pool@[r.unwrap() as int])
            && pool@[r.unwrap() as int].id == id,
{
    let mut i: usize = 0;
    while i < pool.len()
        invariant
            i <= pool@.len(),
        decreases pool@.len() - i,
    {
        let s = pool[i];
        if (matches!(s.state, SlotState::Starting | SlotState::Running | SlotState::Stopping))
            && s.id == id {
            return Some(i);
        }
        i += 1;
    }
    None
}

} // verus!
