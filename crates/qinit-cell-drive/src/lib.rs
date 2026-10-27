// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qinit-cell-drive`: the drive's decisions (spec 2026-10-27 §5.2, plan P1), proved by Verus
//! (`proof:qinit-cell-drive`). A loop token is `slot << 3 | source`: every token routes to at
//! most one (slot, source) pair and every pair has its own token, so each event reaches exactly
//! one cell. The table has a compile-time capacity; `first_free` finds the slot for a new cell
//! or reports the table full.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use qinit_cell_core::Timer;
use vstd::prelude::*;

verus! {

/// Cells one table holds.
pub const CAPACITY: u16 = 64;

/// What a token's event is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The main process's pidfd.
    Main,
    /// The readiness pipe.
    Ready,
    /// The exec-error pipe (plan P8).
    ExecError,
    /// `cgroup.events`.
    Events,
    /// The polite-stop grace deadline.
    Grace,
    /// The post-kill deadline.
    Kill,
}

pub open spec fn kind_of(s: Source) -> u64 {
    match s {
        Source::Main => 0,
        Source::Ready => 1,
        Source::ExecError => 2,
        Source::Events => 3,
        Source::Grace => 4,
        Source::Kill => 5,
    }
}

pub open spec fn spec_token(slot: u16, s: Source) -> u64 {
    ((slot as u64) << 3u64) | kind_of(s)
}

pub open spec fn source_of(k: u64) -> Option<Source> {
    if k == 0 {
        Some(Source::Main)
    } else if k == 1 {
        Some(Source::Ready)
    } else if k == 2 {
        Some(Source::ExecError)
    } else if k == 3 {
        Some(Source::Events)
    } else if k == 4 {
        Some(Source::Grace)
    } else if k == 5 {
        Some(Source::Kill)
    } else {
        None
    }
}

pub open spec fn spec_route(t: u64) -> Option<(u16, Source)> {
    if (t >> 3u64) >= CAPACITY as u64 {
        None
    } else {
        match source_of(t & 7u64) {
            Some(s) => Some(((t >> 3u64) as u16, s)),
            None => None,
        }
    }
}

proof fn lemma_split(slot: u64, k: u64)
    by (bit_vector)
    requires
        slot < 65536,
        k < 8,
    ensures
        ((slot << 3u64) | k) >> 3u64 == slot,
        ((slot << 3u64) | k) & 7u64 == k,
{
}

/// Every pair's token routes back to it.
pub proof fn lemma_roundtrip(slot: u16, s: Source)
    requires
        slot < CAPACITY,
    ensures
        spec_route(spec_token(slot, s)) == Some((slot, s)),
{
    lemma_split(slot as u64, kind_of(s));
}

/// Every routed token is exactly the token for its pair.
pub proof fn lemma_route_inverse(t: u64, slot: u16, s: Source)
    requires
        spec_route(t) == Some((slot, s)),
    ensures
        t == spec_token(slot, s),
{
    assert((t >> 3u64) < 64);
    assert(source_of(t & 7u64) == Some(s));
    assert(kind_of(s) == (t & 7u64));
    assert((((t >> 3u64) as u16) as u64) == (t >> 3u64)) by (bit_vector)
        requires
            (t >> 3u64) < 64,
    ;
    assert(((t >> 3u64) << 3u64) | (t & 7u64) == t) by (bit_vector);
}

/// Different pairs have different tokens.
pub proof fn lemma_injective(a: u16, s: Source, b: u16, u: Source)
    requires
        a < CAPACITY,
        b < CAPACITY,
        spec_token(a, s) == spec_token(b, u),
    ensures
        a == b,
        s == u,
{
    lemma_roundtrip(a, s);
    lemma_roundtrip(b, u);
}

/// The token for `slot`'s `s` events.
#[must_use]
pub fn token(slot: u16, s: Source) -> (t: u64)
    requires
        slot < CAPACITY,
    ensures
        t == spec_token(slot, s),
        spec_route(t) == Some((slot, s)),
        t < (CAPACITY as u64) << 3u64,
{
    proof {
        lemma_roundtrip(slot, s);
        let k = kind_of(s);
        assert(k < 8);
        assert((CAPACITY as u64) << 3u64 == 512u64) by (bit_vector);
        assert(((slot as u64) << 3u64) | k < 512u64) by (bit_vector)
            requires
                slot < 64,
                k < 8,
        ;
    }
    let k: u64 = match s {
        Source::Main => 0,
        Source::Ready => 1,
        Source::ExecError => 2,
        Source::Events => 3,
        Source::Grace => 4,
        Source::Kill => 5,
    };
    (u64::from(slot) << 3u64) | k
}

/// The (slot, source) pair a token names, or `None` for a token no cell owns.
#[must_use]
pub fn route(t: u64) -> (r: Option<(u16, Source)>)
    ensures
        r == spec_route(t),
{
    let slot = t >> 3u64;
    if slot >= u64::from(CAPACITY) {
        return None;
    }
    proof {
        assert((t & 7u64) < 8u64) by (bit_vector);
    }
    let s = match t & 7u64 {
        0 => Source::Main,
        1 => Source::Ready,
        2 => Source::ExecError,
        3 => Source::Events,
        4 => Source::Grace,
        5 => Source::Kill,
        _ => return None,
    };
    #[allow(clippy::cast_possible_truncation)]  // slot < CAPACITY here, so it fits
    let slot = slot as u16;
    Some((slot, s))
}

/// The source a deadline's expiry arrives on.
#[must_use]
pub fn timer_source(t: Timer) -> (s: Source)
    ensures
        (t == Timer::Grace ==> s == Source::Grace),
        (t == Timer::Kill ==> s == Source::Kill),
{
    match t {
        Timer::Grace => Source::Grace,
        Timer::Kill => Source::Kill,
    }
}

/// The deadline a source carries, if it is a timer.
#[must_use]
pub fn source_timer(s: Source) -> (t: Option<Timer>)
    ensures
        (s == Source::Grace ==> t == Some(Timer::Grace)),
        (s == Source::Kill ==> t == Some(Timer::Kill)),
        (!(s == Source::Grace || s == Source::Kill) ==> t is None),
{
    match s {
        Source::Grace => Some(Timer::Grace),
        Source::Kill => Some(Timer::Kill),
        _ => None,
    }
}

/// The first unused slot, or `None` when every slot is used (the table is full).
#[must_use]
pub fn first_free(used: &[bool]) -> (r: Option<usize>)
    ensures
        match r {
            Some(i) => i < used@.len() && !used@[i as int] && forall|j: int|
                0 <= j < i ==> used@[j],
            None => forall|j: int| 0 <= j < used@.len() ==> used@[j],
        },
{
    let mut i: usize = 0;
    while i < used.len()
        invariant
            i <= used@.len(),
            forall|j: int| 0 <= j < i ==> used@[j],
        decreases used@.len() - i,
    {
        if !used[i] {
            return Some(i);
        }
        i += 1;
    }
    None
}

} // verus!
