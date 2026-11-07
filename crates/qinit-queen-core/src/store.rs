// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The store: a fixed table of key and descriptor number. A lookup is a linear scan, which is
//! what the proof can carry and all the table size needs. Queen's binary owns the descriptors;
//! this table names them.
use vstd::prelude::*;

verus! {

/// The table's size: two descriptors for each of 4352 cells (directory, main), two for each of
/// 4096 logger pipes, and the three fixed entries.
pub const CAPACITY: usize = 4352 * 2 + 4096 * 2 + 3;

/// One slot: `key` 0 is a free slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub key: u64,
    pub fd: i32,
}

/// A free slot.
pub const FREE: Entry = Entry { key: 0, fd: -1 };

/// What a [`put`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Put {
    /// A new key went into a free slot.
    Stored,
    /// The key was held: its descriptor is replaced, and the old one is named so it can be closed.
    Replaced(i32),
    /// The key is new and no slot is free; nothing changed.
    Full,
}

/// No two used slots share a key.
pub open spec fn unique(t: Seq<Entry>) -> bool {
    forall|i: int, j: int| 0 <= i < j < t.len() && t[i].key != 0 ==> t[i].key != t[j].key
}

/// Uniqueness at one pair of slots.
proof fn pair(t: Seq<Entry>, a: int, b: int)
    requires
        unique(t),
        0 <= a < b < t.len(),
        t[a].key != 0,
    ensures
        t[a].key != t[b].key,
{
}

/// Some slot holds `key`.
pub open spec fn holds_key(t: Seq<Entry>, key: u64) -> bool {
    exists|i: int| 0 <= i < t.len() && t[i].key == key
}

/// How many of the first `n` slots are used.
pub open spec fn used(t: Seq<Entry>, n: nat) -> nat
    decreases n,
{
    if n == 0 || n > t.len() {
        0
    } else {
        used(t, (n - 1) as nat) + (if t[n - 1].key != 0 {
            1nat
        } else {
            0nat
        })
    }
}

/// `t` is `old` with slot `i` set to `e`.
pub open spec fn only_slot(t: Seq<Entry>, old: Seq<Entry>, i: int, e: Entry) -> bool {
    &&& t.len() == old.len()
    &&& 0 <= i < t.len()
    &&& t[i] == e
    &&& forall|j: int| 0 <= j < t.len() && j != i ==> t[j] == old[j]
}

/// Holds `key` under `fd`. A new key goes into the first free slot, an old one is replaced in
/// place. `key` is never 0.
pub fn put(table: &mut [Entry], key: u64, fd: i32) -> (r: Put)
    requires
        key != 0,
        unique(old(table)@),
    ensures
        final(table)@.len() == old(table)@.len(),
        unique(final(table)@),
        match r {
            Put::Stored => {
                &&& !holds_key(old(table)@, key)
                &&& exists|i: int|
                    0 <= i < final(table)@.len() && old(table)@[i].key == 0 && only_slot(
                        final(table)@,
                        old(table)@,
                        i,
                        Entry { key, fd },
                    )
            },
            Put::Replaced(f) => exists|i: int|
                0 <= i < final(table)@.len() && old(table)@[i].key == key && old(table)@[i].fd == f
                    && only_slot(final(table)@, old(table)@, i, Entry { key, fd }),
            Put::Full => {
                &&& !holds_key(old(table)@, key)
                &&& final(table)@ == old(table)@
                &&& forall|i: int| 0 <= i < final(table)@.len() ==> final(table)@[i].key != 0
            },
        },
{
    let ghost before = table@;
    assert(unique(before));
    let n = table.len();
    let mut i: usize = 0;
    let mut free: Option<usize> = None;
    while i < n
        invariant
            n == table@.len(),
            table@ == before,
            before == old(table)@,
            unique(before),
            i <= n,
            forall|j: int| 0 <= j < i ==> table@[j].key != key,
            match free {
                Some(f) => f < i && table@[f as int].key == 0 && forall|j: int|
                    0 <= j < f ==> table@[j].key != 0,
                None => forall|j: int| 0 <= j < i ==> table@[j].key != 0,
            },
        decreases n - i,
    {
        let e = table[i];
        if e.key == key {
            table[i] = Entry { key, fd };
            proof {
                assert(e == before[i as int]);
                assert(only_slot(table@, before, i as int, Entry { key, fd }));
                assert forall|a: int| 0 <= a < table@.len() implies table@[a].key
                    == before[a].key by {
                    if a == i as int {
                        assert(table@[a].key == key);
                    }
                }
                assert(unique(table@)) by {
                    assert forall|a: int, b: int|
                        0 <= a < b < table@.len() && table@[a].key != 0 implies table@[a].key
                        != table@[b].key by {
                        assert(table@[a].key == before[a].key);
                        assert(table@[b].key == before[b].key);
                        assert(0 <= a < b < before.len());
                        if before[a].key != 0 {
                            pair(before, a, b);
                        }
                    }
                }
            }
            return Put::Replaced(e.fd);
        }
        if free.is_none() && e.key == 0 {
            free = Some(i);
        }
        i += 1;
    }
    #[allow(clippy::single_match_else)]  // both arms carry proofs
    match free {
        Some(f) => {
            table[f] = Entry { key, fd };
            proof {
                assert(!holds_key(before, key)) by {
                    assert forall|j: int| 0 <= j < before.len() implies before[j].key != key by {}
                }
                assert(only_slot(table@, before, f as int, Entry { key, fd }));
                assert(unique(table@)) by {
                    assert forall|a: int, b: int|
                        0 <= a < b < table@.len() && table@[a].key != 0 implies table@[a].key
                        != table@[b].key by {
                        if a == f as int {
                            assert(table@[b].key == before[b].key);
                        } else if b == f as int {
                            assert(table@[a].key == before[a].key);
                        } else {
                            assert(table@[a] == before[a] && table@[b] == before[b]);
                            assert(0 <= a < b < before.len());
                            if before[a].key != 0 {
                                pair(before, a, b);
                            }
                        }
                    }
                }
            }
            Put::Stored
        },
        None => {
            proof {
                assert(!holds_key(before, key)) by {
                    assert forall|j: int| 0 <= j < before.len() implies before[j].key != key by {}
                }
            }
            Put::Full
        },
    }
}

/// Forgets `key` (never 0) and returns its descriptor, or `None` when it is not held.
pub fn take(table: &mut [Entry], key: u64) -> (r: Option<i32>)
    requires
        key != 0,
        unique(old(table)@),
    ensures
        final(table)@.len() == old(table)@.len(),
        unique(final(table)@),
        match r {
            Some(f) => exists|i: int|
                0 <= i < final(table)@.len() && old(table)@[i].key == key && old(table)@[i].fd == f
                    && only_slot(final(table)@, old(table)@, i, FREE),
            None => !holds_key(old(table)@, key) && final(table)@ == old(table)@,
        },
{
    let ghost before = table@;
    assert(unique(before));
    let n = table.len();
    let mut i: usize = 0;
    while i < n
        invariant
            n == table@.len(),
            table@ == before,
            before == old(table)@,
            unique(before),
            i <= n,
            forall|j: int| 0 <= j < i ==> table@[j].key != key,
        decreases n - i,
    {
        let e = table[i];
        if e.key == key {
            table[i] = FREE;
            proof {
                assert(e == before[i as int]);
                assert(only_slot(table@, before, i as int, FREE));
                assert(unique(table@)) by {
                    assert forall|a: int, b: int|
                        0 <= a < b < table@.len() && table@[a].key != 0 implies table@[a].key
                        != table@[b].key by {
                        if a == i as int {
                            assert(table@[a] == FREE);
                        } else if b == i as int {
                            assert(table@[b].key == 0);
                        } else {
                            assert(table@[a] == before[a] && table@[b] == before[b]);
                            assert(0 <= a < b < before.len());
                            if before[a].key != 0 {
                                pair(before, a, b);
                            }
                        }
                    }
                }
            }
            return Some(e.fd);
        }
        i += 1;
    }
    None
}

/// How many slots are used.
#[must_use]
pub fn count(table: &[Entry]) -> (c: u32)
    requires
        table@.len() <= 0xFFFF_FFFF,
    ensures
        c == used(table@, table@.len() as nat),
{
    let n = table.len();
    let mut i: usize = 0;
    let mut c: u32 = 0;
    while i < n
        invariant
            n == table@.len(),
            i <= n,
            n <= 0xFFFF_FFFF,
            c == used(table@, i as nat),
            c <= i,
        decreases n - i,
    {
        if table[i].key != 0 {
            c += 1;
        }
        i += 1;
    }
    c
}

/// The first used slot at or after `cursor`, with its index.
#[must_use]
pub fn next_held(table: &[Entry], cursor: usize) -> (r: Option<(usize, Entry)>)
    ensures
        match r {
            Some((i, e)) => {
                &&& cursor <= i < table@.len()
                &&& e == table@[i as int]
                &&& e.key != 0
                &&& forall|j: int| cursor <= j < i ==> table@[j].key == 0
            },
            None => forall|j: int| cursor <= j < table@.len() ==> table@[j].key == 0,
        },
{
    let n = table.len();
    let mut i = cursor;
    while i < n
        invariant
            n == table@.len(),
            cursor <= i || i == cursor,
            forall|j: int| cursor <= j < i ==> table@[j].key == 0,
        decreases n - i,
    {
        let e = table[i];
        if e.key != 0 {
            return Some((i, e));
        }
        i += 1;
    }
    None
}

} // verus!
