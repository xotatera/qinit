// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Which node or instance slot a cell belongs to. The cell layer numbers cells by table slot and
//! reuses a slot as soon as its cell is removed, so a cell id means one owner only between its
//! `bind` and its `unbind`.
use qinit_cell::CellId;
use std::collections::{BTreeMap, BTreeSet};

/// What a cell belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Owner {
    /// A node, by index in the database.
    Node(u32),
    /// An instance, by slot.
    Instance(u32),
}

/// The cell table of the effects layer.
#[derive(Debug, Default)]
pub struct Routes {
    by_cell: BTreeMap<CellId, Owner>,
    by_owner: BTreeMap<Owner, CellId>,
    muted: BTreeSet<CellId>,
}

impl Routes {
    /// `cell` belongs to `owner` from now on (any earlier mute of the slot ends).
    pub fn bind(&mut self, cell: CellId, owner: Owner) {
        self.muted.remove(&cell);
        if let Some(old) = self.by_owner.insert(owner, cell) {
            self.by_cell.remove(&old);
        }
        self.by_cell.insert(cell, owner);
    }

    /// Whom a notice of `cell` is for; `None` for a cell nobody owns or one that is muted.
    #[must_use]
    pub fn owner(&self, cell: CellId) -> Option<Owner> {
        if self.muted.contains(&cell) {
            return None;
        }
        self.by_cell.get(&cell).copied()
    }

    /// The cell of `owner`.
    #[must_use]
    pub fn cell(&self, owner: Owner) -> Option<CellId> {
        self.by_owner.get(&owner).copied()
    }

    /// Drops every later notice of `cell`: its failure was already told to colony another way.
    pub fn mute(&mut self, cell: CellId) {
        self.muted.insert(cell);
    }

    /// Forgets `cell` and its owner.
    pub fn unbind(&mut self, cell: CellId) {
        if let Some(owner) = self.by_cell.remove(&cell) {
            self.by_owner.remove(&owner);
        }
        self.muted.remove(&cell);
    }

    /// Every bound cell with its owner, in cell order.
    pub fn cells(&self) -> impl Iterator<Item = (CellId, Owner)> + '_ {
        self.by_cell.iter().map(|(&c, &o)| (c, o))
    }

    /// The node table was renumbered: new node `i` was node `map[i]` before (`u32::MAX` for a
    /// new node). Node owners move with their node; a cell whose node is absent from `map` has no
    /// owner afterwards (its cell is for the refresh to stop). Instance owners are slots and stay.
    pub fn remap(&mut self, map: &[u32]) {
        let old: Vec<(CellId, Owner)> = self.cells().collect();
        self.by_cell.clear();
        self.by_owner.clear();
        for (cell, owner) in old {
            match owner {
                Owner::Instance(_) => self.bind(cell, owner),
                Owner::Node(was) => {
                    if let Some(now) = map.iter().position(|&m| m == was) {
                        let now = u32::try_from(now).unwrap_or(u32::MAX);
                        self.bind(cell, Owner::Node(now));
                    }
                }
            }
        }
    }
}
