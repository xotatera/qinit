// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qinit-queen-core`: the pure half of queen, proved by Verus (`proof:qinit-queen-core`): the
//! records on the channel between queen and colony, the store table, and the state machine that
//! decides what queen does with every event. No allocation and no `std`: queen's binary
//! (`qinit-queen`) performs the actions this crate names.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod machine;
mod record;
pub mod store;

pub use record::*;
