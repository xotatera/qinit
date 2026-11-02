// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qinit-db-core`: the compiled database core (spec 2026-11-02 §3, database format, and §3.1,
//! the validator obligations), proved by Verus (`proof:qinit-db-core`).
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod layout;
mod validate;

pub use layout::*;
pub use validate::*;
