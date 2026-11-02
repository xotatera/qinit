// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qinit-db-core`: the compiled database core (frames and compiled database spec).
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod layout;
mod validate;

pub use layout::*;
pub use validate::*;
