// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qinit-overseer-core`: the launch request format (spec 2026-11-03 §4), its total decoder and
//! the in-place accessors a decoded request allows, proved by Verus
//! (`proof:qinit-overseer-core`). No allocation and no `std`: the executor reads the request
//! from a sealed memory file and works over the bytes in place.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod bpf;
mod decode;
mod layout;
mod plan;
mod spec;

pub use bpf::*;
pub use decode::*;
pub use layout::*;
pub use plan::*;
#[allow(unused_imports)] // the specification is erased outside verification
pub use spec::*;
