// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The validator's obligations V1-V8 as spec functions over the database bytes, one
//! submodule per group of rules; [`well_formed`] is their conjunction.
#![allow(unused_imports, clippy::wildcard_imports)] // spec-only re-exports; Verus erases them

mod graph;
mod lists;
mod paths;
mod policy;
mod pool;
mod records;
mod tables;

pub use graph::*;
pub use lists::*;
pub use paths::*;
pub use policy::*;
pub use pool::*;
pub use records::*;
pub use tables::*;
use vstd::prelude::*;

verus! {

/// A database the validator accepts: V1-V8.
pub open spec fn well_formed(b: Seq<u8>) -> bool {
    &&& v1(b)
    &&& v2(b)
    &&& v3(b)
    &&& v4(b)
    &&& v5(b)
    &&& v6(b)
    &&& v7(b)
    &&& v8(b)
}

} // verus!
