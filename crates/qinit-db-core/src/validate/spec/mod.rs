// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The validator's obligations V1-V8 as spec functions over the database bytes, one
//! submodule per group of rules; [`well_formed`] is their conjunction.

mod graph;
mod lists;
mod pool;
mod records;
mod tables;

#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items: Verus erases them
pub use graph::*;
#[allow(unused_imports, clippy::wildcard_imports)]
pub use lists::*;
#[allow(unused_imports, clippy::wildcard_imports)]
pub use pool::*;
#[allow(unused_imports, clippy::wildcard_imports)]
pub use records::*;
#[allow(unused_imports, clippy::wildcard_imports)]
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
