// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qinit-frames`: the frame compiler (spec 2026-11-02 §5-§8: frame schema, amend layers,
//! compile pipeline, errors).
#![forbid(unsafe_code)]

pub mod compile;
pub mod dump;
pub mod error;
pub mod expand;
mod graph;
pub mod layers;
pub mod policy;
pub mod provenance;
pub mod resolve;
pub mod schema;
pub mod units;
