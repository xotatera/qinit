// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Gate caching: a gate is skipped when every input it declares is unchanged
//! since it last passed.
//! - `contracts`: a spine's interface text, for contract-keyed proofs.
//! - `glob`: input declarations.
//! - `key`: the manifest of everything a result depends on, hashed with git.
//! - `not_inputs`: ignored directories declared not to be inputs.
//! - `outside`: path dependencies outside the repository, for cargo gates.
//! - `store`: one file per pass under the git common dir.
//!
//! Errors never turn into skips: they only ever lead to running the gate.
pub mod contracts;
pub mod glob;
pub mod key;
pub mod not_inputs;
pub mod outside;
pub mod store;
