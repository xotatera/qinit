// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! `qinit-proto-core`: the QCP1 control protocol message format, its total decoder, the encoder
//! and the authorization function, proved by Verus (`proof:qinit-proto-core`). No allocation and
//! no `std`: a message is read and written in place.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod authz;
mod decode;
mod encode;
pub mod launch;
mod layout;
mod lists;
mod spec;
mod utf8;

pub use authz::*;
pub use decode::*;
pub use encode::*;
pub use layout::*;
pub use lists::{count_elements, env_elements_ok, nul_list_ok};
#[allow(unused_imports)] // the specification is erased outside verification
pub use spec::*;
pub use utf8::utf8_ok;
