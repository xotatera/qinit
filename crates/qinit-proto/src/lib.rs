// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qinit-proto`: colony's side of the control protocol (spec 2026-11-04 §3). It owns the
//! accepted connections, frames messages over `SOCK_SEQPACKET` with descriptors, takes each
//! peer's identity at `accept`, applies the connection limits and hands decoded requests to
//! [`qinit_colony::Colony::handle`]. It is driven by readiness callbacks, so the daemon puts it
//! in its own event loop unchanged; [`testing`] has a small loop for the tests.
#![forbid(unsafe_code)]

mod server;
#[cfg(feature = "testing")]
pub mod testing;

pub use server::{ConnId, Full, Limits, MAX_DB_READ, Server};
