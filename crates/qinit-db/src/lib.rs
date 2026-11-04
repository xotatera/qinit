// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qinit-db`: the compiled database runtime (spec 2026-11-02 §3, database format).
//!
//! [`write`] flattens a [`Model`] into the byte format of `docs/db-format.md`; [`open`] checks
//! the length and CRC and runs the proved validator of `qinit-db-core`; [`Reader::decode`]
//! turns an opened database back into a [`Model`].
#![forbid(unsafe_code)]

mod crc;
mod model;
mod read;
mod write;

pub use crc::crc32;
pub use model::{
    Cred, Edge, Group, GroupKind, Kind, Launch, Mode, Model, Node, Ready, Reload, Restart,
    RestartOn, RestartPolicy, Route, Seccomp, Securebits, Stop, StopMode, Target, ordering_edges,
};
pub use read::{ReadError, Reader, open};
pub use write::{WriteError, write};
