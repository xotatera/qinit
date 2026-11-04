// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qinit-overseer`: the executor that turns a launch request into a running service
//! (spec 2026-11-03 §3, §4): strict identity resolution, output routes by file type, the
//! step runner over the proved plan of `qinit-overseer-core`, the pid-namespace supervisor and
//! the request builder from the database model. `unsafe` stays in `qinit-sys`.
#![forbid(unsafe_code)]

pub mod identity;
pub mod output;
pub mod request;
pub mod run;
pub mod status;
pub mod supervisor;
pub mod view;
