// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qinit-colony`: the runtime around the proved colony core (spec 2026-11-02 §6). It owns the
//! node table, feeds the core one input at a time, drains the core's actions into an
//! [`Effects`] implementation, and turns the effects' failures into inputs. [`sim`] is a
//! scripted simulation with virtual time for host tests; the real cells, event loop and
//! re-adoption from the comb are the colony daemon's (sub-project 7).
#![forbid(unsafe_code)]

mod effects;
mod engine;
mod instance;
pub mod sim;
mod swap;
pub mod text;

pub use effects::{Effects, Errno, InstanceSpec, NodeSpec};
pub use engine::{Colony, Error, Notice, Outcome};
pub use instance::{Exit, InstanceView, LaunchArgs, LaunchError, RING};
pub use qinit_colony_core::{Reason, Report, Request, SlotState, State, StopMode, TimerKind, Why};
pub use swap::SwapError;
