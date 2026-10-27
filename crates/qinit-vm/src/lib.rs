// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! `qinit-vm`: the host side of qinit's guest tests (spec 2026-10-27 §6). Builds the pinned
//! kernel, packs static guest programs into an initrd, boots QEMU (KVM or TCG) and reads the
//! verdict lines a guest prints on its serial console. Seeded from alloy's `alloy-test-qemu`.
// Every fallible function returns one string naming the step, its cause and its log; a
// per-function `# Errors` section would only repeat that.
#![allow(clippy::missing_errors_doc)]

pub mod guests;
pub mod initrd;
pub mod kernel;
pub mod qemu;
pub mod supervise;
pub mod verdict;
