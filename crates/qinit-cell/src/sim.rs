// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! A deterministic [`Effects`] for host tests (spec §6.1 tier 2): it records every call and
//! answers from scripted queues; no cgroup, clone3 or loop is touched.
use crate::effects::{Command, Effects, Reaped};
use qinit_cell_core::{Handle, ReadyMode, Sig, Timer};
use qinit_cell_drive::Source;
use qinit_sys::Errno;
use std::collections::VecDeque;
use std::ffi::CStr;
use std::os::fd::OwnedFd;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    Create(u16, String),
    OpenExisting(u16, String),
    Spawn(u16, ReadyMode),
    AdoptMain(u16),
    SignalMain(u16, Handle, Sig),
    Freeze(u16, bool),
    SignalMembers(u16, Sig),
    Kill(u16),
    Remove(u16, String),
    Arm(u16, Timer, u32),
    Cancel(u16, Timer),
    Close(u16, Source),
    Release(u16),
}

#[derive(Default)]
pub struct Sim {
    pub calls: Vec<Call>,
    /// `read_level` answers, front first; `(false, false)` when empty.
    pub levels: VecDeque<(bool, bool)>,
    /// `read_ready` chunks; an empty chunk (or none left) is EOF.
    pub ready_chunks: VecDeque<Vec<u8>>,
    /// `read_exec_error` answers; `None` (exec succeeded) when empty.
    pub exec_errors: VecDeque<Option<Errno>>,
    pub create_fails: bool,
    /// `adopt_main` refuses the pidfd (EBADF).
    pub adopt_fails: bool,
    /// `open_existing`'s answer: `(cgroup id, populated)`, or ENOENT when `None`.
    pub existing: Option<(u64, bool)>,
    pub children: VecDeque<Reaped>,
    /// `take_reaped` answers, all at once.
    pub reaped: Vec<(libc::pid_t, i32)>,
}

fn name(c: &CStr) -> String {
    c.to_string_lossy().into_owned()
}

impl Effects for Sim {
    fn create(&mut self, slot: u16, n: &CStr) -> Result<(), Errno> {
        self.calls.push(Call::Create(slot, name(n)));
        if self.create_fails {
            Err(Errno(libc::EEXIST))
        } else {
            Ok(())
        }
    }
    fn open_existing(&mut self, slot: u16, n: &CStr) -> Result<(u64, bool), Errno> {
        self.calls.push(Call::OpenExisting(slot, name(n)));
        self.existing.ok_or(Errno(libc::ENOENT))
    }
    fn read_level(&mut self, _slot: u16) -> Result<(bool, bool), Errno> {
        Ok(self.levels.pop_front().unwrap_or((false, false)))
    }
    fn spawn(&mut self, slot: u16, _cmd: Command, ready: ReadyMode) -> Result<Handle, Errno> {
        self.calls.push(Call::Spawn(slot, ready));
        Ok(u32::from(slot))
    }
    fn adopt_main(&mut self, slot: u16, _pidfd: OwnedFd) -> Result<Handle, Errno> {
        self.calls.push(Call::AdoptMain(slot));
        if self.adopt_fails {
            Err(Errno(libc::EBADF))
        } else {
            Ok(u32::from(slot))
        }
    }
    fn signal_main(&mut self, slot: u16, main: Handle, sig: Sig) -> Result<(), Errno> {
        self.calls.push(Call::SignalMain(slot, main, sig));
        Ok(())
    }
    fn freeze(&mut self, slot: u16, on: bool) -> Result<(), Errno> {
        self.calls.push(Call::Freeze(slot, on));
        Ok(())
    }
    fn signal_members(&mut self, slot: u16, sig: Sig) -> Result<(), Errno> {
        self.calls.push(Call::SignalMembers(slot, sig));
        Ok(())
    }
    fn kill(&mut self, slot: u16) -> Result<(), Errno> {
        self.calls.push(Call::Kill(slot));
        Ok(())
    }
    fn remove(&mut self, slot: u16, n: &CStr) -> Result<(), Errno> {
        self.calls.push(Call::Remove(slot, name(n)));
        Ok(())
    }
    fn arm(&mut self, slot: u16, timer: Timer, ms: u32) -> Result<(), Errno> {
        self.calls.push(Call::Arm(slot, timer, ms));
        Ok(())
    }
    fn cancel(&mut self, slot: u16, timer: Timer) -> Result<(), Errno> {
        self.calls.push(Call::Cancel(slot, timer));
        Ok(())
    }
    fn read_ready(&mut self, _slot: u16, buf: &mut [u8]) -> Result<usize, Errno> {
        let chunk = self.ready_chunks.pop_front().unwrap_or_default();
        let n = chunk.len().min(buf.len());
        buf[..n].copy_from_slice(&chunk[..n]);
        Ok(n)
    }
    fn read_exec_error(&mut self, _slot: u16) -> Result<Option<Errno>, Errno> {
        Ok(self.exec_errors.pop_front().flatten())
    }
    fn close(&mut self, slot: u16, source: Source) {
        self.calls.push(Call::Close(slot, source));
    }
    fn release(&mut self, slot: u16) {
        self.calls.push(Call::Release(slot));
    }
    fn reap_children(&mut self) -> Result<Vec<Reaped>, Errno> {
        Ok(self.children.drain(..).collect())
    }
    fn take_reaped(&mut self) -> Vec<(libc::pid_t, i32)> {
        std::mem::take(&mut self.reaped)
    }
    fn cgroup_id(&self, _slot: u16) -> Option<u64> {
        None
    }
}
