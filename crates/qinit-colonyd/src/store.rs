// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Colony's side of queen's store: what queen holds for colony across a restart, and the channel
//! colony puts it through. Without a queen (`standalone`) every call does nothing.
use qinit_colony::ShutdownMode;
use qinit_ipc::memfd::{read_all, sealed};
use qinit_ipc::{Errno, poll_readable, poll_writable, recv, send_nowait};
use qinit_queen_core::{FromColony, Mode, ToColony, decode_to_colony, encode_from_colony};
use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::time::Duration;

/// Where colony's cell table is kept.
pub const KEY_CELLS: u64 = 1;
/// Where the nodes' state is kept.
pub const KEY_NODES: u64 = 2;
/// Where the database colony runs from is kept. Queen drops this key when the machine leaves
/// rescue or the hold (`qinit_queen_core::store::DB_KEY`), so the next colony reads `--db`.
pub const KEY_DB: u64 = 3;
/// The first key colony allocates for a descriptor.
const FIRST_KEY: u64 = 16;

/// Each wait of the hand-over.
const HAND_OVER_MS: i32 = 10_000;
/// How long a send waits for room in a socket queen is not reading.
const SEND_MS: i32 = 1_000;
/// The largest state entry colony reads back.
const MAX_STATE: usize = 256 * 1024 * 1024;

pub struct Store {
    /// Colony's end of the channel; `None` without a queen, or once queen is gone.
    link: Option<OwnedFd>,
    /// The channel after a send that failed for good, still open: the loop that watches it lets
    /// go of it first ([`Store::take_lost`]), so its number cannot be reused behind the loop.
    lost: Option<OwnedFd>,
    /// What queen handed over and colony has not taken.
    held: BTreeMap<u64, OwnedFd>,
    /// Every key queen holds for colony, as far as colony knows.
    known: BTreeSet<u64>,
    next_key: u64,
    /// Queen did not read for `SEND_MS`: further sends do not wait, until one goes through.
    stalled: bool,
    /// Lines for the log, oldest first.
    warnings: Vec<String>,
}

fn mode_of(m: ShutdownMode) -> Mode {
    match m {
        ShutdownMode::Halt => Mode::Halt,
        ShutdownMode::Poweroff => Mode::Poweroff,
        ShutdownMode::Reboot => Mode::Reboot,
    }
}

impl Store {
    /// No queen: nothing is held or saved.
    #[must_use]
    pub fn standalone() -> Store {
        Store {
            link: None,
            lost: None,
            held: BTreeMap::new(),
            known: BTreeSet::new(),
            next_key: FIRST_KEY,
            stalled: false,
            warnings: Vec::new(),
        }
    }

    /// Reads queen's hand-over from `link` until `HeldEnd`, each wait bounded by 10 s.
    ///
    /// # Errors
    /// Text naming what went wrong: a wait that ran out, a closed channel, a record that does not
    /// decode, an unexpected kind, or a count that does not match the entries received.
    pub fn attach(link: OwnedFd) -> Result<Store, String> {
        qinit_sys::fd::set_nonblocking(&link).map_err(|e| format!("the channel to queen: {e}"))?;
        let mut s = Store::standalone();
        loop {
            match poll_readable(link.as_fd(), HAND_OVER_MS) {
                Ok(true) => {}
                Ok(false) => return Err("queen did not finish the hand-over in 10 s".into()),
                Err(e) => return Err(format!("the channel to queen: {e:?}")),
            }
            let mut buf = [0u8; 32];
            let r = match recv(link.as_fd(), &mut buf) {
                Ok(r) => r,
                Err(Errno(libc::EAGAIN)) => continue,
                Err(e) => return Err(format!("the channel to queen: {e:?}")),
            };
            if r.len == 0 && r.fds.is_empty() {
                return Err("queen closed the channel during the hand-over".into());
            }
            if r.truncated || r.ctrunc {
                return Err("queen sent a record that did not fit".into());
            }
            let mut fds = r.fds;
            match decode_to_colony(&buf[..r.len], fds.len()) {
                Some(ToColony::Held { key }) => {
                    let Some(fd) = fds.pop() else {
                        return Err("a held entry came without its descriptor".into());
                    };
                    if s.held.insert(key, fd).is_some() {
                        return Err(format!("queen held key {key} twice"));
                    }
                    s.known.insert(key);
                }
                Some(ToColony::HeldEnd { count }) => {
                    if usize::try_from(count).ok() != Some(s.held.len()) {
                        return Err(format!(
                            "queen's count of {count} entries does not match the {} received",
                            s.held.len()
                        ));
                    }
                    s.next_key = s
                        .held
                        .keys()
                        .max()
                        .map_or(FIRST_KEY, |k| (k + 1).max(FIRST_KEY));
                    s.link = Some(link);
                    return Ok(s);
                }
                Some(other) => return Err(format!("queen sent {other:?} during the hand-over")),
                None => return Err("queen sent a record that does not decode".into()),
            }
        }
    }

    /// The descriptor queen held under `key`, once.
    pub fn take(&mut self, key: u64) -> Option<OwnedFd> {
        self.held.remove(&key)
    }

    /// A key no held entry uses.
    pub fn allocate(&mut self) -> u64 {
        let k = self.next_key;
        self.next_key += 1;
        k
    }

    /// Asks queen to hold `fd` under `key`, replacing what it held. A send that finds the
    /// socket full waits at most one second, then is dropped. Whether it went: a caller that
    /// names the key in a state must not do so until it has, and tries again if it has not.
    /// Without a queen nothing is held and nothing is named, so it is `true`.
    pub fn put(&mut self, key: u64, fd: BorrowedFd<'_>) -> bool {
        if self.link.is_none() {
            return true;
        }
        let sent = self.send(&encode_from_colony(FromColony::Put { key }), Some(fd));
        if sent {
            self.known.insert(key);
            self.held.remove(&key);
        }
        sent
    }

    /// Asks queen to close and forget `key`. Whether it went (`true` too when queen was never
    /// told of the key): a key whose `Drop` was dropped stays to be forgotten again.
    pub fn forget(&mut self, key: u64) -> bool {
        if !self.known.contains(&key) {
            return true;
        }
        if self.send(&encode_from_colony(FromColony::Drop { key }), None) {
            self.known.remove(&key);
            self.held.remove(&key);
            true
        } else {
            self.link.is_none()
        }
    }

    /// Saves `bytes` under `key`, as a sealed memory file. Whether it went, as for
    /// [`Store::put`].
    pub fn save(&mut self, key: u64, bytes: &[u8]) -> bool {
        if self.link.is_none() {
            return true;
        }
        match sealed(c"qinit-state", bytes) {
            Ok(fd) => self.put(key, fd.as_fd()),
            Err(e) => {
                self.warnings
                    .push(format!("cannot make a state entry: {e:?}"));
                false
            }
        }
    }

    /// What queen held under `key`, read from the start. The entry stays held.
    pub fn load(&mut self, key: u64) -> Option<Vec<u8>> {
        read_all(self.held.get(&key)?.as_fd(), MAX_STATE).ok()
    }

    /// Tells queen the shutdown has begun, ending in `mode`.
    pub fn announce(&mut self, mode: ShutdownMode) {
        self.send(
            &encode_from_colony(FromColony::Shutdown {
                mode: mode_of(mode),
            }),
            None,
        );
    }

    /// Lets go of the channel: queen is gone, and colony carries on without saving.
    pub fn detach(&mut self) {
        self.link = None;
    }

    /// The channel a failed send ended, once: the caller removes it from its loop and drops it.
    pub fn take_lost(&mut self) -> Option<OwnedFd> {
        self.lost.take()
    }

    /// The channel, for the loop to watch.
    #[must_use]
    pub fn link(&self) -> Option<BorrowedFd<'_>> {
        self.link.as_ref().map(AsFd::as_fd)
    }

    /// One record from queen, without waiting; `None` when there is none.
    ///
    /// # Errors
    /// Text naming a closed channel, a record that does not decode or one that is out of place.
    #[allow(clippy::should_implement_trait)] // `Result<Option<_>>`, and not an iterator
    pub fn next(&mut self) -> Result<Option<ToColony>, String> {
        let Some(link) = self.link.as_ref() else {
            return Ok(None);
        };
        let mut buf = [0u8; 32];
        let r = match recv(link.as_fd(), &mut buf) {
            Ok(r) => r,
            Err(Errno(libc::EAGAIN)) => return Ok(None),
            Err(e) => return Err(format!("the channel to queen: {e:?}")),
        };
        if r.len == 0 && r.fds.is_empty() {
            return Err("queen closed the channel".into());
        }
        let fds = r.fds.len();
        if r.truncated || r.ctrunc {
            return Err("queen sent a record that did not fit".into());
        }
        match decode_to_colony(&buf[..r.len], fds) {
            Some(rec @ (ToColony::Request { .. } | ToColony::Reaped)) => Ok(Some(rec)),
            Some(rec @ ToColony::Refused { key }) => {
                self.known.remove(&key);
                Ok(Some(rec))
            }
            Some(other) => Err(format!("queen sent {other:?} outside the hand-over")),
            None => Err("queen sent a record that does not decode".into()),
        }
    }

    /// Forgets every entry queen handed over that nothing took: no state names it (a leftover of
    /// an earlier colony's work). The three state entries stay.
    pub fn forget_unclaimed(&mut self) {
        let keys: Vec<u64> = self.held.keys().copied().collect();
        for key in keys {
            if ![KEY_CELLS, KEY_NODES, KEY_DB].contains(&key) {
                let _ = self.forget(key);
            }
        }
    }

    /// Drops every key colony knows queen holds: the shutdown is complete, nothing is left to
    /// re-adopt.
    pub fn clear(&mut self) {
        for key in std::mem::take(&mut self.known) {
            let _ = self.send(&encode_from_colony(FromColony::Drop { key }), None);
        }
        self.held.clear();
    }

    /// How many lines [`Store::warnings`] has.
    #[must_use]
    pub fn warnings_pending(&self) -> usize {
        self.warnings.len()
    }

    /// The oldest line for the log, if any: a save dropped because queen does not read, or the
    /// channel closing.
    pub fn warnings(&mut self) -> Option<String> {
        if self.warnings.is_empty() {
            None
        } else {
            Some(self.warnings.remove(0))
        }
    }

    /// Sends one record; whether it went. A full socket is waited on once; a closed one ends
    /// the link.
    fn send(&mut self, bytes: &[u8; 16], fd: Option<BorrowedFd<'_>>) -> bool {
        let Some(link) = self.link.as_ref() else {
            return false;
        };
        let fds: Vec<BorrowedFd<'_>> = fd.into_iter().collect();
        let mut result = send_nowait(link.as_fd(), bytes, &fds);
        if matches!(result, Err(Errno(libc::EAGAIN))) && !self.stalled {
            let wait = i32::try_from(Duration::from_millis(1000).as_millis()).unwrap_or(SEND_MS);
            if poll_writable(link.as_fd(), wait).unwrap_or(false) {
                result = send_nowait(link.as_fd(), bytes, &fds);
            }
        }
        match result {
            Ok(()) => {
                self.stalled = false;
                true
            }
            Err(Errno(libc::EAGAIN)) => {
                if !self.stalled {
                    self.stalled = true;
                    self.warnings.push(
                        "queen does not read its channel: a state save was dropped".to_string(),
                    );
                }
                false
            }
            Err(e) => {
                self.lost = self.link.take();
                self.warnings.push(format!(
                    "queen closed its channel ({e:?}): state is no longer saved"
                ));
                false
            }
        }
    }
}
