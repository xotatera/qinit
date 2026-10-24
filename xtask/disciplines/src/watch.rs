// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Waiting for a file or directory to change on inotify events, not by
//! polling: an event wakes the wait, and a deadline bounds it.
//!
//! Deadlines are spent in slices ([`Budget`]): the host scheduler (atc)
//! can freeze a gate step for minutes, and the clock runs on while it is
//! frozen. A slice cut short by a freeze ends on thaw, so a freeze costs
//! one slice; the waiter and what it waits on, in the same cgroup, are
//! frozen and thawed together.
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub use inotify::WatchMask;
use inotify::{EventMask, Inotify};

/// A wait's limit, spent in [`Budget::SLICE`]s rather than read off the
/// clock, so time frozen by a pause is not counted (one slice at most).
/// Under load a slice lasts at least its length, so the limit never ends
/// early.
pub struct Budget {
    left: Duration,
    last: Option<Instant>,
    spent: bool,
}

impl Budget {
    pub const SLICE: Duration = Duration::from_millis(50);

    #[must_use]
    pub fn new(limit: Duration) -> Budget {
        Budget {
            left: limit,
            last: None,
            spent: false,
        }
    }

    /// The next message on `rx`; `Timeout` once the budget is spent,
    /// `Disconnected` when the sender is gone. The slice a message arrives
    /// in, and the time since the previous call returned (the caller's
    /// work), are each charged for the time they took, at most one slice,
    /// so frequent messages still spend the budget; a spent budget takes
    /// one message already waiting, then no more.
    ///
    /// # Errors
    /// As above.
    pub fn recv<T>(&mut self, rx: &mpsc::Receiver<T>) -> Result<T, mpsc::RecvTimeoutError> {
        if let Some(last) = self.last {
            self.left = self.left.saturating_sub(last.elapsed().min(Self::SLICE));
        }
        let got = self.next(rx);
        self.last = Some(Instant::now());
        got
    }

    fn next<T>(&mut self, rx: &mpsc::Receiver<T>) -> Result<T, mpsc::RecvTimeoutError> {
        loop {
            if self.left.is_zero() {
                if std::mem::replace(&mut self.spent, true) {
                    return Err(mpsc::RecvTimeoutError::Timeout);
                }
                return rx.try_recv().map_err(|e| match e {
                    mpsc::TryRecvError::Empty => mpsc::RecvTimeoutError::Timeout,
                    mpsc::TryRecvError::Disconnected => mpsc::RecvTimeoutError::Disconnected,
                });
            }
            let slice = Self::SLICE.min(self.left);
            let start = Instant::now();
            let got = rx.recv_timeout(slice);
            self.left -= start.elapsed().min(slice);
            match got {
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                other => return other,
            }
        }
    }
}

/// Waits until `check` holds, checking once the watch on `path` is in place
/// (so a change made before it is not missed) and again after each `mask`
/// event; `Ok(false)` once `deadline` is spent ([`Budget`]).
///
/// A thread blocks on the events; removing the watch at the end (on a
/// return or a panic in `check`) queues `IN_IGNORED`, which ends it, so
/// nothing outlives the call.
///
/// # Errors
/// When inotify cannot start or `path` cannot be watched.
pub fn wait_until(
    path: &Path,
    mask: WatchMask,
    deadline: Duration,
    check: &mut dyn FnMut() -> bool,
) -> std::io::Result<bool> {
    let mut budget = Budget::new(deadline);
    let mut inotify = Inotify::init()?;
    let watches = inotify.watches();
    let wd = watches.clone().add(path, mask)?;
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        while let Ok(mut events) = inotify.read_events_blocking(&mut buffer) {
            let ignored = events.any(|e| e.mask.contains(EventMask::IGNORED));
            if tx.send(()).is_err() || ignored {
                return;
            }
        }
    });
    // Ends the reader even when `check` panics.
    let _stop = Stop {
        watches,
        wd: Some(wd),
        reader: Some(reader),
    };
    let mut held = check();
    while !held && budget.recv(&rx).is_ok() {
        held = check();
    }
    Ok(held)
}

/// Removes the watch, which queues `IN_IGNORED` and so ends the reader,
/// then joins it. Removing fails only when the watch is already gone (the
/// path was removed), and then the kernel has queued `IN_IGNORED` itself.
struct Stop {
    watches: inotify::Watches,
    wd: Option<inotify::WatchDescriptor>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Stop {
    fn drop(&mut self) {
        if let Some(wd) = self.wd.take() {
            let _ = self.watches.remove(wd);
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}
