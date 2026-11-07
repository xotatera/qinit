// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Queen's log lines for `/dev/kmsg`: `<6>queen: ` or `<3>queen: `, one fixed event and its
//! numbers, newline last. Formatted by hand into a caller's buffer: no allocation.
use qinit_queen_core::Mode;
use qinit_queen_core::machine::Event;

/// A line being written into a fixed buffer; what does not fit is cut.
struct Line<'a> {
    buf: &'a mut [u8; 128],
    len: usize,
}

impl Line<'_> {
    fn put(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.len < 127 {
                self.buf[self.len] = b;
                self.len += 1;
            }
        }
    }

    /// `n` in decimal, right-aligned in `width` columns.
    fn num(&mut self, n: i64, width: usize) {
        let mut digits = [0u8; 20];
        let mut at = digits.len();
        let neg = n < 0;
        let mut v = n.unsigned_abs();
        loop {
            at -= 1;
            digits[at] = b'0' + u8::try_from(v % 10).unwrap_or(0);
            v /= 10;
            if v == 0 {
                break;
            }
        }
        let used = digits.len() - at + usize::from(neg);
        for _ in used..width {
            self.put(b" ");
        }
        if neg {
            self.put(b"-");
        }
        self.put(&digits[at..]);
    }

    fn mode(&mut self, m: Mode) {
        self.put(match m {
            Mode::Halt => b"halt",
            Mode::Poweroff => b"poweroff",
            Mode::Reboot => b"reboot",
        });
    }

    fn finish(self) -> usize {
        self.buf[self.len] = b'\n';
        self.len + 1
    }
}

fn start(buf: &mut [u8; 128], err: bool) -> Line<'_> {
    let mut l = Line { buf, len: 0 };
    l.put(if err { b"<3>queen: " } else { b"<6>queen: " });
    l
}

/// Whether `ev` is a failure (`<3>`), as opposed to news (`<6>`).
#[must_use]
pub fn is_failure(ev: &Event) -> bool {
    matches!(
        ev,
        Event::LimitTripped
            | Event::Hold
            | Event::ExecFailed
            | Event::ChannelBad
            | Event::StoreFull(_)
            | Event::SpawnFailed
    )
}

/// Writes the line for `ev` into `buf`; returns its length.
#[must_use]
pub fn format(ev: &Event, buf: &mut [u8; 128]) -> usize {
    let mut l = start(buf, is_failure(ev));
    match *ev {
        Event::ColonyStarted(pid) => {
            l.put(b"colony started, pid");
            l.num(i64::from(pid), 7);
        }
        Event::ColonyExited(status) => {
            l.put(b"colony ended, status");
            l.num(i64::from(status), 6);
        }
        Event::LimitTripped => l.put(b"colony keeps ending, running rescue"),
        Event::RescueStarted(pid) => {
            l.put(b"rescue started, pid");
            l.num(i64::from(pid), 7);
        }
        Event::RescueEnded(status) => {
            l.put(b"rescue ended, status");
            l.num(i64::from(status), 6);
        }
        Event::Hold => l.put(b"nothing runs, holding"),
        Event::Shutdown(m) => {
            l.put(b"shutdown begins, ends in ");
            l.mode(m);
        }
        Event::ExecZero(m) => {
            l.put(b"handing over to zero: ");
            l.mode(m);
        }
        Event::ExecFailed => l.put(b"zero did not start"),
        Event::ChannelBad => l.put(b"colony sent a bad record"),
        Event::StoreFull(key) => {
            l.put(b"store full, refused key");
            l.num(i64::try_from(key).unwrap_or(i64::MAX), 7);
        }
        Event::SpawnFailed => l.put(b"could not start a process"),
        Event::CadIgnored => l.put(b"ctrl-alt-del ignored"),
    }
    l.finish()
}

/// The line for a signal queen ignores.
#[must_use]
pub fn format_signal(signo: u32, buf: &mut [u8; 128]) -> usize {
    let mut l = start(buf, false);
    l.put(b"signal");
    l.num(i64::from(signo), 3);
    l.put(b" ignored");
    l.finish()
}

/// The line for one drain that reaped orphans.
#[must_use]
pub fn format_orphans(count: u32, last_pid: i32, buf: &mut [u8; 128]) -> usize {
    let mut l = start(buf, false);
    l.put(b"reaped");
    l.num(i64::from(count), 5);
    l.put(b" orphans, last pid");
    l.num(i64::from(last_pid), 7);
    l.finish()
}
