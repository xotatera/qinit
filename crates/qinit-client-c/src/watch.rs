// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! The notice stream: `qinit_watch` turns a client into a watcher, `qinit_watch_next` reads it.
use crate::{Fail, Inner, enter, flag, out, put, qinit_client, text};
use crate::{
    QINIT_EVENT_INSTANCE, QINIT_EVENT_NODE, QINIT_EVENT_SHUTDOWN_COMPLETE, QINIT_EVENT_SWAPPED,
    QINIT_TARGET_MAX, QINIT_WATCH_ENDED, QINIT_WATCH_EVENT, QINIT_WATCH_TIMEOUT, name, qinit_event,
};
use ::qinit_client::{Event, Next, Report, Scope};
use std::ffi::{c_char, c_int};
use std::time::Duration;

/// The report word of `r` in a notice of `kind`.
fn report_word(kind: u32, r: Report) -> u32 {
    (0..9)
        .find(|&w| Report::from_wire(kind, w) == Some(r))
        .unwrap_or(0)
}

fn event(e: Event) -> qinit_event {
    match e {
        Event::Node {
            name: n,
            report,
            state,
            status,
        } => qinit_event {
            kind: QINIT_EVENT_NODE,
            name: name(&n),
            id: 0,
            state: state.state,
            detail: state.detail,
            report: report_word(QINIT_EVENT_NODE, report),
            status: status.unwrap_or(0),
        },
        Event::Instance {
            frame,
            id,
            report,
            state,
            status,
        } => qinit_event {
            kind: QINIT_EVENT_INSTANCE,
            name: name(&frame),
            id,
            state,
            detail: 0,
            report: report_word(QINIT_EVENT_INSTANCE, report),
            status: status.unwrap_or(0),
        },
        Event::Swapped => qinit_event {
            kind: QINIT_EVENT_SWAPPED,
            ..qinit_event::ZERO
        },
        Event::ShutdownComplete { still_populated } => qinit_event {
            kind: QINIT_EVENT_SHUTDOWN_COMPLETE,
            status: i32::try_from(still_populated).unwrap_or(i32::MAX),
            ..qinit_event::ZERO
        },
    }
}

/// Turns the connection into a stream of state notices: everything (`all` 1, `target` NULL or
/// empty) or one node or instance (`all` 0, `target` its name or `<frame>#<id>`). From then on
/// the client accepts only `qinit_watch_next`, `qinit_fd`, `qinit_last_error` and `qinit_close`.
/// A watch colony refuses (an unknown target, say) leaves the client as it was, and it
/// goes on asking. Only a lost connection ends it: then `qinit_fd` is -1 and every call but
/// `qinit_last_error` and `qinit_close` is `QINIT_E_ARGUMENT`.
///
/// # Safety
/// `c` is NULL or a live client; `target` NULL or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_watch(
    c: *mut qinit_client,
    all: c_int,
    target: *const c_char,
) -> c_int {
    let body = |cl: &mut qinit_client| -> Result<c_int, Fail> {
        let scope = if flag(all)? {
            // SAFETY: by the contract, a non-null `target` is a NUL-terminated string.
            if !target.is_null() && unsafe { *target } != 0 {
                return Err(Fail::ARGUMENT);
            }
            Scope::All
        } else {
            // SAFETY: by the contract, `target` is null or a NUL-terminated string.
            Scope::Target(unsafe { text(target, QINIT_TARGET_MAX) }?)
        };
        cl.client()?;
        let Inner::Client(client) = std::mem::replace(&mut cl.inner, Inner::Spent) else {
            return Err(Fail::UNEXPECTED);
        };
        match client.watch(scope) {
            Ok(w) => {
                cl.inner = Inner::Watching(w);
                Ok(0)
            }
            Err(refused) => {
                if let Some(client) = refused.client {
                    cl.inner = Inner::Client(client);
                }
                Err(refused.error.into())
            }
        }
    };
    // SAFETY: the contract of `enter` is this function's.
    unsafe { enter(c, body) }.unwrap_or_else(|kind| kind)
}

/// The next event of the watch, within `timeout_ms` (-1: no limit): `QINIT_WATCH_EVENT` with
/// `*out` filled, `QINIT_WATCH_ENDED` with the final state in `out->state` and `out->detail`
/// (the watch is over), or `QINIT_WATCH_TIMEOUT` (the stream is as it was, `*out` zeroed). It
/// fails with `-QINIT_E_*`; `-QINIT_E_UNEXPECTED` once the stream has ended or closed.
///
/// # Safety
/// `c` is NULL or a live client; `out` NULL or writable for a `qinit_event`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qinit_watch_next(
    c: *mut qinit_client,
    timeout_ms: i32,
    out: *mut qinit_event,
) -> c_int {
    let body = |cl: &mut qinit_client| -> Result<c_int, Fail> {
        let out = self::out(out)?;
        let timeout = match timeout_ms {
            -1 => None,
            n => Some(Duration::from_millis(
                u64::try_from(n).map_err(|_| Fail::ARGUMENT)?,
            )),
        };
        let Inner::Watching(w) = &mut cl.inner else {
            return Err(Fail::ARGUMENT);
        };
        let (rc, v) = match w.next(timeout)? {
            Next::Event(e) => (QINIT_WATCH_EVENT, event(e)),
            Next::Ended(s) => (
                QINIT_WATCH_ENDED,
                qinit_event {
                    state: s.state,
                    detail: s.detail,
                    ..qinit_event::ZERO
                },
            ),
            Next::Timeout => (QINIT_WATCH_TIMEOUT, qinit_event::ZERO),
        };
        // SAFETY: `out` is non-null and, by the contract, writable.
        unsafe { put(out, v) };
        Ok(rc)
    };
    // SAFETY: the contract of `enter` is this function's.
    unsafe { enter(c, body) }.unwrap_or_else(|kind| -kind)
}
