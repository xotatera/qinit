// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The deadline bounds a blocked step (spec 2026-11-03 R4, plan P15).
use qinit_overseer::request::Stream;
use qinit_vm_guests::{queue_connections, run, run_to_end, spec, stream_listener};

fn blocked_connect() -> Result<(), String> {
    let _listener = stream_listener("/tmp/blk", 1)?;
    let _queued = queue_connections("/tmp/blk", 2)?;
    let mut request = spec("svc", "say", &["never"]);
    request.stdout = Stream::Path("/tmp/blk".into());
    request.deadline_ms = 500;
    let o = run_to_end("dl", request, false)?;
    let sig = o.signal()?;
    if sig != libc::SIGALRM {
        return Err(format!("killed by signal {sig}, want SIGALRM"));
    }
    match o.failure {
        None => Ok(()),
        Some(f) => Err(format!("unexpected failure record {f:?}")),
    }
}

fn main() {
    run(
        "deadline",
        &[(
            "a_blocked_connect_ends_the_executor_at_the_deadline",
            blocked_connect,
        )],
    )
}
