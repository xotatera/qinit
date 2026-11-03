// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The overseer's credential and descriptor sequence on a real kernel: identity, environment,
//! capabilities, securebits, `no_new_privs`, the readiness pipe and the descriptors that
//! arrive (spec 2026-11-03 §4, steps 5 to 7 and 11).
use qinit_cell::{Polite, ReadyMode, Report};
use qinit_overseer::request::{RequestSpec, Securebits, Stream};
use qinit_overseer::status::step_name;
use qinit_vm_guests::{
    HANG_GUARD, Launched, capture, cells, e, expect, launch, read_all, remove, run, spec, status_of,
};

/// `CAP_NET_BIND_SERVICE`.
const NET_BIND_SERVICE: u64 = 1 << 10;
/// `CAP_SYS_ADMIN`.
const SYS_ADMIN: u64 = 1 << 21;

/// The value of the `key:` line of `show`'s output, whitespace-normalised.
fn field(out: &str, key: &str) -> Result<String, String> {
    out.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}:")))
        .map(|v| v.split_whitespace().collect::<Vec<_>>().join(" "))
        .ok_or_else(|| format!("no {key} line in {out:?}"))
}

/// The environment entries `show` printed, sorted.
fn env_of(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| l.strip_prefix("env: "))
        .map(str::to_string)
        .collect()
}

/// A launch failure's record as text: the step it names and the errno.
fn failure(l: &Launched, request: &RequestSpec) -> Option<String> {
    let bytes = request.bytes().ok()?;
    status_of(l).map(|s| {
        format!(
            "launch failed at step {} ({}): errno {}",
            s.step,
            step_name(&bytes, s.step),
            s.errno
        )
    })
}

/// Launches `request` with standard output captured, runs it to its exit and returns what it
/// printed.
fn shown(name: &str, mut request: RequestSpec) -> Result<String, String> {
    let mut cells = cells()?;
    let (reader, writer) = capture();
    request.stdout = Stream::Fd(6);
    let l = launch(
        &mut cells,
        name,
        &request,
        vec![(writer, 6)],
        ReadyMode::Exit,
    )?;
    expect(&mut cells, l.id, Report::Empty)?;
    if let Some(why) = failure(&l, &request) {
        return Err(why);
    }
    remove(&mut cells, l.id)?;
    Ok(read_all(reader))
}

fn identity_env_cwd_umask() -> Result<(), String> {
    let mut request = spec("svc", "show", &[]);
    request.env = vec!["EXTRA=1".into()];
    request.cwd = "/tmp".into();
    request.umask = 0o077;
    let out = shown("ident", request)?;
    let ids = [
        ("Uid", "1000 1000 1000 1000"),
        ("Gid", "1000 1000 1000 1000"),
    ];
    for (key, want) in ids {
        let got = field(&out, key)?;
        if got != want {
            return Err(format!("{key} is {got:?}, want {want:?}"));
        }
    }
    for (key, want) in [("Groups", "10"), ("cwd", "/tmp"), ("Umask", "0077")] {
        let got = field(&out, key)?;
        if got != want {
            return Err(format!("{key} is {got:?}, want {want:?}"));
        }
    }
    let want = [
        "EXTRA=1",
        "HOME=/home/svc",
        "LOGNAME=svc",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "USER=svc",
    ];
    let env = env_of(&out);
    if env == want {
        Ok(())
    } else {
        Err(format!("environment {env:?}, want {want:?}"))
    }
}

fn caps_of(out: &str, want: &[(&str, &str)]) -> Result<(), String> {
    for (key, value) in want {
        let got = field(out, key)?;
        if got != *value {
            return Err(format!("{key} is {got:?}, want {value:?}"));
        }
    }
    Ok(())
}

fn ambient_caps() -> Result<(), String> {
    let mut request = spec("svc", "show", &[]);
    request.caps = NET_BIND_SERVICE;
    let out = shown("ambient", request)?;
    let bit = "0000000000000400";
    caps_of(
        &out,
        &[
            ("CapAmb", bit),
            ("CapEff", bit),
            ("CapPrm", bit),
            ("CapBnd", bit),
        ],
    )
}

fn capability_less_root() -> Result<(), String> {
    let out = shown("rootless", spec("root", "show", &[]))?;
    let none = "0000000000000000";
    caps_of(
        &out,
        &[
            ("CapAmb", none),
            ("CapEff", none),
            ("CapPrm", none),
            ("CapBnd", none),
        ],
    )?;
    let uid = field(&out, "Uid")?;
    if uid == "0 0 0 0" {
        Ok(())
    } else {
        Err(format!("Uid is {uid:?}, want root"))
    }
}

fn noroot_locked() -> Result<(), String> {
    let mut request = spec("root", "show", &[]);
    request.securebits = Securebits::NorootLocked;
    let out = shown("noroot", request)?;
    let bits = field(&out, "SecBits")?;
    let value =
        u32::from_str_radix(bits.trim_start_matches("0x"), 16).map_err(|x| x.to_string())?;
    if value & 3 == 3 {
        Ok(())
    } else {
        Err(format!("securebits {bits}, want NOROOT and NOROOT_LOCKED"))
    }
}

fn no_new_privs() -> Result<(), String> {
    let on = shown("nnp-on", spec("svc", "show", &[]))?;
    let mut request = spec("svc", "show", &[]);
    request.nnp = false;
    request.caps = SYS_ADMIN;
    let off = shown("nnp-off", request)?;
    let (on, off) = (field(&on, "NoNewPrivs")?, field(&off, "NoNewPrivs")?);
    if (on.as_str(), off.as_str()) == ("1", "0") {
        Ok(())
    } else {
        Err(format!("NoNewPrivs on {on:?} off {off:?}, want 1 and 0"))
    }
}

fn readiness_pipe() -> Result<(), String> {
    let mut cells = cells()?;
    let (reader, writer) = capture();
    let mut request = spec("svc", "ready-show", &[]);
    request.stdout = Stream::Fd(6);
    request.ready_fd = Some(5);
    let l = launch(
        &mut cells,
        "ready",
        &request,
        vec![(writer, 6)],
        ReadyMode::Pipe,
    )?;
    expect(&mut cells, l.id, Report::Ready)?;
    e(cells.stop(l.id, Polite::Main, HANG_GUARD, HANG_GUARD))?;
    expect(&mut cells, l.id, Report::Empty)?;
    if let Some(why) = failure(&l, &request) {
        return Err(why);
    }
    remove(&mut cells, l.id)?;
    let env = env_of(&read_all(reader));
    if env.iter().any(|v| v == "QINIT_READY_FD=3") {
        Ok(())
    } else {
        Err(format!("environment {env:?} lacks QINIT_READY_FD=3"))
    }
}

fn declared_descriptors_only() -> Result<(), String> {
    let out = shown("fds", spec("svc", "fds", &[]))?;
    if out.trim() == "0 1 2" {
        Ok(())
    } else {
        Err(format!("descriptors {:?}, want \"0 1 2\"", out.trim()))
    }
}

fn status_pipe_at_eof() -> Result<(), String> {
    let mut cells = cells()?;
    let request = spec("svc", "exit-0", &[]);
    let l = launch(&mut cells, "eof", &request, Vec::new(), ReadyMode::Exit)?;
    expect(&mut cells, l.id, Report::Empty)?;
    let record = status_of(&l);
    remove(&mut cells, l.id)?;
    match record {
        None => Ok(()),
        Some(s) => Err(format!("status record {s:?} after a successful launch")),
    }
}

fn main() {
    run(
        "launch",
        &[
            (
                "a_non_root_user_gets_its_identity_env_cwd_and_umask",
                identity_env_cwd_umask,
            ),
            (
                "capabilities_are_kept_as_ambient_for_a_non_root_user",
                ambient_caps,
            ),
            (
                "a_capability_less_root_has_empty_sets",
                capability_less_root,
            ),
            ("noroot_locked_securebits_are_set", noroot_locked),
            ("nnp_is_on_when_asked_and_off_when_not", no_new_privs),
            ("the_readiness_pipe_arrives_at_fd_3", readiness_pipe),
            (
                "only_the_declared_descriptors_arrive",
                declared_descriptors_only,
            ),
            (
                "a_successful_launch_leaves_the_status_pipe_at_eof",
                status_pipe_at_eof,
            ),
        ],
    )
}
