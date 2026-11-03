// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Output routes by file type on a real kernel (spec 2026-11-03 R7).
use qinit_overseer::request::{RequestSpec, Stream};
use qinit_overseer::status::{Status, step_name};
use qinit_vm_guests::{e, run, run_to_end, spec};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::{UnixDatagram, UnixListener};

#[allow(clippy::needless_pass_by_value)] // call sites pass fresh values; a reference would only add noise
fn want<T: PartialEq + std::fmt::Debug>(got: T, expected: T, what: &str) -> Result<(), String> {
    if got == expected {
        Ok(())
    } else {
        Err(format!("{what}: {got:?}, want {expected:?}"))
    }
}

fn say(path: &str, text: &str) -> RequestSpec {
    let mut request = spec("svc", "say", &[text]);
    request.stdout = Stream::Path(path.to_string());
    request
}

fn ok(name: &str, request: RequestSpec) -> Result<(), String> {
    let o = run_to_end(name, request, false)?;
    if let Some(f) = o.failure {
        return Err(format!("launch failed: {f:?}"));
    }
    want(o.code()?, 0, "the helper's exit")
}

fn regular_file() -> Result<(), String> {
    e(std::fs::create_dir_all("/tmp/out"))?;
    ok("rf1", say("/tmp/out/log", "one"))?;
    ok("rf2", say("/tmp/out/log", "two"))?;
    want(
        e(std::fs::read_to_string("/tmp/out/log"))?,
        "one\ntwo\n".to_string(),
        "content",
    )?;
    let meta = e(std::fs::metadata("/tmp/out/log"))?;
    want(meta.mode() & 0o777, 0o640, "mode")?;
    want(meta.uid(), 0, "owner")
}

fn root_opens() -> Result<(), String> {
    e(std::fs::create_dir_all("/tmp/rootonly"))?;
    e(std::fs::set_permissions(
        "/tmp/rootonly",
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    ))?;
    ok("ro1", say("/tmp/rootonly/log", "private"))?;
    want(
        e(std::fs::read_to_string("/tmp/rootonly/log"))?,
        "private\n".to_string(),
        "content",
    )
}

fn char_device() -> Result<(), String> {
    ok("cd1", say("/dev/null", "gone"))
}

fn mkfifo(path: &str) -> Result<(), String> {
    let c = e(std::ffi::CString::new(path))?;
    e(qinit_sys::fd::mkfifo(&c, 0o666).map_err(|x| x.to_string()))
}

fn fifo_with_reader() -> Result<(), String> {
    mkfifo("/tmp/ff1")?;
    let mut reader = e(std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/tmp/ff1"))?;
    ok("ff1", say("/tmp/ff1", "piped"))?;
    let mut text = String::new();
    e(reader.read_to_string(&mut text))?;
    want(text, "piped\n".to_string(), "fifo content")
}

fn fifo_without_reader() -> Result<(), String> {
    mkfifo("/tmp/ff2")?;
    let o = run_to_end("ff2", say("/tmp/ff2", "nobody"), false)?;
    let Some(Status { step, errno }) = o.failure else {
        return Err("no failure record".into());
    };
    want(errno, libc::ENXIO, "errno")?;
    want(step_name(&o.request, step), "open-stdout", "step")?;
    want(o.code()?, 127, "exit")
}

fn sockets() -> Result<(), String> {
    let listener = e(UnixListener::bind("/tmp/s1"))?;
    ok("sk1", say("/tmp/s1", "stream"))?;
    let (mut peer, _) = e(listener.accept())?;
    let mut text = String::new();
    e(peer.read_to_string(&mut text))?;
    want(text, "stream\n".to_string(), "stream content")?;
    let server = e(UnixDatagram::bind("/tmp/s2"))?;
    ok("sk2", say("/tmp/s2", "dgram"))?;
    let mut buf = [0u8; 64];
    let n = e(server.recv(&mut buf))?;
    want(
        String::from_utf8_lossy(&buf[..n]).into_owned(),
        "dgram\n".to_string(),
        "dgram content",
    )
}

fn routed_fd() -> Result<(), String> {
    let o = run_to_end("rd1", spec("svc", "say", &["routed"]), true)?;
    want(o.out, "routed\n".to_string(), "captured")
}

fn errors_follow_output() -> Result<(), String> {
    let o = run_to_end("ef1", spec("svc", "show", &[]), true)?;
    if o.out.lines().any(|l| l == "err") {
        Ok(())
    } else {
        Err(format!("no err line in {:?}", o.out))
    }
}

fn main() {
    run(
        "output",
        &[
            ("a_regular_file_is_appended_and_created_0640", regular_file),
            ("root_opens_the_file_the_service_could_not", root_opens),
            ("a_char_device_is_written_directly", char_device),
            ("a_fifo_with_a_reader_receives_the_output", fifo_with_reader),
            (
                "a_fifo_without_a_reader_fails_the_launch_with_enxio",
                fifo_without_reader,
            ),
            ("a_unix_stream_and_a_dgram_socket_are_connected", sockets),
            ("a_pipe_route_is_the_routed_fd", routed_fd),
            ("errors_default_to_output", errors_follow_output),
        ],
    )
}
