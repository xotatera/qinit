// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Launch failures name their step and errno (spec 2026-11-03 R3).
use qinit_overseer::request::{RequestSpec, Stream};
use qinit_overseer::status::{STEP_DECODE, STEP_IDENTITY, Status, step_name};
use qinit_vm_guests::{run, run_to_end, spec};

fn failed(name: &str, request: RequestSpec) -> Result<(Status, String), String> {
    let o = run_to_end(name, request, false)?;
    let Some(status) = o.failure else {
        return Err("no failure record".into());
    };
    if o.code()? != 127 {
        return Err(format!("exit {:?}, want 127", o.exit));
    }
    let step = step_name(&o.request, status.step).to_string();
    Ok((status, step))
}

fn at(name: &str, request: RequestSpec, step: &str, errno: i32) -> Result<(), String> {
    let (got, got_step) = failed(name, request)?;
    if got_step == step && got.errno == errno {
        Ok(())
    } else {
        Err(format!(
            "failed at {got_step} with {}, want {step} with {errno}",
            got.errno
        ))
    }
}

fn unknown_user() -> Result<(), String> {
    at(
        "f1",
        spec("nobody-here", "exit-0", &[]),
        "identity",
        libc::ENOENT,
    )
}

fn root_alias() -> Result<(), String> {
    at("f2", spec("toor", "exit-0", &[]), "identity", libc::EPERM)
}

fn missing_executable() -> Result<(), String> {
    let mut request = spec("svc", "exit-0", &[]);
    request.argv = vec!["/nonexistent".into()];
    at("f3", request, "exec", libc::ENOENT)
}

fn cwd_not_enterable() -> Result<(), String> {
    e_dir("/tmp/rootonly")?;
    let mut request = spec("svc", "exit-0", &[]);
    request.cwd = "/tmp/rootonly".into();
    at("f4", request, "chdir", libc::EACCES)
}

fn e_dir(path: &str) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|x| x.to_string())?;
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .map_err(|x| x.to_string())
}

fn missing_listed_path() -> Result<(), String> {
    let mut request = spec("svc", "exit-0", &[]);
    request.ns = 1;
    request.paths = vec!["ro:/init".into(), "ro:/nonexistent".into()];
    at("f5", request, "view-entry", libc::ENOENT)
}

fn unpassed_fd() -> Result<(), String> {
    let mut request = spec("svc", "exit-0", &[]);
    request.stdout = Stream::Fd(9);
    at("f6", request, "open-stdout", libc::EBADF)
}

fn nnp_off_without_sys_admin() -> Result<(), String> {
    let request = RequestSpec {
        argv: vec!["/init".into()],
        user: "root".into(),
        nnp: false,
        ns: 1,
        paths: vec!["ro:/init".into()],
        ..RequestSpec::default()
    };
    let o = run_to_end("f7", request, false)?;
    match o.failure {
        Some(Status {
            step: STEP_DECODE,
            errno,
        }) if errno == libc::EINVAL => Ok(()),
        other => Err(format!(
            "record {other:?}, want decode/EINVAL (identity is {STEP_IDENTITY})"
        )),
    }
}

fn tiny_nofile() -> Result<(), String> {
    // With three descriptors allowed, creating the Landlock ruleset (a new descriptor) fails.
    let mut request = spec("svc", "exit-0", &[]);
    request.rlimits[7] = Some(3);
    request.ns = 1;
    request.paths = vec!["ro:/init".into()];
    let (got, step) = failed("f8", request)?;
    if step != "rlimit-nofile"
        && step != "decode"
        && step != "identity"
        && got.errno == libc::EMFILE
    {
        Ok(())
    } else {
        Err(format!(
            "failed at {step} with {}, want EMFILE after rlimit-nofile",
            got.errno
        ))
    }
}

fn main() {
    run(
        "fail",
        &[
            ("an_unknown_user_fails_at_identity", unknown_user),
            ("uid_zero_under_another_name_fails_at_identity", root_alias),
            ("a_missing_executable_fails_at_exec", missing_executable),
            (
                "a_cwd_the_user_cannot_enter_fails_at_chdir",
                cwd_not_enterable,
            ),
            (
                "a_missing_listed_path_fails_at_its_view_step",
                missing_listed_path,
            ),
            ("an_unpassed_routed_fd_fails_the_launch", unpassed_fd),
            ("a_tiny_nofile_fails_after_its_step", tiny_nofile),
            (
                "nnp_off_without_sys_admin_fails_at_decode",
                nnp_off_without_sys_admin,
            ),
        ],
    )
}
