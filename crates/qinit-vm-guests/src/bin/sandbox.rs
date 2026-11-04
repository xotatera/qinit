// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The sandbox on a real kernel: Landlock, the seccomp filters and the namespaces (spec
//! 2026-11-03 §4 steps 3, 9 and 10, §3).
use qinit_cell::{Polite, ReadyMode, Report};
use qinit_overseer::request::{RequestSpec, Seccomp, Stream, UserMap};
use qinit_vm_guests::{
    ALLOW_MIN, HANG_GUARD, capture, cells, e, expect, launch, read_all, remove, reports_of, run,
    run_to_end, spec, status_of,
};

/// `CAP_SYS_ADMIN`, for the calls the kernel would otherwise refuse the `svc` user.
const SYS_ADMIN: u64 = 1 << 21;
/// Namespace bits of the request: mount, pid, ipc, uts, net.
const NS_MOUNT: u32 = 1;
const NS_PID: u32 = 1 << 1;
const NS_USER: u32 = 1 << 5;
/// `CAP_SETGID`, `CAP_SETUID`.
const SETIDS: u64 = (1 << 6) | (1 << 7);
const NS_UTS: u32 = 1 << 3;
const NS_NET: u32 = 1 << 4;

#[allow(clippy::needless_pass_by_value)] // call sites pass fresh values; a reference would only add noise
fn want<T: PartialEq + std::fmt::Debug>(got: T, expected: T, what: &str) -> Result<(), String> {
    if got == expected {
        Ok(())
    } else {
        Err(format!("{what}: {got:?}, want {expected:?}"))
    }
}

fn probe_path(name: &str, path: &str, mode: &str, paths: &[&str]) -> Result<i32, String> {
    let mut request = spec("svc", "probe-path", &[path, mode]);
    request.ns = NS_MOUNT;
    request.paths = paths.iter().map(ToString::to_string).collect();
    let o = run_to_end(name, request, false)?;
    if let Some(f) = o.failure {
        return Err(format!("launch failed: {f:?}"));
    }
    o.code()
}

fn landlock() -> Result<(), String> {
    e(std::fs::create_dir_all("/tmp/ll"))?;
    e(qinit_sys::fd::chown(c"/tmp/ll", 1000, 1000).map_err(|x| x.to_string()))?;
    let rules = ["ro:/etc", "ro:/init", "rw:/tmp/ll"];
    let eacces = libc::EACCES;
    want(
        probe_path("ll1", "/etc/passwd", "r", &rules)?,
        0,
        "read of /etc/passwd",
    )?;
    // The bind is read-only and Landlock grants no write: either refuses, whichever the
    // kernel asks first.
    let w = probe_path("ll2", "/etc/passwd", "w", &rules)?;
    if w != eacces && w != libc::EROFS {
        return Err(format!("write of /etc/passwd: {w}, want EACCES or EROFS"));
    }
    want(
        probe_path("ll3", "/tmp/ll/x", "w", &rules)?,
        0,
        "write of /tmp/ll/x",
    )?;
    want(
        probe_path("ll4", "/proc/self/status", "r", &rules)?,
        libc::ENOENT,
        "read of the unlisted /proc",
    )
}

/// Runs the helper `role` in a view of `paths` (`/init`, which every helper needs, is added).
fn viewed(
    name: &str,
    role: &str,
    args: &[&str],
    paths: &[&str],
    ns: u32,
) -> Result<(i32, String), String> {
    let mut request = spec("svc", role, args);
    request.ns = NS_MOUNT | ns;
    let mut list: Vec<String> = paths.iter().map(ToString::to_string).collect();
    list.push("ro:/init".into());
    list.sort_by(|a, b| a[3..].cmp(&b[3..]));
    request.paths = list;
    let o = run_to_end(name, request, true)?;
    if let Some(f) = o.failure {
        return Err(format!("launch failed: {f:?}"));
    }
    Ok((o.code()?, o.out.trim().to_string()))
}

fn an_unlisted_path_does_not_exist() -> Result<(), String> {
    want(
        viewed("v1", "probe-path", &["/overseer", "r"], &["ro:/etc"], 0)?.0,
        libc::ENOENT,
        "open of an unlisted path",
    )?;
    want(
        viewed("v2", "probe-path", &["/etc/passwd", "r"], &["ro:/etc"], 0)?.0,
        0,
        "open of a listed path",
    )
}

fn the_root_is_read_only() -> Result<(), String> {
    want(
        viewed("v3", "probe-statvfs", &["/"], &["ro:/etc"], 0)?.0,
        0,
        "the root is read-only",
    )
}

fn a_ro_bind_below_rw_is_read_only() -> Result<(), String> {
    e(std::fs::create_dir_all("/tmp/rwp/sub"))?;
    let paths = ["rw:/tmp/rwp", "ro:/tmp/rwp/sub"];
    want(
        viewed("v4", "probe-statvfs", &["/tmp/rwp"], &paths, 0)?.0,
        1,
        "the rw parent is writable",
    )?;
    want(
        viewed("v5", "probe-statvfs", &["/tmp/rwp/sub"], &paths, 0)?.0,
        0,
        "the ro child is read-only",
    )
}

fn a_submount_below_a_listed_dir_appears_read_only() -> Result<(), String> {
    e(std::fs::create_dir_all("/tmp/srv/m"))?;
    e(
        qinit_sys::mount::mount("tmpfs", std::path::Path::new("/tmp/srv/m"), "tmpfs", 0)
            .map_err(|x| x.to_string()),
    )?;
    let r = viewed("v6", "probe-statvfs", &["/tmp/srv/m"], &["ro:/tmp/srv"], 0);
    let _ = qinit_sys::mount::umount_detach(std::path::Path::new("/tmp/srv/m"));
    want(r?.0, 0, "the submount is read-only")
}

fn a_listed_symlink_is_a_symlink() -> Result<(), String> {
    let _ = std::fs::remove_file("/tmp/lnk");
    e(std::os::unix::fs::symlink("/init", "/tmp/lnk"))?;
    want(
        viewed("v7", "probe-kind", &["/tmp/lnk"], &["ro:/tmp/lnk"], 0)?.0,
        10,
        "a listed symlink",
    )
}

fn a_listed_file_is_bound_as_a_file() -> Result<(), String> {
    want(
        viewed("v8", "probe-kind", &["/etc/passwd"], &["ro:/etc/passwd"], 0)?.0,
        12,
        "a listed file",
    )?;
    want(
        viewed(
            "v9",
            "probe-path",
            &["/etc/passwd", "r"],
            &["ro:/etc/passwd"],
            0,
        )?
        .0,
        0,
        "reading a listed file",
    )
}

fn fixed_dev_nodes_work_and_shm_tmp_are_private() -> Result<(), String> {
    for (i, node) in ["null", "zero", "full", "random", "urandom"]
        .iter()
        .enumerate()
    {
        let path = format!("/dev/{node}");
        want(
            viewed(
                &format!("vd{i}"),
                "probe-path",
                &[&path, "r"],
                &["ro:/etc"],
                0,
            )?
            .0,
            0,
            &format!("reading {path}"),
        )?;
    }
    want(
        viewed("vd5", "probe-path", &["/dev/null", "w"], &["ro:/etc"], 0)?.0,
        0,
        "writing /dev/null",
    )?;
    for (i, path) in ["/tmp/private-x", "/dev/shm/private-x"].iter().enumerate() {
        want(
            viewed(
                &format!("vp{i}"),
                "probe-path",
                &[path, "w"],
                &["ro:/etc"],
                0,
            )?
            .0,
            0,
            &format!("writing {path}"),
        )?;
        if std::path::Path::new(path).exists() {
            return Err(format!("{path} reached the host"));
        }
    }
    Ok(())
}

fn proc_in_a_pid_namespace_shows_only_the_namespace() -> Result<(), String> {
    let (code, out) = viewed("vq", "probe-procs", &[], &["ro:/proc"], NS_PID)?;
    want(code, 0, "the helper's exit")?;
    let n: usize = e(out.parse())?;
    if (1..=3).contains(&n) {
        Ok(())
    } else {
        Err(format!("{n} processes in /proc, want the namespace's few"))
    }
}

fn a_mount_namespace_without_paths_keeps_the_host_copy() -> Result<(), String> {
    e(std::fs::write("/tmp/hostonly", b"x"))?;
    // No path list: no view. The host's tree is there (a copy of it) ...
    want(
        probe_path("mh1", "/etc/passwd", "r", &[])?,
        0,
        "the host's /etc/passwd is readable",
    )?;
    // ... but `/tmp` is a private tmpfs, so the host's file is not.
    want(
        probe_path("mh2", "/tmp/hostonly", "r", &[])?,
        libc::ENOENT,
        "the host's /tmp file is absent",
    )
}

fn a_fresh_proc_is_read_only_for_a_ro_entry() -> Result<(), String> {
    want(
        viewed("vq2", "probe-statvfs", &["/proc"], &["ro:/proc"], NS_PID)?.0,
        0,
        "a ro:/proc in a pid namespace is read-only",
    )
}

fn no_view_mount_takes_part_in_a_peer_group() -> Result<(), String> {
    // A host mount made after the view was built must not appear in it, so no mount of the view
    // may still be a slave of (or share with) the host's.
    e(std::fs::create_dir_all("/tmp/srv"))?;
    // A shared host tree, as a service manager's host has: the view's binds become its slaves.
    e(qinit_sys::mount::mount(
        "none",
        std::path::Path::new("/"),
        "none",
        libc::MS_SHARED | libc::MS_REC,
    )
    .map_err(|x| x.to_string()))?;
    let (code, out) = viewed(
        "vp",
        "probe-propagation",
        &[],
        &["ro:/proc", "ro:/tmp/srv"],
        0,
    )?;
    want(code, 0, "the helper's exit")?;
    want(out.as_str(), "0", "mounts with a shared: or master: field")
}

fn the_view_builds_with_a_read_only_root() -> Result<(), String> {
    // D49: the view's root lives below /run, so a read-only host root does not stop it.
    let root = std::path::Path::new("/");
    let remount = |flags: libc::c_ulong| {
        qinit_sys::mount::mount("none", root, "none", libc::MS_REMOUNT | flags)
            .map_err(|x| x.to_string())
    };
    // An earlier launch left the mount point behind; a read-only root must find none.
    let _ = std::fs::remove_dir("/.qinit-view");
    let _ = std::fs::remove_dir("/run/qinit/view");
    remount(libc::MS_RDONLY)?;
    if !qinit_sys::fs::is_readonly(root).map_err(|x| x.to_string())? {
        remount(0)?;
        return Err("the host root did not become read-only".into());
    }
    let r = viewed("vr", "probe-path", &["/etc/passwd", "r"], &["ro:/etc"], 0);
    remount(0)?;
    want(r?.0, 0, "open of a listed path with a read-only host root")
}

fn a_planted_symlink_below_a_writable_entry_is_refused() -> Result<(), String> {
    // D48: with `rw:/tmp/w` listed, `ro:/tmp/w/s` is opened below it without following symlinks,
    // so a link the service planted there cannot redirect the entry to a host path.
    let _ = std::fs::remove_dir_all("/tmp/w");
    e(std::fs::create_dir_all("/tmp/w"))?;
    e(std::os::unix::fs::symlink("/etc", "/tmp/w/s"))?;
    match viewed(
        "vw",
        "probe-path",
        &["/tmp/w/s/passwd", "r"],
        &["rw:/tmp/w", "ro:/tmp/w/s"],
        0,
    ) {
        // Only the entry's open can fail with ELOOP in a launch that lists plain directories.
        Err(m) if m.contains(&format!("errno: {}", libc::ELOOP)) => Ok(()),
        other => Err(format!(
            "a planted symlink: {other:?}, want a view-entry ELOOP"
        )),
    }
}

fn a_symlinked_directory_outside_a_writable_entry_still_works() -> Result<(), String> {
    let _ = std::fs::remove_file("/tmp/ro_s");
    e(std::os::unix::fs::symlink("/etc", "/tmp/ro_s"))?;
    want(
        viewed("vx", "probe-kind", &["/tmp/ro_s"], &["ro:/tmp/ro_s"], 0)?.0,
        10,
        "a listed symlink with no writable ancestor",
    )
}

/// Lists `entry` over a host directory `/tmp/fol` with an empty `m` below it, starts a service that
/// looks for `/tmp/fol/m/marker` after a second, and mounts a `tmpfs` holding the marker on the
/// host's `m` while the service runs. The service's exit: 0 when it saw the marker.
fn mount_after_the_service_started(name: &str, entry: &str) -> Result<i32, String> {
    // A shared host tree, as a service manager's host has.
    e(qinit_sys::mount::mount(
        "none",
        std::path::Path::new("/"),
        "none",
        libc::MS_SHARED | libc::MS_REC,
    )
    .map_err(|x| x.to_string()))?;
    let _ = qinit_sys::mount::umount_detach(std::path::Path::new("/tmp/fol/m"));
    e(std::fs::create_dir_all("/tmp/fol/m"))?;
    let mounter = std::thread::spawn(|| -> Result<(), String> {
        std::thread::sleep(std::time::Duration::from_millis(300));
        let m = std::path::Path::new("/tmp/fol/m");
        e(qinit_sys::mount::mount("tmpfs", m, "tmpfs", 0).map_err(|x| x.to_string()))?;
        e(std::fs::write("/tmp/fol/m/marker", b"x"))
    });
    let r = viewed(
        name,
        "probe-wait-file",
        &["/tmp/fol/m/marker", "1500"],
        &[entry],
        0,
    );
    let done = mounter
        .join()
        .map_err(|_| "the mounting thread panicked".to_string())?;
    let _ = qinit_sys::mount::umount_detach(std::path::Path::new("/tmp/fol/m"));
    done?;
    Ok(r?.0)
}

fn a_following_entry_sees_a_later_host_mount() -> Result<(), String> {
    want(
        mount_after_the_service_started("fo1", "rs:/tmp/fol")?,
        0,
        "the marker of a mount made after the launch, through rs:",
    )
}

fn a_plain_entry_does_not_see_a_later_host_mount() -> Result<(), String> {
    want(
        mount_after_the_service_started("fo2", "ro:/tmp/fol")?,
        libc::ENOENT,
        "the marker of a mount made after the launch, through ro:",
    )
}

fn a_setuid_binary_outside_the_list_is_absent() -> Result<(), String> {
    e(std::fs::write("/tmp/su", b"x"))?;
    e(std::fs::set_permissions(
        "/tmp/su",
        std::os::unix::fs::PermissionsExt::from_mode(0o4755),
    ))?;
    want(
        viewed("vs", "probe-path", &["/tmp/su", "r"], &["ro:/etc"], 0)?.0,
        libc::ENOENT,
        "an unlisted setuid file",
    )
}

fn syscall(name: &str, seccomp: Seccomp, caps: u64, call: &str) -> Result<String, String> {
    let mut request = spec("svc", "probe-syscall", &[call]);
    request.seccomp = seccomp;
    request.caps = caps;
    let o = run_to_end(name, request, true)?;
    if let Some(f) = o.failure {
        return Err(format!("launch failed: {f:?}"));
    }
    want(o.code()?, 0, "the helper's exit")?;
    Ok(o.out.trim().to_string())
}

fn errno(n: i32) -> String {
    n.to_string()
}

fn default_denylist() -> Result<(), String> {
    let d = Seccomp::Default;
    want(
        syscall("sd1", d.clone(), SYS_ADMIN, "ptrace")?,
        errno(libc::EPERM),
        "ptrace",
    )?;
    want(
        syscall("sd2", d.clone(), SYS_ADMIN, "unshare-net")?,
        errno(libc::EPERM),
        "unshare",
    )?;
    want(
        syscall("sd3", d.clone(), SYS_ADMIN, "clone3")?,
        errno(libc::ENOSYS),
        "clone3",
    )?;
    want(
        syscall("sd4", d, SYS_ADMIN, "getppid")?,
        "ok".to_string(),
        "getppid",
    )
}

fn deny_list() -> Result<(), String> {
    let d = || Seccomp::Deny(vec![110]);
    want(
        syscall("sx1", d(), 0, "getppid")?,
        errno(libc::EPERM),
        "getppid",
    )?;
    want(
        syscall("sx2", d(), 0, "ptrace")?,
        errno(libc::EPERM),
        "ptrace",
    )
}

fn allow_list() -> Result<(), String> {
    let list: Vec<u32> = ALLOW_MIN.iter().map(|(_, n)| *n).collect();
    want(
        syscall("sa1", Seccomp::Allow(list), 0, "getppid")?,
        errno(libc::EPERM),
        "getppid under the allowlist",
    )
}

fn pid_request(role: &str) -> RequestSpec {
    let mut request = spec("svc", role, &[]);
    request.ns = NS_PID;
    request
}

fn pid_namespace() -> Result<(), String> {
    let o = run_to_end("pn1", pid_request("pid"), true)?;
    want(o.out.trim(), "2", "the service's pid")?;
    want(o.code()?, 0, "exit status relayed")?;
    // The supervisor relays a polite stop: TERM reaches the service through two processes.
    let mut cells = cells()?;
    let (reader, writer) = capture();
    let mut request = pid_request("ready-show");
    request.stdout = Stream::Fd(6);
    request.ready_fd = Some(5);
    let l = launch(
        &mut cells,
        "pn2",
        &request,
        vec![(writer, 6)],
        ReadyMode::Pipe,
    )?;
    expect(&mut cells, l.id, Report::Ready)?;
    e(cells.stop(l.id, Polite::Main, HANG_GUARD, HANG_GUARD))?;
    let seen = expect(&mut cells, l.id, Report::Empty)?;
    // A clean exit (status 0) is not reported on its own: any `MainExited` is a failure.
    let reports = reports_of(&seen, l.id);
    if let Some(r) = reports.iter().find(|r| matches!(r, Report::MainExited(_))) {
        return Err(format!("the main did not exit cleanly after a stop: {r:?}"));
    }
    want(status_of(&l), None, "the status record")?;
    remove(&mut cells, l.id)?;
    let _ = read_all(reader);
    // A signal death of the service is seen as the same signal.
    let o = run_to_end("pn3", pid_request("raise-usr1"), false)?;
    want(o.signal()?, libc::SIGUSR1, "the relayed signal")
}

/// Starts a ready-show service in a pid namespace, stops it politely and waits for the cell to
/// empty. A supervisor that misses its child's exit leaves the stop to time out.
fn start_and_stop(name: &str) -> Result<(), String> {
    let mut cells = cells()?;
    let (reader, writer) = capture();
    let mut request = pid_request("ready-show");
    request.stdout = Stream::Fd(6);
    request.ready_fd = Some(5);
    let l = launch(
        &mut cells,
        name,
        &request,
        vec![(writer, 6)],
        ReadyMode::Pipe,
    )?;
    expect(&mut cells, l.id, Report::Ready)?;
    e(cells.stop(l.id, Polite::Main, HANG_GUARD, HANG_GUARD))?;
    expect(&mut cells, l.id, Report::Empty)?;
    remove(&mut cells, l.id)?;
    let _ = read_all(reader);
    Ok(())
}

fn supervisor_sees_every_exit() -> Result<(), String> {
    // The exit lands right after the forwarded TERM: the window between reaping and waiting.
    let started = std::time::Instant::now();
    for i in 0..30 {
        start_and_stop(&format!("ps{i}"))?;
    }
    let took = started.elapsed();
    if took < std::time::Duration::from_secs(20) {
        Ok(())
    } else {
        Err(format!("30 starts and stops took {took:?}, a stop hung"))
    }
}

fn supervisors_drop_the_parents_descriptors() -> Result<(), String> {
    let mut cells = cells()?;
    let (out_r, out_w) = capture();
    // A pipe the request does not mention, routed anyway: only a holder that never closed it
    // keeps its read end from reaching EOF.
    let (held_r, held_w) = capture();
    let mut request = pid_request("ready-show");
    request.stdout = Stream::Fd(6);
    request.ready_fd = Some(5);
    let l = launch(
        &mut cells,
        "pd1",
        &request,
        vec![(out_w, 6), (held_w, 9)],
        ReadyMode::Pipe,
    )?;
    expect(&mut cells, l.id, Report::Ready)?;
    // Blocks until the last write end is closed; the harness's hang guard ends a holder that
    // never lets go.
    let mut file = std::fs::File::from(held_r);
    let eof = matches!(std::io::Read::read(&mut file, &mut [0u8; 1]), Ok(0));
    e(cells.stop(l.id, Polite::Main, HANG_GUARD, HANG_GUARD))?;
    expect(&mut cells, l.id, Report::Empty)?;
    remove(&mut cells, l.id)?;
    let _ = read_all(out_r);
    if eof {
        Ok(())
    } else {
        Err("a supervisor still holds a descriptor of its parent".into())
    }
}

fn hostname() -> Result<(), String> {
    let before = e(std::fs::read_to_string("/proc/sys/kernel/hostname"))?;
    let mut request = spec("svc", "hostname-set", &[]);
    request.ns = NS_UTS;
    request.caps = SYS_ADMIN;
    let o = run_to_end("uts", request, true)?;
    want(o.out.trim(), "inside", "the hostname inside")?;
    let after = e(std::fs::read_to_string("/proc/sys/kernel/hostname"))?;
    want(after, before, "the guest's own hostname")
}

fn loopback() -> Result<(), String> {
    let mut request = spec("svc", "ifaces", &[]);
    request.ns = NS_NET;
    let o = run_to_end("net", request, true)?;
    want(o.out.trim(), "lo up", "interfaces")
}

fn userns_request(role: &str, args: &[&str], ns: u32) -> RequestSpec {
    let mut request = spec("svc", role, args);
    request.ns = NS_USER | ns;
    request
}

fn inside_uid_0_outside_the_declared_uid() -> Result<(), String> {
    let o = run_to_end("u1", userns_request("userns-show", &[], 0), true)?;
    want(o.code()?, 0, "the helper's exit")?;
    let lines: Vec<&str> = o.out.lines().collect();
    want(lines.first().copied(), Some("ids 0 0"), "inside ids")?;
    // Inside 0 is the outside `svc` (1000), one id long; `setgroups` is denied.
    want(lines.get(1).copied(), Some("uid_map 0 1000 1"), "uid_map")?;
    want(lines.get(2).copied(), Some("gid_map 0 1000 1"), "gid_map")?;
    want(lines.get(3).copied(), Some("setgroups deny"), "setgroups")
}

/// The owner on the host of a file `/tmp/<name>` that a service running with `ids` created.
fn owner_of_a_service_file(name: &str, range: bool, ids: (u32, u32)) -> Result<u32, String> {
    let path = format!("/tmp/{name}");
    let _ = std::fs::remove_file(&path);
    let mut request = userns_request("probe-path", &[&path, "w"], 0);
    if range {
        request.user_map = UserMap::Range;
    }
    (request.inside_uid, request.inside_gid) = ids;
    want(
        run_to_end(name, request, true)?.code()?,
        0,
        "creating the file",
    )?;
    let owner = std::os::unix::fs::MetadataExt::uid(&e(std::fs::metadata(&path))?);
    let _ = std::fs::remove_file(&path);
    Ok(owner)
}

fn inside_uid_1000_with_an_own_map() -> Result<(), String> {
    let mut show = userns_request("userns-show", &[], 0);
    show.inside_uid = 1000;
    show.inside_gid = 1001;
    let o = run_to_end("ui1", show, true)?;
    want(o.code()?, 0, "the helper's exit")?;
    let lines: Vec<&str> = o.out.lines().collect();
    want(lines.first().copied(), Some("ids 1000 1001"), "inside ids")?;
    want(
        lines.get(1).copied(),
        Some("uid_map 1000 1000 1"),
        "uid_map",
    )?;
    want(
        lines.get(2).copied(),
        Some("gid_map 1001 1000 1"),
        "gid_map",
    )?;
    // The inside id 1000 is the outside `svc` (1000): its files belong to it on the host.
    want(
        owner_of_a_service_file("ui1f", false, (1000, 1001))?,
        1000,
        "owner on the host",
    )
}

fn inside_uid_1000_with_a_range_map() -> Result<(), String> {
    let mut show = userns_request("userns-show", &[], 0);
    show.user_map = UserMap::Range;
    show.inside_uid = 1000;
    show.inside_gid = 1000;
    let o = run_to_end("ui2", show, true)?;
    want(o.code()?, 0, "the helper's exit")?;
    let lines: Vec<&str> = o.out.lines().collect();
    want(lines.first().copied(), Some("ids 1000 1000"), "inside ids")?;
    want(
        lines.get(1).copied(),
        Some("uid_map 0 1000 1 1 100000 65536"),
        "range uid_map",
    )?;
    // Inside 1000 is the 1000th subordinate id: outside 100000 + 999.
    want(
        owner_of_a_service_file("ui2f", true, (1000, 1000))?,
        100_999,
        "owner on the host",
    )
}

fn an_unmapped_inside_id_fails_the_launch() -> Result<(), String> {
    let mut request = userns_request("userns-show", &[], 0);
    request.user_map = UserMap::Range;
    request.inside_uid = 65_537;
    let o = run_to_end("ui3", request, true)?;
    let failure = o.failure.ok_or("no failure record")?;
    want(
        (failure.step, failure.errno),
        (qinit_overseer::status::STEP_IDENTITY, libc::ERANGE),
        "failure step and errno",
    )
}

fn a_range_map_lets_inside_root_setuid_1() -> Result<(), String> {
    let mut own = userns_request("setuid-1", &[], 0);
    own.caps = SETIDS;
    let o = run_to_end("u2", own, true)?;
    want(
        o.out.trim(),
        libc::EINVAL.to_string().as_str(),
        "setuid(1), own map",
    )?;
    let mut range = userns_request("setuid-1", &[], 0);
    range.caps = SETIDS;
    range.user_map = UserMap::Range;
    let o = run_to_end("u3", range, true)?;
    want(o.out.trim(), "ok", "setuid(1), range map")?;
    let o = run_to_end(
        "u4",
        {
            let mut r = userns_request("userns-show", &[], 0);
            r.user_map = UserMap::Range;
            r
        },
        true,
    )?;
    let lines: Vec<&str> = o.out.lines().collect();
    want(
        lines.get(1).copied(),
        Some("uid_map 0 1000 1 1 100000 65536"),
        "range uid_map",
    )?;
    want(
        lines.get(3).copied(),
        Some("setgroups allow"),
        "range setgroups",
    )
}

fn lo_is_configurable_inside_with_net() -> Result<(), String> {
    let o = run_to_end("u5", userns_request("ifaces", &[], NS_NET), true)?;
    want(o.out.trim(), "lo up", "interfaces")
}

fn sethostname_works_with_uts() -> Result<(), String> {
    let mut request = userns_request("hostname-set", &[], NS_UTS);
    request.caps = SYS_ADMIN;
    let before = e(std::fs::read_to_string("/proc/sys/kernel/hostname"))?;
    let o = run_to_end("u6", request, true)?;
    want(o.out.trim(), "inside", "the hostname inside")?;
    let after = e(std::fs::read_to_string("/proc/sys/kernel/hostname"))?;
    want(after, before, "the guest's own hostname")
}

fn default_seccomp_denies_mount_inside() -> Result<(), String> {
    for (i, (seccomp, want_out)) in [
        (Seccomp::Default, libc::EPERM.to_string()),
        (Seccomp::None, "ok".to_string()),
    ]
    .into_iter()
    .enumerate()
    {
        let mut request = userns_request("probe-syscall", &["mount"], NS_MOUNT);
        request.caps = SYS_ADMIN;
        request.seccomp = seccomp;
        // No path list: Landlock refuses every mount to a process it restricts.
        let o = run_to_end(&format!("u7{i}"), request, true)?;
        want(o.out.trim(), want_out.as_str(), "mount inside")?;
    }
    Ok(())
}

fn inside_root_cannot_loosen_the_view() -> Result<(), String> {
    let mut request = userns_request("loosen", &["/etc"], NS_MOUNT);
    request.caps = SYS_ADMIN;
    request.seccomp = Seccomp::None;
    request.nnp = true;
    request.paths = vec!["ro:/etc".into(), "ro:/init".into()];
    let o = run_to_end("u8", request, true)?;
    let words: Vec<&str> = o.out.split_whitespace().collect();
    want(words.first().copied(), Some("remount"), "output")?;
    let refused = |w: Option<&&str>| {
        let n: i32 = w.and_then(|x| x.parse().ok()).unwrap_or(0);
        n == libc::EPERM || n == libc::EINVAL
    };
    if !refused(words.get(1)) || !refused(words.get(3)) {
        return Err(format!(
            "the inside root changed its view: {:?}",
            o.out.trim()
        ));
    }
    Ok(())
}

fn a_root_only_directory_is_listable() -> Result<(), String> {
    // The parent is root-only; the listed directory below it is not. Only the view's real root
    // can reach it to bind it.
    e(std::fs::create_dir_all("/tmp/rootonly/open"))?;
    e(std::fs::set_permissions(
        "/tmp/rootonly",
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    ))?;
    e(std::fs::set_permissions(
        "/tmp/rootonly/open",
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    ))?;
    e(std::fs::write("/tmp/rootonly/open/f", b"x"))?;
    let mut request = userns_request("probe-path", &["/tmp/rootonly/open/f", "r"], NS_MOUNT);
    request.paths = vec!["ro:/init".into(), "ro:/tmp/rootonly/open".into()];
    let o = run_to_end("u9", request, true)?;
    want(o.code()?, 0, "reading below a root-only parent")
}

#[allow(clippy::too_many_lines)] // the table of cases is the whole body
fn main() {
    run(
        "sandbox",
        &[
            ("landlock_grants_ro_and_rw_and_denies_the_rest", landlock),
            (
                "inside_uid_0_outside_the_declared_uid",
                inside_uid_0_outside_the_declared_uid,
            ),
            (
                "a_range_map_lets_inside_root_setuid_1",
                a_range_map_lets_inside_root_setuid_1,
            ),
            (
                "lo_is_configurable_inside_with_net",
                lo_is_configurable_inside_with_net,
            ),
            ("sethostname_works_with_uts", sethostname_works_with_uts),
            (
                "default_seccomp_denies_mount_inside",
                default_seccomp_denies_mount_inside,
            ),
            (
                "inside_root_cannot_loosen_the_view",
                inside_root_cannot_loosen_the_view,
            ),
            (
                "a_root_only_directory_is_listable",
                a_root_only_directory_is_listable,
            ),
            (
                "an_unlisted_path_does_not_exist",
                an_unlisted_path_does_not_exist,
            ),
            ("the_root_is_read_only", the_root_is_read_only),
            (
                "inside_uid_1000_with_an_own_map",
                inside_uid_1000_with_an_own_map,
            ),
            (
                "inside_uid_1000_with_a_range_map",
                inside_uid_1000_with_a_range_map,
            ),
            (
                "an_unmapped_inside_id_fails_the_launch",
                an_unmapped_inside_id_fails_the_launch,
            ),
            (
                "a_ro_bind_below_rw_is_read_only",
                a_ro_bind_below_rw_is_read_only,
            ),
            (
                "a_submount_below_a_listed_dir_appears_read_only",
                a_submount_below_a_listed_dir_appears_read_only,
            ),
            (
                "a_listed_symlink_is_a_symlink",
                a_listed_symlink_is_a_symlink,
            ),
            (
                "a_listed_file_is_bound_as_a_file",
                a_listed_file_is_bound_as_a_file,
            ),
            (
                "fixed_dev_nodes_work_and_shm_tmp_are_private",
                fixed_dev_nodes_work_and_shm_tmp_are_private,
            ),
            (
                "proc_in_a_pid_namespace_shows_only_the_namespace",
                proc_in_a_pid_namespace_shows_only_the_namespace,
            ),
            (
                "a_mount_namespace_without_paths_keeps_the_host_copy",
                a_mount_namespace_without_paths_keeps_the_host_copy,
            ),
            (
                "a_fresh_proc_is_read_only_for_a_ro_entry",
                a_fresh_proc_is_read_only_for_a_ro_entry,
            ),
            (
                "no_view_mount_takes_part_in_a_peer_group",
                no_view_mount_takes_part_in_a_peer_group,
            ),
            (
                "the_view_builds_with_a_read_only_root",
                the_view_builds_with_a_read_only_root,
            ),
            (
                "a_planted_symlink_below_a_writable_entry_is_refused",
                a_planted_symlink_below_a_writable_entry_is_refused,
            ),
            (
                "a_symlinked_directory_outside_a_writable_entry_still_works",
                a_symlinked_directory_outside_a_writable_entry_still_works,
            ),
            (
                "a_following_entry_sees_a_later_host_mount",
                a_following_entry_sees_a_later_host_mount,
            ),
            (
                "a_plain_entry_does_not_see_a_later_host_mount",
                a_plain_entry_does_not_see_a_later_host_mount,
            ),
            (
                "a_setuid_binary_outside_the_list_is_absent",
                a_setuid_binary_outside_the_list_is_absent,
            ),
            ("the_default_denylist_returns_eperm", default_denylist),
            ("a_deny_list_adds_to_the_default", deny_list),
            ("an_allow_list_permits_only_its_calls", allow_list),
            (
                "a_pid_namespace_has_a_supervisor_that_relays_signals_and_status",
                pid_namespace,
            ),
            (
                "a_supervisor_sees_every_exit_of_its_child",
                supervisor_sees_every_exit,
            ),
            (
                "supervisors_hold_no_descriptor_of_their_parent",
                supervisors_drop_the_parents_descriptors,
            ),
            ("uts_isolation_hides_a_hostname_change", hostname),
            ("net_isolation_leaves_only_loopback_up", loopback),
        ],
    )
}
