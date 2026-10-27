// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use qinit_vm::supervise::run_logged;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

fn log(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("qinit-vm-{name}-{}.log", std::process::id()))
}

fn sh(script: &str) -> Command {
    let mut c = Command::new("sh");
    c.args(["-c", script]);
    c
}

#[test]
fn a_clean_exit_is_ok_and_its_output_is_logged() {
    let l = log("ok");
    run_logged(sh("echo hello; echo oops >&2"), &l, Duration::from_secs(30)).unwrap();
    let text = std::fs::read_to_string(&l).unwrap();
    assert!(text.contains("hello") && text.contains("oops"), "{text}");
    std::fs::remove_file(&l).unwrap();
}

#[test]
fn a_failing_step_names_its_exit_code_and_log() {
    let l = log("fail");
    let e = run_logged(sh("exit 3"), &l, Duration::from_secs(30)).unwrap_err();
    assert!(
        e.contains("exit code 3") && e.contains(&*l.to_string_lossy()),
        "{e}"
    );
    std::fs::remove_file(&l).unwrap();
}

#[test]
fn a_step_past_its_deadline_is_killed() {
    let l = log("late");
    let e = run_logged(sh("exec sleep 600"), &l, Duration::from_millis(200)).unwrap_err();
    assert!(e.contains("did not finish within"), "{e}");
    std::fs::remove_file(&l).unwrap();
}

#[test]
fn a_missing_program_is_an_error() {
    let l = log("missing");
    let e = run_logged(
        Command::new("/nonexistent/qinit-vm-tool"),
        &l,
        Duration::from_secs(30),
    )
    .unwrap_err();
    assert!(e.contains("start"), "{e}");
    std::fs::remove_file(&l).unwrap();
}

#[test]
fn the_deadline_kill_reaches_the_whole_process_group() {
    use std::io::Read;
    let l = log("group");
    let fifo = std::env::temp_dir().join(format!("qinit-vm-fifo-{}", std::process::id()));
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let mut cmd = sh("exec 3>\"$0\"; sleep 600 & wait");
    cmd.arg(&fifo);
    let log2 = l.clone();
    let t = std::thread::spawn(move || run_logged(cmd, &log2, Duration::from_millis(300)));
    // Both the shell and its background `sleep` hold the fifo's write end; reading reaches EOF
    // only when both are dead. Were only the shell killed, this would wait out the sleep.
    let mut rest = Vec::new();
    std::fs::File::open(&fifo)
        .unwrap()
        .read_to_end(&mut rest)
        .unwrap();
    let e = t.join().unwrap().unwrap_err();
    assert!(e.contains("did not finish within"), "{e}");
    std::fs::remove_file(&fifo).unwrap();
    std::fs::remove_file(&l).unwrap();
}
