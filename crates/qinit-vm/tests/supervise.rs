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

/// One attempt: `Some(Ok(error text))` when the child started and the deadline kill emptied its
/// whole process group; `None` when the deadline came before the child's first byte.
fn group_attempt(deadline: Duration) -> Option<String> {
    use qinit_event::{Loop, Ready};
    use std::io::Read;
    use std::os::fd::AsFd;
    use std::os::unix::fs::OpenOptionsExt;
    let l = log("group");
    let fifo = std::env::temp_dir().join(format!("qinit-vm-fifo-{}", std::process::id()));
    let _ = std::fs::remove_file(&fifo);
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    // A reader without a writer opens at once; it sees hangup only after a writer came and
    // every writer is gone.
    let mut reader = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&fifo)
        .unwrap();
    // The shell announces itself, then leaves `sleep` holding the fifo in the same group.
    let mut cmd = sh("exec 3>\"$0\"; echo up >&3; sleep 600 & wait");
    cmd.arg(&fifo);
    let (done_rx, done_tx) = std::io::pipe().unwrap();
    let log2 = l.clone();
    let t = std::thread::spawn(move || {
        let r = run_logged(cmd, &log2, deadline);
        drop(done_tx);
        r
    });
    let mut lp = Loop::new().unwrap();
    lp.add_fd(reader.as_fd(), 1).unwrap();
    lp.add_fd(done_rx.as_fd(), 2).unwrap();
    let (mut up, mut closed) = (false, false);
    let mut buf = [0u8; 16];
    while !closed {
        for ev in lp.wait().unwrap() {
            match ev {
                Ready::Readable(1) | Ready::Hangup(1) => match reader.read(&mut buf) {
                    Ok(0) if up => closed = true,
                    Ok(n) if n > 0 => up = true,
                    _ => {}
                },
                Ready::Readable(2) | Ready::Hangup(2) => {
                    lp.remove(2).unwrap();
                    if !up {
                        // The deadline beat the shell's start; the group is gone.
                        t.join().unwrap().unwrap_err();
                        std::fs::remove_file(&fifo).unwrap();
                        std::fs::remove_file(&l).unwrap();
                        return None;
                    }
                }
                _ => {}
            }
        }
    }
    // Were only the shell killed, `sleep` would still hold the fifo and this point never comes.
    let e = t.join().unwrap().unwrap_err();
    std::fs::remove_file(&fifo).unwrap();
    std::fs::remove_file(&l).unwrap();
    Some(e)
}

#[test]
fn the_deadline_kill_reaches_the_whole_process_group() {
    // A deadline shorter than the shell's start just ends that attempt; each retry doubles it.
    let mut deadline = Duration::from_millis(300);
    for _ in 0..6 {
        if let Some(e) = group_attempt(deadline) {
            assert!(e.contains("did not finish within"), "{e}");
            return;
        }
        deadline *= 2;
    }
    panic!("the shell never started within {deadline:?}");
}
