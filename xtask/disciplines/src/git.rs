// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Every git child of the runner goes through `command()`, which strips the
//! repository-local environment a hook hands down (an absolute `GIT_DIR` in a
//! linked worktree would point the child at the wrong repository).
use std::process::Command;

/// `git rev-parse --local-env-vars`. `tests/git.rs` asserts this
/// covers the installed git's list.
pub const LOCAL_ENV_VARS: &[&str] = &[
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_OBJECT_DIRECTORY",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_GRAFT_FILE",
    "GIT_INDEX_FILE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_REPLACE_REF_BASE",
    "GIT_PREFIX",
    "GIT_SHALLOW_FILE",
    "GIT_COMMON_DIR",
];

#[must_use]
pub fn command() -> Command {
    let mut cmd = Command::new("git");
    for var in LOCAL_ENV_VARS {
        cmd.env_remove(var);
    }
    cmd
}

/// Runs git in `root` with `input` on stdin. A separate thread writes the
/// input, so a full stdout pipe cannot deadlock the run. The caller reads
/// the status: some commands exit 1 to answer (`check-ignore`).
///
/// # Errors
/// When git cannot be spawned, or its stdin cannot be written.
pub fn with_stdin(
    root: &std::path::Path,
    args: &[&str],
    input: Vec<u8>,
) -> Result<std::process::Output, String> {
    use std::io::Write;
    use std::process::Stdio;
    let name = args.first().copied().unwrap_or("");
    let mut child = command()
        .args(args)
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("git {name}: {e}"))?;
    let mut stdin = child.stdin.take().ok_or("git: no stdin")?;
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let out = child
        .wait_with_output()
        .map_err(|e| format!("git {name}: {e}"))?;
    writer
        .join()
        .map_err(|_| "git: stdin writer panicked".to_string())?
        .map_err(|e| format!("git {name}: {e}"))?;
    Ok(out)
}
