// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Hooks hand git children an absolute `GIT_DIR` in linked worktrees; the
//! runner's git commands must not inherit it.
#[test]
fn scrub_list_covers_the_installed_git() {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--local-env-vars"])
        .output()
        .unwrap();
    for var in String::from_utf8(out.stdout).unwrap().lines() {
        assert!(
            xtask::git::LOCAL_ENV_VARS.contains(&var),
            "{var} missing from LOCAL_ENV_VARS"
        );
    }
}

#[test]
fn command_removes_every_listed_var() {
    let cmd = xtask::git::command();
    let removed: Vec<String> = cmd
        .get_envs()
        .filter(|(_, v)| v.is_none())
        .map(|(k, _)| k.to_string_lossy().into_owned())
        .collect();
    for var in xtask::git::LOCAL_ENV_VARS {
        assert!(removed.iter().any(|r| r == var), "{var} not removed");
    }
}
