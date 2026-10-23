// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Exercises the installed git hooks in disposable repositories.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

const CANARY: &str =
    "> [!IMPORTANT]\n> Remove these two lines to confirm that a human has reviewed this change.\n";
const STAND_IN: &str = r#"#!/usr/bin/env bash
printf '%s|context=%s|gitdir=%s\n' "$*" "${DISCIPLINES_GATE_CONTEXT:-}" "${GIT_DIR-unset}" >>"$LOG"
if [ -n "${FAIL_ON:-}" ] && [[ "$*" == *"$FAIL_ON"* ]]; then exit 1; fi
"#;

struct Repo {
    dir: PathBuf,
    fail_on: String,
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Repo {
    fn new() -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("qinit-hooks-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let work = dir.join("work");
        let bin = dir.join("bin");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        write_exec(&bin.join("cargo"), STAND_IN);
        std::fs::write(
            dir.join("gitconfig"),
            "[user]\n\tname = fixture\n\temail = fixture@example.invalid\n[init]\n\tdefaultBranch = main\n",
        )
        .unwrap();

        let repo = Self {
            dir,
            fail_on: String::new(),
        };
        repo.ok(&["init", "-q"]);
        std::fs::write(repo.work().join(".gitignore"), "/target/\n").unwrap();
        std::fs::write(
            repo.work().join("README.md"),
            format!("{CANARY}\nfixture\n"),
        )
        .unwrap();
        std::fs::write(repo.work().join("a"), "1\n").unwrap();
        repo.ok(&["add", "-A"]);
        repo.ok(&["commit", "-qm", "first"]);

        let source = qinit_xtask::repo_root().join(".githooks");
        copy_hooks(&source, &repo.work().join(".githooks"));
        repo.ok(&["add", ".githooks"]);
        repo.ok(&["commit", "-qm", "add fixture hooks"]);
        let hooks = repo.hooks_dir();
        std::fs::create_dir_all(&hooks).unwrap();
        copy_hooks(&source, &hooks);
        repo.ok(&["config", "core.hooksPath", hooks.to_str().unwrap()]);
        repo.ok(&["config", "merge.ff", "false"]);
        repo.clear_log();
        repo
    }

    fn work(&self) -> PathBuf {
        self.dir.join("work")
    }

    fn hooks_dir(&self) -> PathBuf {
        self.work().join(".git/hooks")
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("log")).unwrap_or_default()
    }

    fn clear_log(&self) {
        let _ = std::fs::remove_file(self.dir.join("log"));
    }

    fn git_env(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let path = format!(
            "{}:{}",
            self.dir.join("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut command = Command::new("git");
        command
            .args(args)
            .current_dir(self.work())
            .env("PATH", path)
            .env("LOG", self.dir.join("log"))
            .env("FAIL_ON", &self.fail_on)
            .env("HOME", &self.dir)
            .env("GIT_CONFIG_GLOBAL", self.dir.join("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("DISCIPLINES_ALLOW_UNGATED_MAIN")
            .env_remove("DISCIPLINES_GATE_CONTEXT")
            .env_remove("DISCIPLINES_MAIN_BRANCH");
        for (key, value) in env {
            command.env(key, value);
        }
        command.output().unwrap()
    }

    fn git(&self, args: &[&str]) -> Output {
        self.git_env(args, &[])
    }

    fn ok(&self, args: &[&str]) -> String {
        let output = self.git(args);
        assert!(output.status.success(), "git {args:?}: {}", stderr(&output));
        String::from_utf8(output.stdout).unwrap()
    }

    fn rev(&self, revision: &str) -> String {
        self.ok(&["rev-parse", revision]).trim().to_owned()
    }

    fn reviewed_commit(&self, branch: &str) {
        self.ok(&["switch", "-q", "-c", branch, "main"]);
        std::fs::write(self.work().join("README.md"), "fixture\n").unwrap();
        self.ok(&["add", "README.md"]);
        self.ok(&["commit", "-qm", "reviewed"]);
    }

    fn run_hook(&self, hook: &str, input: &str) -> Output {
        Command::new(self.hooks_dir().join(hook))
            .current_dir(self.work())
            .env("PATH", std::env::var("PATH").unwrap())
            .env("HOME", &self.dir)
            .env("GIT_CONFIG_GLOBAL", self.dir.join("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child.stdin.as_mut().unwrap().write_all(input.as_bytes())?;
                child.wait_with_output()
            })
            .unwrap()
    }
}

fn copy_hooks(source: &Path, destination: &Path) {
    std::fs::create_dir_all(destination).unwrap();
    for entry in std::fs::read_dir(source).expect("read committed hooks") {
        let entry = entry.unwrap();
        let text = std::fs::read_to_string(entry.path()).unwrap();
        write_exec(&destination.join(entry.file_name()), &text);
    }
}

fn write_exec(path: &Path, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn setup_is_opt_in_and_uses_the_common_git_dir_from_a_linked_worktree() {
    let repo = Repo::new();
    let linked = repo.dir.join("linked");
    repo.ok(&[
        "worktree",
        "add",
        "-q",
        "-b",
        "feat/linked",
        linked.to_str().unwrap(),
        "main",
    ]);
    assert!(
        linked.join(".git").is_file(),
        "linked worktree has a .git file"
    );

    let setup = linked.join(".githooks/setup-hooks.sh");
    let output = Command::new(&setup)
        .current_dir(&linked)
        .env("HOME", &repo.dir)
        .env("GIT_CONFIG_GLOBAL", repo.dir.join("gitconfig"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let common = repo.ok(&["rev-parse", "--path-format=absolute", "--git-common-dir"]);
    let hooks = PathBuf::from(common.trim()).join("hooks");
    for hook in [
        "branch-guard.sh",
        "worktree-clean.sh",
        "pre-commit",
        "pre-merge-commit",
        "pre-push",
        "reference-transaction",
    ] {
        assert!(
            hooks.join(hook).is_symlink(),
            "{hook} is linked in the common hooks directory"
        );
    }
    assert_eq!(repo.ok(&["config", "merge.ff"]).trim(), "false");
}

#[test]
fn commit_guards_refuse_main_and_unprefixed_branches_but_accept_prefixed_work() {
    let repo = Repo::new();
    std::fs::write(repo.work().join("a"), "2\n").unwrap();
    repo.ok(&["add", "a"]);
    let main = repo.git(&["commit", "-qm", "direct"]);
    assert!(!main.status.success());
    assert!(
        stderr(&main).contains("Direct commits to main"),
        "{}",
        stderr(&main)
    );

    repo.ok(&["switch", "-q", "-c", "wip", "main"]);
    let invalid = repo.git(&["commit", "-qm", "wip"]);
    assert!(!invalid.status.success());
    assert!(stderr(&invalid).contains("prefix/"), "{}", stderr(&invalid));

    repo.ok(&["switch", "-q", "-c", "feat/accepted", "main"]);
    repo.ok(&["commit", "-qm", "accepted"]);
    assert!(
        repo.log().contains("xtask gate --only fmt|context=|"),
        "{}",
        repo.log()
    );
}

#[test]
fn pre_merge_runs_the_full_main_gate_and_refuses_dirty_worktrees() {
    let repo = Repo::new();
    repo.reviewed_commit("feat/reviewed");
    repo.ok(&["switch", "-q", "main"]);
    repo.clear_log();
    repo.ok(&["merge", "-q", "--no-edit", "feat/reviewed"]);
    assert!(
        repo.log().contains("xtask gate|context=main|gitdir=unset"),
        "{}",
        repo.log()
    );

    let dirty = Repo::new();
    dirty.reviewed_commit("feat/dirty");
    dirty.ok(&["switch", "-q", "main"]);
    std::fs::write(dirty.work().join("stray"), "untracked\n").unwrap();
    let rejected = dirty.git(&["merge", "-q", "--no-edit", "feat/dirty"]);
    assert!(!rejected.status.success());
    assert!(
        stderr(&rejected).contains("untracked: stray"),
        "{}",
        stderr(&rejected)
    );
}

#[test]
fn reference_transaction_admits_only_a_gated_non_fast_forward_main_merge() {
    let repo = Repo::new();
    repo.reviewed_commit("feat/merge");
    repo.ok(&["switch", "-q", "main"]);
    repo.ok(&["merge", "-q", "--no-edit", "feat/merge"]);
    let merge = repo.rev("main");
    let parents = repo.ok(&["rev-list", "--parents", "-n", "1", "main"]);
    assert_eq!(
        parents.split_whitespace().count(),
        3,
        "main is a merge commit"
    );

    repo.ok(&["switch", "-q", "-c", "feat/other", "main"]);
    std::fs::write(repo.work().join("b"), "other\n").unwrap();
    repo.ok(&["add", "b"]);
    repo.ok(&["commit", "-qm", "other"]);
    let other = repo.rev("HEAD");
    repo.ok(&["switch", "-q", "main"]);
    let refused = repo.git(&["update-ref", "refs/heads/main", &other]);
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("main guard: refusing"),
        "{}",
        stderr(&refused)
    );
    assert_eq!(repo.rev("main"), merge);
}

#[test]
fn pre_push_checks_each_incoming_branch_and_tag_tree_not_the_checkout_and_allows_deletions() {
    let repo = Repo::new();
    repo.reviewed_commit("feat/reviewed");
    let reviewed = repo.rev("HEAD");
    repo.ok(&["switch", "-q", "main"]);
    let canary = repo.rev("main");
    let zeros = "0000000000000000000000000000000000000000";

    let branch = repo.run_hook(
        "pre-push",
        &format!("refs/heads/main {canary} refs/heads/main {zeros}\n"),
    );
    assert!(!branch.status.success());
    assert!(
        stderr(&branch).contains("refs/heads/main -> refs/heads/main"),
        "{}",
        stderr(&branch)
    );

    repo.ok(&["tag", "-a", "canary-tag", "-m", "fixture", &canary]);
    let tag_sha = repo.rev("canary-tag");
    let tag = repo.run_hook(
        "pre-push",
        &format!("refs/tags/canary-tag {tag_sha} refs/tags/canary-tag {zeros}\n"),
    );
    assert!(!tag.status.success());
    assert!(
        stderr(&tag).contains("refs/tags/canary-tag -> refs/tags/canary-tag"),
        "{}",
        stderr(&tag)
    );

    let accepted = repo.run_hook(
        "pre-push",
        &format!("refs/heads/feat/reviewed {reviewed} refs/heads/feat/reviewed {zeros}\n"),
    );
    assert!(accepted.status.success(), "{}", stderr(&accepted));
    let deletion = repo.run_hook(
        "pre-push",
        &format!("(delete) {zeros} refs/heads/obsolete {canary}\n"),
    );
    assert!(deletion.status.success(), "{}", stderr(&deletion));
}
