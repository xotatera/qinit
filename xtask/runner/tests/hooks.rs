// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Exercises the installed git hooks in disposable repositories.

use std::cell::RefCell;
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
    fail_on: RefCell<String>,
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Repo {
    fn new() -> Self {
        Self::new_with_hooks(true)
    }

    fn uninstalled() -> Self {
        Self::new_with_hooks(false)
    }

    fn new_with_hooks(install_hooks: bool) -> Self {
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
            fail_on: RefCell::new(String::new()),
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
        if install_hooks {
            let hooks = repo.hooks_dir();
            std::fs::create_dir_all(&hooks).unwrap();
            copy_hooks(&source, &hooks);
            repo.ok(&["config", "core.hooksPath", hooks.to_str().unwrap()]);
            repo.ok(&["config", "merge.ff", "false"]);
        }
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
            .env("FAIL_ON", self.fail_on.borrow().as_str())
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

    fn fail_on(&self, command: &str) {
        self.fail_on.replace(command.to_owned());
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
fn setup_is_opt_in_and_uses_stable_common_hook_sources_from_a_linked_worktree() {
    let repo = Repo::uninstalled();
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
        assert!(hooks.join("qinit").join(hook).is_file());
    }
    assert!(
        !repo.git(&["config", "--get", "merge.ff"]).status.success(),
        "setup must not mutate merge.ff"
    );

    repo.ok(&["worktree", "remove", "--force", linked.to_str().unwrap()]);
    std::fs::write(repo.work().join("a"), "2\n").unwrap();
    repo.ok(&["add", "a"]);
    let rejected = repo.git(&["commit", "-qm", "direct after linked worktree removal"]);
    assert!(!rejected.status.success(), "{}", stderr(&rejected));
    assert!(
        stderr(&rejected).contains("Direct commits to main"),
        "{}",
        stderr(&rejected)
    );
}

#[test]
fn setup_refuses_an_inactive_hooks_path_without_changing_settings() {
    let repo = Repo::uninstalled();
    let alternate = repo.dir.join("alternate-hooks");
    std::fs::create_dir_all(&alternate).unwrap();
    repo.ok(&["config", "core.hooksPath", alternate.to_str().unwrap()]);
    repo.ok(&["config", "merge.ff", "only"]);

    let setup = repo.work().join(".githooks/setup-hooks.sh");
    let output = Command::new(&setup)
        .current_dir(repo.work())
        .env("HOME", &repo.dir)
        .env("GIT_CONFIG_GLOBAL", repo.dir.join("gitconfig"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("effective core.hooksPath"),
        "{}",
        stderr(&output)
    );
    assert_eq!(
        repo.ok(&["config", "--get", "core.hooksPath"]).trim(),
        alternate.to_str().unwrap()
    );
    assert_eq!(repo.ok(&["config", "--get", "merge.ff"]).trim(), "only");
}

#[test]
fn setup_refuses_unrelated_active_hooks_without_changing_them_or_merge_settings() {
    let repo = Repo::uninstalled();
    let hooks = repo.hooks_dir();
    std::fs::create_dir_all(&hooks).unwrap();
    let existing = hooks.join("pre-commit");
    std::fs::write(&existing, "#!/bin/sh\nexit 0\n").unwrap();
    repo.ok(&["config", "merge.ff", "only"]);

    let setup = repo.work().join(".githooks/setup-hooks.sh");
    let output = Command::new(&setup)
        .current_dir(repo.work())
        .env("HOME", &repo.dir)
        .env("GIT_CONFIG_GLOBAL", repo.dir.join("gitconfig"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("already exists"),
        "{}",
        stderr(&output)
    );
    assert_eq!(
        std::fs::read_to_string(existing).unwrap(),
        "#!/bin/sh\nexit 0\n"
    );
    assert_eq!(repo.ok(&["config", "--get", "merge.ff"]).trim(), "only");
}

#[test]
fn setup_refreshes_only_its_verified_installed_sources_and_links() {
    let repo = Repo::uninstalled();
    let setup = repo.work().join(".githooks/setup-hooks.sh");
    let run_setup = || {
        Command::new(&setup)
            .current_dir(repo.work())
            .env("HOME", &repo.dir)
            .env("GIT_CONFIG_GLOBAL", repo.dir.join("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap()
    };

    let installed = run_setup();
    assert!(installed.status.success(), "{}", stderr(&installed));
    let source = repo.work().join(".githooks/pre-commit");
    let refreshed = format!(
        "{}# refreshed fixture source\n",
        std::fs::read_to_string(&source).unwrap()
    );
    std::fs::write(&source, &refreshed).unwrap();

    let updated = run_setup();
    assert!(updated.status.success(), "{}", stderr(&updated));
    let hooks = repo.hooks_dir();
    assert_eq!(
        std::fs::read_to_string(hooks.join("qinit/pre-commit")).unwrap(),
        refreshed
    );
    assert_eq!(
        std::fs::read_link(hooks.join("pre-commit")).unwrap(),
        PathBuf::from("qinit/pre-commit")
    );
}

#[test]
fn setup_refuses_hardlinked_source_without_mutating_the_foreign_file() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let repo = Repo::uninstalled();
    let setup = repo.work().join(".githooks/setup-hooks.sh");
    let run_setup = || {
        Command::new(&setup)
            .current_dir(repo.work())
            .env("HOME", &repo.dir)
            .env("GIT_CONFIG_GLOBAL", repo.dir.join("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap()
    };
    let installed = run_setup();
    assert!(installed.status.success(), "{}", stderr(&installed));

    let foreign = repo.dir.join("foreign-hook");
    std::fs::write(&foreign, "foreign hook\n").unwrap();
    std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o600)).unwrap();
    let installed_source = repo.hooks_dir().join("qinit/pre-commit");
    std::fs::remove_file(&installed_source).unwrap();
    std::fs::hard_link(&foreign, &installed_source).unwrap();
    let mode = std::fs::metadata(&foreign).unwrap().mode();

    let refused = run_setup();
    assert!(!refused.status.success(), "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains("not a qinit-owned hook source"),
        "{}",
        stderr(&refused)
    );
    assert_eq!(std::fs::read_to_string(&foreign).unwrap(), "foreign hook\n");
    assert_eq!(std::fs::metadata(&foreign).unwrap().mode(), mode);
}

#[test]
fn setup_refuses_hidden_foreign_qinit_source_entries() {
    let repo = Repo::uninstalled();
    let setup = repo.work().join(".githooks/setup-hooks.sh");
    let run_setup = || {
        Command::new(&setup)
            .current_dir(repo.work())
            .env("HOME", &repo.dir)
            .env("GIT_CONFIG_GLOBAL", repo.dir.join("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap()
    };
    let installed = run_setup();
    assert!(installed.status.success(), "{}", stderr(&installed));

    let hidden = repo.hooks_dir().join("qinit/.foreign");
    std::fs::write(&hidden, "foreign source\n").unwrap();

    let refused = run_setup();
    assert!(!refused.status.success(), "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains("not a qinit hook source"),
        "{}",
        stderr(&refused)
    );
    assert_eq!(std::fs::read_to_string(hidden).unwrap(), "foreign source\n");
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
fn failing_full_gate_refuses_main_merge_without_moving_main() {
    let repo = Repo::new();
    repo.reviewed_commit("feat/failing-gate");
    repo.ok(&["switch", "-q", "main"]);
    let main = repo.rev("main");
    repo.fail_on("xtask gate");

    let rejected = repo.git(&["merge", "-q", "--no-edit", "feat/failing-gate"]);
    assert!(!rejected.status.success(), "{}", stderr(&rejected));
    assert!(
        stderr(&rejected).contains("MERGE BLOCKED"),
        "{}",
        stderr(&rejected)
    );
    assert_eq!(repo.rev("main"), main);
}

#[test]
fn literal_main_is_protected_when_the_configured_branch_is_trunk() {
    let repo = Repo::new();
    repo.reviewed_commit("feat/literal-main");
    repo.ok(&["switch", "-q", "main"]);
    let main = repo.rev("main");
    repo.fail_on("xtask gate");

    let rejected = repo.git_env(
        &["merge", "-q", "--no-edit", "feat/literal-main"],
        &[("DISCIPLINES_MAIN_BRANCH", "trunk")],
    );
    assert!(!rejected.status.success(), "{}", stderr(&rejected));
    assert!(
        stderr(&rejected).contains("MERGE BLOCKED"),
        "{}",
        stderr(&rejected)
    );
    assert_eq!(repo.rev("main"), main);

    let update_ref = repo.git_env(
        &[
            "update-ref",
            "refs/heads/main",
            &repo.rev("feat/literal-main"),
        ],
        &[("DISCIPLINES_MAIN_BRANCH", "trunk")],
    );
    assert!(!update_ref.status.success(), "{}", stderr(&update_ref));
    assert!(
        stderr(&update_ref).contains("main guard: refusing"),
        "{}",
        stderr(&update_ref)
    );
    assert_eq!(repo.rev("main"), main);
}

#[test]
fn configured_extra_branch_remains_protected() {
    let repo = Repo::new();
    repo.ok(&["branch", "trunk", "main"]);
    repo.ok(&["switch", "-q", "trunk"]);
    repo.ok(&["switch", "-q", "-c", "feat/trunk", "trunk"]);
    std::fs::write(repo.work().join("README.md"), "fixture\n").unwrap();
    repo.ok(&["add", "README.md"]);
    repo.ok(&["commit", "-qm", "reviewed trunk change"]);
    repo.ok(&["switch", "-q", "trunk"]);
    let trunk = repo.rev("trunk");
    repo.fail_on("xtask gate");

    let rejected = repo.git_env(
        &["merge", "-q", "--no-edit", "feat/trunk"],
        &[("DISCIPLINES_MAIN_BRANCH", "trunk")],
    );
    assert!(!rejected.status.success(), "{}", stderr(&rejected));
    assert!(
        stderr(&rejected).contains("MERGE BLOCKED"),
        "{}",
        stderr(&rejected)
    );
    assert_eq!(repo.rev("trunk"), trunk);
}

#[test]
fn pack_refs_deletes_loose_main_and_configured_protected_refs() {
    let repo = Repo::new();
    repo.ok(&["branch", "trunk", "main"]);
    let main = repo.rev("main");
    let trunk = repo.rev("trunk");
    let loose_main = repo.work().join(".git/refs/heads/main");
    let loose_trunk = repo.work().join(".git/refs/heads/trunk");
    assert!(loose_main.exists(), "main must start loose");
    assert!(loose_trunk.exists(), "trunk must start loose");

    let packed = repo.git_env(
        &["pack-refs", "--all", "--prune"],
        &[("DISCIPLINES_MAIN_BRANCH", "trunk")],
    );
    assert!(packed.status.success(), "{}", stderr(&packed));
    assert!(!loose_main.exists(), "main loose ref was not deleted");
    assert!(!loose_trunk.exists(), "trunk loose ref was not deleted");
    assert_eq!(repo.rev("main"), main);
    assert_eq!(repo.rev("trunk"), trunk);
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

impl Repo {
    /// A commit on a new branch from main whose README.md is `readme`, or has
    /// no README.md at all for `None`.
    fn readme_commit(&self, branch: &str, readme: Option<&str>) -> String {
        self.ok(&["switch", "-q", "-c", branch, "main"]);
        match readme {
            Some(text) => std::fs::write(self.work().join("README.md"), text).unwrap(),
            None => {
                self.ok(&["rm", "-q", "README.md"]);
            }
        }
        self.ok(&["add", "-A"]);
        self.ok(&["commit", "-qm", "readme variant"]);
        self.rev("HEAD")
    }

    fn pre_push(&self, branch: &str, sha: &str) -> Output {
        let zeros = "0000000000000000000000000000000000000000";
        self.run_hook(
            "pre-push",
            &format!("refs/heads/{branch} {sha} refs/heads/{branch} {zeros}\n"),
        )
    }
}

const CANARY_LINE_1: &str = "> [!IMPORTANT]";
const CANARY_LINE_2: &str =
    "> Remove these two lines to confirm that a human has reviewed this change.";

#[test]
fn pre_push_normalises_the_canary_like_the_gate() {
    let repo = Repo::new();
    for (index, readme) in [
        format!("{CANARY_LINE_1}\r\n{CANARY_LINE_2}\r\n\r\nfixture\r\n"),
        format!("\u{feff}{CANARY_LINE_1}\n{CANARY_LINE_2}\n"),
        format!("\n  \n{CANARY_LINE_1}\n{CANARY_LINE_2}\n"),
        format!(" {CANARY_LINE_1}\n\t{CANARY_LINE_2}  \n"),
        format!("\u{feff}\r\n {CANARY_LINE_1} \r\n{CANARY_LINE_2}\t\r\n"),
    ]
    .iter()
    .enumerate()
    {
        let branch = format!("feat/variant-{index}");
        let sha = repo.readme_commit(&branch, Some(readme));
        let refused = repo.pre_push(&branch, &sha);
        assert!(!refused.status.success(), "{readme:?}");
        assert!(
            stderr(&refused).contains("review canary remains"),
            "{readme:?}: {}",
            stderr(&refused)
        );
    }
    for (index, readme) in [
        "fixture\n".to_string(),
        format!("{CANARY_LINE_1}\n\n{CANARY_LINE_2}\n"),
        format!("fixture\n{CANARY_LINE_1}\n{CANARY_LINE_2}\n"),
    ]
    .iter()
    .enumerate()
    {
        let branch = format!("feat/reviewed-{index}");
        let sha = repo.readme_commit(&branch, Some(readme));
        let accepted = repo.pre_push(&branch, &sha);
        assert!(
            accepted.status.success(),
            "{readme:?}: {}",
            stderr(&accepted)
        );
    }
}

#[test]
fn pre_push_refuses_a_ref_without_a_readme_with_a_clear_message() {
    let repo = Repo::new();
    let sha = repo.readme_commit("feat/no-readme", None);
    let refused = repo.pre_push("feat/no-readme", &sha);
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("has no README.md"),
        "{}",
        stderr(&refused)
    );
}

impl Repo {
    fn setup(&self) -> Output {
        Command::new(self.work().join(".githooks/setup-hooks.sh"))
            .current_dir(self.work())
            .env("HOME", &self.dir)
            .env("GIT_CONFIG_GLOBAL", self.dir.join("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap()
    }

    /// A dispatcher directory configured as `core.hooksPath`.
    fn dispatcher(&self) -> PathBuf {
        let dispatcher = self.dir.join("dispatcher");
        std::fs::create_dir_all(&dispatcher).unwrap();
        self.ok(&["config", "core.hooksPath", dispatcher.to_str().unwrap()]);
        dispatcher
    }
}

#[test]
fn setup_refuses_a_dispatcher_that_is_not_declared() {
    let repo = Repo::uninstalled();
    repo.dispatcher();
    let refused = repo.setup();
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("qinit.hooksDispatcher"),
        "{}",
        stderr(&refused)
    );
    assert!(!repo.hooks_dir().join("qinit").exists());
}

#[test]
fn setup_refuses_a_declared_dispatcher_that_is_not_the_effective_hooks_path() {
    let repo = Repo::uninstalled();
    repo.dispatcher();
    let other = repo.dir.join("other-dispatcher");
    std::fs::create_dir_all(&other).unwrap();
    repo.ok(&["config", "qinit.hooksDispatcher", other.to_str().unwrap()]);
    let refused = repo.setup();
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("is not the effective hooks path"),
        "{}",
        stderr(&refused)
    );
    assert!(!repo.hooks_dir().join("qinit").exists());
}

#[test]
fn setup_installs_behind_a_declared_dispatcher_and_names_the_chain_targets() {
    let repo = Repo::uninstalled();
    let dispatcher = repo.dispatcher();
    // Not normalised: a `..` component and a trailing slash.
    let declared = format!("{}/../dispatcher/", dispatcher.display());
    repo.ok(&["config", "qinit.hooksDispatcher", &declared]);
    let installed = repo.setup();
    assert!(installed.status.success(), "{}", stderr(&installed));
    let hooks = repo.hooks_dir();
    for hook in [
        "pre-commit",
        "pre-merge-commit",
        "pre-push",
        "reference-transaction",
    ] {
        assert_eq!(
            std::fs::read_link(hooks.join(hook)).unwrap(),
            PathBuf::from(format!("qinit/{hook}"))
        );
    }
    assert_eq!(std::fs::read_dir(&dispatcher).unwrap().count(), 0);
    let stdout = String::from_utf8_lossy(&installed.stdout);
    let common = std::fs::canonicalize(repo.work().join(".git/hooks")).unwrap();
    assert!(
        stdout.contains(&format!("must chain to {}/<hook>", common.display())),
        "{stdout}"
    );
}
