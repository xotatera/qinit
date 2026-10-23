// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The changelog gate: the comparison, the context, and the gate against
//! scratch repositories with real git (branch, merge in a hook, main tip).
use std::path::{Path, PathBuf};

use xtask::changelog::{Context, check, context, releases, unreleased};
use xtask::gates::changelog_in;

const BASE: &str =
    "# Changelog\n\n## [Unreleased]\n\n### Added\n\n- one\n\n## [0.1.0]\n\n- first\n";

fn with_entry(line: &str) -> String {
    BASE.replace("- one\n", &format!("- one\n{line}\n"))
}

#[test]
fn the_unreleased_section_and_the_releases_are_read() {
    assert_eq!(unreleased(BASE), Some(vec!["### Added", "- one"]));
    assert_eq!(releases(BASE), vec!["## [0.1.0]"]);
    assert_eq!(unreleased("# Changelog\n"), None);
}

#[test]
fn a_new_entry_passes() {
    assert_eq!(check(BASE, &with_entry("- two")), Ok(()));
    assert_eq!(check(BASE, &with_entry("* two")), Ok(()));
    assert_eq!(check("", BASE), Ok(()), "the file is new");
    assert_eq!(
        check(BASE, &BASE.replace("- one", "- one, reworded")),
        Ok(())
    );
}

#[test]
fn a_release_passes() {
    let released = BASE.replace(
        "## [Unreleased]\n\n### Added\n\n- one\n",
        "## [Unreleased]\n\n## [0.2.0]\n\n### Added\n\n- one\n",
    );
    assert_eq!(check(BASE, &released), Ok(()));
}

#[test]
fn no_new_entry_fails() {
    assert!(check(BASE, BASE).is_err());
    assert!(
        check(BASE, &with_entry("### Fixed")).is_err(),
        "a heading is no entry"
    );
    assert!(check(BASE, &with_entry("   ")).is_err());
    let dropped = BASE.replace("- one\n", "");
    assert!(check(BASE, &dropped).is_err());
    let moved = format!("{BASE}- one\n");
    assert!(
        check(BASE, &moved).is_err(),
        "an entry under a release is not new"
    );
}

#[test]
fn a_duplicated_entry_counts_once_per_copy() {
    assert_eq!(check(BASE, &with_entry("- one")), Ok(()));
}

#[test]
fn a_file_without_an_unreleased_section_fails() {
    let e = check(BASE, "# Changelog\n").unwrap_err();
    assert!(e.contains("no `## [Unreleased]`"), "{e}");
}

#[test]
fn the_context_follows_the_hook_then_the_branch() {
    assert_eq!(context(true, Some("main"), "main"), Ok(Context::Merging));
    assert_eq!(context(true, None, "main"), Ok(Context::Merging));
    assert_eq!(context(false, Some("main"), "main"), Ok(Context::MainTip));
    assert_eq!(context(false, Some("trunk"), "trunk"), Ok(Context::MainTip));
    assert_eq!(context(false, Some("fix/x"), "main"), Ok(Context::Branch));
    assert!(context(false, None, "main").is_err());
}

/// A scratch repository with real git and no hooks.
struct Repo(PathBuf);
impl Drop for Repo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Repo {
    fn new(name: &str) -> Repo {
        let r = Repo::empty(name);
        r.write(BASE);
        r.commit("base");
        r
    }

    /// `git init` alone: `main` is unborn.
    fn empty(name: &str) -> Repo {
        let dir =
            std::env::temp_dir().join(format!("xtask-changelog-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let r = Repo(dir);
        r.git(&["init", "-q", "-b", "main"]);
        r
    }

    fn git(&self, args: &[&str]) {
        let out = xtask::git::command()
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
            ])
            .args(args)
            .current_dir(&self.0)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn write(&self, text: &str) {
        std::fs::write(self.0.join("CHANGELOG.md"), text).unwrap();
    }

    fn commit(&self, message: &str) {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "--allow-empty", "-m", message]);
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

#[test]
fn a_branch_needs_an_entry_committed_or_not() {
    let r = Repo::new("branch");
    r.git(&["switch", "-q", "-c", "fix/x"]);
    std::fs::write(r.path().join("code.rs"), "fn f() {}\n").unwrap();
    r.commit("code");
    assert!(changelog_in(r.path(), false, "main").is_err(), "no entry");
    r.write(&with_entry("- fixed f"));
    assert_eq!(
        changelog_in(r.path(), false, "main"),
        Ok(()),
        "uncommitted entry"
    );
    r.commit("entry");
    assert_eq!(
        changelog_in(r.path(), false, "main"),
        Ok(()),
        "committed entry"
    );
}

#[test]
fn a_merge_in_a_hook_compares_head_with_the_merged_tree() {
    let r = Repo::new("merge");
    r.git(&["switch", "-q", "-c", "fix/with"]);
    r.write(&with_entry("- with an entry"));
    r.commit("with");
    r.git(&["switch", "-q", "main"]);
    r.git(&["switch", "-q", "-c", "fix/without"]);
    std::fs::write(r.path().join("code.rs"), "fn f() {}\n").unwrap();
    r.commit("without");
    r.git(&["switch", "-q", "main"]);
    // The state `pre-merge-commit` and a concluding `pre-commit` see: on
    // main, the merged tree on disk.
    r.git(&["merge", "-q", "--no-ff", "--no-commit", "fix/without"]);
    assert!(changelog_in(r.path(), true, "main").is_err());
    r.git(&["merge", "--abort"]);
    r.git(&["merge", "-q", "--no-ff", "--no-commit", "fix/with"]);
    assert_eq!(changelog_in(r.path(), true, "main"), Ok(()));
}

#[test]
fn on_main_the_merge_at_head_is_checked() {
    let r = Repo::new("tip");
    r.git(&["switch", "-q", "-c", "fix/with"]);
    r.write(&with_entry("- with an entry"));
    r.commit("with");
    r.git(&["switch", "-q", "main"]);
    r.git(&["merge", "-q", "--no-ff", "-m", "merge with", "fix/with"]);
    assert_eq!(changelog_in(r.path(), false, "main"), Ok(()));
    r.git(&["switch", "-q", "-c", "fix/without"]);
    std::fs::write(r.path().join("code.rs"), "fn f() {}\n").unwrap();
    r.commit("without");
    r.git(&["switch", "-q", "main"]);
    r.git(&[
        "merge",
        "-q",
        "--no-ff",
        "-m",
        "merge without",
        "fix/without",
    ]);
    assert!(changelog_in(r.path(), false, "main").is_err());
}

#[test]
fn a_detached_head_outside_a_hook_fails() {
    let r = Repo::new("detached");
    r.git(&["switch", "-q", "--detach"]);
    assert!(
        changelog_in(r.path(), false, "main")
            .unwrap_err()
            .contains("detached")
    );
}

const NO_ENTRY: &str = "# Changelog\n\n## [Unreleased]\n";

#[test]
fn before_the_first_commit_the_file_on_disk_needs_an_entry() {
    let r = Repo::empty("unborn");
    r.write(NO_ENTRY);
    assert!(changelog_in(r.path(), false, "main").is_err());
    r.write(BASE);
    assert_eq!(changelog_in(r.path(), false, "main"), Ok(()));
}

#[test]
fn a_first_commit_on_main_needs_an_entry() {
    // A generated project's first commit lands on main directly.
    let r = Repo::new("root");
    assert_eq!(changelog_in(r.path(), false, "main"), Ok(()));
    let bare = Repo::empty("root-bare");
    bare.write(NO_ENTRY);
    bare.commit("base");
    assert!(changelog_in(bare.path(), false, "main").is_err());
}

#[test]
fn a_later_commit_on_main_that_is_not_a_merge_fails() {
    let r = Repo::new("linear");
    r.write(&with_entry("- straight onto main"));
    r.commit("direct");
    assert!(
        changelog_in(r.path(), false, "main")
            .unwrap_err()
            .contains("not a merge")
    );
}

#[test]
fn a_branch_with_nothing_on_main_needs_an_entry() {
    let r = Repo::empty("no-main");
    r.git(&["switch", "-q", "-c", "feat/x"]);
    r.write(NO_ENTRY);
    r.commit("start");
    assert!(changelog_in(r.path(), false, "main").is_err());
    r.write(BASE);
    assert_eq!(changelog_in(r.path(), false, "main"), Ok(()));
}

#[test]
fn a_main_that_exists_only_on_a_remote_is_still_the_base() {
    // A clone working on a branch without a local main: the remote's main
    // is the base, not an empty file.
    let origin = Repo::new("origin");
    let clone = Repo::empty("clone");
    clone.git(&["remote", "add", "origin", origin.path().to_str().unwrap()]);
    clone.git(&["fetch", "-q", "origin"]);
    clone.git(&["switch", "-q", "-c", "feat/x", "origin/main"]);
    std::fs::write(clone.path().join("code.rs"), "fn f() {}\n").unwrap();
    clone.commit("code");
    assert!(
        changelog_in(clone.path(), false, "main").is_err(),
        "no entry"
    );
    clone.write(&with_entry("- remote-based"));
    assert_eq!(changelog_in(clone.path(), false, "main"), Ok(()));
}

#[test]
fn origin_wins_over_other_remotes() {
    // `fork` sorts first and is stale: its main lacks origin's entry, which
    // would then count as this branch's.
    let origin = Repo::new("o");
    let fork = Repo::new("fork-remote");
    origin.write(&with_entry("- on origin"));
    origin.commit("origin entry");
    let clone = Repo::empty("multi");
    clone.git(&["remote", "add", "origin", origin.path().to_str().unwrap()]);
    clone.git(&["remote", "add", "fork", fork.path().to_str().unwrap()]);
    clone.git(&["fetch", "-q", "--all"]);
    clone.git(&["switch", "-q", "-c", "feat/x", "origin/main"]);
    std::fs::write(clone.path().join("code.rs"), "fn f() {}\n").unwrap();
    clone.commit("code");
    assert!(changelog_in(clone.path(), false, "main").is_err());
}
