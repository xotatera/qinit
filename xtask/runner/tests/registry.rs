// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pins qinit's actual stages: the repository and its tooling workspace.

use qinit_xtask::STAGES;

#[test]
fn qinit_has_only_repository_and_tooling_stages() {
    let stages: Vec<(&str, &str)> = STAGES.iter().map(|s| (s.name, s.dir)).collect();
    assert_eq!(stages, [("repo", ""), ("xtask", "xtask")]);
}

#[test]
fn repository_stage_starts_with_the_review_canary() {
    let names: Vec<&str> = qinit_xtask::repo_registry()
        .iter()
        .map(|gate| gate.name)
        .collect();
    assert_eq!(names, ["canary"]);
}

#[test]
fn canary_reports_the_human_review_instruction_only_on_main() {
    assert_eq!(qinit_xtask::canary(false, true), Ok(()));
    assert_eq!(qinit_xtask::canary(true, false), Ok(()));
    let failure = qinit_xtask::canary(true, true).unwrap_err();
    assert!(failure.contains("Remove these two lines to confirm"));
}
