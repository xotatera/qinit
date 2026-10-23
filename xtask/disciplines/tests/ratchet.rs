// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The lint ratchet's pure logic: lint tables read from manifest text, the
//! clippy runs they need, and clippy's JSON judged against them. The
//! fixtures are real `cargo clippy --workspace --all-targets
//! --message-format=json` output (clippy 1.99.0) from a two-crate workspace
//! at `/ws`, trimmed to the fields the judge reads: `a` depends on `b`;
//! `doc_markdown` fires three times (once in `b`, twice in `a`),
//! `must_use_candidate` twice in `a`, plus an unused variable and a
//! `cast_possible_truncation` in `a`; each finding appears once per target.
//! `clippy-error.jsonl` is a type error in `b`.
use std::collections::BTreeSet;
use std::path::Path;

use xtask::ratchet::{self, Allow, Governed, Policy, Run, Table, Verdict};

const RUN: &str = include_str!("fixtures/clippy-ratchet.jsonl");
const ERROR: &str = include_str!("fixtures/clippy-error.jsonl");

fn allow(lint: &str, ratchet: Option<usize>, at: usize) -> Allow {
    Allow {
        lint: lint.to_string(),
        clippy: true,
        ratchet,
        line: at,
    }
}

fn table(what: &str, allows: Vec<Allow>, packages: &[&str]) -> Governed {
    Governed {
        what: what.to_string(),
        allows,
        packages: names(packages),
    }
}

fn names(packages: &[&str]) -> BTreeSet<String> {
    packages.iter().map(|p| (*p).to_string()).collect()
}

fn policy(tables: Vec<Governed>) -> Policy {
    Policy {
        tables,
        ungoverned: BTreeSet::new(),
        errors: Vec::new(),
        build_root: "/ws/target".to_string(),
    }
}

/// The fixture's findings other than `doc_markdown`, as the judge renders
/// their first lines (`must_use_candidate` at two places).
const OTHERS: [&str; 4] = [
    "warning: unused variable: `unused`",
    "warning: this function could have a `#[must_use]` attribute",
    "warning: this function could have a `#[must_use]` attribute",
    "warning: casting `u64` to `u32` may truncate the value",
];

fn first_lines(failures: &[String]) -> Vec<&str> {
    failures
        .iter()
        .map(|f| f.lines().next().unwrap_or_default())
        .collect()
}

#[test]
fn workspace_allows_carry_ratchets_or_justifications() {
    let manifest = r#"[workspace]
members = ["a"]

[workspace.lints.rust]
unsafe_code = "forbid"
dead_code = "allow"  # generated bindings

[workspace.lints.clippy]
pedantic = { level = "warn", priority = -1 }
doc_markdown = "allow"  # ratchet: 3
"module_name_repetitions" = { level = "allow", priority = 1 }  # names mirror the spec
must_use_candidate = "allow"
similar_names = "allow"  # ratchet: lots
too-many-lines = "allow"  # Ratchet 4
cast_lossless = "allow"  # RATCHET:2
needless_return = "allow"  # ratchet: 0
nursery = "allow"  # ratchet: 7
"#;
    let (allows, errors) = ratchet::allows(manifest, Table::Workspace);
    assert_eq!(
        allows,
        [
            Allow {
                lint: "dead_code".to_string(),
                clippy: false,
                ratchet: None,
                line: 6
            },
            allow("doc_markdown", Some(3), 10),
            allow("module_name_repetitions", None, 11),
            allow("too_many_lines", Some(4), 14),
            allow("cast_lossless", Some(2), 15),
        ]
    );
    assert_eq!(
        errors,
        [
            "line 12: `must_use_candidate` is allowed without a justification comment",
            "line 13: `similar_names`: bad ratchet count `ratchet: lots`",
            "line 16: `needless_return`: a ratchet of 0 is a fixed lint: delete the allow line",
            "line 17: `nursery` is a lint group: ratchet its lints one by one (clippy reports each by name)",
        ]
    );
    assert_eq!(
        ratchet::allows(manifest, Table::Package),
        (Vec::new(), Vec::new()),
        "the workspace's tables are not a package's"
    );
}

#[test]
fn other_spellings_inline_tables_rust_ratchets_and_warnings() {
    let manifest = r#"[package]
name = "p"
description = "a # inside a string is not a comment" # but this is

[lints]
clippy.doc_markdown = "allow"  # ratchet: 1
rust = { dead_code = "allow" }
rust.unused = "allow"  # ratchet: 2
clippy.pedantic = { level = "warn", priority = -1 }
rust.warnings = "allow"  # quiet

[lints.clippy.similar_names]
level = "allow"  # names mirror the paper
priority = 1
"#;
    let (allows, errors) = ratchet::allows(manifest, Table::Package);
    assert_eq!(
        allows,
        [
            allow("doc_markdown", Some(1), 6),
            allow("similar_names", None, 13)
        ]
    );
    assert_eq!(
        errors,
        [
            "line 7: an allow inside an inline table: give it its own line and a justification comment",
            "line 8: `unused`: ratchets are for clippy lints",
            "line 10: allowing `warnings` hides every warning from the lint gate",
        ]
    );
    let nested = "[workspace]\nlints = { clippy = { doc_markdown = \"allow\" } }\n";
    assert_eq!(
        ratchet::allows(nested, Table::Workspace).1,
        [
            "line 2: an allow inside an inline table: give it its own line and a justification comment"
        ]
    );
}

#[test]
fn a_package_is_governed_by_the_workspace_its_own_table_or_nothing() {
    let governed = |m: &str| ratchet::governed_by(&format!("[package]\nname = \"p\"\n{m}"));
    assert_eq!(
        governed("[lints]\nworkspace = true\n"),
        Some(Table::Workspace)
    );
    assert_eq!(
        governed("[lints.clippy]\nall = \"warn\"\n"),
        Some(Table::Package)
    );
    assert_eq!(
        governed("[lints]\nclippy.all = \"warn\"\n"),
        Some(Table::Package)
    );
    assert_eq!(
        ratchet::governed_by("lints = { clippy = { all = \"warn\" } }\n[package]\nname = \"p\"\n"),
        Some(Table::Package)
    );
    assert_eq!(governed("[lints.clippyx]\nall = \"warn\"\n"), None);
    assert_eq!(governed("# [lints]\n# workspace = true\n"), None);
}

#[test]
fn package_ids_name_their_package() {
    assert_eq!(ratchet::package_name("path+file:///ws/a#0.1.0"), "a");
    assert_eq!(
        ratchet::package_name("path+file:///ws/dir#name@0.1.0"),
        "name"
    );
}

#[test]
fn packages_are_grouped_by_the_lints_their_table_ratchets() {
    let mut p = policy(vec![
        table(
            "Cargo.toml",
            vec![
                allow("doc_markdown", Some(3), 10),
                allow("must_use_candidate", None, 11),
            ],
            &["a", "b"],
        ),
        table(
            "c/Cargo.toml",
            vec![allow("similar_names", None, 4)],
            &["c"],
        ),
    ]);
    p.ungoverned = names(&["d"]);
    assert_eq!(
        ratchet::groups(&p, false),
        [
            Run {
                packages: vec!["c".to_string(), "d".to_string()],
                warn: BTreeSet::new()
            },
            Run {
                packages: vec!["a".to_string(), "b".to_string()],
                warn: names(&["doc_markdown"])
            },
        ]
    );
    let measuring = ratchet::groups(&p, true);
    assert_eq!(measuring.len(), 3, "{measuring:#?}");
    assert!(measuring.contains(&Run {
        packages: vec!["a".to_string(), "b".to_string()],
        warn: names(&["doc_markdown", "must_use_candidate"])
    }));
    let one = policy(vec![table("Cargo.toml", Vec::new(), &["a", "b"])]);
    assert_eq!(ratchet::groups(&one, false).len(), 1);
}

#[test]
fn an_exact_ratchet_passes_and_every_other_finding_fails_once() {
    let p = policy(vec![table(
        "Cargo.toml",
        vec![
            allow("doc_markdown", Some(3), 10),
            allow("must_use_candidate", None, 11),
        ],
        &["a", "b"],
    )]);
    // A permanent allow does not budget findings that still arrive (a
    // source attribute re-enabled the lint).
    let v = ratchet::judge(&p, RUN);
    assert_eq!(first_lines(&v.findings), OTHERS);
    assert_eq!(v.counts, Vec::<String>::new());
}

#[test]
fn a_count_that_moved_names_both_numbers() {
    let judge = |n: usize| {
        let p = policy(vec![table(
            "Cargo.toml",
            vec![allow("doc_markdown", Some(n), 10)],
            &["a", "b"],
        )]);
        ratchet::judge(&p, RUN).counts
    };
    assert_eq!(judge(3), Vec::<String>::new());
    assert_eq!(
        judge(2),
        ["Cargo.toml:10: `doc_markdown` has 3 findings, the ratchet allows 2: fix the new ones"]
    );
    assert_eq!(
        judge(5),
        ["Cargo.toml:10: `doc_markdown` is down to 3 findings: lower its ratchet from 5 to 3"]
    );
    let none = policy(vec![table(
        "Cargo.toml",
        vec![allow("needless_pass_by_value", Some(1), 9)],
        &["a", "b"],
    )]);
    assert!(
        ratchet::judge(&none, RUN).counts.contains(
            &"Cargo.toml:9: `needless_pass_by_value` has no findings left: delete its allow line"
                .to_string()
        )
    );
}

#[test]
fn each_table_counts_only_its_own_packages() {
    // `b`'s table does not ratchet `doc_markdown`: its finding fails, and
    // `a`'s ratchet counts `a`'s two.
    let p = policy(vec![
        table("Cargo.toml", Vec::new(), &["b"]),
        table(
            "a/Cargo.toml",
            vec![allow("doc_markdown", Some(2), 7)],
            &["a"],
        ),
    ]);
    let failures = ratchet::judge(&p, RUN).findings;
    assert_eq!(
        first_lines(&failures),
        [
            "warning: item in documentation is missing backticks",
            OTHERS[0],
            OTHERS[1],
            OTHERS[2],
            OTHERS[3]
        ]
    );
    assert!(failures[0].contains("b/src/lib.rs"), "{failures:#?}");
}

#[test]
fn packages_outside_the_workspace_are_not_judged() {
    let only_b = policy(vec![table("Cargo.toml", Vec::new(), &["b"])]);
    let failures = ratchet::judge(&only_b, RUN).findings;
    assert_eq!(
        failures.len(),
        1,
        "a's findings are not judged: {failures:#?}"
    );
    let mut ungoverned = policy(Vec::new());
    ungoverned.ungoverned = names(&["a", "b"]);
    assert_eq!(
        ratchet::judge(&ungoverned, RUN).findings.len(),
        7,
        "a member no table governs is judged"
    );
}

#[test]
fn errors_fail_and_notes_do_not() {
    let p = policy(vec![table("Cargo.toml", Vec::new(), &["a", "b"])]);
    let failures = ratchet::judge(&p, ERROR).findings;
    assert_eq!(failures.len(), 1, "{failures:#?}");
    assert!(
        failures[0].starts_with("error[E0308]: mismatched types"),
        "{failures:#?}"
    );
    assert_eq!(
        ratchet::judge(&p, "not json\n{\"reason\": \"build-finished\"}\n"),
        Verdict::default()
    );
}

#[test]
fn measure_prints_ready_lines_per_table() {
    let p = policy(vec![
        table(
            "Cargo.toml",
            vec![
                allow("doc_markdown", Some(9), 10),
                Allow {
                    clippy: false,
                    ..allow("dead_code", None, 5)
                },
            ],
            &["b"],
        ),
        table(
            "a/Cargo.toml",
            vec![
                allow("doc_markdown", None, 3),
                allow("must_use_candidate", None, 4),
            ],
            &["a"],
        ),
    ]);
    assert_eq!(
        ratchet::measure(&p, RUN),
        "# Cargo.toml\ndoc_markdown = \"allow\"  # ratchet: 1\n# a/Cargo.toml\ndoc_markdown = \"allow\"  # ratchet: 2\nmust_use_candidate = \"allow\"  # ratchet: 2\n"
    );
}

const METADATA: &str = r#"{"workspace_root": "/ws", "target_directory": "/ws/target", "packages": [
  {"name": "a", "manifest_path": "/ws/a/Cargo.toml"},
  {"name": "b", "manifest_path": "/ws/b/Cargo.toml"},
  {"name": "c", "manifest_path": "/ws/c/Cargo.toml"}
]}"#;

fn manifests(path: &Path) -> std::io::Result<String> {
    Ok(match path.to_str().unwrap_or_default() {
        "/ws/Cargo.toml" => "[workspace.lints.clippy]\ndoc_markdown = \"allow\"  # ratchet: 1\n",
        "/ws/a/Cargo.toml" => "[package]\nname = \"a\"\n[lints]\nworkspace = true\n",
        "/ws/b/Cargo.toml" => {
            "[package]\nname = \"b\"\n[lints.clippy]\nsimilar_names = \"allow\"\n"
        }
        "/ws/c/Cargo.toml" => "[package]\nname = \"c\"\n",
        _ => return Err(std::io::Error::other("no such manifest")),
    }
    .to_string())
}

#[test]
fn the_policy_comes_from_metadata_and_names_its_manifests() {
    let p = ratchet::policy(METADATA, &manifests).unwrap();
    assert_eq!(
        p.tables,
        [
            table(
                "Cargo.toml",
                vec![allow("doc_markdown", Some(1), 2)],
                &["a"]
            ),
            table("b/Cargo.toml", Vec::new(), &["b"]),
        ]
    );
    assert_eq!(p.ungoverned, names(&["c"]));
    assert_eq!(
        p.errors,
        [
            "b/Cargo.toml: line 4: `similar_names` is allowed without a justification comment",
            "c/Cargo.toml: package `c` has no lint policy: set `[lints] workspace = true`, or give it its own `[lints.clippy]`",
        ]
    );
    let missing = METADATA.replace("/ws/c/", "/ws/gone/");
    assert_eq!(
        ratchet::policy(&missing, &manifests).unwrap_err(),
        "cannot read /ws/gone/Cargo.toml: no such manifest"
    );
    assert!(ratchet::policy("{}", &manifests).is_err());
    assert!(ratchet::policy("nope", &manifests).is_err());
}

/// Two findings of one lint on one line are two places; one finding
/// reported by two targets is one.
#[test]
fn a_place_is_file_line_and_column() {
    let finding = |col: u32| {
        format!(
            r#"{{"reason":"compiler-message","package_id":"path+file:///ws/a#0.1.0","message":{{"level":"warning","code":{{"code":"clippy::doc_markdown"}},"message":"m","spans":[{{"file_name":"a/src/lib.rs","line_start":1,"column_start":{col}}}],"rendered":"r{col}"}}}}"#
        )
    };
    let json = [finding(5), finding(5), finding(9)].join("\n");
    let p = policy(vec![table(
        "Cargo.toml",
        vec![allow("doc_markdown", Some(2), 1)],
        &["a"],
    )]);
    assert_eq!(ratchet::judge(&p, &json), Verdict::default());
}

/// A run lints the members its packages depend on with its own flags;
/// only its own packages' lines are kept.
#[test]
fn a_run_keeps_its_own_packages_lines() {
    let run = Run {
        packages: vec!["a".to_string()],
        warn: BTreeSet::new(),
    };
    let kept = ratchet::own(&run, RUN);
    assert!(
        !kept.is_empty() && kept.lines().all(|l| l.contains("/ws/a#")),
        "{kept}"
    );
    assert_eq!(kept.lines().count(), 12, "a's twelve lines of fourteen");
    let none = Run {
        packages: Vec::new(),
        warn: BTreeSet::new(),
    };
    assert_eq!(ratchet::own(&none, RUN), "");
}

/// Several runs build apart, each in a directory named by its packages.
#[test]
fn each_run_has_its_own_build_directory() {
    let run = |p: &[&str]| Run {
        packages: p.iter().map(|s| (*s).to_string()).collect(),
        warn: BTreeSet::new(),
    };
    let a = ratchet::run_dir("/b", &run(&["a"]));
    assert!(
        a.starts_with("/b/lint/") && a.len() == "/b/lint/".len() + 16,
        "{a}"
    );
    assert_ne!(a, ratchet::run_dir("/b", &run(&["a", "c"])));
    assert_eq!(a, ratchet::run_dir("/b", &run(&["a"])));
    assert_eq!(
        ratchet::policy(METADATA, &manifests).unwrap().build_root,
        "/ws/target"
    );
}
