// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use xtask::sleeps::{MARKER, PATTERN, is_sleep, ledger, scan};

const LEDGER: &str = "\
### D3 — Kept on purpose · `ACCEPTED`\n\
### D4 — Gone · `RESOLVED` (fix/x)\n\
### D12 — Later · `OPEN`\n";

fn call() -> String {
    format!("    std::{PATTERN}(d);")
}

#[test]
fn the_ledger_is_read_by_id_and_status() {
    let l = ledger(LEDGER);
    assert_eq!(l.get(&3).map(String::as_str), Some("ACCEPTED"));
    assert_eq!(l.get(&4).map(String::as_str), Some("RESOLVED"));
    assert_eq!(l.get(&12).map(String::as_str), Some("OPEN"));
    assert_eq!(l.len(), 3);
}

#[test]
fn sleeps_hit() {
    for line in [
        call(),
        format!("use std::{PATTERN};"),
        "use std::thread::{self, sleep};".to_string(),
    ] {
        assert!(is_sleep(&line), "{line}");
        assert_eq!(scan(&line, &ledger(LEDGER)).len(), 1, "{line}");
    }
}

#[test]
fn near_misses_pass() {
    for line in [
        r#".args(["sleep", "300"])"#,
        "fn sleeping(marker: &str) -> bool {",
        "use std::thread::{self, spawn};",
        "// a sleeper process",
    ] {
        assert!(!is_sleep(line), "{line}");
        assert!(scan(line, &ledger(LEDGER)).is_empty(), "{line}");
    }
}

#[test]
fn a_marker_citing_an_accepted_entry_exempts_its_line_only() {
    let text = format!("{} // {MARKER} (D3)\n{}\n", call(), call());
    let hits = scan(&text, &ledger(LEDGER));
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].line, 2);
}

#[test]
fn a_marker_citing_anything_else_is_a_hit() {
    for (cite, why) in [
        ("(D9)", "D9 is not in DEFERRED.md"),
        ("(D4)", "D4 is RESOLVED, not ACCEPTED"),
        ("(D12)", "D12 is OPEN, not ACCEPTED"),
        ("(polls the kernel)", "the marker must cite a ledger entry"),
        ("", "the marker must cite a ledger entry"),
    ] {
        let text = format!("{} // {MARKER} {cite}", call());
        let hits = scan(&text, &ledger(LEDGER));
        assert_eq!(hits.len(), 1, "{cite}");
        assert!(hits[0].why.starts_with(why), "{cite}: {}", hits[0].why);
    }
}

#[test]
fn a_marker_on_a_line_without_a_sleep_is_stale() {
    let hits = scan(&format!("let x = 1; // {MARKER} (D3)"), &ledger(LEDGER));
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].why, "a marker on a line that does not sleep");
}

#[test]
fn a_tree_without_rust_sources_fails() {
    let dir = std::env::temp_dir().join(format!("xtask-sleeps-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let git = |args: &[&str]| {
        assert!(
            xtask::git::command()
                .args(args)
                .current_dir(&dir)
                .status()
                .unwrap()
                .success()
        );
    };
    git(&["init", "-q"]);
    std::fs::write(dir.join("DEFERRED.md"), LEDGER).unwrap();
    std::fs::write(dir.join("README.md"), "no code").unwrap();
    let result = xtask::gates::sleep_scan(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(result.unwrap_err().contains("vacuously"));
}

#[test]
fn sleep_in_a_multi_line_thread_import_hits() {
    let text = "use std::thread::{\n    sleep, spawn,\n};\nfn f() {}\n";
    let hits = scan(text, &ledger(LEDGER));
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].line, 2);
    let other = "use std::io::{\n    sleep,\n};\n";
    assert!(scan(other, &ledger(LEDGER)).is_empty(), "not std::thread");
}

#[test]
fn nested_and_public_thread_imports_hit() {
    let nested = "use std::{\n    thread::{sleep, spawn},\n    io,\n};\n";
    let hits = scan(nested, &ledger(LEDGER));
    assert_eq!(
        hits.iter().map(|h| h.line).collect::<Vec<_>>(),
        [2],
        "{hits:?}"
    );
    for line in [
        "pub use std::thread::{sleep};",
        "pub(crate) use std::thread::{self, sleep};",
    ] {
        assert_eq!(scan(line, &ledger(LEDGER)).len(), 1, "{line}");
    }
    let other = "use std::{\n    io::{sleep},\n    thread::{spawn},\n};\n";
    assert!(
        scan(other, &ledger(LEDGER)).is_empty(),
        "not std::thread's sleep"
    );
}

#[test]
fn the_scaffolds_ledger_headings_are_read_too() {
    let l = ledger("### D1 · OPEN · Replace the worked examples\n### D2 · ACCEPTED · Kept\n");
    assert_eq!(l.get(&1).map(String::as_str), Some("OPEN"));
    assert_eq!(l.get(&2).map(String::as_str), Some("ACCEPTED"));
    let title = ledger("### D5 — OPEN questions about RESOLVED work · `ACCEPTED`\n");
    assert_eq!(
        title.get(&5).map(String::as_str),
        Some("ACCEPTED"),
        "the backticked status wins over words in the title"
    );
}

#[test]
fn a_stray_backtick_in_a_title_does_not_shift_the_status() {
    let l = ledger("### D9 — OPEN a ` b · `ACCEPTED`\n");
    assert_eq!(l.get(&9).map(String::as_str), Some("ACCEPTED"));
}

#[test]
fn a_thread_sleep_path_inside_a_multi_line_std_import_hits() {
    // rustfmt's shape for a long std import.
    let text = format!("use std::{{\n    {PATTERN},\n    time::Duration,\n}};\n");
    let hits = scan(&text, &ledger(LEDGER));
    assert_eq!(
        hits.iter().map(|h| h.line).collect::<Vec<_>>(),
        [2],
        "{hits:?}"
    );
}

#[test]
fn a_braced_use_closed_at_the_end_of_a_line_ends_the_import() {
    let text = format!(
        "use std::{{\n    io, fs}};\nfn f() {{ {}; }}\n",
        call().trim()
    );
    let hits = scan(&text, &ledger(LEDGER));
    assert_eq!(
        hits.iter().map(|h| h.line).collect::<Vec<_>>(),
        [3],
        "{hits:?}"
    );
}

#[test]
fn a_group_closing_inside_a_multi_line_use_keeps_the_use_open() {
    let text =
        "use std::{\n    sync::{\n        Arc, Mutex,\n    },\n    thread::{sleep, spawn},\n};\n";
    let hits = scan(text, &ledger(LEDGER));
    assert_eq!(
        hits.iter().map(|h| h.line).collect::<Vec<_>>(),
        [5],
        "{hits:?}"
    );
}

#[test]
fn a_thread_group_opened_on_its_own_line_inside_a_use_hits() {
    let text = "use std::{\n    thread::{\n        sleep,\n        spawn,\n    },\n    io,\n};\n";
    let hits = scan(text, &ledger(LEDGER));
    assert_eq!(
        hits.iter().map(|h| h.line).collect::<Vec<_>>(),
        [3],
        "{hits:?}"
    );
    let other = "use std::{\n    io::{\n        sleep,\n    },\n};\n";
    assert!(scan(other, &ledger(LEDGER)).is_empty(), "not std::thread");
}
