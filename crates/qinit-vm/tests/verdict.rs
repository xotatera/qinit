// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use qinit_vm::verdict::{Outcome, judge, parse};

#[test]
fn verdict_lines_are_read_and_others_ignored() {
    let serial = "[    0.1] boot noise\r\nQINIT-VM spawn first PASS\r\nQINIT-VM spawn second FAIL child left fd 4 open\r\nQINIT-VM other x PASS\r\nQINIT-VM spawn END\r\n";
    let r = parse("spawn", serial);
    assert!(r.finished);
    assert_eq!(r.verdicts.len(), 2);
    assert_eq!(r.verdicts[0].case, "first");
    assert_eq!(r.verdicts[0].outcome, Outcome::Pass);
    assert_eq!(
        r.verdicts[1].outcome,
        Outcome::Fail("child left fd 4 open".into())
    );
    let e = judge("spawn", &r).unwrap_err();
    assert!(
        e.contains("second") && e.contains("child left fd 4 open"),
        "{e}"
    );
}

#[test]
fn a_suite_without_its_end_line_failed() {
    let r = parse("ready", "QINIT-VM ready one PASS\n");
    assert!(!r.finished);
    assert!(judge("ready", &r).unwrap_err().contains("never finished"));
}

#[test]
fn a_finished_suite_with_no_case_failed() {
    let r = parse("probe", "QINIT-VM probe END\n");
    assert!(judge("probe", &r).unwrap_err().contains("no case"));
}

#[test]
fn all_passes_count() {
    let r = parse(
        "probe",
        "QINIT-VM probe a PASS\nQINIT-VM probe b PASS\nQINIT-VM probe END\n",
    );
    assert_eq!(judge("probe", &r), Ok(2));
}
