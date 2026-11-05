// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Colony's own memory across a restart: the `cells`, `nodes` and `colony.db` files.
use qinit_colony::{Counters, Reason, SavedTerminal};
use qinit_colonyd::state::{CellLine, NodeLine, State};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

/// A temporary run directory removed when it goes out of scope.
struct Run(PathBuf);

impl Run {
    fn new(tag: &str) -> Run {
        let d = std::env::temp_dir().join(format!("qinit-state-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Run(d)
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn cells() -> Vec<CellLine> {
    vec![
        CellLine {
            name: "db".into(),
            cgroup_id: 4_242,
            ready: true,
            pid: 311,
            start_time: 9_001,
        },
        CellLine {
            name: "getty@tty1".into(),
            cgroup_id: 77,
            ready: false,
            pid: 0,
            start_time: 0,
        },
    ]
}

fn nodes() -> Vec<NodeLine> {
    let counters = Counters {
        burst_begin_ms: 10,
        burst_count: 4,
        backoff_exp: 2,
        last_start_ms: 30,
        ended_ms: 40,
    };
    vec![
        NodeLine {
            name: "a".into(),
            wanted: true,
            terminal: None,
            counters: Counters::default(),
        },
        NodeLine {
            name: "crashy".into(),
            wanted: true,
            terminal: Some(SavedTerminal::Quarantined(Reason::Breaker)),
            counters,
        },
        NodeLine {
            name: "job".into(),
            wanted: false,
            terminal: Some(SavedTerminal::Done),
            counters: Counters::default(),
        },
        NodeLine {
            name: "x".into(),
            wanted: false,
            terminal: Some(SavedTerminal::Quarantined(Reason::StopFailed)),
            counters,
        },
    ]
}

#[test]
fn cells_and_nodes_round_trip() {
    let run = Run::new("round");
    let s = State::open(&run.0).unwrap();
    assert_eq!(s.read_cells(), Ok(None), "absent is not an error");
    s.write_cells(&cells()).unwrap();
    s.write_nodes(&nodes()).unwrap();
    s.write_db(b"database bytes\0\xff").unwrap();
    assert_eq!(s.read_cells(), Ok(Some(cells())));
    assert_eq!(s.read_nodes(), Ok(Some(nodes())));
    assert_eq!(
        s.read_db().unwrap().as_deref(),
        Some(&b"database bytes\0\xff"[..])
    );
    s.clear();
    assert_eq!(s.read_cells(), Ok(None));
    assert_eq!(s.read_nodes(), Ok(None));
    assert_eq!(s.read_db(), Ok(None));
}

#[test]
fn every_reason_word_round_trips() {
    let run = Run::new("reasons");
    let s = State::open(&run.0).unwrap();
    let lines: Vec<NodeLine> = [
        Reason::Breaker,
        Reason::Cascade,
        Reason::StartTimeout,
        Reason::StopFailed,
    ]
    .into_iter()
    .enumerate()
    .map(|(i, r)| NodeLine {
        name: format!("n{i}"),
        wanted: true,
        terminal: Some(SavedTerminal::Quarantined(r)),
        counters: Counters::default(),
    })
    .collect();
    s.write_nodes(&lines).unwrap();
    assert_eq!(s.read_nodes(), Ok(Some(lines)));
}

#[test]
fn a_malformed_line_refuses_the_file() {
    let run = Run::new("bad");
    let s = State::open(&run.0).unwrap();
    let dir = run.0.join("state");
    std::fs::write(dir.join("cells"), "db 1 1 2 3\nbroken line\n").unwrap();
    let err = s.read_cells().unwrap_err();
    assert!(err.contains("line 2"), "{err}");
    std::fs::write(dir.join("cells"), "db 1 2 3 4\n").unwrap();
    assert!(
        s.read_cells().unwrap_err().contains("line 1"),
        "ready must be 0 or 1"
    );
    std::fs::write(
        dir.join("nodes"),
        "a 1 off 0 0 0 0 0\nb 1 sleeping 0 0 0 0 0\n",
    )
    .unwrap();
    assert!(s.read_nodes().unwrap_err().contains("line 2"));
    std::fs::write(dir.join("nodes"), "a 1 quarantined:wat 0 0 0 0 0\n").unwrap();
    assert!(s.read_nodes().unwrap_err().contains("line 1"));
    std::fs::write(dir.join("nodes"), "a 1 off 0 0 0 0 -5\n").unwrap();
    assert!(
        s.read_nodes().unwrap_err().contains("line 1"),
        "a negative time"
    );
}

#[test]
fn files_are_0600_and_the_directory_0700() {
    let run = Run::new("modes");
    let s = State::open(&run.0).unwrap();
    s.write_cells(&cells()).unwrap();
    s.write_nodes(&nodes()).unwrap();
    s.write_db(b"x").unwrap();
    let dir = run.0.join("state");
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    for f in ["cells", "nodes", "colony.db"] {
        let m = std::fs::metadata(dir.join(f)).unwrap();
        assert_eq!(m.permissions().mode() & 0o7777, 0o600, "{f}");
        assert_eq!(m.uid(), unsafe_free_uid(), "{f} belongs to the writer");
    }
    // No temporary file is left behind.
    let mut left: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    left.sort();
    assert_eq!(left, ["cells", "colony.db", "nodes"]);
}

/// The uid of the running process, read from a file it just made.
fn unsafe_free_uid() -> u32 {
    let probe = std::env::temp_dir().join(format!("qinit-uid-{}", std::process::id()));
    std::fs::write(&probe, b"").unwrap();
    let uid = std::fs::metadata(&probe).unwrap().uid();
    std::fs::remove_file(&probe).unwrap();
    uid
}

#[test]
fn a_write_is_a_rename_not_a_truncate() {
    let run = Run::new("rename");
    let s = State::open(&run.0).unwrap();
    s.write_nodes(&nodes()).unwrap();
    let mut old = std::fs::File::open(run.0.join("state/nodes")).unwrap();
    s.write_nodes(&nodes()[..1]).unwrap();
    let mut text = String::new();
    old.read_to_string(&mut text).unwrap();
    assert_eq!(
        text.lines().count(),
        4,
        "a reader holding the old file still reads all of it"
    );
    assert_eq!(s.read_nodes().unwrap().unwrap().len(), 1);
}

#[test]
fn a_state_directory_that_is_a_symlink_or_a_file_is_refused() {
    let run = Run::new("link");
    let elsewhere = run.0.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, run.0.join("state")).unwrap();
    assert!(State::open(&run.0).is_err(), "a symlink named state");
    std::fs::remove_file(run.0.join("state")).unwrap();
    std::fs::write(run.0.join("state"), b"").unwrap();
    assert!(State::open(&run.0).is_err(), "a file named state");
}

#[test]
fn an_existing_state_directory_is_kept_and_made_private() {
    let run = Run::new("reopen");
    let dir = run.0.join("state");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(dir.join("cells"), "db 1 1 2 3\n").unwrap();
    let s = State::open(&run.0).unwrap();
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    assert_eq!(
        s.read_cells().unwrap().unwrap().len(),
        1,
        "what was there is still there"
    );
}

#[test]
fn the_start_time_is_field_22_even_when_the_command_name_holds_spaces_and_brackets() {
    use qinit_colonyd::state::parse_start_time;
    let line = "311 (my (odd) name) S 1 311 311 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10 \
                18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0";
    assert_eq!(parse_start_time(line), Some(987_654));
    assert_eq!(parse_start_time("garbage"), None);
    assert_eq!(parse_start_time("1 (x) S 1 2"), None, "a short line");
    // And for a real process.
    assert!(qinit_colonyd::state::start_time(i32::try_from(std::process::id()).unwrap()).is_some());
}
